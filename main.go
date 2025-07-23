package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Message structures for end-to-end encrypted messaging
type Message struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "message", "join", "leave", "key_exchange"
	Metadata  Metadata  `json:"metadata"`
	Encrypted bool      `json:"encrypted"`
	Signature string    `json:"signature,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// MODIFIED: Metadata now supports different content types for E2EE
type Metadata struct {
	// Used for sending E2EE messages. map[recipient_username]encrypted_content
	Content map[string]string `json:"content,omitempty"`
	// Used for simple broadcast messages (join/leave) or for delivering a single encrypted payload
	SingleContent string  `json:"single_content,omitempty"`
	Author        string  `json:"author"`
	AuthorID      string  `json:"author_id"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	DeletedAt     *string `json:"deleted_at,omitempty"`
	ChannelID     string  `json:"channel_id"`
	ChannelName   string  `json:"channel_name"`
	PublicKey     string  `json:"public_key,omitempty"`
	// Used to send the list of existing users to a new joiner
	ExistingUsers map[string]string `json:"existing_users,omitempty"`
}

// Server state for managing connections and rooms
type Server struct {
	connections map[string]*ClientConnection
	rooms       map[string]*Room
	mutex       sync.RWMutex
}

// MODIFIED: ClientConnection now stores the user's public key
type ClientConnection struct {
	ID        string
	Conn      *quic.Conn // Changed to pointer to fix original issue
	UserID    string
	RoomID    string
	PublicKey string // Added to store the client's public key
}

type Room struct {
	ID      string
	Clients map[string]*ClientConnection
	mutex   sync.RWMutex
}

var server *Server

func main() {
	log.Println("Starting Ultra-Secure QUIC Messaging Server...")
	if err := generateCertIfNotExists(); err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}
	server = &Server{
		connections: make(map[string]*ClientConnection),
		rooms:       make(map[string]*Room),
	}
	startServer()
	select {}
}

func startServer() {
	config := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}
	tlsConfig := generateTLSConfig()
	listener, err := quic.ListenAddr(":4433", tlsConfig, config)
	if err != nil {
		log.Fatalf("Error starting QUIC listener: %v", err)
	}
	log.Printf("🔒 Ultra-Secure QUIC server listening on :4433")
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		connID := generateSecureID()
		log.Printf("🔗 New secure connection: %s", connID)
		go handleConnection(conn, connID)
	}
}

func handleConnection(conn *quic.Conn, connID string) {
	defer func() {
		server.mutex.Lock()
		client, exists := server.connections[connID]
		if exists {
			if client.RoomID != "" {
				if room, roomExists := server.rooms[client.RoomID]; roomExists {
					room.mutex.Lock()
					delete(room.Clients, connID)
					room.mutex.Unlock()

					leaveMsg := Message{
						ID:   generateSecureID(),
						Type: "leave",
						Metadata: Metadata{
							Author:        client.UserID,
							SingleContent: fmt.Sprintf("%s has left the room", client.UserID),
							ChannelID:     client.RoomID,
						},
					}
					broadcastSimpleMessageToRoom(client.RoomID, leaveMsg, connID)
				}
			}
			delete(server.connections, connID)
		}
		server.mutex.Unlock()
		conn.CloseWithError(0, "connection closed")
		log.Printf("🔒 Connection %s securely closed", connID)
	}()

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Error accepting stream for %s: %v", connID, err)
			return
		}
		go handleStream(stream, conn, connID)
	}
}

func handleStream(stream *quic.Stream, conn *quic.Conn, connID string) {
	defer stream.Close()
	var msg Message
	if err := json.NewDecoder(stream).Decode(&msg); err != nil {
		if err != io.EOF {
			log.Printf("Error decoding message from %s: %v", connID, err)
		}
		return
	}

	switch msg.Type {
	case "join":
		handleJoin(stream, conn, connID, msg)
	case "message":
		handleMessage(stream, connID, msg)
	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

// REWRITTEN: handleJoin now syncs keys for the new user
func handleJoin(stream *quic.Stream, conn *quic.Conn, connID string, msg Message) {
	server.mutex.Lock()
	room, exists := server.rooms[msg.Metadata.ChannelID]
	if !exists {
		room = &Room{
			ID:      msg.Metadata.ChannelID,
			Clients: make(map[string]*ClientConnection),
		}
		server.rooms[msg.Metadata.ChannelID] = room
	}
	server.mutex.Unlock()

	room.mutex.Lock()
	existingUsers := make(map[string]string)
	for _, c := range room.Clients {
		existingUsers[c.UserID] = c.PublicKey
	}

	client := &ClientConnection{
		ID:        connID,
		Conn:      conn,
		UserID:    msg.Metadata.Author,
		RoomID:    msg.Metadata.ChannelID,
		PublicKey: msg.Metadata.PublicKey,
	}
	room.Clients[connID] = client
	room.mutex.Unlock()

	server.mutex.Lock()
	server.connections[connID] = client
	server.mutex.Unlock()

	log.Printf("👤 User %s (%s) joined room %s", msg.Metadata.Author, connID, msg.Metadata.ChannelID)

	response := Message{
		ID:        generateSecureID(),
		Type:      "join_ack",
		Timestamp: time.Now(),
		Metadata: Metadata{
			SingleContent: "Successfully joined secure room",
			ChannelID:     msg.Metadata.ChannelID,
			ExistingUsers: existingUsers,
		},
	}
	if err := json.NewEncoder(stream).Encode(response); err != nil {
		log.Printf("Error sending join confirmation: %v", err)
	}

	joinMsg := Message{
		ID:        generateSecureID(),
		Type:      "user_joined",
		Timestamp: time.Now(),
		Metadata: Metadata{
			Author:        msg.Metadata.Author,
			SingleContent: fmt.Sprintf("%s joined the room", msg.Metadata.Author),
			ChannelID:     msg.Metadata.ChannelID,
			PublicKey:     msg.Metadata.PublicKey,
		},
	}
	broadcastSimpleMessageToRoom(msg.Metadata.ChannelID, joinMsg, connID)
}

// REWRITTEN: handleMessage now calls the smart broadcast function
func handleMessage(stream *quic.Stream, connID string, msg Message) {
	server.mutex.RLock()
	client, exists := server.connections[connID]
	server.mutex.RUnlock()

	if !exists {
		log.Printf("Client %s not found", connID)
		return
	}

	log.Printf("📨 Encrypted message bundle from %s in room %s", msg.Metadata.Author, msg.Metadata.ChannelID)
	msg.Timestamp = time.Now()
	msg.ID = generateSecureID()

	broadcastEncryptedMessageToRoom(client.RoomID, msg)

	ack := Message{
		ID:   generateSecureID(),
		Type: "message_ack",
		Metadata: Metadata{
			SingleContent: "Message bundle received by server.",
		},
	}
	if err := json.NewEncoder(stream).Encode(ack); err != nil {
		log.Printf("Error sending message ack: %v", err)
	}
}

// NEW: This function acts as a smart relay for E2EE messages
func broadcastEncryptedMessageToRoom(roomID string, msg Message) {
	server.mutex.RLock()
	room, exists := server.rooms[roomID]
	server.mutex.RUnlock()
	if !exists {
		return
	}

	room.mutex.RLock()
	defer room.mutex.RUnlock()

	for _, client := range room.Clients {
		encryptedContent, ok := msg.Metadata.Content[client.UserID]
		if !ok {
			continue // No specific content for this user
		}

		personalMsg := Message{
			ID:        msg.ID,
			Type:      "message",
			Encrypted: true,
			Timestamp: msg.Timestamp,
			Metadata: Metadata{
				Author:        msg.Metadata.Author,
				ChannelID:     msg.Metadata.ChannelID,
				SingleContent: encryptedContent, // Send only the relevant ciphertext
			},
		}

		go func(c *ClientConnection, m Message) {
			stream, err := c.Conn.OpenStreamSync(context.Background())
			if err != nil {
				log.Printf("Error opening stream to %s: %v", c.ID, err)
				return
			}
			defer stream.Close()
			if err := json.NewEncoder(stream).Encode(m); err != nil {
				log.Printf("Error broadcasting to %s: %v", c.ID, err)
			}
		}(client, personalMsg)
	}
}

// RENAMED: This function handles simple, non-E2EE broadcasts like join/leave events
func broadcastSimpleMessageToRoom(roomID string, msg Message, excludeConnID string) {
	server.mutex.RLock()
	room, exists := server.rooms[roomID]
	server.mutex.RUnlock()
	if !exists {
		return
	}

	room.mutex.RLock()
	defer room.mutex.RUnlock()

	for clientID, client := range room.Clients {
		if clientID == excludeConnID {
			continue
		}
		go func(c *ClientConnection) {
			stream, err := c.Conn.OpenStreamSync(context.Background())
			if err != nil {
				log.Printf("Error opening stream to %s: %v", c.ID, err)
				return
			}
			defer stream.Close()
			if err := json.NewEncoder(stream).Encode(msg); err != nil {
				log.Printf("Error broadcasting to %s: %v", c.ID, err)
			}
		}(client)
	}
}

// --- Utility and TLS Functions (Unchanged) ---

func generateTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatalf("Error loading TLS certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"secure-messaging-v1"},
		MinVersion:   tls.VersionTLS13,
	}
}

func generateCertIfNotExists() error {
	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		return generateSelfSignedCert()
	}
	return nil
}

func generateSelfSignedCert() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Secure Messaging"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	certOut, err := os.Create("cert.pem")
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()
	keyOut, err := os.Create("key.pem")
	if err != nil {
		return err
	}
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	keyOut.Close()
	log.Println("🔐 Generated self-signed certificate.")
	return nil
}

func generateSecureID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
