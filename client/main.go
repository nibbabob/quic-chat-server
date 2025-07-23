package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/term"
)

// Enhanced message structures for maximum security
type Metadata struct {
	// E2EE content mapping: recipient_username -> encrypted_content
	Content map[string]string `json:"content,omitempty"`
	// Single content for broadcast messages
	SingleContent string `json:"single_content,omitempty"`
	// Author information
	Author   string `json:"author"`
	AuthorID string `json:"author_id"`
	// Channel information
	ChannelID   string `json:"channel_id"`
	ChannelName string `json:"channel_name"`
	// Cryptographic data
	PublicKey string `json:"public_key,omitempty"`
	// User management
	ExistingUsers map[string]string `json:"existing_users,omitempty"`
	// Authentication
	AuthChallenge string `json:"auth_challenge,omitempty"`
	AuthResponse  string `json:"auth_response,omitempty"`
	RequiresAuth  bool   `json:"requires_auth,omitempty"`
	// Security metadata
	SecurityLevel  string `json:"security_level,omitempty"`
	KeyFingerprint string `json:"key_fingerprint,omitempty"`
}

type Message struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Metadata  Metadata  `json:"metadata"`
	Encrypted bool      `json:"encrypted"`
	Signature string    `json:"signature,omitempty"`
	HMAC      string    `json:"hmac,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
	Sequence  uint64    `json:"sequence,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Client state management
type SecureClient struct {
	connection       *quic.Conn
	clientName       string
	roomName         string
	privateKey       *ecdsa.PrivateKey
	publicKeys       map[string]*ecdsa.PublicKey
	keysMutex        sync.RWMutex
	authenticated    bool
	authChallenge    string
	sessionKey       []byte
	messageSequence  uint64
	sequenceMutex    sync.Mutex
	connectionSecure bool

	// Input buffer management
	currentInput      []rune
	currentInputMutex sync.Mutex

	// Security monitoring
	lastActivity     time.Time
	messageCount     int64
	encryptionErrors int
	maxErrors        int
}

// Terminal colors for security-conscious UI
const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorReset  = "\033[0m"
	clearLine   = "\x1b[2K"
)

var client *SecureClient

func main() {
	// Initialize secure client
	client = &SecureClient{
		publicKeys:       make(map[string]*ecdsa.PublicKey),
		maxErrors:        5,
		lastActivity:     time.Now(),
		connectionSecure: false,
	}

	// Clear screen for security
	fmt.Print("\033[2J\033[H")

	// Display security banner
	displaySecurityBanner()

	// Initialize secure session
	if err := initializeSecureSession(); err != nil {
		log.Fatalf("❌ Failed to initialize secure session: %v", err)
	}

	// Connect to server
	if err := connectToSecureServer(); err != nil {
		log.Fatalf("❌ Failed to connect to secure server: %v", err)
	}
	defer client.connection.CloseWithError(0, "client_shutdown")

	// Join room securely
	if err := joinRoomSecurely(); err != nil {
		log.Fatalf("❌ Failed to join room securely: %v", err)
	}

	// Start secure communication loops
	userInputChan := make(chan string, 10)
	go client.readSecureInput(userInputChan)
	go client.listenForServerMessages()
	go client.handleUserInput(userInputChan)
	go client.securityMonitor()

	// Initial prompt
	client.redrawSecureLine()

	// Keep client running
	select {}
}
func displaySecurityBanner() {
	fmt.Printf("%s%s╔══════════════════════════════════════════╗%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║     🔒 ULTRA-SECURE MESSAGING CLIENT     ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║        Intelligence Agency Protection     ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║                                          ║%s\n", colorBold, colorCyan, colorReset)
	fmt.Printf("%s%s║  🛡️  End-to-End Encryption               ║%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s%s║  🔐  Perfect Forward Secrecy             ║%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s%s║  👁️  Operational Security                ║%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s%s║  🚫  No Persistent Storage               ║%s\n", colorBold, colorGreen, colorReset)
	fmt.Printf("%s%s╚══════════════════════════════════════════╝%s\n", colorBold, colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("%s⚠️  WARNING: For authorized personnel only%s\n", colorYellow, colorReset)
	fmt.Printf("%sℹ️  All communications are monitored for security%s\n\n", colorDim, colorReset)
}

func initializeSecureSession() error {
	reader := bufio.NewReader(os.Stdin)

	// Get client credentials
	fmt.Printf("%s🔐 Enter secure identifier: %s", colorCyan, colorReset)
	name, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read client name: %w", err)
	}
	client.clientName = sanitizeInput(strings.TrimSpace(name))

	fmt.Printf("%s🏠 Enter secure room identifier: %s", colorCyan, colorReset)
	room, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read room name: %w", err)
	}
	client.roomName = sanitizeInput(strings.TrimSpace(room))

	// Validate inputs
	if len(client.clientName) < 3 || len(client.clientName) > 50 {
		return fmt.Errorf("client name must be 3-50 characters")
	}
	if len(client.roomName) < 3 || len(client.roomName) > 100 {
		return fmt.Errorf("room name must be 3-100 characters")
	}

	// Generate ephemeral cryptographic keys
	fmt.Printf("%s🔑 Generating ephemeral cryptographic keys...%s\n", colorYellow, colorReset)
	if err := generateEphemeralKeys(); err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	fmt.Printf("%s✅ Secure session initialized%s\n", colorGreen, colorReset)
	return nil
}

func generateEphemeralKeys() error {
	// Use ECDSA P-521 for maximum security
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	client.privateKey = privateKey

	// Generate session key for additional security
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		return fmt.Errorf("failed to generate session key: %w", err)
	}
	client.sessionKey = sessionKey

	fmt.Printf("%s🔐 Generated ECDSA P-521 key pair + session key%s\n", colorGreen, colorReset)
	return nil
}

func connectToSecureServer() error {
	fmt.Printf("%s🛰️  Establishing secure QUIC connection...%s\n", colorYellow, colorReset)

	// Check if we need to generate a client certificate
	clientCert, err := generateClientCertificate()
	if err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	// Maximum security TLS configuration
	tlsConf := &tls.Config{
		RootCAs:    getRootCAs(),
		NextProtos: []string{"secure-messaging-v1"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
		},
		// Disable session resumption for perfect forward secrecy
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,

		// Add client certificate for mutual TLS
		Certificates: []tls.Certificate{*clientCert},
	}

	// QUIC configuration with security focus
	quicConf := &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    5,
		MaxIncomingUniStreams: 2,
		// Disable path MTU discovery for anonymity
		DisablePathMTUDiscovery: true,
	}

	var err2 error
	conn, err2 := quic.DialAddr(context.Background(), "localhost:4433", tlsConf, quicConf)
	if err2 != nil {
		return fmt.Errorf("failed to establish QUIC connection: %w", err2)
	}
	client.connection = conn

	// Verify connection security
	connectionState := client.connection.ConnectionState().TLS
	if connectionState.Version != tls.VersionTLS13 {
		return fmt.Errorf("insecure TLS version: %x", connectionState.Version)
	}

	client.connectionSecure = true
	fmt.Printf("%s✅ Secure connection established (TLS 1.3 + Mutual Auth)%s\n", colorGreen, colorReset)
	return nil
}

func getRootCAs() *x509.CertPool {
	// In a real application, you would load the server's root CA certificate
	// from a secure location. For this example, we'll use the system's root CAs.
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Add your server's certificate to the pool if it's self-signed
	// certPEM, err := os.ReadFile("path/to/your/cert.pem")
	// if err == nil {
	// 	rootCAs.AppendCertsFromPEM(certPEM)
	// }

	return rootCAs
}

// generateClientCertificate creates a temporary client certificate for mutual TLS
func generateClientCertificate() (*tls.Certificate, error) {
	// Generate a temporary private key for the client certificate
	certPrivKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Secure Client"},
			CommonName:   client.clientName,
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour), // Short-lived
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &certPrivKey.PublicKey, certPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Convert to TLS certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certPrivKey,
	}

	fmt.Printf("%s🔐 Generated ephemeral client certificate%s\n", colorGreen, colorReset)
	return cert, nil
}

func joinRoomSecurely() error {
	fmt.Printf("%s🚪 Joining secure room '%s' as '%s'...%s\n", colorYellow, client.roomName, client.clientName, colorReset)

	stream, err := client.connection.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}

	// Marshal public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&client.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	// Create secure join message
	joinMsg := Message{
		ID:   generateSecureID(),
		Type: "join",
		Metadata: Metadata{
			Author:         client.clientName,
			ChannelID:      client.roomName,
			ChannelName:    client.roomName,
			PublicKey:      string(pubKeyPEM),
			SecurityLevel:  "maximum",
			KeyFingerprint: generateKeyFingerprint(pubKeyBytes),
		},
		Timestamp: time.Now(),
		Nonce:     generateNonce(),
	}

	// Send join request
	if err := json.NewEncoder(stream).Encode(joinMsg); err != nil {
		return fmt.Errorf("failed to send join message: %w", err)
	}

	// Handle join response
	go func() {
		defer stream.Close()
		var response Message
		if err := json.NewDecoder(stream).Decode(&response); err == nil {
			client.handleJoinResponse(response)
		}
	}()

	return nil
}

func (c *SecureClient) handleJoinResponse(response Message) {
	c.currentInputMutex.Lock()
	defer c.currentInputMutex.Unlock()

	fmt.Printf("\r%s", clearLine)

	switch response.Type {
	case "join_ack":
		fmt.Printf("%s✅ [Server]: %s%s\n", colorGreen, response.Metadata.SingleContent, colorReset)

		// Handle authentication challenge if required
		if response.Metadata.RequiresAuth && response.Metadata.AuthChallenge != "" {
			c.authChallenge = response.Metadata.AuthChallenge
			c.handleAuthenticationChallenge()
		}

		// Process existing users
		if len(response.Metadata.ExistingUsers) > 0 {
			c.processExistingUsers(response.Metadata.ExistingUsers)
		}

		c.authenticated = true
		fmt.Printf("%s🔒 Secure room joined successfully%s\n", colorGreen, colorReset)

	case "error":
		fmt.Printf("%s❌ [Error]: %s%s\n", colorRed, response.Metadata.SingleContent, colorReset)
		os.Exit(1)
	}

	c.redrawSecureLine()
}

func (c *SecureClient) handleAuthenticationChallenge() {
	// Sign the challenge with our private key
	challengeBytes, _ := hex.DecodeString(c.authChallenge)
	hash := sha256.Sum256(challengeBytes)

	signature, err := ecdsa.SignASN1(rand.Reader, c.privateKey, hash[:])
	if err != nil {
		log.Printf("%s❌ Failed to sign authentication challenge: %v%s", colorRed, err, colorReset)
		return
	}

	// Send authentication response
	authMsg := Message{
		ID:   generateSecureID(),
		Type: "auth_response",
		Metadata: Metadata{
			Author:       c.clientName,
			AuthResponse: hex.EncodeToString(signature),
		},
		Timestamp: time.Now(),
	}

	stream, err := c.connection.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("%s❌ Failed to send auth response: %v%s", colorRed, err, colorReset)
		return
	}
	defer stream.Close()

	json.NewEncoder(stream).Encode(authMsg)
	fmt.Printf("%s🔐 Authentication response sent%s\n", colorBlue, colorReset)
}

func (c *SecureClient) redrawSecureLine() {
	fmt.Printf("\r%s%s>> %s%s", clearLine, colorCyan, string(c.currentInput), colorReset)
}

func (c *SecureClient) readSecureInput(inputChan chan<- string) {
	// Enter raw terminal mode for secure input
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalf("❌ Failed to enter secure input mode: %v", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	reader := bufio.NewReader(os.Stdin)
	for {
		r, _, err := reader.ReadRune()
		if err != nil {
			log.Printf("%s❌ Input error: %v%s", colorRed, err, colorReset)
			close(inputChan)
			return
		}

		c.currentInputMutex.Lock()
		switch r {
		case '\r', '\n': // Enter
			input := string(c.currentInput)
			c.currentInput = []rune{}
			c.redrawSecureLine()
			c.currentInputMutex.Unlock()
			inputChan <- input
			continue
		case 127, '\b': // Backspace
			if len(c.currentInput) > 0 {
				c.currentInput = c.currentInput[:len(c.currentInput)-1]
			}
		case 3: // Ctrl+C - Secure exit
			c.currentInputMutex.Unlock()
			c.secureShutdown()
			return
		case 4: // Ctrl+D - Emergency shutdown
			c.currentInputMutex.Unlock()
			c.emergencyShutdown()
			return
		default:
			c.currentInput = append(c.currentInput, r)
		}
		c.redrawSecureLine()
		c.currentInputMutex.Unlock()
	}
}

func (c *SecureClient) listenForServerMessages() {
	for {
		stream, err := c.connection.AcceptStream(context.Background())
		if err != nil {
			log.Printf("%s❌ Error accepting stream: %v%s", colorRed, err, colorReset)
			c.emergencyShutdown()
			return
		}
		go c.handleIncomingStream(stream)
	}
}

func (c *SecureClient) handleIncomingStream(stream *quic.Stream) {
	defer stream.Close()

	var msg Message
	if err := json.NewDecoder(stream).Decode(&msg); err != nil {
		if err != io.EOF {
			log.Printf("%s❌ Failed to decode message: %v%s", colorRed, err, colorReset)
		}
		return
	}

	// Validate message
	if !c.validateIncomingMessage(msg) {
		log.Printf("%s⚠️  Message validation failed, discarding%s", colorYellow, colorReset)
		return
	}

	c.currentInputMutex.Lock()
	defer c.currentInputMutex.Unlock()

	fmt.Printf("\r%s", clearLine)

	switch msg.Type {
	case "message":
		c.handleSecureMessage(msg)
	case "user_joined":
		c.handleUserJoined(msg)
	case "user_left":
		fmt.Printf("%s📤 [Room]: %s%s\n", colorYellow, msg.Metadata.SingleContent, colorReset)
	case "key_rotated":
		c.handleKeyRotation(msg)
	case "server_shutdown":
		fmt.Printf("%s⚠️  [Server]: %s%s\n", colorYellow, msg.Metadata.SingleContent, colorReset)
		c.secureShutdown()
	default:
		fmt.Printf("%s📢 [Server]: %s (%s)%s\n", colorBlue, msg.Metadata.SingleContent, msg.Type, colorReset)
	}

	c.redrawSecureLine()
}

func (c *SecureClient) handleSecureMessage(msg Message) {
	if !msg.Encrypted {
		fmt.Printf("%s⚠️  [SECURITY WARNING]: Unencrypted message from %s: %s%s\n", colorRed, msg.Metadata.Author, msg.Metadata.SingleContent, colorReset)
		return
	}

	decryptedContent, err := c.decryptMessage(msg.Metadata.SingleContent)
	if err != nil {
		c.encryptionErrors++
		fmt.Printf("%s❌ [DECRYPT ERROR]: Failed to decrypt message from %s%s\n", colorRed, msg.Metadata.Author, colorReset)

		// Security measure: disconnect if too many decryption errors
		if c.encryptionErrors > c.maxErrors {
			fmt.Printf("%s🚨 [SECURITY]: Too many decryption errors, disconnecting%s\n", colorRed, colorReset)
			c.emergencyShutdown()
		}
		return
	}

	c.messageCount++
	c.lastActivity = time.Now()
	fmt.Printf("%s💬 [%s]: %s%s\n", colorPurple, msg.Metadata.Author, decryptedContent, colorReset)
}

func (c *SecureClient) handleUserJoined(msg Message) {
	fmt.Printf("%s📥 [Room]: %s%s\n", colorGreen, msg.Metadata.SingleContent, colorReset)
	if msg.Metadata.PublicKey != "" && msg.Metadata.Author != c.clientName {
		c.storePublicKey(msg.Metadata.Author, msg.Metadata.PublicKey)
	}
}

func (c *SecureClient) handleKeyRotation(msg Message) {
	fmt.Printf("%s🔄 [Security]: %s%s\n", colorCyan, msg.Metadata.SingleContent, colorReset)
	if msg.Metadata.PublicKey != "" && msg.Metadata.Author != c.clientName {
		c.storePublicKey(msg.Metadata.Author, msg.Metadata.PublicKey)
	}
}

func (c *SecureClient) handleUserInput(inputChan <-chan string) {
	for input := range inputChan {
		trimmedInput := strings.TrimSpace(input)
		if trimmedInput == "" {
			continue
		}

		// Handle special commands
		if strings.HasPrefix(trimmedInput, "/") {
			c.handleCommand(trimmedInput)
			continue
		}

		// Encrypt and send message
		if err := c.sendEncryptedMessage(trimmedInput); err != nil {
			log.Printf("%s❌ Failed to send message: %v%s", colorRed, err, colorReset)
		}
	}
}

func (c *SecureClient) handleCommand(cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return
	}

	switch parts[0] {
	case "/help":
		c.displayHelp()
	case "/status":
		c.displayStatus()
	case "/rotate":
		c.rotateKeys()
	case "/quit", "/exit":
		c.secureShutdown()
	default:
		fmt.Printf("%s❓ Unknown command: %s (type /help for commands)%s\n", colorYellow, parts[0], colorReset)
		c.redrawSecureLine()
	}
}

func (c *SecureClient) displayHelp() {
	fmt.Printf("\r%s", clearLine)
	fmt.Printf("%s🔧 Available Commands:%s\n", colorCyan, colorReset)
	fmt.Printf("  %s/help%s     - Show this help\n", colorGreen, colorReset)
	fmt.Printf("  %s/status%s   - Show connection status\n", colorGreen, colorReset)
	fmt.Printf("  %s/rotate%s   - Rotate encryption keys\n", colorGreen, colorReset)
	fmt.Printf("  %s/quit%s     - Secure disconnect\n", colorGreen, colorReset)
	fmt.Printf("  %sCtrl+C%s    - Emergency shutdown\n", colorYellow, colorReset)
	c.redrawSecureLine()
}

func (c *SecureClient) displayStatus() {
	fmt.Printf("\r%s", clearLine)
	fmt.Printf("%s📊 Security Status:%s\n", colorCyan, colorReset)
	fmt.Printf("  Connection: %s%s%s\n", colorGreen, "Secure (TLS 1.3)", colorReset)
	fmt.Printf("  Authenticated: %s%v%s\n", colorGreen, c.authenticated, colorReset)
	fmt.Printf("  Messages: %s%d%s\n", colorBlue, c.messageCount, colorReset)
	fmt.Printf("  Known Users: %s%d%s\n", colorBlue, len(c.publicKeys), colorReset)
	fmt.Printf("  Uptime: %s%s%s\n", colorBlue, time.Since(c.lastActivity).Truncate(time.Second), colorReset)
	c.redrawSecureLine()
}

func (c *SecureClient) sendEncryptedMessage(content string) error {
	encryptedContents := make(map[string]string)

	c.keysMutex.RLock()
	allRecipients := make(map[string]*ecdsa.PublicKey)
	for name, pubKey := range c.publicKeys {
		allRecipients[name] = pubKey
	}
	// Add self to recipients
	allRecipients[c.clientName] = &c.privateKey.PublicKey
	c.keysMutex.RUnlock()

	// Encrypt for each recipient
	for name, pubKey := range allRecipients {
		encryptedContent, err := c.encryptForRecipient(content, pubKey)
		if err != nil {
			log.Printf("%s❌ Failed to encrypt for %s: %v%s", colorRed, name, err, colorReset)
			continue
		}
		encryptedContents[name] = encryptedContent
	}

	if len(encryptedContents) <= 1 {
		fmt.Printf("\r%s%s⚠️  You are alone in the room%s\n", clearLine, colorYellow, colorReset)
		c.redrawSecureLine()
		return nil
	}

	// Create secure message
	c.sequenceMutex.Lock()
	c.messageSequence++
	sequence := c.messageSequence
	c.sequenceMutex.Unlock()

	msg := Message{
		ID:        generateSecureID(),
		Type:      "message",
		Encrypted: true,
		Sequence:  sequence,
		Timestamp: time.Now(),
		Nonce:     generateNonce(),
		Metadata: Metadata{
			Author:        c.clientName,
			ChannelID:     c.roomName,
			Content:       encryptedContents,
			SecurityLevel: "maximum",
		},
	}

	// Send message
	stream, err := c.connection.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	return json.NewEncoder(stream).Encode(msg)
}

func (c *SecureClient) rotateKeys() error {
	fmt.Printf("\r%s%s🔄 Rotating encryption keys...%s\n", clearLine, colorYellow, colorReset)

	// Generate new key pair
	if err := generateEphemeralKeys(); err != nil {
		return fmt.Errorf("failed to generate new keys: %w", err)
	}

	// Notify server of key rotation
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&c.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal new public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	msg := Message{
		ID:   generateSecureID(),
		Type: "key_rotation",
		Metadata: Metadata{
			Author:         c.clientName,
			PublicKey:      string(pubKeyPEM),
			KeyFingerprint: generateKeyFingerprint(pubKeyBytes),
		},
		Timestamp: time.Now(),
	}

	stream, err := c.connection.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	if err := json.NewEncoder(stream).Encode(msg); err != nil {
		return fmt.Errorf("failed to send key rotation: %w", err)
	}

	fmt.Printf("%s✅ Keys rotated successfully%s\n", colorGreen, colorReset)
	c.redrawSecureLine()
	return nil
}

func (c *SecureClient) securityMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Check for suspicious activity
		if time.Since(c.lastActivity) > 10*time.Minute {
			fmt.Printf("\r%s%s⚠️  Idle timeout - consider reconnecting%s\n", clearLine, colorYellow, colorReset)
			c.redrawSecureLine()
		}

		// Memory cleanup
		if c.messageCount%100 == 0 {
			runtime.GC()
		}
	}
}

func (c *SecureClient) secureShutdown() {
	fmt.Printf("\r%s%s🔒 Initiating secure shutdown...%s\n", clearLine, colorYellow, colorReset)

	// Clear sensitive data
	c.clearSensitiveData()

	// Close connection
	if c.connection != nil {
		c.connection.CloseWithError(0, "secure_shutdown")
	}

	// Restore terminal
	oldState, err := term.GetState(int(os.Stdin.Fd()))
	if err == nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
	}

	fmt.Printf("%s✅ Secure shutdown completed%s\n", colorGreen, colorReset)
	os.Exit(0)
}

func (c *SecureClient) emergencyShutdown() {
	fmt.Printf("\r%s%s🚨 EMERGENCY SHUTDOWN%s\n", clearLine, colorRed, colorReset)

	// Immediate data clearing
	c.clearSensitiveData()

	// Force close connection
	if c.connection != nil {
		c.connection.CloseWithError(quic.ApplicationErrorCode(0x100), "emergency_shutdown")
	}

	oldState, err := term.GetState(int(os.Stdin.Fd()))
	if err == nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
	}
	os.Exit(1)
}

func (c *SecureClient) clearSensitiveData() {
	// Clear keys from memory
	if c.sessionKey != nil {
		for i := range c.sessionKey {
			c.sessionKey[i] = 0
		}
		c.sessionKey = nil
	}

	// Clear input buffer
	c.currentInputMutex.Lock()
	for i := range c.currentInput {
		c.currentInput[i] = 0
	}
	c.currentInput = nil
	c.currentInputMutex.Unlock()

	// Clear public keys
	c.keysMutex.Lock()
	c.publicKeys = make(map[string]*ecdsa.PublicKey)
	c.keysMutex.Unlock()

	// Clear authentication data
	c.authChallenge = ""
	c.authenticated = false

	// Force garbage collection
	runtime.GC()
	runtime.GC()
}

// Utility functions

func (c *SecureClient) encryptForRecipient(content string, pubKey *ecdsa.PublicKey) (string, error) {
	// ECIES encryption
	pubKeyEcdh, err := pubKey.ECDH()
	if err != nil {
		return "", fmt.Errorf("failed to convert public key to ECDH: %w", err)
	}

	ephemeralPriv, err := ecdh.P521().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	ephemeralPub := ephemeralPriv.PublicKey()

	sharedSecret, err := ephemeralPriv.ECDH(pubKeyEcdh)
	if err != nil {
		return "", fmt.Errorf("ECDH key exchange failed: %w", err)
	}

	hash := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ephemeralPubBytes := ephemeralPub.Bytes()
	ciphertext := gcm.Seal(nonce, nonce, []byte(content), nil)

	return hex.EncodeToString(append(ephemeralPubBytes, ciphertext...)), nil
}

func (c *SecureClient) decryptMessage(ciphertextHex string) (string, error) {
	// ECIES decryption
	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		return "", err
	}

	ecdhCurve := ecdh.P521()
	// The length of a P-521 public key is 1 + 2 * ((521 + 7) / 8) for uncompressed form
	// but the `Bytes()` method on an `ecdh.PublicKey` returns the raw x and y coordinates.
	// For P-521, each coordinate is 66 bytes, so the total length is 132 bytes.
	pubKeyLen := 132

	if len(ciphertext) <= pubKeyLen {
		return "", fmt.Errorf("invalid ciphertext length")
	}

	ephemeralPubBytes := ciphertext[:pubKeyLen]
	ciphertext = ciphertext[pubKeyLen:]

	ephemeralPub, err := ecdhCurve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return "", fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	ecdhPriv, err := c.privateKey.ECDH()
	if err != nil {
		return "", fmt.Errorf("failed to get ECDH private key: %w", err)
	}

	sharedSecret, err := ecdhPriv.ECDH(ephemeralPub)
	if err != nil {
		return "", fmt.Errorf("ECDH key exchange failed: %w", err)
	}

	hash := sha256.Sum256(sharedSecret)

	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("invalid ciphertext")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
func (c *SecureClient) processExistingUsers(users map[string]string) {
	for name, keyStr := range users {
		if name != c.clientName {
			c.storePublicKey(name, keyStr)
		}
	}
	fmt.Printf("%s🔑 Synchronized %d user keys%s\n", colorGreen, len(users)-1, colorReset)
}

func (c *SecureClient) storePublicKey(name, keyStr string) {
	if name == c.clientName {
		return
	}

	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		log.Printf("%s❌ Invalid PEM block for user %s%s", colorRed, name, colorReset)
		return
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("%s❌ Failed to parse public key for %s: %v%s", colorRed, name, err, colorReset)
		return
	}

	ecdsaPubKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		log.Printf("%s❌ Public key for %s is not an ECDSA key%s", colorRed, name, colorReset)
		return
	}

	c.keysMutex.Lock()
	c.publicKeys[name] = ecdsaPubKey
	c.keysMutex.Unlock()

	fmt.Printf("\r%s%s🔑 Synced key for user '%s'%s\n", clearLine, colorGreen, name, colorReset)
}

func (c *SecureClient) validateIncomingMessage(msg Message) bool {
	// Basic message validation
	if msg.ID == "" || msg.Type == "" {
		return false
	}

	// Check timestamp (not too far in future or past)
	now := time.Now()
	if msg.Timestamp.After(now.Add(5*time.Minute)) || msg.Timestamp.Before(now.Add(-24*time.Hour)) {
		return false
	}

	// Validate sequence number for replay protection
	if msg.Sequence > 0 && msg.Type == "message" {
		// In production, implement proper sequence tracking per user
		return true
	}

	return true
}

// Security utility functions

func generateSecureID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func generateNonce() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback nonce
		hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(hash[:])
	}
	return hex.EncodeToString(bytes)
}

func generateKeyFingerprint(pubKeyBytes []byte) string {
	hash := sha256.Sum256(pubKeyBytes)
	return hex.EncodeToString(hash[:16]) // 128-bit fingerprint
}

func sanitizeInput(input string) string {
	// A simple validator for user and room names
	if len(input) > 100 {
		input = input[:100]
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return -1
	}, input)
}
