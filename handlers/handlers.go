package handlers

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"quic-chat-server/config"
	"quic-chat-server/messaging"
	"quic-chat-server/security"
	"quic-chat-server/types"
	"quic-chat-server/utils"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

var (
	server       *types.Server
	serverConfig *config.Config
	logger       = security.NewSecureLogger()
	shutdownChan = make(chan struct{})
	shutdownOnce sync.Once
)

// InitializeServer initializes the server with secure defaults
func InitializeServer(cfg *config.Config) {
	server = &types.Server{
		Connections: make(map[string]*types.ClientConnection),
		Rooms:       make(map[string]*types.Room),
		StartTime:   time.Now(),
	}
	serverConfig = cfg

	logger.Info("🚀 Secure handler subsystem initialized", map[string]interface{}{
		"max_connections": cfg.Server.MaxConnections,
		"max_rooms":       cfg.Server.MaxRoomsPerServer,
		"auth_required":   cfg.Security.RequireClientAuth,
	})
}

// GetServer returns the server instance for other packages
func GetServer() *types.Server {
	return server
}

// HandleSecureConnection manages incoming connections with maximum security
func HandleSecureConnection(conn *quic.Conn, connID string) {
	// Validate connection immediately
	remoteAddr := conn.RemoteAddr().String()
	if err := security.ValidateClientConnection(remoteAddr, ""); err != nil {
		logger.Warn("🚫 Connection rejected by security validation", map[string]interface{}{
			"conn_id":     connID[:8] + "...",
			"remote_hash": security.HashIPAddress(remoteAddr),
			"reason":      err.Error(),
		})
		conn.CloseWithError(0x100, "security_validation_failed")
		return
	}

	// Check connection limits
	server.Mutex.Lock()
	connectionCount := len(server.Connections)
	server.Mutex.Unlock()

	if connectionCount >= serverConfig.Server.MaxConnections {
		logger.Warn("🚫 Connection rejected: server at capacity", map[string]interface{}{
			"conn_id":         connID[:8] + "...",
			"current_conns":   connectionCount,
			"max_connections": serverConfig.Server.MaxConnections,
		})
		conn.CloseWithError(0x101, "server_capacity_exceeded")
		return
	}

	// Setup connection cleanup
	defer func() {
		cleanupConnection(connID)
		logger.Info("🔌 Connection closed", map[string]interface{}{
			"conn_id": connID[:8] + "...",
		})
	}()

	// Set connection timeout
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(serverConfig.Server.ConnectionTimeout)*time.Second)
	defer cancel()

	logger.Info("✅ Secure connection accepted", map[string]interface{}{
		"conn_id":     connID[:8] + "...",
		"remote_hash": security.HashIPAddress(remoteAddr),
		"tls_version": "1.3",
	})

	// Main connection loop
	for {
		select {
		case <-ctx.Done():
			logger.Warn("⏰ Connection timeout", map[string]interface{}{
				"conn_id": connID[:8] + "...",
			})
			return
		case <-shutdownChan:
			logger.Info("🛑 Graceful shutdown - closing connection", map[string]interface{}{
				"conn_id": connID[:8] + "...",
			})
			return
		default:
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				if !isConnectionClosed(err) {
					logger.Error("❌ Error accepting stream", map[string]interface{}{
						"conn_id": connID[:8] + "...",
						"error":   err.Error(),
					})
				}
				return
			}
			go handleSecureStream(stream, conn, connID)
		}
	}
}

// handleSecureStream processes individual streams with comprehensive security
func handleSecureStream(stream *quic.Stream, conn *quic.Conn, connID string) {
	defer stream.Close()

	// Set stream timeout
	streamCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Read message with size limits
	var msg types.Message
	decoder := json.NewDecoder(io.LimitReader(stream, int64(serverConfig.Security.MaxMessageSize)))

	if err := decoder.Decode(&msg); err != nil {
		if err != io.EOF {
			logger.Error("❌ Message decode error", map[string]interface{}{
				"conn_id": connID[:8] + "...",
				"error":   err.Error(),
			})
			sendErrorResponse(stream, "invalid_message_format")
		}
		return
	}

	// Validate message structure and content
	if err := validateMessage(&msg); err != nil {
		logger.Warn("🚫 Message validation failed", map[string]interface{}{
			"conn_id": connID[:8] + "...",
			"error":   err.Error(),
		})
		sendErrorResponse(stream, "message_validation_failed")
		return
	}

	// Route message based on type
	switch msg.Type {
	case "join":
		handleSecureJoin(streamCtx, stream, conn, connID, msg)
	case "message":
		handleSecureMessage(streamCtx, stream, connID, msg)
	case "heartbeat":
		handleHeartbeat(stream, connID)
	case "key_rotation":
		handleKeyRotation(stream, connID, msg)
	default:
		logger.Warn("🚫 Unknown message type", map[string]interface{}{
			"conn_id": connID[:8] + "...",
			"type":    msg.Type,
		})
		sendErrorResponse(stream, "unknown_message_type")
	}
}

// handleSecureJoin manages room joining with enhanced security
func handleSecureJoin(_ context.Context, stream *quic.Stream, conn *quic.Conn, connID string, msg types.Message) {
	// Validate join request
	if err := validateJoinRequest(&msg); err != nil {
		logger.Warn("🚫 Join request validation failed", map[string]interface{}{
			"conn_id": connID[:8] + "...",
			"error":   err.Error(),
		})
		sendErrorResponse(stream, "join_validation_failed")
		return
	}

	// Check room limits
	server.Mutex.RLock()
	roomCount := len(server.Rooms)
	server.Mutex.RUnlock()

	if roomCount >= serverConfig.Server.MaxRoomsPerServer {
		sendErrorResponse(stream, "server_room_limit_exceeded")
		return
	}

	// Get or create room
	server.Mutex.Lock()
	room, exists := server.Rooms[msg.Metadata.ChannelID]
	if !exists {
		room = &types.Room{
			ID:      msg.Metadata.ChannelID,
			Clients: make(map[string]*types.ClientConnection),
		}
		server.Rooms[msg.Metadata.ChannelID] = room
		logger.Info("🏠 New secure room created", map[string]interface{}{
			"room_id": msg.Metadata.ChannelID,
		})
	}
	server.Mutex.Unlock()

	// Check room user limits
	room.Mutex.RLock()
	userCount := len(room.Clients)
	room.Mutex.RUnlock()

	if userCount >= serverConfig.Server.MaxUsersPerRoom {
		sendErrorResponse(stream, "room_user_limit_exceeded")
		return
	}

	// Collect existing users and their public keys
	room.Mutex.Lock()
	existingUsers := make(map[string]string)
	for _, c := range room.Clients {
		existingUsers[c.UserID] = c.PublicKey
	}

	// Generate challenge for client authentication
	challenge := generateAuthChallenge()

	// Create client connection
	client := &types.ClientConnection{
		ID:            connID,
		Conn:          conn,
		UserID:        msg.Metadata.Author,
		RoomID:        msg.Metadata.ChannelID,
		PublicKey:     msg.Metadata.PublicKey,
		AuthChallenge: challenge,
		Authenticated: false,
		JoinTime:      time.Now(),
		LastActivity:  time.Now(),
		MessageCount:  0,
		RateLimiter:   types.RateLimiter{WindowStart: time.Now()},
	}

	room.Clients[connID] = client
	room.Mutex.Unlock()

	server.Mutex.Lock()
	server.Connections[connID] = client
	server.Mutex.Unlock()

	logger.Info("👤 User joined secure room", map[string]interface{}{
		"user_id":       msg.Metadata.Author,
		"conn_id":       connID[:8] + "...",
		"room_id":       msg.Metadata.ChannelID,
		"room_users":    len(existingUsers) + 1,
		"auth_required": serverConfig.Security.RequireClientAuth,
	})

	// Send join acknowledgment with challenge
	response := types.Message{
		ID:        utils.GenerateSecureID(),
		Type:      "join_ack",
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			SingleContent: "Successfully joined secure room",
			ChannelID:     msg.Metadata.ChannelID,
			ExistingUsers: existingUsers,
			AuthChallenge: challenge,
			RequiresAuth:  serverConfig.Security.RequireClientAuth,
		},
	}

	if err := json.NewEncoder(stream).Encode(response); err != nil {
		logger.Error("❌ Failed to send join acknowledgment", map[string]interface{}{
			"conn_id": connID[:8] + "...",
			"error":   err.Error(),
		})
		return
	}

	// Notify other users of new joiner (after authentication if required)
	if !serverConfig.Security.RequireClientAuth {
		notifyUserJoined(msg.Metadata.ChannelID, connID, msg.Metadata.Author, msg.Metadata.PublicKey)
	}
}

// handleSecureMessage processes encrypted messages with security validation
func handleSecureMessage(_ context.Context, stream *quic.Stream, connID string, msg types.Message) {
	server.Mutex.RLock()
	client, exists := server.Connections[connID]
	server.Mutex.RUnlock()

	if !exists {
		sendErrorResponse(stream, "client_not_found")
		return
	}

	// Check authentication if required
	if serverConfig.Security.RequireClientAuth && !client.Authenticated {
		sendErrorResponse(stream, "authentication_required")
		return
	}

	// Validate message content and rate limits
	remoteAddr := client.Conn.RemoteAddr().String()
	messageData, _ := json.Marshal(msg.Metadata.Content)

	if err := security.ValidateMessage(messageData, client.UserID, remoteAddr); err != nil {
		logger.Warn("🚫 Message security validation failed", map[string]interface{}{
			"user_id": client.UserID,
			"conn_id": connID[:8] + "...",
			"error":   err.Error(),
		})
		sendErrorResponse(stream, "message_security_validation_failed")
		return
	}

	// Update client activity
	client.LastActivity = time.Now()
	client.MessageCount++

	// Add security metadata
	msg.Timestamp = time.Now()
	msg.ID = utils.GenerateSecureID()
	msg.Metadata.AuthorID = client.UserID
	msg.Metadata.CreatedAt = msg.Timestamp.Format(time.RFC3339)

	logger.Info("📨 Secure message received", map[string]interface{}{
		"user_id":      client.UserID,
		"conn_id":      connID[:8] + "...",
		"room_id":      client.RoomID,
		"recipients":   len(msg.Metadata.Content),
		"message_size": len(messageData),
	})

	// Route encrypted message to recipients
	messaging.BroadcastEncryptedMessageToRoom(client.RoomID, msg)

	// Send acknowledgment
	ack := types.Message{
		ID:   utils.GenerateSecureID(),
		Type: "message_ack",
		Metadata: types.Metadata{
			SingleContent: "Message delivered securely",
			MessageID:     msg.ID,
		},
	}

	if err := json.NewEncoder(stream).Encode(ack); err != nil {
		logger.Error("❌ Failed to send message acknowledgment", map[string]interface{}{
			"conn_id": connID[:8] + "...",
			"error":   err.Error(),
		})
	}
}

// handleHeartbeat processes heartbeat messages for connection keepalive
func handleHeartbeat(stream *quic.Stream, connID string) {
	server.Mutex.RLock()
	client, exists := server.Connections[connID]
	server.Mutex.RUnlock()

	if exists {
		client.LastActivity = time.Now()
	}

	response := types.Message{
		ID:        utils.GenerateSecureID(),
		Type:      "heartbeat_ack",
		Timestamp: time.Now(),
	}

	json.NewEncoder(stream).Encode(response)
}

// handleKeyRotation processes key rotation requests
func handleKeyRotation(stream *quic.Stream, connID string, msg types.Message) {
	server.Mutex.RLock()
	client, exists := server.Connections[connID]
	server.Mutex.RUnlock()

	if !exists || !client.Authenticated {
		sendErrorResponse(stream, "unauthorized_key_rotation")
		return
	}

	// Update client's public key
	client.PublicKey = msg.Metadata.PublicKey
	client.LastActivity = time.Now()

	logger.Info("🔄 Client key rotation completed", map[string]interface{}{
		"user_id": client.UserID,
		"conn_id": connID[:8] + "...",
	})

	// Notify other room members of new key
	notifyKeyRotation(client.RoomID, connID, client.UserID, msg.Metadata.PublicKey)

	response := types.Message{
		ID:   utils.GenerateSecureID(),
		Type: "key_rotation_ack",
		Metadata: types.Metadata{
			SingleContent: "Key rotation successful",
		},
	}

	json.NewEncoder(stream).Encode(response)
}

// ForceCloseAllConnections forcibly closes all active connections (for shutdown)
func ForceCloseAllConnections() {
	shutdownOnce.Do(func() {
		close(shutdownChan)
	})

	server.Mutex.Lock()
	defer server.Mutex.Unlock()

	logger.Warn("🚨 Force closing all connections", map[string]interface{}{
		"connection_count": len(server.Connections),
	})

	for connID, client := range server.Connections {
		if client.Conn != nil {
			client.Conn.CloseWithError(0x200, "server_shutdown")
		}
		delete(server.Connections, connID)
	}

	// Clear all rooms
	for roomID := range server.Rooms {
		delete(server.Rooms, roomID)
	}
}

// KickUser kicks a user from the server.
func KickUser(userID string) bool {
	server.Mutex.RLock()
	defer server.Mutex.RUnlock()

	var clientToKick *types.ClientConnection

	for _, client := range server.Connections {
		if client.UserID == userID {
			clientToKick = client
			break
		}
	}

	if clientToKick != nil && clientToKick.Conn != nil {
		// Just close the connection. The deferred cleanup in HandleSecureConnection
		// will take care of removing the user from all maps, preventing a deadlock.
		clientToKick.Conn.CloseWithError(0x102, "kicked_by_admin")
		logger.Info("👢 User kicked by admin", map[string]interface{}{
			"user_id": userID,
		})
		return true
	}

	return false
}

// Helper functions

func cleanupConnection(connID string) {
	server.Mutex.Lock()
	defer server.Mutex.Unlock()

	client, exists := server.Connections[connID]
	if !exists {
		// Already cleaned up, which can happen in the kick scenario
		return
	}

	if client.RoomID != "" {
		if room, roomExists := server.Rooms[client.RoomID]; roomExists {
			room.Mutex.Lock()
			delete(room.Clients, connID)

			// Notify other users of departure
			if client.Authenticated {
				notifyUserLeft(client.RoomID, connID, client.UserID)
			}

			// Clean up empty rooms
			if len(room.Clients) == 0 {
				delete(server.Rooms, client.RoomID)
				logger.Info("🏠 Empty room cleaned up", map[string]interface{}{
					"room_id": client.RoomID,
				})
			}
			room.Mutex.Unlock()
		}
	}
	delete(server.Connections, connID)
}

func validateMessage(msg *types.Message) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	if msg.Type == "" {
		return fmt.Errorf("message type is required")
	}

	if len(msg.Type) > 50 {
		return fmt.Errorf("message type too long")
	}

	// Validate metadata
	if msg.Metadata.Author == "" && msg.Type != "heartbeat" {
		return fmt.Errorf("author is required")
	}

	if len(msg.Metadata.Author) > 100 {
		return fmt.Errorf("author name too long")
	}

	return nil
}

func validateJoinRequest(msg *types.Message) error {
	if msg.Metadata.Author == "" {
		return fmt.Errorf("author required for join")
	}

	if msg.Metadata.ChannelID == "" {
		return fmt.Errorf("channel ID required for join")
	}

	if len(msg.Metadata.ChannelID) > 100 {
		return fmt.Errorf("channel ID too long")
	}

	if msg.Metadata.PublicKey == "" {
		return fmt.Errorf("public key required for join")
	}

	// Validate public key format (basic check)
	if len(msg.Metadata.PublicKey) < 100 || len(msg.Metadata.PublicKey) > 2048 {
		return fmt.Errorf("invalid public key format")
	}

	return nil
}

func generateAuthChallenge() string {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	return fmt.Sprintf("%x", challenge)
}

func sendErrorResponse(stream *quic.Stream, errorCode string) {
	errorMsg := types.Message{
		ID:   utils.GenerateSecureID(),
		Type: "error",
		Metadata: types.Metadata{
			SingleContent: errorCode,
		},
	}
	_ = json.NewEncoder(stream).Encode(errorMsg)
}

func notifyUserJoined(roomID, excludeConnID, userID, publicKey string) {
	joinMsg := types.Message{
		ID:        utils.GenerateSecureID(),
		Type:      "user_joined",
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			Author:        userID,
			SingleContent: fmt.Sprintf("%s joined the room", userID),
			ChannelID:     roomID,
			PublicKey:     publicKey,
		},
	}
	messaging.BroadcastSimpleMessageToRoom(roomID, joinMsg, excludeConnID)
}

func notifyUserLeft(roomID, excludeConnID, userID string) {
	leaveMsg := types.Message{
		ID:        utils.GenerateSecureID(),
		Type:      "user_left",
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			Author:        userID,
			SingleContent: fmt.Sprintf("%s left the room", userID),
			ChannelID:     roomID,
		},
	}
	messaging.BroadcastSimpleMessageToRoom(roomID, leaveMsg, excludeConnID)
}

func notifyKeyRotation(roomID, excludeConnID, userID, newPublicKey string) {
	keyRotationMsg := types.Message{
		ID:        utils.GenerateSecureID(),
		Type:      "key_rotated",
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			Author:        userID,
			SingleContent: fmt.Sprintf("%s rotated their encryption key", userID),
			ChannelID:     roomID,
			PublicKey:     newPublicKey,
		},
	}
	messaging.BroadcastSimpleMessageToRoom(roomID, keyRotationMsg, excludeConnID)
}

func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	// Check for common connection closed errors
	errStr := err.Error()
	if strings.Contains(errStr, "connection closed") || strings.Contains(errStr, "Application error") {
		return true
	}
	// Check for specific quic-go error codes that mean the connection is gone
	if qErr, ok := err.(*quic.ApplicationError); ok {
		// 0 is a graceful close. 0x102 is our custom "kicked" code. 0x200 is shutdown.
		if qErr.ErrorCode == 0 || qErr.ErrorCode == 0x102 || qErr.ErrorCode == 0x200 {
			return true
		}
	}
	return false
}
