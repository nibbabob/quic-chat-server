package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"quic-chat-server/config"
	"quic-chat-server/messaging"
	"quic-chat-server/security"
	"quic-chat-server/types"
	"quic-chat-server/utils"
	"sync"
	"time"
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
// It now accepts the `types.Connection` interface.
func HandleSecureConnection(conn types.Connection, connID string) {
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

	// This is a simplified loop for demonstration. A real implementation would
	// likely have a more complex stream management logic.
	for {
		select {
		case <-ctx.Done():
			logger.Warn("⏰ Connection timeout", map[string]interface{}{
				"conn_id": connID[:8] + "...",
			})
			// BUG FIX: Explicitly close the connection on timeout.
			conn.CloseWithError(0x103, "connection_timed_out")
			return
		case <-shutdownChan:
			logger.Info("🛑 Graceful shutdown - closing connection", map[string]interface{}{
				"conn_id": connID[:8] + "...",
			})
			return
		default:
			// In a real server, this loop would be responsible for accepting streams.
			// To prevent a busy-loop in tests and real execution, we add a small sleep.
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// handleSecureStream processes individual streams with comprehensive security
func handleSecureStream(stream types.Stream, conn types.Connection, connID string) {
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(30 * time.Second))

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

	if err := validateMessage(&msg); err != nil {
		logger.Warn("🚫 Message validation failed", map[string]interface{}{
			"conn_id": connID[:8] + "...",
			"error":   err.Error(),
		})
		sendErrorResponse(stream, "message_validation_failed")
		return
	}

	switch msg.Type {
	case "join":
		handleSecureJoin(stream, conn, connID, msg)
	case "message":
		handleSecureMessage(stream, connID, msg)
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
func handleSecureJoin(stream types.Stream, conn types.Connection, connID string, msg types.Message) {
	if err := validateJoinRequest(&msg); err != nil {
		sendErrorResponse(stream, "join_validation_failed")
		return
	}

	server.Mutex.Lock()
	if len(server.Rooms) >= serverConfig.Server.MaxRoomsPerServer {
		server.Mutex.Unlock()
		sendErrorResponse(stream, "server_room_limit_exceeded")
		return
	}

	room, exists := server.Rooms[msg.Metadata.ChannelID]
	if !exists {
		room = types.NewSecureRoom(msg.Metadata.ChannelID, "standard")
		server.Rooms[msg.Metadata.ChannelID] = room
	}
	server.Mutex.Unlock()

	room.Mutex.Lock()
	if len(room.Clients) >= serverConfig.Server.MaxUsersPerRoom {
		room.Mutex.Unlock()
		sendErrorResponse(stream, "room_user_limit_exceeded")
		return
	}

	client := types.NewSecureClientConnection(connID, conn, msg.Metadata.Author)
	client.RoomID = msg.Metadata.ChannelID
	client.PublicKey = msg.Metadata.PublicKey

	room.Clients[connID] = client
	room.Mutex.Unlock()

	server.Mutex.Lock()
	server.Connections[connID] = client
	server.Mutex.Unlock()

	// BUG FIX: Correctly call notifyUserJoined when auth is not required.
	if !serverConfig.Security.RequireClientAuth {
		notifyUserJoined(client.RoomID, connID, client.UserID, client.PublicKey)
	}

	json.NewEncoder(stream).Encode(types.Message{Type: "join_ack"})
}

// handleSecureMessage processes encrypted messages with security validation
func handleSecureMessage(stream types.Stream, connID string, msg types.Message) {
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

	// Update client activity
	client.LastActivity = time.Now()
	client.MessageCount++

	// Route encrypted message to recipients
	messaging.BroadcastEncryptedMessageToRoom(client.RoomID, msg)
}

// handleHeartbeat processes heartbeat messages for connection keepalive
func handleHeartbeat(stream types.Stream, connID string) {
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
func handleKeyRotation(stream types.Stream, connID string, msg types.Message) {
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
		clientToKick.Conn.CloseWithError(0x102, "kicked_by_admin")
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
	return nil
}

func validateJoinRequest(msg *types.Message) error {
	if msg.Metadata.Author == "" || msg.Metadata.ChannelID == "" || msg.Metadata.PublicKey == "" {
		return fmt.Errorf("author, channelID, and publicKey are required for join")
	}
	return nil
}

func sendErrorResponse(stream types.Stream, errorCode string) {
	errorMsg := types.Message{
		ID:   utils.GenerateSecureID(),
		Type: "error",
		Metadata: types.Metadata{
			SingleContent: errorCode,
		},
	}
	json.NewEncoder(stream).Encode(errorMsg)
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
