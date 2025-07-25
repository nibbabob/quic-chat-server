package messaging

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"quic-chat-server/config"
	"quic-chat-server/security"
	"quic-chat-server/types"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	server            *types.Server
	serverConfig      *config.Config
	messageSequence   uint64
	sequenceMutex     sync.Mutex
	logger            = security.NewSecureLogger()
	shutdownChan      = make(chan struct{})
	userSequence      = make(map[string]uint64)
	userSequenceMutex sync.Mutex
	hmacSecret        []byte
)

// InitializeServer initializes the messaging subsystem
func InitializeServer(cfg *config.Config) {
	serverConfig = cfg
	messageSequence = 0

	logger.Info("📡 Secure messaging subsystem initialized", map[string]interface{}{
		"max_message_size": cfg.Security.MaxMessageSize,
		"rate_limit":       cfg.Security.RateLimitMessagesPerMinute,
		"forward_secrecy":  cfg.Security.EnablePerfectForwardSecrecy,
	})
}

// SetHMACSecret sets the HMAC secret for message integrity checks.
// This should be called once during initialization.
func SetHMACSecret(secret []byte) {
	hmacSecret = secret
}

// BroadcastEncryptedMessageToRoom handles E2EE message delivery with security validation
func BroadcastEncryptedMessageToRoom(roomID string, msg types.Message) {
	if server == nil {
		logger.Error("❌ Server not initialized", nil)
		return
	}

	server.Mutex.RLock()
	room, exists := server.Rooms[roomID]
	server.Mutex.RUnlock()

	if !exists {
		logger.Warn("🚫 Attempted message to non-existent room", map[string]interface{}{
			"room_id": roomID,
		})
		return
	}

	// Validate message before processing
	if err := validateSecureMessage(&msg); err != nil {
		logger.Warn("🚫 Message validation failed", map[string]interface{}{
			"room_id": roomID,
			"author":  msg.Metadata.Author,
			"error":   err.Error(),
		})
		return
	}

	// Add security metadata
	addSecurityMetadata(&msg)

	room.Mutex.RLock()
	clientCount := len(room.Clients)
	deliveryCount := 0
	successCount := 0
	failureCount := 0

	// Create delivery tracking
	deliveryResults := make(chan DeliveryResult, clientCount)

	for _, client := range room.Clients {
		// Check if there's encrypted content for this recipient
		encryptedContent, hasContent := msg.Metadata.Content[client.UserID]
		if !hasContent {
			continue // No content for this user
		}

		deliveryCount++

		// Create personalized message for this recipient
		personalMsg := createPersonalMessage(msg, encryptedContent, client)

		// Deliver message asynchronously with timeout
		go deliverMessageToClient(client, personalMsg, deliveryResults)
	}
	room.Mutex.RUnlock()

	// Wait for all deliveries to complete with timeout
	go handleDeliveryResults(deliveryResults, deliveryCount, roomID, msg.Metadata.Author, &successCount, &failureCount)

	// Record audit entry
	room.AddAuditEntry(types.NewAuditEntry(
		types.EventTypeMessage,
		msg.Metadata.Author,
		"", // No specific connection ID for broadcasts
		roomID,
		types.SeverityLow,
		map[string]interface{}{
			"recipients":     deliveryCount,
			"message_id":     msg.ID,
			"encrypted":      msg.Encrypted,
			"content_length": len(fmt.Sprintf("%v", msg.Metadata.Content)),
		},
	))

	logger.Info("📨 E2EE message broadcast initiated", map[string]interface{}{
		"room_id":    roomID,
		"author":     msg.Metadata.Author,
		"message_id": msg.ID,
		"recipients": deliveryCount,
	})
}

// BroadcastSimpleMessageToRoom handles non-E2EE broadcasts (join/leave notifications)
func BroadcastSimpleMessageToRoom(roomID string, msg types.Message, excludeConnID string) {
	if server == nil {
		logger.Error("❌ Server not initialized", nil)
		return
	}

	server.Mutex.RLock()
	room, exists := server.Rooms[roomID]
	server.Mutex.RUnlock()

	if !exists {
		return
	}

	// Add security metadata
	addSecurityMetadata(&msg)

	room.Mutex.RLock()
	clientCount := len(room.Clients)
	deliveryCount := 0
	deliveryResults := make(chan DeliveryResult, clientCount)

	for clientID, client := range room.Clients {
		if clientID == excludeConnID {
			continue
		}

		deliveryCount++
		go deliverMessageToClient(client, msg, deliveryResults)
	}
	room.Mutex.RUnlock()

	// Handle delivery results
	successCount := 0
	failureCount := 0
	go handleDeliveryResults(deliveryResults, deliveryCount, roomID, msg.Metadata.Author, &successCount, &failureCount)

	// Record audit entry
	room.AddAuditEntry(types.NewAuditEntry(
		msg.Type, // join, leave, etc.
		msg.Metadata.Author,
		excludeConnID,
		roomID,
		types.SeverityLow,
		map[string]interface{}{
			"message_type": msg.Type,
			"recipients":   deliveryCount,
			"excluded":     excludeConnID != "",
		},
	))

	logger.Info("📢 Simple message broadcast", map[string]interface{}{
		"room_id":    roomID,
		"type":       msg.Type,
		"author":     msg.Metadata.Author,
		"recipients": deliveryCount,
	})
}

// NotifyClientsShutdown notifies all connected clients of server shutdown
func NotifyClientsShutdown(ctx context.Context) {
	if server == nil {
		return
	}

	logger.Warn("🚨 Notifying all clients of server shutdown", nil)

	shutdownMsg := types.Message{
		ID:        generateSecureMessageID(),
		Type:      "server_shutdown",
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			Author:        "system",
			SingleContent: "Server is shutting down for maintenance. Please reconnect in a few minutes.",
		},
	}

	server.Mutex.RLock()
	totalClients := len(server.Connections)
	notificationsSent := 0

	// Notify all connected clients
	for _, client := range server.Connections {
		select {
		case <-ctx.Done():
			logger.Warn("⏰ Shutdown notification timeout", map[string]interface{}{
				"notified": notificationsSent,
				"total":    totalClients,
			})
			server.Mutex.RUnlock()
			return
		default:
			go func(c *types.ClientConnection) {
				if err := sendDirectMessage(c, shutdownMsg); err == nil {
					notificationsSent++
				}
			}(client)
		}
	}
	server.Mutex.RUnlock()

	// Wait a moment for notifications to be sent
	time.Sleep(2 * time.Second)

	logger.Info("📢 Shutdown notifications sent", map[string]interface{}{
		"total_clients": totalClients,
		"notified":      notificationsSent,
	})
}

// Message delivery types and structures

type DeliveryResult struct {
	ClientID  string
	UserID    string
	Success   bool
	Error     error
	Latency   time.Duration
	Timestamp time.Time
}

type MessageDeliveryStats struct {
	TotalRecipients      int
	SuccessfulDeliveries int
	FailedDeliveries     int
	AverageLatency       time.Duration
	DeliveryErrors       []DeliveryError
}

type DeliveryError struct {
	ClientID  string
	UserID    string
	Error     string
	Timestamp time.Time
}

// Core message delivery functions

func deliverMessageToClient(client *types.ClientConnection, msg types.Message, resultChan chan<- DeliveryResult) {
	startTime := time.Now()
	result := DeliveryResult{
		ClientID:  client.ID,
		UserID:    client.UserID,
		Timestamp: startTime,
	}

	// Check if client connection is still valid
	if client.Conn == nil {
		result.Success = false
		result.Error = fmt.Errorf("client connection is nil")
		result.Latency = time.Since(startTime)
		resultChan <- result
		return
	}

	// Create delivery context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Attempt message delivery
	if err := sendDirectMessage(client, msg); err != nil {
		result.Success = false
		result.Error = err

		// Log delivery failure
		logger.Warn("📤 Message delivery failed", map[string]interface{}{
			"client_id": client.ID[:8] + "...",
			"user_id":   client.UserID,
			"error":     err.Error(),
		})
	} else {
		result.Success = true

		// Update client activity
		client.LastActivity = time.Now()
		client.MessageCount++
	}

	result.Latency = time.Since(startTime)

	select {
	case resultChan <- result:
	case <-ctx.Done():
		// Timeout occurred
	}
}

func sendDirectMessage(client *types.ClientConnection, msg types.Message) error {
	// Create a new stream for this message
	stream, err := client.Conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}
	defer stream.Close()

	// Set stream deadline
	stream.SetDeadline(time.Now().Add(5 * time.Second))

	// Encode and send message
	encoder := json.NewEncoder(stream)
	if err := encoder.Encode(msg); err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	return nil
}

func handleDeliveryResults(resultChan <-chan DeliveryResult, expectedCount int, roomID, author string, successCount, failureCount *int) {
	timeout := time.After(15 * time.Second)
	receivedCount := 0

	for receivedCount < expectedCount {
		select {
		case result := <-resultChan:
			receivedCount++
			if result.Success {
				*successCount++
			} else {
				*failureCount++

				// Log persistent failures
				if result.Error != nil {
					logger.Error("📤 Message delivery error", map[string]interface{}{
						"client_id": result.ClientID[:8] + "...",
						"user_id":   result.UserID,
						"error":     result.Error.Error(),
						"latency":   result.Latency.String(),
					})
				}
			}

		case <-timeout:
			logger.Warn("⏰ Message delivery timeout", map[string]interface{}{
				"room_id":  roomID,
				"author":   author,
				"expected": expectedCount,
				"received": receivedCount,
				"missing":  expectedCount - receivedCount,
			})
			return
		}
	}

	// Log delivery summary
	logger.Info("📈 Message delivery completed", map[string]interface{}{
		"room_id":      roomID,
		"author":       author,
		"successful":   *successCount,
		"failed":       *failureCount,
		"total":        expectedCount,
		"success_rate": fmt.Sprintf("%.1f%%", float64(*successCount)/float64(expectedCount)*100),
	})
}

// Message validation and security functions

func validateSecureMessage(msg *types.Message) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}

	if !msg.IsValid() {
		return fmt.Errorf("message failed basic validation")
	}

	// Validate content size
	contentSize := calculateContentSize(msg)
	if contentSize > serverConfig.Security.MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max: %d)", contentSize, serverConfig.Security.MaxMessageSize)
	}

	// Validate sequence number for replay protection
	if msg.Sequence > 0 && !isValidSequence(msg.Sequence, msg.Metadata.Author) {
		return fmt.Errorf("invalid sequence number - possible replay attack")
	}

	// Validate HMAC if present
	if msg.HMAC != "" && !validateMessageHMAC(msg) {
		return fmt.Errorf("HMAC validation failed - message integrity compromised")
	}

	return nil
}

func addSecurityMetadata(msg *types.Message) {
	// Add sequence number
	sequenceMutex.Lock()
	messageSequence++
	msg.Sequence = messageSequence
	sequenceMutex.Unlock()

	// Add security timestamp
	msg.Timestamp = time.Now()

	// Add message ID if not present
	if msg.ID == "" {
		msg.ID = generateSecureMessageID()
	}

	// Update metadata timestamps
	msg.Metadata.CreatedAt = msg.Timestamp.Format(time.RFC3339)
	msg.Metadata.UpdatedAt = msg.Metadata.CreatedAt

	// Add security level
	msg.Metadata.SecurityLevel = "maximum"
}

func createPersonalMessage(originalMsg types.Message, encryptedContent string, _ *types.ClientConnection) types.Message {
	return types.Message{
		ID:        originalMsg.ID,
		Type:      "message",
		Encrypted: true,
		Sequence:  originalMsg.Sequence,
		Timestamp: originalMsg.Timestamp,
		Metadata: types.Metadata{
			Author:        originalMsg.Metadata.Author,
			AuthorID:      originalMsg.Metadata.AuthorID,
			ChannelID:     originalMsg.Metadata.ChannelID,
			SingleContent: encryptedContent, // Only the relevant ciphertext
			CreatedAt:     originalMsg.Metadata.CreatedAt,
			UpdatedAt:     originalMsg.Metadata.UpdatedAt,
			SecurityLevel: "maximum",
		},
	}
}

// Utility functions

func generateSecureMessageID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a less secure method if rand.Read fails, and log the error.
		// A panic here could bring down the whole server.
		logger.Error("Failed to generate secure message ID, using fallback", map[string]interface{}{"error": err})
		return fmt.Sprintf("insecure-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

func calculateContentSize(msg *types.Message) int {
	// Calculate total size of message content
	size := len(msg.Metadata.SingleContent)

	for _, content := range msg.Metadata.Content {
		size += len(content)
	}

	// Add metadata size
	if data, err := json.Marshal(msg.Metadata); err == nil {
		size += len(data)
	}

	return size
}

func isValidSequence(sequence uint64, author string) bool {
	userSequenceMutex.Lock()
	defer userSequenceMutex.Unlock()
	lastSequence, ok := userSequence[author]
	if !ok || sequence > lastSequence {
		userSequence[author] = sequence
		return true
	}
	return false
}

func validateMessageHMAC(msg *types.Message) bool {
	if msg.HMAC == "" {
		return true // No HMAC to validate
	}
	return ValidateMessageIntegrity(msg, hmacSecret)
}

// generateMessageHMAC creates a deterministic representation of the message for HMAC signing.
// This is critical to prevent vulnerabilities from non-deterministic JSON marshaling.
func generateMessageHMAC(msg *types.Message, secret []byte) string {
	// Create a canonical representation of the message data.
	// This ensures the HMAC is always calculated on the exact same string for the same message.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("id:%s;", msg.ID))
	sb.WriteString(fmt.Sprintf("type:%s;", msg.Type))
	sb.WriteString(fmt.Sprintf("author:%s;", msg.Metadata.Author))
	sb.WriteString(fmt.Sprintf("channel_id:%s;", msg.Metadata.ChannelID))
	sb.WriteString(fmt.Sprintf("sequence:%d;", msg.Sequence))
	sb.WriteString(fmt.Sprintf("timestamp:%d;", msg.Timestamp.UnixNano()))

	// Sort and add content map to the canonical string
	if len(msg.Metadata.Content) > 0 {
		keys := make([]string, 0, len(msg.Metadata.Content))
		for k := range msg.Metadata.Content {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteString(fmt.Sprintf("content[%s]:%s;", k, msg.Metadata.Content[k]))
		}
	} else {
		sb.WriteString(fmt.Sprintf("single_content:%s;", msg.Metadata.SingleContent))
	}

	canonicalData := sb.String()

	// Create HMAC-SHA256
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(canonicalData))
	return hex.EncodeToString(h.Sum(nil))
}

// ValidateMessageIntegrity validates message HMAC using provided secret
func ValidateMessageIntegrity(msg *types.Message, secret []byte) bool {
	if msg.HMAC == "" {
		return false
	}

	expectedHMAC := generateMessageHMAC(msg, secret)
	return hmac.Equal([]byte(msg.HMAC), []byte(expectedHMAC))
}

// SetServer sets the server instance for the messaging subsystem
func SetServer(s *types.Server) {
	server = s
}

// GetMessageStats returns current messaging statistics
func GetMessageStats() map[string]interface{} {
	if server == nil {
		return map[string]interface{}{"status": "not_initialized"}
	}

	server.Mutex.RLock()
	defer server.Mutex.RUnlock()

	roomCount := len(server.Rooms)
	connectionCount := len(server.Connections)

	totalMessages := int64(0)
	totalRoomUsers := 0

	for _, room := range server.Rooms {
		room.Mutex.RLock()
		totalMessages += room.MessageCount
		totalRoomUsers += len(room.Clients)
		room.Mutex.RUnlock()
	}

	return map[string]interface{}{
		"active_rooms":       roomCount,
		"active_connections": connectionCount,
		"total_room_users":   totalRoomUsers,
		"total_messages":     totalMessages,
		"message_sequence":   messageSequence,
		"uptime":             time.Since(server.StartTime).String(),
	}
}

// Emergency functions for security incidents

func EmergencyShutdownMessaging() {
	logger.Warn("🚨 EMERGENCY: Messaging subsystem shutdown initiated", nil)

	// Close shutdown channel to stop all messaging operations
	select {
	case <-shutdownChan:
		// Already closed
	default:
		close(shutdownChan)
	}

	// Clear all pending message queues (if any were implemented)
	// Force garbage collection to clear message buffers
	runtime.GC()

	logger.Warn("🛑 Messaging subsystem emergency shutdown completed", nil)
}

func PurgeRoomHistory(roomID string) {
	if server == nil {
		return
	}

	server.Mutex.Lock()
	defer server.Mutex.Unlock()

	if room, exists := server.Rooms[roomID]; exists {
		room.Mutex.Lock()
		// Clear audit log
		room.AuditLog = room.AuditLog[:0]
		room.MessageCount = 0
		room.Mutex.Unlock()

		logger.Warn("🗑️ Room history purged", map[string]interface{}{
			"room_id": roomID,
		})
	}
}
