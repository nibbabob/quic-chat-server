package messaging

import (
	"context"
	"errors"
	"net"
	"quic-chat-server/config"
	"quic-chat-server/types"
	"sync"
	"testing"
	"time"
)

// MockStream provides a mock implementation of the types.Stream interface for testing.
type MockStream struct {
	sync.Mutex
	WriteBuffer [][]byte
	ReadBuffer  []byte
	CloseCalled bool
}

func (m *MockStream) Read(p []byte) (n int, err error) {
	m.Lock()
	defer m.Unlock()
	if len(m.ReadBuffer) == 0 {
		return 0, errors.New("mock stream read error")
	}
	n = copy(p, m.ReadBuffer)
	m.ReadBuffer = m.ReadBuffer[n:]
	return n, nil
}
func (m *MockStream) Write(p []byte) (n int, err error) {
	m.Lock()
	defer m.Unlock()
	m.WriteBuffer = append(m.WriteBuffer, p)
	return len(p), nil
}
func (m *MockStream) Close() error {
	m.Lock()
	defer m.Unlock()
	m.CloseCalled = true
	return nil
}
func (m *MockStream) SetDeadline(t time.Time) error { return nil }

// MockConnection provides a mock implementation of the types.Connection interface for testing.
type MockConnection struct {
	sync.Mutex
	LastStream      *MockStream
	OpenStreamError error
}

func (m *MockConnection) OpenStreamSync(ctx context.Context) (types.Stream, error) {
	m.Lock()
	defer m.Unlock()
	if m.OpenStreamError != nil {
		return nil, m.OpenStreamError
	}
	m.LastStream = &MockStream{}
	return m.LastStream, nil
}
func (m *MockConnection) SendMessage(msg types.Message) error { return nil }
func (m *MockConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (m *MockConnection) CloseWithError(code uint64, reason string) error { return nil }

// setupMessagingTest initializes the messaging subsystem with a mock server for testing.
func setupMessagingTest(t *testing.T) (*config.Config, func()) {
	t.Setenv("HMAC_SECRET", "a-super-secret-hmac-key-for-testing")
	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config for messaging test: %v", err)
	}

	InitializeServer(cfg)
	SetHMACSecret([]byte(cfg.Security.HMACSecret))

	// Initialize a mock server
	mockServer := &types.Server{
		Connections: make(map[string]*types.ClientConnection),
		Rooms:       make(map[string]*types.Room),
		Mutex:       sync.RWMutex{},
		StartTime:   time.Now(),
	}
	// Inject the mock server into the messaging package
	SetServer(mockServer)

	cleanup := func() {
		// Reset global state after the test
		server = nil
		serverConfig = nil
		messageSequence = 0
		userSequence = make(map[string]uint64)
	}

	return cfg, cleanup
}

// TestBroadcastEncryptedMessageToRoom covers broadcasting encrypted messages.
func TestBroadcastEncryptedMessageToRoom(t *testing.T) {
	_, cleanup := setupMessagingTest(t)
	defer cleanup()

	roomID := "secure-room"
	server.Rooms[roomID] = types.NewSecureRoom(roomID, "maximum")

	// Add mock clients
	client1Conn := &MockConnection{}
	client2Conn := &MockConnection{}
	server.Rooms[roomID].Clients["client1"] = types.NewSecureClientConnection("client1", client1Conn, "user1")
	server.Rooms[roomID].Clients["client2"] = types.NewSecureClientConnection("client2", client2Conn, "user2")

	msg := types.Message{
		ID:   "msg1", // Add an ID to pass validation
		Type: "message",
		Metadata: types.Metadata{
			Author: "user2",
			Content: map[string]string{
				"user1": "encrypted-for-user1",
				"user2": "encrypted-for-user2",
			},
		},
		Timestamp: time.Now(), // Add a valid timestamp
	}

	// 1. Test successful broadcast
	BroadcastEncryptedMessageToRoom(roomID, msg)
	time.Sleep(100 * time.Millisecond) // Allow goroutines to execute

	if client1Conn.LastStream == nil || len(client1Conn.LastStream.WriteBuffer) == 0 {
		t.Error("Client 1 did not receive the message")
	}
	if client2Conn.LastStream == nil || len(client2Conn.LastStream.WriteBuffer) == 0 {
		t.Error("Client 2 did not receive the message")
	}

	// 2. Test broadcast to a non-existent room (should not panic)
	BroadcastEncryptedMessageToRoom("ghost-room", msg)

	// 3. Test with an invalid message (too large)
	serverConfig.Security.MaxMessageSize = 10
	BroadcastEncryptedMessageToRoom(roomID, msg) // Should be rejected
}

// TestBroadcastSimpleMessageToRoom covers simple notifications.
func TestBroadcastSimpleMessageToRoom(t *testing.T) {
	_, cleanup := setupMessagingTest(t)
	defer cleanup()

	roomID := "notify-room"
	server.Rooms[roomID] = types.NewSecureRoom(roomID, "standard")
	client1Conn := &MockConnection{}
	server.Rooms[roomID].Clients["client1"] = types.NewSecureClientConnection("client1", client1Conn, "user1")

	msg := types.Message{Type: "user_joined", Metadata: types.Metadata{Author: "user1"}}
	BroadcastSimpleMessageToRoom(roomID, msg, "client-to-exclude")
	time.Sleep(100 * time.Millisecond)

	if client1Conn.LastStream == nil {
		t.Error("Simple message was not broadcast")
	}
}

// TestNotifyClientsShutdown ensures shutdown notifications are sent.
func TestNotifyClientsShutdown(t *testing.T) {
	_, cleanup := setupMessagingTest(t)
	defer cleanup()

	client1Conn := &MockConnection{}
	server.Connections["client1"] = types.NewSecureClientConnection("client1", client1Conn, "user1")

	NotifyClientsShutdown(context.Background())
	time.Sleep(100 * time.Millisecond)

	if client1Conn.LastStream == nil {
		t.Error("Shutdown message was not sent")
	}
}

// TestValidateMessageIntegrity checks HMAC validation logic.
func TestValidateMessageIntegrity(t *testing.T) {
	cfg, cleanup := setupMessagingTest(t)
	defer cleanup()

	msg := &types.Message{
		ID:        "test-id",
		Type:      "message",
		Sequence:  1,
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			Author:        "test-user",
			ChannelID:     "test-channel",
			SingleContent: "hello",
		},
	}

	// 1. Generate a valid HMAC
	msg.HMAC = generateMessageHMAC(msg, []byte(cfg.Security.HMACSecret))
	if !ValidateMessageIntegrity(msg, []byte(cfg.Security.HMACSecret)) {
		t.Error("ValidateMessageIntegrity() failed for a valid HMAC")
	}

	// 2. Test with an invalid HMAC
	msg.HMAC = "invalid-hmac"
	if ValidateMessageIntegrity(msg, []byte(cfg.Security.HMACSecret)) {
		t.Error("ValidateMessageIntegrity() succeeded for an invalid HMAC")
	}

	// 3. Test with no HMAC
	msg.HMAC = ""
	if ValidateMessageIntegrity(msg, []byte(cfg.Security.HMACSecret)) {
		t.Error("ValidateMessageIntegrity() succeeded for a message with no HMAC")
	}
}

// TestGetMessageStats verifies that server stats are returned correctly.
func TestGetMessageStats(t *testing.T) {
	_, cleanup := setupMessagingTest(t)
	defer cleanup()

	// 1. Test initial state
	stats := GetMessageStats()
	if stats["active_rooms"].(int) != 0 {
		t.Errorf("Initial active_rooms = %d; want 0", stats["active_rooms"])
	}

	// 2. Test with some data
	server.Rooms["room1"] = types.NewSecureRoom("room1", "standard")
	server.Connections["conn1"] = types.NewSecureClientConnection("conn1", &MockConnection{}, "user1")
	stats = GetMessageStats()
	if stats["active_rooms"].(int) != 1 {
		t.Errorf("Active_rooms with data = %d; want 1", stats["active_rooms"])
	}
	if stats["active_connections"].(int) != 1 {
		t.Errorf("Active_connections with data = %d; want 1", stats["active_connections"])
	}
}

// TestEmergencyShutdownAndPurge tests the emergency functions.
func TestEmergencyShutdownAndPurge(t *testing.T) {
	_, cleanup := setupMessagingTest(t)
	defer cleanup()

	roomID := "room-to-purge"
	room := types.NewSecureRoom(roomID, "standard")
	room.AddAuditEntry(types.NewAuditEntry("test_event", "user", "conn", "room", "low", nil))
	server.Rooms[roomID] = room

	// 1. Test PurgeRoomHistory
	if len(server.Rooms[roomID].AuditLog) == 0 {
		t.Fatal("Test setup failed: audit log is empty before purge")
	}
	PurgeRoomHistory(roomID)
	if len(server.Rooms[roomID].AuditLog) != 0 {
		t.Error("PurgeRoomHistory() did not clear the audit log")
	}

	// 2. Test EmergencyShutdownMessaging (should not panic)
	EmergencyShutdownMessaging()
}
