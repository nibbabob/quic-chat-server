package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"quic-chat-server/config"
	"quic-chat-server/messaging"
	"quic-chat-server/security"
	"quic-chat-server/types"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// MockStream provides a mock implementation of the types.Stream interface for testing.
type MockStream struct {
	sync.Mutex
	ReadBuffer  []byte
	WriteBuffer [][]byte
	CloseCalled bool
	Ctx         context.Context
	Cancel      context.CancelFunc
}

func (m *MockStream) Read(p []byte) (n int, err error) {
	m.Lock()
	defer m.Unlock()
	if len(m.ReadBuffer) == 0 {
		return 0, io.EOF
	}
	n = copy(p, m.ReadBuffer)
	m.ReadBuffer = m.ReadBuffer[n:]
	return n, nil
}
func (m *MockStream) Write(p []byte) (n int, err error) {
	m.Lock()
	defer m.Unlock()
	b := make([]byte, len(p))
	copy(b, p)
	m.WriteBuffer = append(m.WriteBuffer, b)
	return len(p), nil
}
func (m *MockStream) Close() error {
	m.Lock()
	defer m.Unlock()
	m.CloseCalled = true
	if m.Cancel != nil {
		m.Cancel()
	}
	return nil
}
func (m *MockStream) SetDeadline(t time.Time) error { return nil }
func (m *MockStream) Context() context.Context      { return m.Ctx }

// MockConnection provides a mock implementation of the types.Connection interface.
type MockConnection struct {
	AcceptStreamChan chan types.Stream
	CloseWithErrorFn func(code uint64, reason string) error
	RemoteAddrFn     func() net.Addr
}

func (m *MockConnection) AcceptStream(ctx context.Context) (types.Stream, error) {
	select {
	case stream, ok := <-m.AcceptStreamChan:
		if !ok {
			return nil, errors.New("connection closed")
		}
		return stream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (m *MockConnection) OpenStreamSync(ctx context.Context) (types.Stream, error) {
	return &MockStream{}, nil
}
func (m *MockConnection) SendMessage(msg types.Message) error { return nil }
func (m *MockConnection) CloseWithError(code uint64, reason string) error {
	if m.CloseWithErrorFn != nil {
		return m.CloseWithErrorFn(code, reason)
	}
	return nil
}
func (m *MockConnection) RemoteAddr() net.Addr {
	if m.RemoteAddrFn != nil {
		return m.RemoteAddrFn()
	}
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

// setupHandlersTest initializes the necessary components for testing the handlers package.
func setupHandlersTest(t *testing.T) (*config.Config, func()) {
	t.Setenv("IP_HASH_SALT", "546861742773206d79204b756e67204675546861742773206d79204b756e67204675")
	t.Setenv("HMAC_SECRET", "a-super-secret-hmac-key-for-testing")

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config for handlers test: %v", err)
	}
	cfg.Server.ConnectionTimeout = 2 // Increased timeout slightly for stability

	InitializeServer(cfg)
	messaging.InitializeServer(cfg)
	security.InitializeSecurityMonitor(cfg)

	cleanup := func() {
		server = nil
		serverConfig = nil
		shutdownChan = make(chan struct{})
	}
	return cfg, cleanup
}

func TestHandleSecureConnection(t *testing.T) {
	_, cleanup := setupHandlersTest(t)
	defer cleanup()

	mockConn := &MockConnection{
		AcceptStreamChan: make(chan types.Stream, 1),
		CloseWithErrorFn: func(code uint64, reason string) error { return nil },
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		HandleSecureConnection(mockConn, "test-conn-id")
	}()

	validPublicKey := strings.Repeat("a", 128)
	joinMsg := types.Message{
		Type: "join",
		Metadata: types.Metadata{
			Author:    "test-user",
			ChannelID: "test-room",
			PublicKey: validPublicKey,
		},
	}
	joinData, _ := json.Marshal(joinMsg)
	streamCtx, streamCancel := context.WithCancel(context.Background())
	mockStream := &MockStream{ReadBuffer: joinData, Ctx: streamCtx, Cancel: streamCancel}

	mockConn.AcceptStreamChan <- mockStream
	<-streamCtx.Done()

	// *** THE FIX: Assert the state *before* closing the connection. ***
	server.Mutex.RLock()
	if len(server.Connections) != 1 {
		t.Errorf("Expected 1 connection after join, got %d", len(server.Connections))
	}
	if len(server.Rooms) != 1 {
		t.Errorf("Expected 1 room after join, got %d", len(server.Rooms))
	}
	server.Mutex.RUnlock()

	close(mockConn.AcceptStreamChan)
	wg.Wait()
}

func TestConnectionRejectionAtCapacity(t *testing.T) {
	cfg, cleanup := setupHandlersTest(t)
	defer cleanup()

	// Set server to be at capacity
	cfg.Server.MaxConnections = 0

	closeCalled := false
	mockConn := &MockConnection{
		CloseWithErrorFn: func(code uint64, reason string) error {
			closeCalled = true
			if reason != "server_capacity_exceeded" {
				t.Errorf("Expected close reason 'server_capacity_exceeded', got '%s'", reason)
			}
			return nil
		},
	}

	HandleSecureConnection(mockConn, "test-conn-id-reject")

	if !closeCalled {
		t.Error("Expected connection to be closed due to server capacity, but it wasn't")
	}
}

func TestKickUser(t *testing.T) {
	_, cleanup := setupHandlersTest(t)
	defer cleanup()

	closeCalled := false
	mockConn := &MockConnection{
		CloseWithErrorFn: func(code uint64, reason string) error {
			closeCalled = true
			return nil
		},
	}

	server.Mutex.Lock()
	server.Connections["kick-conn-id"] = &types.ClientConnection{
		ID:     "kick-conn-id",
		UserID: "user-to-kick",
		Conn:   mockConn,
	}
	server.Mutex.Unlock()

	kicked := KickUser("user-to-kick")

	if !kicked {
		t.Error("KickUser returned false, expected true")
	}
	if !closeCalled {
		t.Error("Expected the connection's CloseWithError method to be called")
	}
}

func TestHandleSecureStream_InvalidJSON(t *testing.T) {
	_, cleanup := setupHandlersTest(t)
	defer cleanup()

	// Add a connection to the server so stream handling can find it
	server.Mutex.Lock()
	server.Connections["stream-test-conn"] = &types.ClientConnection{
		ID:     "stream-test-conn",
		UserID: "stream-user",
		RoomID: "stream-room",
		Conn:   &MockConnection{}, // The connection itself can be a simple mock
	}
	server.Mutex.Unlock()

	// Test with invalid message format
	streamCtx, streamCancel := context.WithCancel(context.Background())
	mockStream := &MockStream{ReadBuffer: []byte("not json"), Ctx: streamCtx, Cancel: streamCancel}

	// The stream handler is synchronous for this test's purpose
	handleSecureStream(mockStream, nil, "stream-test-conn")

	// Check if an error response was written to the stream
	if len(mockStream.WriteBuffer) == 0 {
		t.Fatal("Expected an error response for invalid JSON, but got none")
	}
	var errorResp types.Message
	if err := json.Unmarshal(mockStream.WriteBuffer[0], &errorResp); err != nil {
		t.Fatalf("Failed to unmarshal error response: %v", err)
	}
	if errorResp.Type != "error" || errorResp.Metadata.SingleContent != "invalid_message_format" {
		t.Errorf("Unexpected error response: %+v", errorResp)
	}
}

func TestIsConnectionClosed(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected bool
	}{
		{"Nil error", nil, false},
		{"Generic connection closed error", errors.New("an error: connection closed by peer"), true},
		{"QUIC graceful close", &quic.ApplicationError{ErrorCode: 0}, true},
		{"QUIC kicked error", &quic.ApplicationError{ErrorCode: 0x102}, true},
		{"QUIC shutdown error", &quic.ApplicationError{ErrorCode: 0x200}, true},
		{"Other QUIC error", &quic.ApplicationError{ErrorCode: 0x500}, false},
		{"Non-close error", errors.New("some other error"), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsConnectionClosed(tc.err); got != tc.expected {
				t.Errorf("IsConnectionClosed() with err '%v' = %v; want %v", tc.err, got, tc.expected)
			}
		})
	}
}

// MockStreamWithError is a mock stream that can be configured to return an error on Write.
type MockStreamWithError struct {
	MockStream
	WriteShouldFail bool
}

func (m *MockStreamWithError) Write(p []byte) (n int, err error) {
	if m.WriteShouldFail {
		return 0, errors.New("mock write error")
	}
	return m.MockStream.Write(p)
}

func TestHandleSecureMessage(t *testing.T) {
	cfg, cleanup := setupHandlersTest(t)
	defer cleanup()

	// Setup a client and room
	roomID := "test-room"
	connID := "test-conn"
	userID := "test-user"

	mockConn := &MockConnection{
		AcceptStreamChan: make(chan types.Stream, 1),
	}
	client := &types.ClientConnection{
		ID:            connID,
		Conn:          mockConn,
		UserID:        userID,
		RoomID:        roomID,
		Authenticated: true,
		LastActivity:  time.Now().Add(-1 * time.Minute),
		MessageCount:  0,
	}
	server.Connections[connID] = client
	server.Rooms[roomID] = &types.Room{
		ID:      roomID,
		Clients: map[string]*types.ClientConnection{connID: client},
	}

	t.Run("Client Not Found", func(t *testing.T) {
		msg := types.Message{Type: "message"}
		data, _ := json.Marshal(msg)
		stream := &MockStream{ReadBuffer: data}
		handleSecureMessage(context.Background(), stream, "non-existent-conn", msg)

		var resp types.Message
		json.Unmarshal(stream.WriteBuffer[0], &resp)
		if resp.Metadata.SingleContent != "client_not_found" {
			t.Errorf("Expected 'client_not_found' error, got '%s'", resp.Metadata.SingleContent)
		}
	})

	t.Run("Authentication Required", func(t *testing.T) {
		client.Authenticated = false
		cfg.Security.RequireClientAuth = true
		msg := types.Message{Type: "message"}
		data, _ := json.Marshal(msg)
		stream := &MockStream{ReadBuffer: data}
		handleSecureMessage(context.Background(), stream, connID, msg)

		var resp types.Message
		json.Unmarshal(stream.WriteBuffer[0], &resp)
		if resp.Metadata.SingleContent != "authentication_required" {
			t.Errorf("Expected 'authentication_required' error, got '%s'", resp.Metadata.SingleContent)
		}
		// Reset for next tests
		client.Authenticated = true
		cfg.Security.RequireClientAuth = false
	})

	t.Run("Successful Message", func(t *testing.T) {
		initialActivity := client.LastActivity
		initialCount := client.MessageCount
		msg := types.Message{Type: "message", Metadata: types.Metadata{Content: map[string]string{"recipient": "encrypted_message"}}}
		data, _ := json.Marshal(msg)
		stream := &MockStream{ReadBuffer: data}
		handleSecureMessage(context.Background(), stream, connID, msg)

		if client.LastActivity.Equal(initialActivity) {
			t.Error("Client LastActivity was not updated")
		}
		if client.MessageCount == initialCount {
			t.Error("Client MessageCount was not updated")
		}

		var resp types.Message
		json.Unmarshal(stream.WriteBuffer[0], &resp)
		if resp.Type != "message_ack" {
			t.Errorf("Expected 'message_ack', got '%s'", resp.Type)
		}
	})

	t.Run("Failed Message Ack", func(t *testing.T) {
		msg := types.Message{Type: "message", Metadata: types.Metadata{Content: map[string]string{"recipient": "encrypted_message"}}}
		data, _ := json.Marshal(msg)
		stream := &MockStreamWithError{MockStream: MockStream{ReadBuffer: data}, WriteShouldFail: true}
		handleSecureMessage(context.Background(), stream, connID, msg)

		// We can't assert on the log output easily without DI, but we can ensure the function doesn't panic.
		// A more advanced test would involve a mock logger.
	})
}

func TestHandleHeartbeat(t *testing.T) {
	_, cleanup := setupHandlersTest(t)
	defer cleanup()

	connID := "heartbeat-conn"
	client := &types.ClientConnection{
		ID:           connID,
		LastActivity: time.Now().Add(-1 * time.Minute),
	}
	server.Connections[connID] = client

	t.Run("Existing Client", func(t *testing.T) {
		initialActivity := client.LastActivity
		stream := &MockStream{}
		handleHeartbeat(stream, connID)

		if client.LastActivity.Equal(initialActivity) {
			t.Error("Client LastActivity was not updated on heartbeat")
		}

		var resp types.Message
		json.Unmarshal(stream.WriteBuffer[0], &resp)
		if resp.Type != "heartbeat_ack" {
			t.Errorf("Expected 'heartbeat_ack', got '%s'", resp.Type)
		}
	})

	t.Run("Non-existent Client", func(t *testing.T) {
		stream := &MockStream{}
		handleHeartbeat(stream, "non-existent-conn")

		// No panic should occur, and an ack should still be sent.
		if len(stream.WriteBuffer) == 0 {
			t.Error("Expected heartbeat_ack even for non-existent client")
		}
	})
}

func TestHandleKeyRotation(t *testing.T) {
	_, cleanup := setupHandlersTest(t)
	defer cleanup()

	connID := "key-rotation-conn"
	userID := "key-rotation-user"
	roomID := "key-rotation-room"
	client := &types.ClientConnection{
		ID:            connID,
		UserID:        userID,
		RoomID:        roomID,
		Authenticated: true,
		PublicKey:     "old-key",
	}
	server.Connections[connID] = client
	server.Rooms[roomID] = &types.Room{
		ID:      roomID,
		Clients: map[string]*types.ClientConnection{connID: client},
	}

	t.Run("Unauthorized", func(t *testing.T) {
		client.Authenticated = false
		msg := types.Message{Type: "key_rotation", Metadata: types.Metadata{PublicKey: "new-key"}}
		data, _ := json.Marshal(msg)
		stream := &MockStream{ReadBuffer: data}
		handleKeyRotation(stream, connID, msg)

		var resp types.Message
		json.Unmarshal(stream.WriteBuffer[0], &resp)
		if resp.Metadata.SingleContent != "unauthorized_key_rotation" {
			t.Errorf("Expected 'unauthorized_key_rotation' error, got '%s'", resp.Metadata.SingleContent)
		}
		client.Authenticated = true // Reset for next test
	})

	t.Run("Success", func(t *testing.T) {
		newKey := "new-public-key"
		msg := types.Message{Type: "key_rotation", Metadata: types.Metadata{PublicKey: newKey}}
		data, _ := json.Marshal(msg)
		stream := &MockStream{ReadBuffer: data}
		handleKeyRotation(stream, connID, msg)

		if client.PublicKey != newKey {
			t.Errorf("Client PublicKey was not updated. Got %s, want %s", client.PublicKey, newKey)
		}

		var resp types.Message
		json.Unmarshal(stream.WriteBuffer[0], &resp)
		if resp.Type != "key_rotation_ack" {
			t.Errorf("Expected 'key_rotation_ack', got '%s'", resp.Type)
		}
	})
}

func TestForceCloseAllConnections(t *testing.T) {
	_, cleanup := setupHandlersTest(t)
	defer cleanup()

	closeCalled1 := false
	mockConn1 := &MockConnection{
		CloseWithErrorFn: func(code uint64, reason string) error {
			closeCalled1 = true
			return nil
		},
	}
	closeCalled2 := false
	mockConn2 := &MockConnection{
		CloseWithErrorFn: func(code uint64, reason string) error {
			closeCalled2 = true
			return nil
		},
	}

	server.Connections["conn1"] = &types.ClientConnection{ID: "conn1", Conn: mockConn1}
	server.Connections["conn2"] = &types.ClientConnection{ID: "conn2", Conn: mockConn2}
	server.Rooms["room1"] = &types.Room{ID: "room1"}

	ForceCloseAllConnections()

	if !closeCalled1 || !closeCalled2 {
		t.Error("Not all client connections were closed")
	}
	if len(server.Connections) != 0 {
		t.Errorf("Expected 0 connections after ForceCloseAllConnections, got %d", len(server.Connections))
	}
	if len(server.Rooms) != 0 {
		t.Errorf("Expected 0 rooms after ForceCloseAllConnections, got %d", len(server.Rooms))
	}

	// Test that shutdownChan is closed
	select {
	case <-shutdownChan:
		// Channel is closed, as expected
	default:
		t.Error("shutdownChan was not closed")
	}
}
