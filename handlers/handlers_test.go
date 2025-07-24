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
