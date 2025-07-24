package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"quic-chat-server/config"
	"quic-chat-server/messaging"
	"quic-chat-server/security"
	"quic-chat-server/types"
	"strings"
	"sync"
	"testing"
	"time"
)

// MockStream implements the types.Stream interface for testing.
type MockStream struct {
	bytes.Buffer
	deadline time.Time
	closed   bool
}

func (s *MockStream) Close() error {
	s.closed = true
	return nil
}
func (s *MockStream) SetDeadline(t time.Time) error {
	s.deadline = t
	return nil
}

// MockConnection implements the types.Connection interface for testing.
type MockConnection struct {
	closed   bool
	closeErr error
}

func (c *MockConnection) OpenStreamSync(ctx context.Context) (types.Stream, error) {
	return &MockStream{}, nil
}
func (c *MockConnection) SendMessage(msg types.Message) error { return nil }
func (c *MockConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}
}
func (c *MockConnection) CloseWithError(code uint64, reason string) error {
	c.closed = true
	c.closeErr = errors.New(reason)
	return nil
}

func newMockConnection() *MockConnection {
	return &MockConnection{}
}

// setupHandlerTest initializes all necessary subsystems for testing the handlers.
func setupHandlerTest(t *testing.T) (*config.Config, func()) {
	t.Setenv("IP_HASH_SALT", "546861742773206d79204b756e67204675546861742773206d79204b756e67204675")
	t.Setenv("HMAC_SECRET", "a-super-secret-hmac-key-for-testing")

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config for handler test: %v", err)
	}

	InitializeServer(cfg)
	messaging.InitializeServer(cfg)
	messaging.SetServer(GetServer())
	security.InitializeSecurityMonitor(cfg)

	cleanup := func() {
		server = nil
		serverConfig = nil
		// Reset shutdown channel for tests that use it
		shutdownChan = make(chan struct{})
		shutdownOnce = sync.Once{}
	}
	return cfg, cleanup
}

func TestHandleSecureConnection(t *testing.T) {
	t.Run("Connection Times Out", func(t *testing.T) {
		cfg, cleanup := setupHandlerTest(t)
		defer cleanup()
		cfg.Server.ConnectionTimeout = 1 // Use a short timeout
		conn := newMockConnection()
		HandleSecureConnection(conn, "test-conn-timeout")
		if !conn.closed {
			t.Fatal("Connection was not closed on timeout")
		}
		if !strings.Contains(conn.closeErr.Error(), "connection_timed_out") {
			t.Errorf("Expected timeout error, got: %v", conn.closeErr)
		}
	})

	t.Run("Connection Rejected At Capacity", func(t *testing.T) {
		cfg, cleanup := setupHandlerTest(t)
		defer cleanup()
		cfg.Server.MaxConnections = 0 // Set capacity to 0
		conn := newMockConnection()
		HandleSecureConnection(conn, "test-conn-capacity")
		if !conn.closed || !strings.Contains(conn.closeErr.Error(), "server_capacity_exceeded") {
			t.Error("Connection was not rejected due to server capacity")
		}
	})
}

func TestHandleSecureStream(t *testing.T) {
	cfg, cleanup := setupHandlerTest(t)
	defer cleanup()
	conn := newMockConnection()
	connID := "test-stream-conn"

	baseClient := &types.ClientConnection{
		ID:            connID,
		Conn:          conn,
		UserID:        "test-user",
		RoomID:        "test-room",
		Authenticated: true,
	}
	server.Connections[connID] = baseClient

	t.Run("Handle Valid Join", func(t *testing.T) {
		msg := types.Message{Type: "join", Metadata: types.Metadata{Author: "test-user", ChannelID: "test-room", PublicKey: "key"}}
		data, _ := json.Marshal(msg)
		stream := &MockStream{Buffer: *bytes.NewBuffer(data)}
		handleSecureStream(stream, conn, connID)
		if len(server.Rooms) != 1 {
			t.Error("handleSecureStream did not create a room for a join message")
		}
		if !strings.Contains(stream.String(), "join_ack") {
			t.Error("Did not receive join_ack")
		}
	})

	t.Run("Handle Join To Full Room", func(t *testing.T) {
		cfg.Server.MaxUsersPerRoom = 0
		msg := types.Message{Type: "join", Metadata: types.Metadata{Author: "new-user", ChannelID: "test-room", PublicKey: "key2"}}
		data, _ := json.Marshal(msg)
		stream := &MockStream{Buffer: *bytes.NewBuffer(data)}
		handleSecureStream(stream, conn, "new-conn")
		if !strings.Contains(stream.String(), "room_user_limit_exceeded") {
			t.Error("Did not receive room_user_limit_exceeded error")
		}
		cfg.Server.MaxUsersPerRoom = 10 // Reset
	})

	t.Run("Handle Heartbeat", func(t *testing.T) {
		msg := types.Message{Type: "heartbeat"}
		data, _ := json.Marshal(msg)
		stream := &MockStream{Buffer: *bytes.NewBuffer(data)}
		handleSecureStream(stream, conn, connID)
		if !strings.Contains(stream.String(), "heartbeat_ack") {
			t.Error("handleSecureStream did not respond to heartbeat with an ack")
		}
	})
}

func TestKickUser(t *testing.T) {
	_, cleanup := setupHandlerTest(t)
	defer cleanup()

	conn := newMockConnection()
	server.Connections["kick-conn-id"] = &types.ClientConnection{
		ID: "kick-conn-id", Conn: conn, UserID: "user-to-kick",
	}

	if !KickUser("user-to-kick") {
		t.Error("KickUser returned false for an existing user")
	}
	if !conn.closed {
		t.Error("KickUser did not close the connection")
	}
	if KickUser("non-existent-user") {
		t.Error("KickUser returned true for a non-existing user")
	}
}

func TestCleanupConnection(t *testing.T) {
	_, cleanup := setupHandlerTest(t)
	defer cleanup()
	connID := "cleanup-conn"
	roomID := "cleanup-room"

	client := types.NewSecureClientConnection(connID, newMockConnection(), "cleanup-user")
	client.RoomID = roomID
	client.Authenticated = true

	room := types.NewSecureRoom(roomID, "standard")
	room.Clients[connID] = client

	server.Connections[connID] = client
	server.Rooms[roomID] = room

	cleanupConnection(connID)

	if _, exists := server.Connections[connID]; exists {
		t.Error("cleanupConnection did not remove the connection from the server")
	}
	if _, exists := server.Rooms[roomID]; exists {
		t.Error("cleanupConnection did not remove the empty room from the server")
	}
}
