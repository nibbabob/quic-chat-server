package types

import (
	"context"
	"io"
	"net"
	"time"
)

// Stream is an interface that abstracts a QUIC stream to allow for mocking.
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	// Add the Context method to fully satisfy the quic.Stream interface for mocks
	Context() context.Context
}

// Connection represents an abstract network connection to a client.
// It decouples the application logic from the underlying transport (e.g., QUIC).
type Connection interface {
	AcceptStream(ctx context.Context) (Stream, error) // <-- ADD THIS LINE
	OpenStreamSync(ctx context.Context) (Stream, error)
	SendMessage(msg Message) error
	RemoteAddr() net.Addr
	CloseWithError(code uint64, reason string) error
}
