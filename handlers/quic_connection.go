package handlers

import (
	"context"
	"encoding/json"
	"net"
	"quic-chat-server/types"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICConnection is a concrete implementation of the types.Connection interface for QUIC.
type QUICConnection struct {
	qConn *quic.Conn
}

// NewQUICConnection creates a new wrapper around a quic.Connection.
func NewQUICConnection(conn *quic.Conn) *QUICConnection {
	return &QUICConnection{qConn: conn}
}

// OpenStreamSync opens a new synchronous QUIC stream.
func (c *QUICConnection) OpenStreamSync(ctx context.Context) (types.Stream, error) {
	return c.qConn.OpenStreamSync(ctx)
}

// SendMessage encodes a message and sends it over a new QUIC stream.
func (c *QUICConnection) SendMessage(msg types.Message) error {
	stream, err := c.qConn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(10 * time.Second))

	return json.NewEncoder(stream).Encode(msg)
}

// RemoteAddr returns the remote network address.
func (c *QUICConnection) RemoteAddr() net.Addr {
	return c.qConn.RemoteAddr()
}

// CloseWithError closes the connection with an application error code.
// The method has been renamed from "Close" to "CloseWithError" to match the interface.
func (c *QUICConnection) CloseWithError(code uint64, reason string) error {
	return c.qConn.CloseWithError(quic.ApplicationErrorCode(code), reason)
}
