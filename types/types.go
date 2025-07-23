package types

import (
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// Message structures for end-to-end encrypted messaging
type Message struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"` // "message", "join", "leave", "key_exchange"
	Metadata  Metadata  `json:"metadata"`
	Encrypted bool      `json:"encrypted"`
	Signature string    `json:"signature,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// MODIFIED: Metadata now supports different content types for E2EE
type Metadata struct {
	// Used for sending E2EE messages. map[recipient_username]encrypted_content
	Content map[string]string `json:"content,omitempty"`
	// Used for simple broadcast messages (join/leave) or for delivering a single encrypted payload
	SingleContent string  `json:"single_content,omitempty"`
	Author        string  `json:"author"`
	AuthorID      string  `json:"author_id"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
	DeletedAt     *string `json:"deleted_at,omitempty"`
	ChannelID     string  `json:"channel_id"`
	ChannelName   string  `json:"channel_name"`
	PublicKey     string  `json:"public_key,omitempty"`
	// Used to send the list of existing users to a new joiner
	ExistingUsers map[string]string `json:"existing_users,omitempty"`
}

// Server state for managing connections and rooms
type Server struct {
	Connections map[string]*ClientConnection
	Rooms       map[string]*Room
	Mutex       sync.RWMutex
}

// MODIFIED: ClientConnection now stores the user's public key
type ClientConnection struct {
	ID        string
	Conn      *quic.Conn // Changed to pointer to fix original issue
	UserID    string
	RoomID    string
	PublicKey string // Added to store the client's public key
}

type Room struct {
	ID      string
	Clients map[string]*ClientConnection
	Mutex   sync.RWMutex
}
