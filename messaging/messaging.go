package messaging

import (
	"context"
	"encoding/json"
	"log"
	"quic-chat-server/types"
)

var server *types.Server

// NEW: This function acts as a smart relay for E2EE messages
func BroadcastEncryptedMessageToRoom(roomID string, msg types.Message) {
	server.Mutex.RLock()
	room, exists := server.Rooms[roomID]
	server.Mutex.RUnlock()
	if !exists {
		return
	}

	room.Mutex.RLock()
	defer room.Mutex.RUnlock()

	for _, client := range room.Clients {
		encryptedContent, ok := msg.Metadata.Content[client.UserID]
		if !ok {
			continue // No specific content for this user
		}

		personalMsg := types.Message{
			ID:        msg.ID,
			Type:      "message",
			Encrypted: true,
			Timestamp: msg.Timestamp,
			Metadata: types.Metadata{
				Author:        msg.Metadata.Author,
				ChannelID:     msg.Metadata.ChannelID,
				SingleContent: encryptedContent, // Send only the relevant ciphertext
			},
		}

		go func(c *types.ClientConnection, m types.Message) {
			stream, err := c.Conn.OpenStreamSync(context.Background())
			if err != nil {
				log.Printf("Error opening stream to %s: %v", c.ID, err)
				return
			}
			defer stream.Close()
			if err := json.NewEncoder(stream).Encode(m); err != nil {
				log.Printf("Error broadcasting to %s: %v", c.ID, err)
			}
		}(client, personalMsg)
	}
}

// RENAMED: This function handles simple, non-E2EE broadcasts like join/leave events
func BroadcastSimpleMessageToRoom(roomID string, msg types.Message, excludeConnID string) {
	server.Mutex.RLock()
	room, exists := server.Rooms[roomID]
	server.Mutex.RUnlock()
	if !exists {
		return
	}

	room.Mutex.RLock()
	defer room.Mutex.RUnlock()

	for clientID, client := range room.Clients {
		if clientID == excludeConnID {
			continue
		}
		go func(c *types.ClientConnection) {
			stream, err := c.Conn.OpenStreamSync(context.Background())
			if err != nil {
				log.Printf("Error opening stream to %s: %v", c.ID, err)
				return
			}
			defer stream.Close()
			if err := json.NewEncoder(stream).Encode(msg); err != nil {
				log.Printf("Error broadcasting to %s: %v", c.ID, err)
			}
		}(client)
	}
}
