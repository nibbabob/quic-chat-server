package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"quic-chat-server/types"
	"time"

	"github.com/quic-go/quic-go"
)

func handleConnection(conn *quic.Conn, connID string) {
	defer func() {
		server.Mutex.Lock()
		client, exists := server.Connections[connID]
		if exists {
			if client.RoomID != "" {
				if room, roomExists := server.Rooms[client.RoomID]; roomExists {
					room.Mutex.Lock()
					delete(room.Clients, connID)
					room.Mutex.Unlock()

					leaveMsg := types.Message{
						ID:   generateSecureID(),
						Type: "leave",
						Metadata: types.Metadata{
							Author:        client.UserID,
							SingleContent: fmt.Sprintf("%s has left the room", client.UserID),
							ChannelID:     client.RoomID,
						},
					}
					broadcastSimpleMessageToRoom(client.RoomID, leaveMsg, connID)
				}
			}
			delete(server.Connections, connID)
		}
		server.Mutex.Unlock()
		conn.CloseWithError(0, "connection closed")
		log.Printf("🔒 Connection %s securely closed", connID)
	}()

	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Error accepting stream for %s: %v", connID, err)
			return
		}
		go handleStream(stream, conn, connID)
	}
}

func handleStream(stream *quic.Stream, conn *quic.Conn, connID string) {
	defer stream.Close()
	var msg types.Message
	if err := json.NewDecoder(stream).Decode(&msg); err != nil {
		if err != io.EOF {
			log.Printf("Error decoding message from %s: %v", connID, err)
		}
		return
	}

	switch msg.Type {
	case "join":
		handleJoin(stream, conn, connID, msg)
	case "message":
		handleMessage(stream, connID, msg)
	default:
		log.Printf("Unknown message type: %s", msg.Type)
	}
}

// REWRITTEN: handleJoin now syncs keys for the new user
func handleJoin(stream *quic.Stream, conn *quic.Conn, connID string, msg types.Message) {
	server.Mutex.Lock()
	room, exists := server.Rooms[msg.Metadata.ChannelID]
	if !exists {
		room = &types.Room{
			ID:      msg.Metadata.ChannelID,
			Clients: make(map[string]*types.ClientConnection),
		}
		server.Rooms[msg.Metadata.ChannelID] = room
	}
	server.Mutex.Unlock()

	room.Mutex.Lock()
	existingUsers := make(map[string]string)
	for _, c := range room.Clients {
		existingUsers[c.UserID] = c.PublicKey
	}

	client := &types.ClientConnection{
		ID:        connID,
		Conn:      conn,
		UserID:    msg.Metadata.Author,
		RoomID:    msg.Metadata.ChannelID,
		PublicKey: msg.Metadata.PublicKey,
	}
	room.Clients[connID] = client
	room.Mutex.Unlock()

	server.Mutex.Lock()
	server.Connections[connID] = client
	server.Mutex.Unlock()

	log.Printf("👤 User %s (%s) joined room %s", msg.Metadata.Author, connID, msg.Metadata.ChannelID)

	response := types.Message{
		ID:        generateSecureID(),
		Type:      "join_ack",
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			SingleContent: "Successfully joined secure room",
			ChannelID:     msg.Metadata.ChannelID,
			ExistingUsers: existingUsers,
		},
	}
	if err := json.NewEncoder(stream).Encode(response); err != nil {
		log.Printf("Error sending join confirmation: %v", err)
	}

	joinMsg := types.Message{
		ID:        generateSecureID(),
		Type:      "user_joined",
		Timestamp: time.Now(),
		Metadata: types.Metadata{
			Author:        msg.Metadata.Author,
			SingleContent: fmt.Sprintf("%s joined the room", msg.Metadata.Author),
			ChannelID:     msg.Metadata.ChannelID,
			PublicKey:     msg.Metadata.PublicKey,
		},
	}
	broadcastSimpleMessageToRoom(msg.Metadata.ChannelID, joinMsg, connID)
}

// REWRITTEN: handleMessage now calls the smart broadcast function
func handleMessage(stream *quic.Stream, connID string, msg types.Message) {
	server.Mutex.RLock()
	client, exists := server.Connections[connID]
	server.Mutex.RUnlock()

	if !exists {
		log.Printf("Client %s not found", connID)
		return
	}

	log.Printf("📨 Encrypted message bundle from %s in room %s", msg.Metadata.Author, msg.Metadata.ChannelID)
	msg.Timestamp = time.Now()
	msg.ID = generateSecureID()

	broadcastEncryptedMessageToRoom(client.RoomID, msg)

	ack := types.Message{
		ID:   generateSecureID(),
		Type: "message_ack",
		Metadata: types.Metadata{
			SingleContent: "Message bundle received by server.",
		},
	}
	if err := json.NewEncoder(stream).Encode(ack); err != nil {
		log.Printf("Error sending message ack: %v", err)
	}
}
