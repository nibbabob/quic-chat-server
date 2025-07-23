package main

import (
	"context"
	"log"
	"quic-chat-server/crypto"
	"quic-chat-server/handlers"

	"quic-chat-server/utils"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	log.Println("Starting Ultra-Secure QUIC Messaging Server...")
	if err := crypto.GenerateCertIfNotExists(); err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	startServer()
	select {}
}

func startServer() {
	config := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}
	tlsConfig := crypto.GenerateTLSConfig()
	listener, err := quic.ListenAddr(":4433", tlsConfig, config)
	if err != nil {
		log.Fatalf("Error starting QUIC listener: %v", err)
	}
	log.Printf("🔒 Ultra-Secure QUIC server listening on :4433")
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		connID := utils.GenerateSecureID()
		log.Printf("🔗 New secure connection: %s", connID)
		go handlers.HandleConnection(conn, connID)
	}
}

// --- Utility and TLS Functions (Unchanged) ---
