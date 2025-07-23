package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"quic-chat-server/handlers"
	"quic-chat-server/types"
	"quic-chat-server/utils"
	"time"

	"github.com/quic-go/quic-go"
)

var server *types.Server

func main() {
	log.Println("Starting Ultra-Secure QUIC Messaging Server...")
	if err := generateCertIfNotExists(); err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}
	server = &types.Server{
		Connections: make(map[string]*types.ClientConnection),
		Rooms:       make(map[string]*types.Room),
	}
	startServer()
	select {}
}

func startServer() {
	config := &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
	}
	tlsConfig := generateTLSConfig()
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

func generateTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("certs/cert.pem", "certs/key.pem")
	if err != nil {
		log.Fatalf("Error loading TLS certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"secure-messaging-v1"},
		MinVersion:   tls.VersionTLS13,
	}
}

func generateCertIfNotExists() error {
	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		return generateSelfSignedCert()
	}
	return nil
}

func generateSelfSignedCert() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Secure Messaging"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	certOut, err := os.Create("cert.pem")
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()
	keyOut, err := os.Create("key.pem")
	if err != nil {
		return err
	}
	privateKeyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	keyOut.Close()
	log.Println("🔐 Generated self-signed certificate.")
	return nil
}
