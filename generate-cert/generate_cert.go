package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

// Hoist crypto functions into variables to allow for mocking in tests.
var (
	rsaGenerateKey        = rsa.GenerateKey
	x509CreateCertificate = x509.CreateCertificate
)

// generateCertificate creates a new self-signed certificate and private key.
// It returns the PEM-encoded certificate and key, or an error.
func generateCertificate() (certPEM, keyPEM []byte, err error) {
	// Generate RSA key
	privateKey, err := rsaGenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a self-signed certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
			CommonName:   "localhost",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM format
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if certPEM == nil {
		return nil, nil, fmt.Errorf("failed to encode certificate to PEM")
	}

	// Encode private key to PEM format
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if keyPEM == nil {
		return nil, nil, fmt.Errorf("failed to encode private key to PEM")
	}

	return certPEM, keyPEM, nil
}

func main() {
	certPEM, keyPEM, err := generateCertificate()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	// Write cert.pem
	if err := os.WriteFile("cert.pem", certPEM, 0644); err != nil {
		log.Fatalf("Failed to write cert.pem: %v", err)
	}
	log.Println("Generated cert.pem")

	// Write key.pem
	if err := os.WriteFile("key.pem", keyPEM, 0600); err != nil {
		log.Fatalf("Failed to write key.pem: %v", err)
	}
	log.Println("Generated key.pem")
}
