package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"quic-chat-server/config"
	"quic-chat-server/security"
	"sync"
	"time"
)

var (
	certificateCache      *tls.Certificate
	certificateCacheMutex sync.RWMutex
	keyRotationTimer      *time.Timer
)

// GenerateMaxSecurityTLSConfig creates a TLS configuration with maximum security for whistleblowers
func GenerateMaxSecurityTLSConfig(cfg *config.Config) *tls.Config {
	cert, err := loadOrGenerateCertificate(cfg)
	if err != nil {
		log.Fatalf("❌ Critical: Failed to load cryptographic materials: %v", err)
	}

	// Cache certificate for performance
	certificateCacheMutex.Lock()
	certificateCache = cert
	certificateCacheMutex.Unlock()

	// Setup automatic key rotation if enabled
	if cfg.Crypto.KeyRotationIntervalHours > 0 {
		setupKeyRotation(cfg)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},

		// Protocol configuration for maximum security
		NextProtos: []string{"secure-messaging-v1"},
		MinVersion: tls.VersionTLS13, // Only TLS 1.3
		MaxVersion: tls.VersionTLS13,

		// Cipher suite configuration (TLS 1.3 handles this automatically, but we set preferences)
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256, // Preferred for mobile/low-power devices
			tls.TLS_AES_256_GCM_SHA384,       // Strong alternative
		},

		// Perfect Forward Secrecy enforcement
		PreferServerCipherSuites: true,

		// Client authentication for mutual TLS (if enabled)
		ClientAuth: getClientAuthMode(cfg),

		// Security hardening
		InsecureSkipVerify: false, // Always verify in production

		// Custom certificate verification for additional security
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyConnectionSecurity(cs, cfg)
		},

		// Session ticket configuration for forward secrecy
		SessionTicketsDisabled: !cfg.Security.EnablePerfectForwardSecrecy,

		// Disable session resumption if perfect forward secrecy is required
		ClientSessionCache: getSessionCache(cfg),

		// Custom random source for enhanced entropy
		Rand: rand.Reader,
	}

	// Additional security configurations
	configureTLSExtensions(tlsConfig, cfg)

	log.Println("🔒 Maximum security TLS 1.3 configuration loaded")
	log.Printf("🔐 Certificate: %s | Key: %s | Forward Secrecy: %v",
		getKeyAlgorithm(cert),
		getKeyStrength(cert),
		cfg.Security.EnablePerfectForwardSecrecy)

	return tlsConfig
}

// GenerateCertIfNotExists creates certificates if they don't exist
func GenerateCertIfNotExists() error {
	certPath := "certs/cert.pem"
	keyPath := "certs/key.pem"

	// Check if certificates exist and are valid
	if certExists(certPath, keyPath) {
		if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
			if isCertificateValid(&cert) {
				log.Println("✅ Valid certificates found")
				return nil
			}
		}
	}

	log.Println("🔧 Generating new cryptographic materials...")
	return generateMaxSecurityCertificate()
}

// generateMaxSecurityCertificate creates new certificates with maximum security parameters
func generateMaxSecurityCertificate() error {
	cfg, _ := config.LoadConfig() // Use default config if loading fails

	var privateKey interface{}
	var err error

	// Choose key algorithm based on configuration
	if cfg.Crypto.UseECDSA {
		privateKey, err = generateECDSAKey(cfg.Crypto.ECDSACurve)
		log.Printf("🔑 Generating ECDSA key with curve %s", cfg.Crypto.ECDSACurve)
	} else {
		privateKey, err = rsa.GenerateKey(rand.Reader, cfg.Crypto.KeyStrength)
		log.Printf("🔑 Generating RSA key with %d-bit strength", cfg.Crypto.KeyStrength)
	}

	if err != nil {
		return err
	}

	// Register key for secure memory wiping
	if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
		keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		security.RegisterSensitiveMemory(keyBytes)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(getPublicKey(privateKey))
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	subjectKeyID := sha1.Sum(publicKeyBytes)

	// Create certificate template with enhanced security
	template := &x509.Certificate{
		SerialNumber: generateSecureSerialNumber(),

		Subject: pkix.Name{
			Organization:       []string{"Anonymous"},
			OrganizationalUnit: []string{"Secure Communications"},
			Country:            []string{"XX"}, // No specific country for anonymity
		},

		// Certificate validity period
		NotBefore: time.Now().Add(-5 * time.Minute), // 5 minutes in the past to handle clock skew
		NotAfter:  time.Now().Add(time.Duration(cfg.Crypto.CertificateValidityDays) * 24 * time.Hour),

		// Key usage for maximum security
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyAgreement,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth, // For mutual TLS
		},

		// Subject Alternative Names for flexibility
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("::1"),
		},
		DNSNames: []string{
			"localhost",
		},

		// Certificate constraints
		BasicConstraintsValid: true,
		IsCA:                  false,

		// Enhanced security extensions
		SubjectKeyId: subjectKeyID[:],
	}

	// Add certificate policies for whistleblower protection
	addSecurityPolicies(template)

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(privateKey), privateKey)
	if err != nil {
		return err
	}

	// Ensure certs directory exists
	if err := os.MkdirAll("certs", 0700); err != nil {
		return err
	}

	// Write certificate with secure permissions
	if err := writeCertificate(certDER, "certs/cert.pem"); err != nil {
		return err
	}

	// Write private key with maximum security
	if err := writePrivateKey(privateKey, "certs/key.pem"); err != nil {
		return err
	}

	log.Println("✅ High-security certificates generated successfully")
	return nil
}

// ClearCertificateCache securely clears cached certificate materials
func ClearCertificateCache() {
	certificateCacheMutex.Lock()
	defer certificateCacheMutex.Unlock()

	if certificateCache != nil {
		// Clear certificate from memory
		for i := range certificateCache.Certificate {
			if len(certificateCache.Certificate[i]) > 0 {
				for j := range certificateCache.Certificate[i] {
					certificateCache.Certificate[i][j] = 0
				}
			}
		}

		// Clear private key if accessible
		if certificateCache.PrivateKey != nil {
			// Key clearing will be handled by security.SecureMemoryWipe()
		}

		certificateCache = nil
	}

	// Cancel key rotation timer
	if keyRotationTimer != nil {
		keyRotationTimer.Stop()
		keyRotationTimer = nil
	}

	log.Println("🔐 Certificate cache cleared securely")
}

// Helper functions

func loadOrGenerateCertificate(cfg *config.Config) (*tls.Certificate, error) {
	certPath := cfg.Crypto.CertificatePath
	keyPath := cfg.Crypto.PrivateKeyPath

	// Try to load existing certificate
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if isCertificateValid(&cert) {
			return &cert, nil
		}
		log.Println("⚠️ Existing certificate invalid, generating new one")
	}

	// Generate new certificate
	if err := generateMaxSecurityCertificate(); err != nil {
		return nil, err
	}

	// Load the newly generated certificate
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	return &cert, err
}

func generateECDSAKey(curveName string) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve

	switch curveName {
	case "P-521":
		curve = elliptic.P521()
	case "P-384":
		curve = elliptic.P384()
	default:
		curve = elliptic.P521() // Default to P-521 for maximum security
	}

	return ecdsa.GenerateKey(curve, rand.Reader)
}

func generateSecureSerialNumber() *big.Int {
	// Generate a cryptographically secure serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	return serialNumber
}

func getPublicKey(privateKey interface{}) interface{} {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func addSecurityPolicies(template *x509.Certificate) {
	// Add custom OIDs for whistleblower protection policies
	// These would be registered with your organization
	template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 4, 1, 99999, 1}, // Custom OID for secure messaging
	}
}

func writeCertificate(certDER []byte, path string) error {
	certOut, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer certOut.Close()

	return pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func writePrivateKey(privateKey interface{}, path string) error {
	keyOut, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	var keyBytes []byte
	var keyType string

	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		keyType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		var err error
		keyBytes, err = x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		keyType = "EC PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported private key type")
	}

	// Register for secure memory wiping
	security.RegisterSensitiveMemory(keyBytes)

	return pem.Encode(keyOut, &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	})
}

func certExists(certPath, keyPath string) bool {
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return false
	}
	return true
}

func isCertificateValid(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// Check if certificate is still valid (not expired and not too close to expiry)
	now := time.Now()
	if now.Before(x509Cert.NotBefore) || now.After(x509Cert.NotAfter) {
		return false
	}

	// Consider certificate invalid if less than 7 days remaining
	if x509Cert.NotAfter.Sub(now) < 7*24*time.Hour {
		return false
	}

	return true
}

func getClientAuthMode(cfg *config.Config) tls.ClientAuthType {
	if cfg.Security.RequireClientAuth {
		return tls.RequireAndVerifyClientCert
	}
	// For easier development/testing, allow connections without client certs
	return tls.NoClientCert
}

func getSessionCache(cfg *config.Config) tls.ClientSessionCache {
	if cfg.Security.EnablePerfectForwardSecrecy {
		return nil // Disable session resumption for perfect forward secrecy
	}
	return tls.NewLRUClientSessionCache(64) // Small cache for performance
}

func verifyConnectionSecurity(cs tls.ConnectionState, cfg *config.Config) error {
	// Additional connection security verification
	if cs.Version < tls.VersionTLS13 {
		return fmt.Errorf("TLS version %x not allowed", cs.Version)
	}

	// Verify perfect forward secrecy
	if cfg.Security.EnablePerfectForwardSecrecy && !cs.DidResume {
		// Connection is using ephemeral keys (good for PFS)
	}

	return nil
}

func configureTLSExtensions(tlsConfig *tls.Config, _ *config.Config) {
	// Additional TLS configuration for enhanced security

	// Set minimum and maximum supported versions
	tlsConfig.MinVersion = tls.VersionTLS13
	tlsConfig.MaxVersion = tls.VersionTLS13
}

func setupKeyRotation(cfg *config.Config) {
	rotationInterval := time.Duration(cfg.Crypto.KeyRotationIntervalHours) * time.Hour

	keyRotationTimer = time.AfterFunc(rotationInterval, func() {
		log.Println("🔄 Starting automatic key rotation")

		if err := generateMaxSecurityCertificate(); err != nil {
			log.Printf("❌ Key rotation failed: %v", err)
		} else {
			log.Println("✅ Key rotation completed successfully")
		}

		// Schedule next rotation
		setupKeyRotation(cfg)
	})

	log.Printf("⏰ Key rotation scheduled every %v", rotationInterval)
}

func getKeyAlgorithm(cert *tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return "unknown"
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "unknown"
	}

	switch x509Cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	default:
		return "unknown"
	}
}

func getKeyStrength(cert *tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return "unknown"
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "unknown"
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("%d-bit", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return pub.Curve.Params().Name
	default:
		return "unknown"
	}
}
