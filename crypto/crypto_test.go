package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"quic-chat-server/config"
	"testing"
	"time"
)

// setupTestEnvironment creates a temporary directory for certs and a basic config.
func setupTestEnvironment(t *testing.T) (*config.Config, func()) {
	// Create a temporary directory for certificates
	tmpDir, err := os.MkdirTemp("", "certs-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create a mock config pointing to the temp directory
	cfg := &config.Config{
		Crypto: config.CryptoConfig{
			CertificatePath:          tmpDir + "/cert.pem",
			PrivateKeyPath:           tmpDir + "/key.pem",
			UseECDSA:                 true,
			ECDSACurve:               "P-384",
			CertificateValidityDays:  30, // Use a longer validity for tests
			KeyRotationIntervalHours: 0,
		},
		Security: config.SecurityConfig{
			EnablePerfectForwardSecrecy: true,
			RequireClientAuth:           true,
			HMACSecret:                  "test-secret-for-crypto-tests",
		},
	}

	// The cleanup function to be called by the test
	cleanup := func() {
		os.RemoveAll(tmpDir)
		ClearCertificateCache()
	}

	return cfg, cleanup
}

// TestGenerateMaxSecurityTLSConfig tests the generation of a TLS config.
func TestGenerateMaxSecurityTLSConfig(t *testing.T) {
	cfg, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tlsConfig := GenerateMaxSecurityTLSConfig(cfg)

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d; want %d", tlsConfig.MinVersion, tls.VersionTLS13)
	}
	if !tlsConfig.SessionTicketsDisabled {
		t.Error("SessionTicketsDisabled should be true for perfect forward secrecy")
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %d; want %d", tlsConfig.ClientAuth, tls.RequireAndVerifyClientCert)
	}
}

// TestGenerateCertIfNotExists covers all certificate generation paths.
func TestGenerateCertIfNotExists(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	t.Setenv("HMAC_SECRET", "a-valid-secret-for-this-test")

	// 1. Test generation when no certs exist
	if err := os.MkdirAll("certs", 0755); err != nil {
		t.Fatalf("Failed to create certs dir: %v", err)
	}
	if err := GenerateCertIfNotExists(); err != nil {
		t.Fatalf("GenerateCertIfNotExists() failed on first run: %v", err)
	}
	if _, err := os.Stat("certs/cert.pem"); os.IsNotExist(err) {
		t.Error("GenerateCertIfNotExists() did not create cert.pem")
	}

	// 2. Test when valid certs already exist
	if err := GenerateCertIfNotExists(); err != nil {
		t.Errorf("GenerateCertIfNotExists() failed on second run: %v", err)
	}
}

// TestCertificateValidationLogic tests the isCertificateValid helper function.
func TestCertificateValidationLogic(t *testing.T) {
	cfg, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// 1. Generate a valid certificate
	if err := generateMaxSecurityCertificate(cfg); err != nil {
		t.Fatalf("Failed to generate certificate for validation test: %v", err)
	}
	validCert, err := tls.LoadX509KeyPair(cfg.Crypto.CertificatePath, cfg.Crypto.PrivateKeyPath)
	if err != nil {
		t.Fatalf("Failed to load generated certificate: %v", err)
	}

	// 2. Test with valid cert
	if !isCertificateValid(&validCert) {
		t.Error("isCertificateValid() returned false for a valid certificate")
	}

	// 3. Test with an expired certificate
	// We cheat by parsing the cert and changing its expiry date
	parsedCert, _ := x509.ParseCertificate(validCert.Certificate[0])
	parsedCert.NotAfter = time.Now().Add(-1 * time.Hour) // Expired an hour ago

	// Re-encode the expired certificate data
	expiredCertBytes, _ := x509.CreateCertificate(nil, parsedCert, parsedCert, validCert.PrivateKey, validCert.PrivateKey)
	expiredCert := tls.Certificate{
		Certificate: [][]byte{expiredCertBytes},
		PrivateKey:  validCert.PrivateKey,
	}
	if isCertificateValid(&expiredCert) {
		t.Error("isCertificateValid() returned true for an expired certificate")
	}

	// 4. Test with a cert that is about to expire
	parsedCert.NotAfter = time.Now().Add(6 * 24 * time.Hour) // Expires in 6 days
	aboutToExpireBytes, _ := x509.CreateCertificate(nil, parsedCert, parsedCert, validCert.PrivateKey, validCert.PrivateKey)
	aboutToExpireCert := tls.Certificate{
		Certificate: [][]byte{aboutToExpireBytes},
		PrivateKey:  validCert.PrivateKey,
	}
	if isCertificateValid(&aboutToExpireCert) {
		t.Error("isCertificateValid() returned true for a certificate about to expire")
	}

	// 5. Test with an empty certificate
	emptyCert := &tls.Certificate{}
	if isCertificateValid(emptyCert) {
		t.Error("isCertificateValid() returned true for an empty certificate")
	}
}

// TestLoadOrGenerateCertificate tests both loading and generating paths.
func TestLoadOrGenerateCertificate(t *testing.T) {
	cfg, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// 1. Test generation path
	cert, err := loadOrGenerateCertificate(cfg)
	if err != nil {
		t.Fatalf("loadOrGenerateCertificate() failed on generation: %v", err)
	}
	if cert == nil {
		t.Fatal("loadOrGenerateCertificate() returned nil cert on generation")
	}

	// 2. Test loading path
	cert2, err := loadOrGenerateCertificate(cfg)
	if err != nil {
		t.Fatalf("loadOrGenerateCertificate() failed on loading: %v", err)
	}
	if cert2 == nil {
		t.Fatal("loadOrGenerateCertificate() returned nil cert on loading")
	}
}

// TestKeyAndCertHelpers tests various small helper functions.
func TestKeyAndCertHelpers(t *testing.T) {
	cfg, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Generate both RSA and ECDSA certs for testing
	cfg.Crypto.UseECDSA = false
	cfg.Crypto.KeyStrength = 4096 // Use a valid strength
	if err := generateMaxSecurityCertificate(cfg); err != nil {
		t.Fatalf("Failed to generate RSA cert: %v", err)
	}
	rsaCert, _ := tls.LoadX509KeyPair(cfg.Crypto.CertificatePath, cfg.Crypto.PrivateKeyPath)

	cfg.Crypto.UseECDSA = true
	cfg.Crypto.ECDSACurve = "P-521"
	if err := generateMaxSecurityCertificate(cfg); err != nil {
		t.Fatalf("Failed to generate ECDSA cert: %v", err)
	}
	ecdsaCert, _ := tls.LoadX509KeyPair(cfg.Crypto.CertificatePath, cfg.Crypto.PrivateKeyPath)

	// Test getKeyAlgorithm
	if alg := getKeyAlgorithm(&rsaCert); alg != "RSA" {
		t.Errorf("getKeyAlgorithm() for RSA = %s; want RSA", alg)
	}
	if alg := getKeyAlgorithm(&ecdsaCert); alg != "ECDSA" {
		t.Errorf("getKeyAlgorithm() for ECDSA = %s; want ECDSA", alg)
	}
	if alg := getKeyAlgorithm(&tls.Certificate{}); alg != "unknown" {
		t.Errorf("getKeyAlgorithm() for empty cert = %s; want unknown", alg)
	}

	// Test getKeyStrength
	if strength := getKeyStrength(&rsaCert); strength != "4096-bit" {
		t.Errorf("getKeyStrength() for RSA = %s; want 4096-bit", strength)
	}
	if strength := getKeyStrength(&ecdsaCert); strength != "P-521" {
		t.Errorf("getKeyStrength() for ECDSA = %s; want P-521", strength)
	}
}

// TestClearCertificateCache ensures the cache is properly cleared.
func TestClearCertificateCache(t *testing.T) {
	cfg, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Generate and cache a certificate
	GenerateMaxSecurityTLSConfig(cfg)
	if certificateCache == nil {
		t.Fatal("Certificate cache was not populated after generating TLS config")
	}

	// Clear the cache
	ClearCertificateCache()
	if certificateCache != nil {
		t.Error("ClearCertificateCache() did not clear the global certificate cache")
	}
}
