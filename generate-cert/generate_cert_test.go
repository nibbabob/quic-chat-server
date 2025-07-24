package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGenerateCertificate verifies the core certificate creation logic.
func TestGenerateCertificate(t *testing.T) {
	certPEM, keyPEM, err := generateCertificate()

	// 1. Check for errors
	if err != nil {
		t.Fatalf("generateCertificate() returned an unexpected error: %v", err)
	}

	// 2. Decode the certificate PEM to validate it
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatal("Failed to decode certificate PEM")
	}
	if certBlock.Type != "CERTIFICATE" {
		t.Errorf("Certificate PEM block has wrong type: got %s, want CERTIFICATE", certBlock.Type)
	}

	// 3. Parse the certificate to ensure it's valid
	_, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// 4. Decode the private key PEM to validate it
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("Failed to decode private key PEM")
	}
	if keyBlock.Type != "RSA PRIVATE KEY" {
		t.Errorf("Private key PEM block has wrong type: got %s, want RSA PRIVATE KEY", keyBlock.Type)
	}

	// 5. Parse the private key to ensure it's valid
	_, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}
}

// TestGenerateCertificateErrors tests the error paths in the generation logic.
func TestGenerateCertificateErrors(t *testing.T) {
	// Keep original functions
	originalRSAFunc := rsaGenerateKey
	originalX509Func := x509CreateCertificate
	// Restore original functions after test
	defer func() {
		rsaGenerateKey = originalRSAFunc
		x509CreateCertificate = originalX509Func
	}()

	t.Run("RSA Generation Failure", func(t *testing.T) {
		// Monkey patch the RSA function to return an error
		rsaGenerateKey = func(random io.Reader, bits int) (*rsa.PrivateKey, error) {
			return nil, errors.New("mock RSA error")
		}
		_, _, err := generateCertificate()
		if err == nil {
			t.Error("generateCertificate() did not return an error when RSA generation failed")
		}
	})

	// Restore RSA func for next test
	rsaGenerateKey = originalRSAFunc

	t.Run("x509 Creation Failure", func(t *testing.T) {
		// Monkey patch the x509 function to return an error
		x509CreateCertificate = func(rand io.Reader, template, parent *x509.Certificate, pub, priv interface{}) ([]byte, error) {
			return nil, errors.New("mock x509 error")
		}
		_, _, err := generateCertificate()
		if err == nil {
			t.Error("generateCertificate() did not return an error when x509 creation failed")
		}
	})
}

// TestMainSuccess tests the successful execution of the main function.
func TestMainSuccess(t *testing.T) {
	tmpDir := t.TempDir()

	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "GO_TEST_MODE=1")
	output, err := cmd.CombinedOutput()

	if err != nil {
		t.Fatalf("Process exited with error: %v\nOutput:\n%s", err, string(output))
	}

	// Check if the files were created
	if _, err := os.Stat(filepath.Join(tmpDir, "cert.pem")); os.IsNotExist(err) {
		t.Error("main() did not create cert.pem")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "key.pem")); os.IsNotExist(err) {
		t.Error("main() did not create key.pem")
	}
}

// TestMainCertWriteError tests the fatal error path when writing cert.pem.
func TestMainCertWriteError(t *testing.T) {
	tmpDir := t.TempDir()

	readOnlyFile := filepath.Join(tmpDir, "cert.pem")
	f, _ := os.Create(readOnlyFile)
	f.Close()
	os.Chmod(readOnlyFile, 0444) // Read-only

	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "GO_TEST_MODE=1")
	err := cmd.Run()

	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("Process was expected to fail due to write error, but it did not. Error: %v", err)
	}
}

// TestMainKeyWriteError tests the fatal error path when writing key.pem.
func TestMainKeyWriteError(t *testing.T) {
	tmpDir := t.TempDir()

	readOnlyFile := filepath.Join(tmpDir, "key.pem")
	f, _ := os.Create(readOnlyFile)
	f.Close()
	os.Chmod(readOnlyFile, 0444) // Read-only

	cmd := exec.Command(os.Args[0], "-test.run=TestMainHelper")
	cmd.Dir = tmpDir
	cmd.Env = append(os.Environ(), "GO_TEST_MODE=1")
	err := cmd.Run()

	if e, ok := err.(*exec.ExitError); !ok || e.Success() {
		t.Fatalf("Process was expected to fail due to write error, but it did not. Error: %v", err)
	}
}

// TestMainHelper is a helper function that gets executed by the sub-processes.
func TestMainHelper(t *testing.T) {
	if os.Getenv("GO_TEST_MODE") != "1" {
		return
	}
	main()
}
