package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"time"
)

// GenerateSecureID generates a cryptographically secure ID
func GenerateSecureID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// This should never happen on a modern OS, but if it does, it's a critical failure.
		log.Fatalf("Fatal error: unable to generate secure random data: %v", err)
	}
	return hex.EncodeToString(bytes)
}

// GenerateNonce generates a cryptographic nonce
func GenerateNonce() string {
	bytes := make([]byte, 32) // 256-bit nonce
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Fatal error: unable to generate secure random data for nonce: %v", err)
	}
	return hex.EncodeToString(bytes)
}

// GenerateToken generates a secure authentication token
func GenerateToken(length int) string {
	if length <= 0 {
		length = 32 // Default to 32 bytes
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("Fatal error: unable to generate secure random data for token: %v", err)
	}

	return hex.EncodeToString(bytes)
}

// SecureCompare performs constant-time string comparison to prevent timing attacks.
func SecureCompare(a, b string) bool {
	// Use the standard library's constant-time comparison function.
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// HashString creates a SHA-256 hash of the input string
func HashString(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// TruncateString safely truncates a string to a maximum length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// SanitizeString removes potentially dangerous characters from a string
func SanitizeString(input string) string {
	// Remove null bytes and control characters
	result := ""
	for _, r := range input {
		if r >= 32 && r <= 126 { // Printable ASCII only
			result += string(r)
		}
	}
	return result
}

// IsValidUserID checks if a user ID meets security requirements
func IsValidUserID(userID string) bool {
	// Check length
	if len(userID) < 3 || len(userID) > 50 {
		return false
	}

	// Check for valid characters (alphanumeric, underscore, hyphen)
	for _, r := range userID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}

	return true
}

// IsValidRoomID checks if a room ID meets security requirements
func IsValidRoomID(roomID string) bool {
	// Check length
	if len(roomID) < 3 || len(roomID) > 100 {
		return false
	}

	// Check for valid characters
	for _, r := range roomID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}

	return true
}

// GenerateFingerprint creates a fingerprint for a public key
func GenerateFingerprint(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	// Return first 16 bytes as hex (128-bit fingerprint)
	return hex.EncodeToString(hash[:16])
}

// SecureRandom generates cryptographically secure random bytes
func SecureRandom(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}

// FormatDuration formats a duration for human-readable display
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	} else {
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	}
}
