package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateSecureID generates a cryptographically secure ID
func GenerateSecureID() string {
	// Generate 16 bytes of random data
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return fmt.Sprintf("%x-%d", sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))), time.Now().UnixNano())
	}

	// Add timestamp component for uniqueness
	timestamp := time.Now().UnixNano()

	// Combine random bytes with timestamp
	combined := fmt.Sprintf("%x-%x", bytes, timestamp)

	return combined
}

// GenerateNonce generates a cryptographic nonce
func GenerateNonce() string {
	bytes := make([]byte, 32) // 256-bit nonce
	if _, err := rand.Read(bytes); err != nil {
		// Fallback using timestamp and hash
		hash := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())))
		return hex.EncodeToString(hash[:])
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
		// Fallback token generation
		hash := sha256.Sum256([]byte(fmt.Sprintf("token-%d-%d", time.Now().UnixNano(), length)))
		return hex.EncodeToString(hash[:length])
	}

	return hex.EncodeToString(bytes)
}

// SecureCompare performs constant-time string comparison
func SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}

	return result == 0
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
func GenerateFingerprint(publicKey string) string {
	hash := sha256.Sum256([]byte(publicKey))
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
