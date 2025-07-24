package utils

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// mockReader is a fake reader that will return an error for our tests.
type mockReader struct{}

func (r mockReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("a catastrophic error from the mock reader")
}

// TestCryptoFuncsWithErrors tests the fatal error paths of the crypto functions.
// This is a special kind of test that checks for code that calls os.Exit.
func TestCryptoFuncsWithErrors(t *testing.T) {
	// Keep a copy of the original reader and restore it after the test.
	originalReader := secureReader
	defer func() {
		secureReader = originalReader
	}()

	// Replace the real reader with our mock that returns an error.
	secureReader = mockReader{}

	// Table of functions that should call log.Fatalf
	tests := []struct {
		name string
		fn   func()
	}{
		{"GenerateSecureID Error", func() { GenerateSecureID() }},
		{"GenerateNonce Error", func() { GenerateNonce() }},
		{"GenerateToken Error", func() { GenerateToken(16) }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// This is a special pattern to test for os.Exit calls.
			if os.Getenv("GO_TEST_FATAL") == "1" {
				tc.fn()
				return
			}
			cmd := exec.Command(os.Args[0], "-test.run="+t.Name())
			cmd.Env = append(os.Environ(), "GO_TEST_FATAL=1")
			err := cmd.Run()
			if e, ok := err.(*exec.ExitError); !ok || e.Success() {
				t.Fatalf("Process ran with err %v, want exit status 1", err)
			}
		})
	}
}

// TestSecureRandomError checks the non-fatal error path of SecureRandom.
func TestSecureRandomError(t *testing.T) {
	originalReader := secureReader
	defer func() {
		secureReader = originalReader
	}()

	secureReader = mockReader{}

	_, err := SecureRandom(16)
	if err == nil {
		t.Error("SecureRandom() did not return an error when the reader failed, but it should have")
	}
}

// TestGenerateSecureID checks if the function produces a unique ID of the correct length and format.
func TestGenerateSecureID(t *testing.T) {
	id1 := GenerateSecureID()
	id2 := GenerateSecureID()

	if len(id1) != 32 {
		t.Errorf("GenerateSecureID() length = %d; want 32", len(id1))
	}

	if id1 == id2 {
		t.Errorf("GenerateSecureID() produced two identical IDs: %s", id1)
	}
}

// TestGenerateNonce checks if the function produces a nonce of the correct length.
func TestGenerateNonce(t *testing.T) {
	nonce := GenerateNonce()
	if len(nonce) != 64 {
		t.Errorf("GenerateNonce() length = %d; want 64", len(nonce))
	}
}

// TestGenerateToken checks for correct token generation with default and custom lengths.
func TestGenerateToken(t *testing.T) {
	t.Run("Default length", func(t *testing.T) {
		token := GenerateToken(0) // Test the default case
		if len(token) != 64 {
			t.Errorf("GenerateToken(0) length = %d; want 64", len(token))
		}
	})

	t.Run("Custom length", func(t *testing.T) {
		token := GenerateToken(16)
		if len(token) != 32 {
			t.Errorf("GenerateToken(16) length = %d; want 32", len(token))
		}
	})
}

// TestSecureCompare validates the constant-time string comparison.
func TestSecureCompare(t *testing.T) {
	tests := map[string]struct {
		a    string
		b    string
		want bool
	}{
		"Equal strings": {
			a:    "password123",
			b:    "password123",
			want: true,
		},
		"Unequal strings": {
			a:    "password123",
			b:    "different",
			want: false,
		},
		"Empty strings": {
			a:    "",
			b:    "",
			want: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := SecureCompare(tc.a, tc.b); got != tc.want {
				t.Errorf("SecureCompare(%q, %q) = %v; want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestHashString ensures the hashing function is consistent.
func TestHashString(t *testing.T) {
	input := "test_string"
	// In a real test, you'd compute this once and store it.
	// For this example, let's just test for consistency and format.

	hash1 := HashString(input)
	hash2 := HashString(input)

	if len(hash1) != 64 {
		t.Errorf("HashString() returned hash of length %d; want 64", len(hash1))
	}
	if hash1 != hash2 {
		t.Errorf("HashString() is not deterministic. Got %s and %s", hash1, hash2)
	}

	// Test empty string
	emptyHash := HashString("")
	if len(emptyHash) != 64 {
		t.Errorf("HashString(\"\") returned hash of length %d; want 64", len(emptyHash))
	}
}

// TestTruncateString checks all truncation scenarios.
func TestTruncateString(t *testing.T) {
	tests := map[string]struct {
		s      string
		maxLen int
		want   string
	}{
		"String shorter than max": {
			s:      "hello",
			maxLen: 10,
			want:   "hello",
		},
		"String equal to max": {
			s:      "hello",
			maxLen: 5,
			want:   "hello",
		},
		"String longer than max": {
			s:      "hello world",
			maxLen: 5,
			want:   "hello",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := TruncateString(tc.s, tc.maxLen); got != tc.want {
				t.Errorf("TruncateString(%q, %d) = %q; want %q", tc.s, tc.maxLen, got, tc.want)
			}
		})
	}
}

// TestSanitizeString covers all sanitization rules and edge cases.
func TestSanitizeString(t *testing.T) {
	tests := map[string]struct {
		input string
		want  string
	}{
		"String with null bytes and control characters": {
			input: "abc\x00123\x07\x1b", // Contains NULL, BELL, ESC
			want:  "abc123",
		},
		"String that is already clean": {
			input: "This-is-a-valid_string.123!",
			want:  "This-is-a-valid_string.123!",
		},
		"Empty string": {
			input: "",
			want:  "",
		},
		"String with only invalid characters": {
			input: "\x01\x02\x03\x04\x05",
			want:  "",
		},
		"String with leading and trailing invalid characters": {
			input: "\n\t leading and trailing \r\n",
			want:  " leading and trailing ",
		},
		"String with UTF-8 characters": {
			input: "Hello, 世界",
			want:  "Hello, ",
		},
		"String with boundary characters": {
			input: " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", // All printable ASCII
			want:  " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
		},
		"String just outside boundaries": {
			input: string(rune(31)) + "a" + string(rune(127)), // Unit Separator and Delete
			want:  "a",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := SanitizeString(tc.input)
			if got != tc.want {
				t.Errorf("SanitizeString() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsValidUserID provides full coverage for user ID validation logic.
func TestIsValidUserID(t *testing.T) {
	tests := map[string]struct {
		input string
		want  bool
	}{
		"Valid user ID":              {"test_user-123", true},
		"Valid user ID with numbers": {"user123", true},
		"User ID too short":          {"ab", false},
		"User ID at min length":      {"abc", true},
		"User ID too long":           {strings.Repeat("a", 51), false},
		"User ID at max length":      {strings.Repeat("a", 50), true},
		"Invalid characters":         {"test!", false},
		"Empty user ID":              {"", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsValidUserID(tc.input); got != tc.want {
				t.Errorf("IsValidUserID(%q) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestIsValidRoomID provides full coverage for room ID validation logic.
func TestIsValidRoomID(t *testing.T) {
	tests := map[string]struct {
		input string
		want  bool
	}{
		"Valid room ID":         {"secret.room_1-2-3", true},
		"Room ID too short":     {"a", false},
		"Room ID at min length": {"abc", true},
		"Room ID too long":      {strings.Repeat("b", 101), false},
		"Room ID at max length": {strings.Repeat("b", 100), true},
		"Invalid characters":    {"secret room!", false},
		"Empty room ID":         {"", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := IsValidRoomID(tc.input); got != tc.want {
				t.Errorf("IsValidRoomID(%q) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestGenerateFingerprint checks the output format and length.
func TestGenerateFingerprint(t *testing.T) {
	// A dummy public key byte slice for testing purposes.
	publicKey := []byte("-----BEGIN PUBLIC KEY-----\n" +
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+d8v1Z/p+I8i/g+g/w3j/h6e/w==" +
		"\n-----END PUBLIC KEY-----\n")

	fingerprint := GenerateFingerprint(publicKey)

	if len(fingerprint) != 32 {
		t.Errorf("GenerateFingerprint() length = %d; want 32", len(fingerprint))
	}
}

// TestSecureRandom checks that the function returns the correct number of bytes and doesn't error.
func TestSecureRandom(t *testing.T) {
	bytes, err := SecureRandom(16)
	if err != nil {
		t.Fatalf("SecureRandom() returned an unexpected error: %v", err)
	}
	if len(bytes) != 16 {
		t.Errorf("SecureRandom(16) length = %d; want 16", len(bytes))
	}
}

// TestFormatDuration covers all time unit formatting logic.
func TestFormatDuration(t *testing.T) {
	tests := map[string]struct {
		d    time.Duration
		want string
	}{
		"Seconds": {
			d:    30 * time.Second,
			want: "30.0s",
		},
		"Minutes": {
			d:    5 * time.Minute,
			want: "5.0m",
		},
		"Hours": {
			d:    3 * time.Hour,
			want: "3.0h",
		},
		"Days": {
			d:    48 * time.Hour,
			want: "2.0d",
		},
		"Mixed minutes and seconds": {
			d:    90 * time.Second,
			want: "1.5m",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := FormatDuration(tc.d); got != tc.want {
				t.Errorf("FormatDuration(%v) = %q; want %q", tc.d, got, tc.want)
			}
		})
	}
}
