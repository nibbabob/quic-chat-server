package utils

import (
	"crypto/rand"
	"fmt"
)

func GenerateSecureID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}
