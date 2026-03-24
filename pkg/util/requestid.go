package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// GenerateRequestID creates a random UUID-style request ID.
// Panics if crypto/rand fails, which indicates a system-level failure.
func GenerateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate request ID: %v", err))
	}

	// Format as UUID (8-4-4-4-12)
	return hex.EncodeToString(b[0:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}
