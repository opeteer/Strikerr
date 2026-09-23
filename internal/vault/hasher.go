package vault

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashContent generates a SHA-256 cryptographic hash of the provided content.
// This is used to maintain the chain of custody for downloaded DOMs, PCAP/HAR logs, and screenshots.
func HashContent(content []byte) string {
	hasher := sha256.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}
