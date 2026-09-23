package tests

import (
	"testing"
	"github.com/opeteer/strikerr/internal/vault"
)

func TestHashContent(t *testing.T) {
	content := []byte("<html>malicious content</html>")
	hash := vault.HashContent(content)
	
	if len(hash) != 64 {
		t.Errorf("Expected SHA-256 hash length 64, got %d", len(hash))
	}
}

func TestTSAToken(t *testing.T) {
	token, err := vault.RequestTSAToken([]byte("test"))
	if err != nil {
		t.Errorf("TSA Request failed: %v", err)
	}
	if token == nil || len(token.Signature) == 0 {
		t.Errorf("Expected valid token signature")
	}
}
