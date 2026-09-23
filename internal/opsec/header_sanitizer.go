package opsec

import (
	"log"
	"strings"
)

var sensitiveHeaders = []string{
	"X-Originating-IP:",
	"Received:",
	"X-Mailer:",
	"User-Agent:",
}

// SanitizeMailHeaders removes IP leaks from raw SMTP envelopes to protect Strikerr infrastructure.
func SanitizeMailHeaders(rawMail string) string {
	lines := strings.Split(rawMail, "\n")
	var safeLines []string

	for _, line := range lines {
		isSensitive := false
		for _, sh := range sensitiveHeaders {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), strings.ToLower(sh)) {
				isSensitive = true
				break
			}
		}
		if !isSensitive {
			safeLines = append(safeLines, line)
		}
	}
	
	log.Println("[OPSEC] Outbound mail headers sanitized. IP leaks stripped.")
	return strings.Join(safeLines, "\n")
}
