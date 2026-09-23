package ingestion

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type CertStreamMessage struct {
	MessageType string `json:"message_type"`
	Data        struct {
		LeafCert struct {
			Subject struct {
				CN string `json:"CN"`
			} `json:"subject"`
			AllDomains []string `json:"all_domains"`
		} `json:"leaf_cert"`
	} `json:"data"`
}

type CertStreamListener struct {
	TargetKeywords []string
	URLQueue       chan string
}

func NewCertStreamListener(queue chan string) *CertStreamListener {
	return &CertStreamListener{
		TargetKeywords: []string{"bca", "mandiri", "bri", "bni", "dana", "ovo", "gopay", "slot", "gacor", "togel"},
		URLQueue:       queue,
	}
}

func (c *CertStreamListener) Listen(ctx context.Context) {
	log.Println("[CERTSTREAM] Connecting to wss://certstream.calidog.io...")

	for {
		select {
		case <-ctx.Done():
			log.Println("[CERTSTREAM] Stopping listener...")
			return
		default:
			c.connectAndListen(ctx)
			time.Sleep(5 * time.Second) // Reconnect backoff
		}
	}
}

func (c *CertStreamListener) connectAndListen(ctx context.Context) {
	ws, _, err := websocket.DefaultDialer.DialContext(ctx, "wss://certstream.calidog.io/", nil)
	if err != nil {
		log.Printf("[CERTSTREAM] Error connecting: %v", err)
		return
	}
	defer ws.Close()

	log.Println("[CERTSTREAM] Connected! Monitoring live certificate transparency logs...")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, message, err := ws.ReadMessage()
			if err != nil {
				log.Printf("[CERTSTREAM] Read error: %v", err)
				return
			}

			var msg CertStreamMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				continue
			}

			if msg.MessageType == "certificate_update" {
				for _, domain := range msg.Data.LeafCert.AllDomains {
					if c.isTarget(domain) {
						log.Printf("[CERTSTREAM] Target domain detected: %s", domain)
						c.URLQueue <- "https://" + domain
					}
				}
			}
		}
	}
}

func (c *CertStreamListener) isTarget(domain string) bool {
	domain = strings.ToLower(domain)
	// Focus on ID domains
	if strings.HasSuffix(domain, ".id") {
		return true
	}
	// Or check for financial keywords in typosquatting attempts
	for _, kw := range c.TargetKeywords {
		if strings.Contains(domain, kw) {
			return true
		}
	}
	return false
}
