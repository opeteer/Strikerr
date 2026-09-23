package ingestion

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"
)

type DorkScanner struct {
	Dorks    []string
	URLQueue chan string
}

func NewDorkScanner(queue chan string) *DorkScanner {
	return &DorkScanner{
		Dorks: []string{
			"site:.go.id intext:\"slot gacor\"",
			"site:.ac.id intext:\"rtp live\"",
			"site:.sch.id intext:\"maxwin\"",
			"site:.go.id inurl:wp-content",
		},
		URLQueue: queue,
	}
}

func (s *DorkScanner) StartScanning(ctx context.Context) {
	log.Println("[DORK_SCANNER] Starting passive dorking operations...")

	ticker := time.NewTicker(2 * time.Minute) // Throttle to avoid rate limits
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[DORK_SCANNER] Stopping scanner...")
			return
		case <-ticker.C:
			dork := s.Dorks[rand.Intn(len(s.Dorks))]
			log.Printf("[DORK_SCANNER] Executing query: %s", dork)

			// Simulate search API returning a compromised URL
			// In production, this would call Serper/Google Custom Search API
			fakeResult := fmt.Sprintf("https://dinas.pemprov.go.id/wp-content/uploads/2023/slot-%d", rand.Intn(1000))
			log.Printf("[DORK_SCANNER] Discovered potential target: %s", fakeResult)
			s.URLQueue <- fakeResult
		}
	}
}
