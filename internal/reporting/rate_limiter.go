package reporting

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RateLimiter enforces a token bucket strategy for outbound abuse reports
// to protect the mail server's IP reputation from spam blacklisting.
type RateLimiter struct {
	mu           sync.Mutex
	tokens       int
	maxTokens    int
	refillRate   time.Duration
	lastRefilled time.Time
}

func NewRateLimiter(maxTokens int, refillRate time.Duration) *RateLimiter {
	rl := &RateLimiter{
		tokens:       maxTokens,
		maxTokens:    maxTokens,
		refillRate:   refillRate,
		lastRefilled: time.Now(),
	}
	go rl.startRefill()
	return rl
}

func (rl *RateLimiter) startRefill() {
	ticker := time.NewTicker(rl.refillRate)
	for range ticker.C {
		rl.mu.Lock()
		if rl.tokens < rl.maxTokens {
			rl.tokens++
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			rl.mu.Lock()
			if rl.tokens > 0 {
				rl.tokens--
				rl.mu.Unlock()
				return nil
			}
			rl.mu.Unlock()
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (rl *RateLimiter) TryAcquire() error {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.tokens > 0 {
		rl.tokens--
		return nil
	}
	return fmt.Errorf("rate limit exceeded")
}
