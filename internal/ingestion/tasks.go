package ingestion

import (
	"encoding/json"
	"github.com/hibiken/asynq"
)

const (
	TypeCrawlWebsite = "task:crawl_website"
)

type CrawlWebsitePayload struct {
	URL        string `json:"url"`
	Source     string `json:"source"`
	RetryCount int    `json:"retry_count"`
}

func NewCrawlWebsiteTask(url, source string) (*asynq.Task, error) {
	payload, err := json.Marshal(CrawlWebsitePayload{URL: url, Source: source})
	if err != nil {
		return nil, err
	}
	// Option: limit max retries to 3 and specify queue
	return asynq.NewTask(TypeCrawlWebsite, payload, asynq.MaxRetry(3), asynq.Queue("critical")), nil
}
