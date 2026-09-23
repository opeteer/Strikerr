package worker

import (
	"context"
	"encoding/json"
	"log"

	"github.com/hibiken/asynq"
	"github.com/opeteer/strikerr/internal/crawler"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/extractor"
	"github.com/opeteer/strikerr/internal/ingestion"
	"github.com/opeteer/strikerr/internal/scoring"
	"github.com/opeteer/strikerr/internal/vault"
)

type TaskProcessor struct {
	browser *crawler.StealthBrowser
}

func NewTaskProcessor() (*TaskProcessor, error) {
	b, err := crawler.NewStealthBrowser()
	if err != nil {
		return nil, err
	}
	return &TaskProcessor{browser: b}, nil
}

func (p *TaskProcessor) ProcessCrawlTask(ctx context.Context, t *asynq.Task) error {
	var payload ingestion.CrawlWebsitePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return err
	}

	log.Printf("[Worker] Processing crawl task for URL: %s", payload.URL)

	// 1. Crawl (This interacts with real web if given a real URL)
	res, err := p.browser.Crawl(ctx, payload.URL)
	if err != nil {
		log.Printf("[Worker] Crawl failed for %s: %v", payload.URL, err)
		return err
	}

	// 2. Extract Data
	info := extractor.ParseDOM(res.DOMContent)

	// 3. Score Threat
	score := scoring.CalculateThreatScore(info, payload.URL, false, false)

	// 4. Save to Database if DB is connected and Threat found
	if database.DB != nil && score > 0 {
		hash := vault.HashContent([]byte(res.DOMContent))
		evidence := database.EvidenceVault{
			DOMHash: hash,
		}
		database.DB.Create(&evidence)

		for _, acc := range info.BankAccounts {
			mule := database.MuleAccount{
				AccountNumber:   acc,
				InstitutionType: "Bank",
				InstitutionName: "Extracted_Bank",
				SourceURL:       payload.URL,
				EvidenceVaultID: &evidence.ID,
				RiskScore:       score,
				Status:          "NEW_DETECTED",
			}
			database.DB.Create(&mule)
		}

		for _, acc := range info.EWallets {
			mule := database.MuleAccount{
				AccountNumber:   acc,
				InstitutionType: "EWallet",
				InstitutionName: "Extracted_Wallet",
				SourceURL:       payload.URL,
				EvidenceVaultID: &evidence.ID,
				RiskScore:       score,
				Status:          "NEW_DETECTED",
			}
			database.DB.Create(&mule)
		}
	}

	log.Printf("[Worker] Completed task for %s with threat score %d", payload.URL, score)
	return nil
}
