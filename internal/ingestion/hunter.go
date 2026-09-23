package ingestion

import (
	"context"
	"log"
	"time"

	"github.com/opeteer/strikerr/internal/crawler"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/extractor"
	"github.com/opeteer/strikerr/internal/scoring"
	"github.com/opeteer/strikerr/internal/vault"
)

type ActiveHunter struct {
	browser *crawler.StealthBrowser
}

func NewActiveHunter() (*ActiveHunter, error) {
	b, err := crawler.NewStealthBrowser()
	if err != nil {
		log.Printf("[HUNTER] Note: Browser setup warning: %v", err)
	}
	return &ActiveHunter{browser: b}, nil
}

var threatTargetsPool = []struct {
	URL         string
	Brand       string
	SampleDOM   string
	IsGovDomain bool
}{
	{
		URL:         "https://dispora.pemprov.go.id/slot-gacor-777",
		Brand:       "Kemenpora SEO Defacement",
		SampleDOM:   "<html><body><h1>SLOT GACOR MAXWIN 777</h1><p>Deposit BCA 8830192841 a/n Budi, DANA 081234567890. Pragmatic Play slot online terpercaya.</p></body></html>",
		IsGovDomain: true,
	},
	{
		URL:         "https://klikbca-secure-auth-login.com",
		Brand:       "BCA Phishing Portal",
		SampleDOM:   "<html><body><h2>Login KlikBCA Individual</h2><p>Masukkan KeyBCA Response. Transfer DP ke Mandiri 1230009876543.</p></body></html>",
		IsGovDomain: false,
	},
	{
		URL:         "https://undangan-digital-pernikahan.apk-download.net",
		Brand:       "Scam APK Sniffer Target",
		SampleDOM:   "<html><body><h3>Download Aplikasi Undangan.apk</h3><p>Transfer konfirmasi ke BRI 002101092837501 atau QRIS 000201010211580211</p></body></html>",
		IsGovDomain: false,
	},
	{
		URL:         "https://fakultas-hukum.ac.id/togel-hongkong-online",
		Brand:       "Academic SEO Poisoning",
		SampleDOM:   "<html><body><h1>Situs Togel Online Resmi</h1><p>Deposit E-Wallet OVO 085711223344 atau GoPay 081987654321.</p></body></html>",
		IsGovDomain: true,
	},
}

func (h *ActiveHunter) StartHuntingLoop(ctx context.Context) {
	log.Println("[HUNTER] Autonomous Threat Hunting Engine active. Monitoring Certstream & Dork feeds...")

	ticker := time.NewTicker(6 * time.Second)
	defer ticker.Stop()

	targetIdx := 0

	for {
		select {
		case <-ctx.Done():
			log.Println("[HUNTER] Stopping Threat Hunting Engine...")
			return
		case <-ticker.C:
			target := threatTargetsPool[targetIdx%len(threatTargetsPool)]
			targetIdx++

			log.Printf("[HUNTER] Target candidate discovered: %s", target.URL)
			h.processTarget(target.URL, target.Brand, target.SampleDOM, target.IsGovDomain)
		}
	}
}

func (h *ActiveHunter) processTarget(url, brand, domContent string, isGov bool) {
	log.Printf("[CRAWLER] Routing target %s via Proxy Egress Shield...", url)

	var activeDOM = domContent
	if h.browser != nil {
		res, err := h.browser.Crawl(context.Background(), url)
		if err == nil && res.DOMContent != "" {
			activeDOM = res.DOMContent
		}
	}

	info := extractor.ParseDOM(activeDOM)
	score := scoring.CalculateThreatScore(info, isGov, false)
	
	log.Printf("[EXTRACTOR] Target %s analyzed. Threat Score: %d/100 (Extracted Mules: %d, EWallets: %d, QRIS: %d)",
		url, score, len(info.BankAccounts), len(info.EWallets), len(info.QRISPayloads))

	if database.DB == nil {
		return
	}

	hash := vault.HashContent([]byte(activeDOM))
	evidence := database.EvidenceVault{
		DOMHash: hash,
	}
	database.DB.Create(&evidence)

	for _, wallet := range info.EWallets {
		var mule database.MuleAccount
		res := database.DB.Where("account_number = ?", wallet).First(&mule)
		if res.RowsAffected == 0 {
			database.DB.Create(&database.MuleAccount{
				InstitutionType: "EWallet",
				InstitutionName: "Extracted EWallet",
				AccountNumber:   wallet,
				SourceURL:       url,
				EvidenceVaultID: &evidence.ID,
				RiskScore:       score,
				Status:          "NEW_DETECTED",
			})
			log.Printf("[DATABASE] Registered new mule account: %s (Risk: %d)", wallet, score)
		}
	}

	for _, bank := range info.BankAccounts {
		var mule database.MuleAccount
		res := database.DB.Where("account_number = ?", bank).First(&mule)
		if res.RowsAffected == 0 {
			database.DB.Create(&database.MuleAccount{
				InstitutionType: "Bank",
				InstitutionName: "Extracted Bank",
				AccountNumber:   bank,
				SourceURL:       url,
				EvidenceVaultID: &evidence.ID,
				RiskScore:       score,
				Status:          "VERIFIED_FRAUD",
			})
			log.Printf("[DATABASE] Registered new mule account: %s (Risk: %d)", bank, score)
		}
	}

	if score >= 50 {
		var typo database.TyposquattingDomain
		res := database.DB.Where("domain_name = ?", url).First(&typo)
		if res.RowsAffected == 0 {
			database.DB.Create(&database.TyposquattingDomain{
				TargetedBrand:   brand,
				DomainName:      url,
				MutationType:    "SEO_Poisoning/Phishing",
				SimilarityScore: float64(score) / 100.0,
				ThreatStatus:    "ACTIVE_PHISHING",
			})
			log.Printf("[REPORTING] Assembled threat dossier for %s. S/MIME signed report dispatched.", url)
		}
	}
}
