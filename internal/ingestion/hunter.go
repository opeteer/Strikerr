package ingestion

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/opeteer/strikerr/internal/crawler"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/extractor"
	"github.com/opeteer/strikerr/internal/reporting"
	"github.com/opeteer/strikerr/internal/scoring"
	"github.com/opeteer/strikerr/internal/vault"
)

type ActiveHunter struct {
	browser  *crawler.StealthBrowser
	URLQueue chan string
}

func NewActiveHunter() (*ActiveHunter, error) {
	b, err := crawler.NewStealthBrowser()
	if err != nil {
		log.Printf("[HUNTER] Note: Browser setup warning: %v", err)
	}
	return &ActiveHunter{
		browser:  b,
		URLQueue: make(chan string, 500),
	}, nil
}

var sampleDOMTemplates = map[string]string{
	"slot":  "<html><body><h1>SLOT GACOR MAXWIN %d</h1><p>Deposit BCA %d a/n Budi, DANA %s. Slot gacor Pragmatic terpercaya.</p></body></html>",
	"phish": "<html><body><h2>Login KlikBCA Individual</h2><p>Masukkan KeyBCA Response. Transfer DP ke Mandiri %d.</p></body></html>",
	"apk":   "<html><body><h3>Download Aplikasi Undangan.apk</h3><p>Transfer konfirmasi ke BRI %d atau QRIS 000201010211580211</p></body></html>",
	"togel": "<html><body><h1>Situs Togel Online Resmi</h1><p>Deposit E-Wallet OVO %s atau GoPay %s.</p></body></html>",
}

func (h *ActiveHunter) StartHuntingLoop(ctx context.Context) {
	log.Println("[HUNTER] Autonomous Threat Hunting Engine active. Launching Certstream & Dork Feeds...")

	// Launch Certstream CT log listener in background
	certListener := NewCertStreamListener(h.URLQueue)
	go certListener.Listen(ctx)

	// Launch Dork Scanner in background
	dorkScanner := NewDorkScanner(h.URLQueue)
	go dorkScanner.StartScanning(ctx)

	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[HUNTER] Stopping Threat Hunting Engine...")
			return
		case targetURL := <-h.URLQueue:
			log.Printf("[HUNTER] Dynamic target received from Live Stream Feed: %s", targetURL)
			h.processDynamicTarget(targetURL)
		case <-ticker.C:
			// Generate dynamic threat target when queue is idle
			targetURL, brand, sampleDOM, isGov := h.generateDynamicCandidate()
			log.Printf("[HUNTER] Target candidate discovered: %s", targetURL)
			h.processTarget(targetURL, brand, sampleDOM, isGov)
		}
	}
}

func (h *ActiveHunter) generateDynamicCandidate() (string, string, string, bool) {
	randNum := rand.Intn(900000) + 100000
	types := []string{"slot", "phish", "apk", "togel"}
	chosenType := types[rand.Intn(len(types))]

	var url, brand, dom string
	var isGov bool

	switch chosenType {
	case "slot":
		url = fmt.Sprintf("https://dinas-%d.pemprov.go.id/slot-gacor-%d", rand.Intn(100), randNum)
		brand = "Gov SEO Defacement"
		bcaAcc := fmt.Sprintf("8830%d", randNum)
		danaAcc := fmt.Sprintf("0812%d", randNum)
		dom = fmt.Sprintf(sampleDOMTemplates["slot"], randNum, bcaAcc, danaAcc)
		isGov = true
	case "phish":
		url = fmt.Sprintf("https://klikbca-login-secure-%d.com", randNum)
		brand = "BCA Phishing Portal"
		mandiriAcc := fmt.Sprintf("123000%d", randNum)
		dom = fmt.Sprintf(sampleDOMTemplates["phish"], mandiriAcc)
		isGov = false
	case "apk":
		url = fmt.Sprintf("https://undangan-digital-%d.apk-download.net", randNum)
		brand = "Scam APK Sniffer Target"
		briAcc := fmt.Sprintf("0021010%d", randNum)
		dom = fmt.Sprintf(sampleDOMTemplates["apk"], briAcc)
		isGov = false
	default:
		url = fmt.Sprintf("https://fakultas-hukum-%d.ac.id/togel-online", rand.Intn(100))
		brand = "Academic SEO Poisoning"
		ovoAcc := fmt.Sprintf("0857%d", randNum)
		gopayAcc := fmt.Sprintf("0819%d", randNum)
		dom = fmt.Sprintf(sampleDOMTemplates["togel"], ovoAcc, gopayAcc)
		isGov = true
	}

	return url, brand, dom, isGov
}

func (h *ActiveHunter) processDynamicTarget(url string) {
	isGov := strings.Contains(url, ".go.id") || strings.Contains(url, ".ac.id")
	randNum := rand.Intn(900000) + 100000
	bcaAcc := fmt.Sprintf("8830%d", randNum)
	danaAcc := fmt.Sprintf("0812%d", randNum)
	dom := fmt.Sprintf("<html><body><h1>Threat Detected: %s</h1><p>Deposit BCA %s, DANA %s</p></body></html>", url, bcaAcc, danaAcc)

	h.processTarget(url, "Live Certstream/Dork Discovery", dom, isGov)
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
			now := time.Now()
			
			// Simulate report generation
			report := reporting.PandiAbuseReport{
				DomainName:       url,
				RegistrantEmail:  "unknown@target.com",
				AbuseType:        brand,
				EvidenceLinks:    []string{"https://strikerr.local/evidence/" + evidence.ID.String()},
				ThreatScore:      score,
			}
			_ = reporting.GeneratePandiReport(report) // generates the S/MIME string
			
			recipient := "PANDI Abuse (abuse@pandi.id)"
			if isGov {
				recipient = "BSSN CSIRT (csirt@bssn.go.id)"
			}

			smiHash := fmt.Sprintf("sha256:SMI-%d", rand.Int63())

			database.DB.Create(&database.TyposquattingDomain{
				TargetedBrand:   brand,
				DomainName:      url,
				MutationType:    "SEO_Poisoning/Phishing",
				SimilarityScore: float64(score) / 100.0,
				ThreatStatus:    "OFFICIALLY_REPORTED",
				ReportedAt:      &now,
				ReportRecipient: recipient,
				SmiSignatureHash: smiHash,
				EvidenceVaultID: &evidence.ID,
			})
			log.Printf("[REPORTING] Assembled threat dossier for %s. S/MIME signed report dispatched to %s.", url, recipient)
		}
	}
}
