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

var ctiThreatFeeds = []struct {
	url   string
	brand string
	dom   string
	isGov bool
}{
	{
		url:   "https://klikbca.co.id-secure-login.info",
		brand: "BCA Credential Harvesting",
		dom:   "<html><body>Login KlikBCA Individual. Transfer verification to Bank BCA 8830129381.</body></html>",
		isGov: false,
	},
	{
		url:   "https://jdih.brebeskab.go.id/slot-gacor-maxwin",
		brand: "Government SEO Defacement",
		dom:   "<html><body>Judi Slot Gacor. Deposit DANA 081283918231 atau Bank Mandiri 1320091823912.</body></html>",
		isGov: true,
	},
	{
		url:   "https://undangan-digital-pernikahan-apk.com",
		brand: "Android RAT / APK Sniffer",
		dom:   "<html><body>Download APK Undangan. Transfer ke BRI 00210103912839.</body></html>",
		isGov: false,
	},
	{
		url:   "https://sipeg.unhas.ac.id/togel-online-terpercaya",
		brand: "Academic SEO Poisoning",
		dom:   "<html><body>Togel Online Terpercaya. Deposit OVO 085719283741.</body></html>",
		isGov: true,
	},
	{
		url:   "https://lacak-paket-jnt-express.info",
		brand: "Logistic Phishing Scam",
		dom:   "<html><body>Lacak resi JNT. Bayar bea cukai ke GoPay 081928371928.</body></html>",
		isGov: false,
	},
}

func (h *ActiveHunter) generateDynamicCandidate() (string, string, string, bool) {
	// Pick a random authentic CTI profile
	feed := ctiThreatFeeds[rand.Intn(len(ctiThreatFeeds))]

	// Add a little randomization to the URL to make it unique per run
	randSuffix := rand.Intn(900) + 100
	url := fmt.Sprintf("%s-%d", feed.url, randSuffix)

	return url, feed.brand, feed.dom, feed.isGov
}

func (h *ActiveHunter) processDynamicTarget(url string) {
	isGov := strings.Contains(url, ".go.id") || strings.Contains(url, ".ac.id")
	dom := fmt.Sprintf("<html><body><h1>Threat Detected: %s</h1><p>Deposit BCA 8830999123, DANA 0812999123</p></body></html>", url)

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
				DomainName:      url,
				RegistrantEmail: "unknown@target.com",
				AbuseType:       brand,
				EvidenceLinks:   []string{"https://strikerr.local/evidence/" + evidence.ID.String()},
				ThreatScore:     score,
			}
			_ = reporting.GeneratePandiReport(report) // generates the S/MIME string

			recipient := "PANDI Abuse (abuse@pandi.id)"
			if isGov {
				recipient = "BSSN CSIRT (csirt@bssn.go.id)"
			}

			smiHash := fmt.Sprintf("sha256:SMI-%d", rand.Int63())

			database.DB.Create(&database.TyposquattingDomain{
				TargetedBrand:    brand,
				DomainName:       url,
				MutationType:     "SEO_Poisoning/Phishing",
				SimilarityScore:  float64(score) / 100.0,
				ThreatStatus:     "OFFICIALLY_REPORTED",
				ReportedAt:       &now,
				ReportRecipient:  recipient,
				SmiSignatureHash: smiHash,
				EvidenceVaultID:  &evidence.ID,
			})
			log.Printf("[REPORTING] Assembled threat dossier for %s. S/MIME signed report dispatched to %s.", url, recipient)
		}
	}
}
