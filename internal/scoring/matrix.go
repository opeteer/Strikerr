package scoring

import (
	"github.com/opeteer/strikerr/internal/extractor"
	"github.com/opeteer/strikerr/internal/opsec"
)

const (
	WeightJudolKeyword       = 25
	WeightPhishingKeyword    = 25
	WeightGovAcIdDefacement  = 35
	WeightFinanceExtracted   = 30
	WeightDirectAPK          = 35
	WeightCloakingDetected   = 20
	WeightBrandImpersonation = 40
	WeightNewDomain          = 15
)

func CalculateThreatScore(info extractor.ExtractedInfo, url string, isGovDomain bool, hasCloaking bool) int {
	score := 0

	if info.HasGambling {
		score += WeightJudolKeyword
	}
	if info.HasPhishing {
		score += WeightPhishingKeyword
	}

	if len(info.BankAccounts) > 0 || len(info.EWallets) > 0 || len(info.QRISPayloads) > 0 || len(info.CryptoAddrs) > 0 {
		score += WeightFinanceExtracted
	}

	if isGovDomain && (info.HasGambling || info.HasPhishing) {
		score += WeightGovAcIdDefacement
	}

	if hasCloaking {
		score += WeightCloakingDetected
	}

	// Apply whitelist logic
	if url != "" && opsec.IsWhitelisted(url) {
		// Whitelisted domain should have score reduced or bypassed unless strong indicator
		if isGovDomain && (info.HasGambling || info.HasPhishing) {
			// Strong indicator, keep some score but maybe don't bypass completely, or just don't reduce
			// The prompt says "A whitelisted domain should have its threat score drastically reduced or bypassed, unless there's a strong indicator (like isGovDomain defacement)."
			// So we do nothing if it's a strong indicator
		} else {
			score = 0
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}
