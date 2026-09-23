package scoring

import "github.com/opeteer/strikerr/internal/extractor"

// Threat Scoring Weights
const (
	WeightJudolKeyword       = 25
	WeightGovAcIdDefacement  = 35
	WeightFinanceExtracted   = 30
	WeightDirectAPK          = 35
	WeightCloakingDetected   = 20
	WeightBrandImpersonation = 40
	WeightNewDomain          = 15
)

// CalculateThreatScore evaluates the extracted data and applies the scoring matrix.
// Returns a threat score between 0 and 100.
func CalculateThreatScore(info *extractor.ExtractedInfo, isGovDomain bool, hasCloaking bool) int {
	score := 0

	if info.JudolScore > 0 {
		score += WeightJudolKeyword
	}

	if len(info.BankAccounts) > 0 || len(info.EWallets) > 0 || len(info.QRISPayloads) > 0 {
		score += WeightFinanceExtracted
	}

	if isGovDomain && info.JudolScore > 0 {
		score += WeightGovAcIdDefacement
	}

	if hasCloaking {
		score += WeightCloakingDetected
	}

	// Cap the score at 100
	if score > 100 {
		score = 100
	}

	return score
}
