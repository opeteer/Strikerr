package scoring

import "github.com/opeteer/strikerr/internal/extractor"

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

func CalculateThreatScore(info extractor.ExtractedInfo, isGovDomain bool, hasCloaking bool) int {
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

	if score > 100 {
		score = 100
	}

	return score
}
