package tests

import (
	"testing"
	"github.com/opeteer/strikerr/internal/extractor"
	"github.com/opeteer/strikerr/internal/scoring"
)

func TestCalculateThreatScore(t *testing.T) {
	// Case 1: Pure Judol
	info1 := extractor.ExtractedInfo{
		HasGambling: true,
	}
	score1 := scoring.CalculateThreatScore(info1, false, false)
	if score1 != scoring.WeightJudolKeyword { // 25
		t.Errorf("Expected %d, got %d", scoring.WeightJudolKeyword, score1)
	}

	// Case 2: Max Threat (Gov + Phishing + Finance)
	info2 := extractor.ExtractedInfo{
		HasPhishing:  true,
		BankAccounts: []string{"123"},
	}
	score2 := scoring.CalculateThreatScore(info2, true, true)
	if score2 != 100 { // 25 + 30 + 35 + 20 = 110 -> 100 cap
		t.Errorf("Expected 100, got %d", score2)
	}
}
