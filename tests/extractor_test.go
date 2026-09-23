package tests

import (
	"testing"
	"github.com/opeteer/strikerr/internal/extractor"
)

func TestFinancialExtractor(t *testing.T) {
	html := "Silakan transfer ke rekening BCA 8830192841 atas nama Budi, atau DANA 081234567890."
	
	banks := extractor.ExtractBanks(html)
	if len(banks) != 1 || banks[0] != "8830192841" {
		t.Errorf("Expected BCA 8830192841, got %v", banks)
	}

	ewallets := extractor.ExtractEWallets(html)
	if len(ewallets) != 1 || ewallets[0] != "081234567890" {
		t.Errorf("Expected DANA 081234567890, got %v", ewallets)
	}
}

func TestQRISAndCrypto(t *testing.T) {
	html := "Donate crypto TRC20: TXX123456789112345678911234567891123. QRIS code string 0002010102123456789012345678901234567890"
	crypto := extractor.ExtractCrypto(html)
	if len(crypto) != 1 {
		t.Errorf("Expected 1 crypto, got %v", crypto)
	}

	qris := extractor.ExtractQRIS(html)
	if len(qris) != 1 {
		t.Errorf("Expected 1 qris, got %v", qris)
	}
}
