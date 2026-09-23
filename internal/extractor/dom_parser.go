package extractor

import (
	"strings"
)

type ExtractedInfo struct {
	BankAccounts []string
	EWallets     []string
	QRISPayloads []string
	CryptoAddrs  []string
	HasGambling  bool
	HasPhishing  bool
}

func ParseDOM(domContent string) ExtractedInfo {
	info := ExtractedInfo{}
	
	info.BankAccounts = ExtractBanks(domContent)
	info.EWallets = ExtractEWallets(domContent)
	info.QRISPayloads = ExtractQRIS(domContent)
	info.CryptoAddrs = ExtractCrypto(domContent)

	lowerDOM := strings.ToLower(domContent)

	gamblingKeywords := []string{"slot", "gacor", "maxwin", "togel", "rtp"}
	for _, kw := range gamblingKeywords {
		if strings.Contains(lowerDOM, kw) {
			info.HasGambling = true
			break
		}
	}

	phishingKeywords := []string{"login bca", "keybca response", "mandiri online", "password"}
	for _, kw := range phishingKeywords {
		if strings.Contains(lowerDOM, kw) {
			info.HasPhishing = true
			break
		}
	}

	return info
}
