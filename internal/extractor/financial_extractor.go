package extractor

import (
	"regexp"
	"strings"
)

var (
	// E-Wallet Patterns (Indonesian numbers + patterns)
	EWalletDanaRegex   = regexp.MustCompile(`(?i)(?:dana|d4na)[\s\:\-]+(08[0-9]{8,11})`)
	EWalletOvoRegex    = regexp.MustCompile(`(?i)(?:ovo|ov0)[\s\:\-]+(08[0-9]{8,11})`)
	EWalletGopayRegex  = regexp.MustCompile(`(?i)(?:gopay|go-pay)[\s\:\-]+(08[0-9]{8,11})`)
	EWalletShopeeRegex = regexp.MustCompile(`(?i)(?:shopeepay|spay)[\s\:\-]+(08[0-9]{8,11})`)
	EWalletLinkAjaRegex= regexp.MustCompile(`(?i)(?:linkaja)[\s\:\-]+(08[0-9]{8,11})`)

	// Bank Account Patterns (length & prefix based)
	BankBcaRegex       = regexp.MustCompile(`(?i)(?:bca)[\s\:\-]+([0-9]{10})`)
	BankMandiriRegex   = regexp.MustCompile(`(?i)(?:mandiri)[\s\:\-]+([0-9]{13})`)
	BankBriRegex       = regexp.MustCompile(`(?i)(?:bri)[\s\:\-]+([0-9]{15})`)
	BankBniRegex       = regexp.MustCompile(`(?i)(?:bni)[\s\:\-]+([0-9]{10})`)
	BankSeabankRegex   = regexp.MustCompile(`(?i)(?:seabank|sea bank)[\s\:\-]+([0-9]{12})`)
	BankJagoRegex      = regexp.MustCompile(`(?i)(?:bank jago|jago)[\s\:\-]+([0-9]{12})`)

	// QRIS Payload Regex (EMVCo standard)
	QrisPayloadRegex   = regexp.MustCompile(`(?i)(000201[0-9A-Z]{30,})`)
	
	// Crypto TRC-20 Address (USDT)
	CryptoTrc20Regex   = regexp.MustCompile(`(?i)(?:usdt|trc20)[\s\:\-]+(T[A-Za-z1-9]{33})`)
)

// ExtractEWallets finds and deduplicates e-wallet numbers
func ExtractEWallets(text string) []string {
	var results []string
	seen := make(map[string]bool)

	extract := func(re *regexp.Regexp) {
		matches := re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			if len(m) > 1 {
				num := strings.ReplaceAll(m[1], " ", "")
				if !seen[num] {
					seen[num] = true
					results = append(results, num)
				}
			}
		}
	}

	extract(EWalletDanaRegex)
	extract(EWalletOvoRegex)
	extract(EWalletGopayRegex)
	extract(EWalletShopeeRegex)
	extract(EWalletLinkAjaRegex)

	return results
}

// ExtractBanks finds and deduplicates bank account numbers
func ExtractBanks(text string) []string {
	var results []string
	seen := make(map[string]bool)

	extract := func(re *regexp.Regexp) {
		matches := re.FindAllStringSubmatch(text, -1)
		for _, m := range matches {
			if len(m) > 1 {
				num := strings.ReplaceAll(m[1], " ", "")
				if !seen[num] {
					seen[num] = true
					results = append(results, num)
				}
			}
		}
	}

	extract(BankBcaRegex)
	extract(BankMandiriRegex)
	extract(BankBriRegex)
	extract(BankBniRegex)
	extract(BankSeabankRegex)
	extract(BankJagoRegex)

	return results
}

// ExtractQRIS finds EMVCo QRIS strings
func ExtractQRIS(text string) []string {
	var results []string
	matches := QrisPayloadRegex.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		if len(m) > 1 {
			results = append(results, m[1])
		}
	}
	return results
}

// ExtractCrypto finds Crypto deposit addresses
func ExtractCrypto(text string) []string {
	var results []string
	matches := CryptoTrc20Regex.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		if len(m) > 1 {
			results = append(results, m[1])
		}
	}
	return results
}
