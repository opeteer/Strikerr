package extractor

import (
	"regexp"
	"strings"
)

// Regex patterns for Indonesian financial mules.
var (
	QRISPattern  = regexp.MustCompile(`00020101021[12]`)
	OvoPattern   = regexp.MustCompile(`(?i)(ovo|gopay|dana)[^\d]*(\d{10,13})`)
	BankPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(bca|mandiri|bni|bri)[^\d]{1,10}(\d{10,16})`),
	}
)

type ExtractedInfo struct {
	BankAccounts []string
	EWallets     []string
	QRISPayloads []string
	JudolScore   int
}

func ParseDOM(content string) *ExtractedInfo {
	info := &ExtractedInfo{}
	
	// Very simple scoring heuristic
	contentLower := strings.ToLower(content)
	if strings.Contains(contentLower, "gacor") || strings.Contains(contentLower, "slot777") {
		info.JudolScore += 30
	}
	
	// Scan for E-Wallets
	ovoMatches := OvoPattern.FindAllStringSubmatch(contentLower, -1)
	for _, m := range ovoMatches {
		if len(m) > 2 {
			info.EWallets = append(info.EWallets, m[1]+": "+m[2])
		}
	}
	
	// Scan for QRIS
	qrisMatches := QRISPattern.FindAllString(content, -1)
	for _, m := range qrisMatches {
		info.QRISPayloads = append(info.QRISPayloads, m)
	}
	
	return info
}
