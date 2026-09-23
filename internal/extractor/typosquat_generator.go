package extractor

import (
	"log"
	"strings"
)

var CommonFinancialBrands = []string{"klikbca", "bankmandiri", "bri", "bni", "dana", "ovo", "gopay", "shopeepay"}

type TyposquatGenerator struct{}

func NewTyposquatGenerator() *TyposquatGenerator {
	return &TyposquatGenerator{}
}

func (t *TyposquatGenerator) GenerateMutations(domain string) []string {
	mutations := make(map[string]bool)
	base := strings.Split(domain, ".")[0]

	// 1. Homograph substitution
	homographs := map[rune]string{
		'a': "а", 'c': "с", 'e': "е", 'i': "і", 'o': "о", 'p': "р", 'l': "1", 'b': "8",
	}
	for i, char := range base {
		if sub, ok := homographs[char]; ok {
			mutated := base[:i] + sub + base[i+1:]
			mutations[mutated+".com"] = true
		}
	}

	// 2. Hyphenation
	for i := 1; i < len(base); i++ {
		mutated := base[:i] + "-" + base[i:]
		mutations[mutated+".com"] = true
	}

	// 3. Bitsquatting (simplified simulation)
	bitsquats := []string{"k", "c", "j"}
	for _, b := range bitsquats {
		mutations[base+b+".com"] = true
	}

	var results []string
	for k := range mutations {
		results = append(results, k)
	}
	return results
}

func (t *TyposquatGenerator) MonitorBrandTyposquatting() {
	log.Println("[TYPOSQUAT] Generating preemptive mutation models for target brands...")
	for _, brand := range CommonFinancialBrands {
		muts := t.GenerateMutations(brand + ".com")
		log.Printf("[TYPOSQUAT] Generated %d mutations for %s (e.g., %s)", len(muts), brand, muts[0])
	}
}
