package reporting

import (
	"fmt"
	"time"
)

type PandiAbuseReport struct {
	DomainName      string
	RegistrantEmail string
	AbuseType       string
	EvidenceLinks   []string
	ThreatScore     int
}

func GeneratePandiReport(report PandiAbuseReport) string {
	template := `To: abuse@pandi.id
From: strike-team@strikerr.local
Subject: [URGENT ABUSE] %s - %s
Date: %s
Content-Type: text/plain; charset="utf-8"

Dear PANDI Abuse Team,

This is an automated threat intelligence report from the Strikerr platform.
We have detected severe malicious activity on a .id registry domain.

Domain Name: %s
Registrant Contact: %s
Abuse Category: %s
Threat Score: %d/100

Cryptographic Evidence Vault Links:
%s

Please review this violation of PANDI domain registration policies and suspend the domain.
A digitally signed PDF dossier is attached (S/MIME).

Best regards,
Strikerr Automated SOC
`
	links := ""
	for _, l := range report.EvidenceLinks {
		links += "- " + l + "\n"
	}

	return fmt.Sprintf(template,
		report.AbuseType, report.DomainName,
		time.Now().Format(time.RFC1123Z),
		report.DomainName, report.RegistrantEmail, report.AbuseType, report.ThreatScore,
		links)
}
