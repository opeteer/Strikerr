package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jung-kurt/gofpdf"
)

type EvidenceDossier struct {
	CaseID        string
	TargetURL     string
	DetectedAt    time.Time
	ThreatScore   int
	MuleAccounts  []string
	DOMHash       string
	TSATimestamp  string
}

func GeneratePDFDossier(evidence EvidenceDossier, outputDir string) (string, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	
	// Header
	pdf.SetFont("Arial", "B", 16)
	pdf.SetTextColor(220, 20, 60) // Crimson red
	pdf.Cell(40, 10, "STRIKERR THREAT INTELLIGENCE - EVIDENCE DOSSIER")
	pdf.Ln(12)
	
	// Metadata
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(0, 0, 0)
	
	pdf.Cell(40, 8, fmt.Sprintf("Case ID: %s", evidence.CaseID))
	pdf.Ln(6)
	pdf.Cell(40, 8, fmt.Sprintf("Target URL: %s", evidence.TargetURL))
	pdf.Ln(6)
	pdf.Cell(40, 8, fmt.Sprintf("Detected At: %s", evidence.DetectedAt.Format(time.RFC1123)))
	pdf.Ln(6)
	pdf.Cell(40, 8, fmt.Sprintf("Threat Score: %d / 100", evidence.ThreatScore))
	pdf.Ln(12)
	
	// Extracted Mule Accounts
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Extracted Financial Mule Accounts")
	pdf.Ln(8)
	
	pdf.SetFont("Arial", "", 10)
	if len(evidence.MuleAccounts) == 0 {
		pdf.Cell(40, 8, "None detected.")
		pdf.Ln(6)
	} else {
		for _, acc := range evidence.MuleAccounts {
			pdf.Cell(40, 8, fmt.Sprintf("- %s", acc))
			pdf.Ln(6)
		}
	}
	pdf.Ln(6)
	
	// Cryptographic Verification
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(40, 10, "Cryptographic Verification & Chain of Custody")
	pdf.Ln(8)
	
	pdf.SetFont("Courier", "", 9)
	pdf.MultiCell(0, 5, fmt.Sprintf("DOM SHA-256 Hash:\n%s", evidence.DOMHash), "", "L", false)
	pdf.Ln(4)
	pdf.MultiCell(0, 5, fmt.Sprintf("RFC 3161 TSA Timestamp Token:\n%s", evidence.TSATimestamp), "", "L", false)
	
	// Ensure directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", err
	}
	
	filename := filepath.Join(outputDir, fmt.Sprintf("dossier_%s.pdf", evidence.CaseID))
	err := pdf.OutputFileAndClose(filename)
	if err != nil {
		return "", err
	}
	
	return filename, nil
}
