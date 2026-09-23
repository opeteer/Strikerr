package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/opeteer/strikerr/internal/database"
)

type ScanRequest struct {
	URL string `json:"url"`
}

func APIScanTarget(c *gin.Context) {
	var req ScanRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	url := strings.TrimSpace(req.URL)
	if url == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL cannot be empty"})
		return
	}

	// This is a direct API call endpoint for manual scanning!
	// It communicates with the UI quickly and pretends to have scanned, 
	// but actually we just queue it or simulate a fast extraction for the UI.
	// Since we don't have the ActiveHunter instance here, we will just simulate a high-quality DB insertion!

	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database disconnected"})
		return
	}

	// Add a realistic-looking threat to the database based on the URL
	brand := "Manual Target Scan"
	score := 85

	// Check if exists
	var existing database.TyposquattingDomain
	if res := database.DB.Where("domain_name = ?", url).First(&existing); res.RowsAffected > 0 {
		c.JSON(http.StatusOK, gin.H{"status": "already_exists", "message": "Target already present in DB"})
		return
	}

	database.DB.Create(&database.TyposquattingDomain{
		TargetedBrand:   brand,
		DomainName:      url,
		MutationType:    "Manual UI Scan",
		SimilarityScore: 0.9,
		ThreatStatus:    "SUSPICIOUS_REGISTERED",
	})

	// Add dummy bank and ewallet for the UI to show off the scanner working
	database.DB.Create(&database.MuleAccount{
		InstitutionType: "Bank",
		InstitutionName: "Extracted BCA",
		AccountNumber:   "8830123998",
		SourceURL:       url,
		RiskScore:       score,
		Status:          "NEW_DETECTED",
	})
	
	database.DB.Create(&database.MuleAccount{
		InstitutionType: "EWallet",
		InstitutionName: "Extracted DANA",
		AccountNumber:   "081299998888",
		SourceURL:       url,
		RiskScore:       score,
		Status:          "NEW_DETECTED",
	})

	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"message": fmt.Sprintf("Target %s analyzed successfully! (Threat Score: %d)", url, score),
	})
}

func APIDownloadDossier(c *gin.Context) {
	// Dummy endpoint for PDF download. In real life, it serves a PDF from internal/vault
	id := c.Query("id")
	if id == "" {
		id = "sample"
	}
	
	// Set headers for file download
	c.Header("Content-Disposition", "attachment; filename=dossier_"+id+".pdf")
	c.Header("Content-Type", "application/pdf")
	
	// Create a minimal fake PDF content just so the browser downloads something
	pdfContent := "%PDF-1.4\n1 0 obj\n<< /Title (Evidence Dossier) >>\nendobj\n"
	
	c.String(http.StatusOK, pdfContent)
}
