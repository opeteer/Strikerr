package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opeteer/strikerr/internal/database"
)

func APIGetMetricDetails(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	metricType := c.Query("type")

	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database disconnected"})
		return
	}

	switch metricType {
	case "active_hunts":
		var targets []database.TyposquattingDomain
		database.DB.Order("created_at desc").Limit(20).Find(&targets)
		c.JSON(http.StatusOK, gin.H{
			"title":       "Active Threat Hunts",
			"description": "Monitored Target Domains. Autonomous threat hunting engines continuously scan incoming CertStream CT Logs and passive Google Dorks for relevant domains.",
			"items":       targets,
		})

	case "frozen_mules":
		var mules []database.MuleAccount
		database.DB.Order("risk_score desc").Limit(20).Find(&mules)
		c.JSON(http.StatusOK, gin.H{
			"title":       "Frozen Mule Accounts",
			"description": "Extracted Bank & E-Wallet Mules. Threat Extractors parse DOM structures using regex matrices to harvest exposed mule accounts.",
			"items":       mules,
		})

	case "verified_takedowns":
		var vault []database.EvidenceVault
		database.DB.Order("created_at desc").Limit(20).Find(&vault)
		c.JSON(http.StatusOK, gin.H{
			"title":       "Verified Takedowns",
			"description": "Forensic Cryptographic Evidence. Each takedown is backed by a DOM SHA-256 hash and a verifiable RFC 3161 TSA timestamp signature.",
			"items":       vault,
		})

	case "officially_reported":
		var domains []database.TyposquattingDomain
		database.DB.Where("threat_status = ?", "OFFICIALLY_REPORTED").Order("reported_at desc").Limit(20).Find(&domains)
		
		type DisplayItem struct {
			DomainName      string `json:"DomainName"`
			InstitutionName string `json:"InstitutionName"`
		}
		
		var items []DisplayItem
		for _, d := range domains {
			items = append(items, DisplayItem{
				DomainName:      d.DomainName,
				InstitutionName: d.ReportRecipient,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"title":       "Officially Reported Websites",
			"description": "Situs web ancaman yang telah dibuatkan laporan penyalahgunaan resmi ber-S/MIME dan dikirimkan secara otomatis ke registri (PANDI), CSIRT, atau OJK.",
			"items":       items,
		})

	case "threat_level":
		c.JSON(http.StatusOK, gin.H{
			"title":       "System Threat Level",
			"description": "Proxy Egress Node Status & Threat Scoring Weights. Indicates current OPSEC masking status.",
			"items": []map[string]string{
				{"metric": "Proxy Status", "value": "SOCKS5 Active"},
				{"metric": "Header Sanitizer", "value": "Strict S/MIME Enforced"},
				{"metric": "Gambling Weight", "value": "+25 Risk Points"},
				{"metric": "Gov Deface Weight", "value": "+35 Risk Points"},
			},
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown metric type"})
	}
}
