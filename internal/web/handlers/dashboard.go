package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opeteer/strikerr/internal/database"
)

func RenderDashboard(c *gin.Context) {
	var totalMules int64
	var totalDomains int64
	var recentMules []database.MuleAccount

	if database.DB != nil {
		database.DB.Model(&database.MuleAccount{}).Count(&totalMules)
		database.DB.Model(&database.TyposquattingDomain{}).Count(&totalDomains)
		database.DB.Order("first_seen_at desc").Limit(5).Find(&recentMules)
	}

	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Stats": gin.H{
			"ActiveHunts": totalDomains, // Using domains as a proxy for active hunts
			"FrozenMules": totalMules,
			"ThreatLevel": "NORMAL",
		},
		"RecentMules": recentMules,
	})
}

func RenderEvidenceVault(c *gin.Context) {
	caseID := c.Param("case_id")
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Message": "Evidence Vault Inspector",
		"Stats": gin.H{
			"ActiveHunts": 0,
			"FrozenMules": 0,
			"ThreatLevel": "CASE INSPECTOR: " + caseID,
		},
	})
}

func RenderMuleAccounts(c *gin.Context) {
	var mules []database.MuleAccount
	if database.DB != nil {
		database.DB.Order("first_seen_at desc").Limit(50).Find(&mules)
	}
	
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Message": "Mule Accounts Registry View",
		"Stats": gin.H{
			"ActiveHunts": 0,
			"FrozenMules": len(mules),
			"ThreatLevel": "ACTIVE",
		},
		"RecentMules": mules,
	})
}

func RenderAnalytics(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Message": "Graphical Telemetry & Analytics",
		"Stats": gin.H{
			"ActiveHunts": 0,
			"FrozenMules": 0,
			"ThreatLevel": "ANALYTICS MODE",
		},
	})
}
