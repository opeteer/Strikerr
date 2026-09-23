package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RenderDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Message": "Welcome to Strikerr SOC Command Center",
		"Stats": gin.H{
			"ActiveHunts": 42,
			"FrozenMules": 128,
			"ThreatLevel": "ELEVATED",
		},
	})
}

func RenderEvidenceVault(c *gin.Context) {
	caseID := c.Param("case_id")
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Message": "Evidence Vault Inspector",
		"Stats": gin.H{
			"ActiveHunts": 1,
			"FrozenMules": 128,
			"ThreatLevel": "CASE INPECTOR: " + caseID,
		},
	})
}

func RenderMuleAccounts(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Message": "Mule Accounts Registry View",
		"Stats": gin.H{
			"ActiveHunts": 42,
			"FrozenMules": 128,
			"ThreatLevel": "ACTIVE",
		},
	})
}

func RenderAnalytics(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"Message": "Graphical Telemetry & Analytics",
		"Stats": gin.H{
			"ActiveHunts": 42,
			"FrozenMules": 128,
			"ThreatLevel": "ANALYTICS MODE",
		},
	})
}
