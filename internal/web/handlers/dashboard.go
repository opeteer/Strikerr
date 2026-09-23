package handlers

import (
	"net/http"
	"github.com/gin-gonic/gin"
)

func RenderDashboard(c *gin.Context) {
	// Mock returning HTML. In reality, c.HTML(...) with HTMX templates
	c.JSON(http.StatusOK, gin.H{
		"message": "Welcome to Strikerr SOC Command Center",
		"stats": gin.H{
			"active_hunts": 42,
			"frozen_mules": 128,
			"threat_level": "ELEVATED",
		},
	})
}

func RenderEvidenceVault(c *gin.Context) {
	caseID := c.Param("case_id")
	c.JSON(http.StatusOK, gin.H{
		"case_id": caseID,
		"status":  "Sealed & Signed",
	})
}

func RenderMuleAccounts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Mule accounts matrix view",
	})
}

func RenderAnalytics(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "Graphical telemetry & PDF export view",
	})
}
