package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/logger"
)

func RenderDashboard(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{})
}

func RenderMuleAccounts(c *gin.Context) {
	c.HTML(http.StatusOK, "mules.html", gin.H{})
}

func RenderLogs(c *gin.Context) {
	c.HTML(http.StatusOK, "logs.html", gin.H{})
}

func APIGetLogs(c *gin.Context) {
	if logger.GlobalBuffer != nil {
		c.JSON(http.StatusOK, logger.GlobalBuffer.GetLogs())
	} else {
		c.JSON(http.StatusOK, []string{})
	}
}

func APIGetStats(c *gin.Context) {
	var totalMules int64
	var totalDomains int64
	var totalEvidence int64
	var recentMules []database.MuleAccount

	if database.DB != nil {
		database.DB.Model(&database.MuleAccount{}).Count(&totalMules)
		database.DB.Model(&database.TyposquattingDomain{}).Count(&totalDomains)
		database.DB.Model(&database.EvidenceVault{}).Count(&totalEvidence)
		database.DB.Order("first_seen_at desc").Limit(10).Find(&recentMules)
	}

	threatLevel := "NORMAL"
	if totalDomains > 0 || totalMules > 0 {
		threatLevel = "ELEVATED THREAT"
	}

	c.JSON(http.StatusOK, gin.H{
		"active_hunts":       totalDomains,
		"frozen_mules":       totalMules,
		"verified_takedowns": totalEvidence,
		"threat_level":       threatLevel,
		"recent_mules":       recentMules,
	})
}

func RenderAnalytics(c *gin.Context) {
	c.HTML(http.StatusOK, "analytics.html", gin.H{})
}
