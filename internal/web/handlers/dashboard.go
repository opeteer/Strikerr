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
	var totalMules int64
	var recentMules []database.MuleAccount

	if database.DB != nil {
		database.DB.Model(&database.MuleAccount{}).Count(&totalMules)
		database.DB.Order("first_seen_at desc").Limit(100).Find(&recentMules)
	}

	c.HTML(http.StatusOK, "mules.html", gin.H{
		"RecentMules": recentMules,
		"Stats": gin.H{
			"FrozenMules": totalMules,
		},
	})
}

func RenderLogs(c *gin.Context) {
	c.HTML(http.StatusOK, "logs.html", gin.H{})
}

func APIGetLogs(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
	if logger.GlobalBuffer != nil {
		c.JSON(http.StatusOK, logger.GlobalBuffer.GetLogs())
	} else {
		c.JSON(http.StatusOK, []string{})
	}
}

func APIGetStats(c *gin.Context) {
	c.Header("Cache-Control", "no-store, no-cache, must-revalidate")

	var totalMules int64
	var totalDomains int64
	var totalEvidence int64
	var reportedCount int64
	var bankCount int64
	var ewalletCount int64
	var recentMules []database.MuleAccount

	type InstCount struct {
		InstitutionName string `json:"name"`
		Count           int64  `json:"count"`
	}
	var instCounts []InstCount

	if database.DB != nil {
		database.DB.Model(&database.MuleAccount{}).Count(&totalMules)
		database.DB.Model(&database.MuleAccount{}).Where("LOWER(institution_type) LIKE ?", "%bank%").Count(&bankCount)
		database.DB.Model(&database.MuleAccount{}).Where("LOWER(institution_type) LIKE ?", "%wallet%").Count(&ewalletCount)
		database.DB.Model(&database.TyposquattingDomain{}).Count(&totalDomains)
		database.DB.Model(&database.TyposquattingDomain{}).Where("threat_status = ?", "OFFICIALLY_REPORTED").Count(&reportedCount)
		database.DB.Model(&database.EvidenceVault{}).Count(&totalEvidence)
		database.DB.Order("first_seen_at desc").Limit(10).Find(&recentMules)

		database.DB.Model(&database.MuleAccount{}).
			Select("institution_name, count(*) as count").
			Group("institution_name").
			Scan(&instCounts)
	}

	// Fallback if counts are equal to 0 but totalMules > 0
	if bankCount == 0 && ewalletCount == 0 && totalMules > 0 {
		ewalletCount = totalMules
	}

	threatLevel := "NORMAL"
	if totalDomains > 0 || totalMules > 0 {
		threatLevel = "ELEVATED THREAT"
	}

	c.JSON(http.StatusOK, gin.H{
		"active_hunts":       totalDomains,
		"frozen_mules":       totalMules,
		"officially_reported": reportedCount,
		"bank_count":         bankCount,
		"ewallet_count":      ewalletCount,
		"verified_takedowns": totalEvidence,
		"threat_level":       threatLevel,
		"recent_mules":       recentMules,
		"institution_stats":  instCounts,
	})
}

func RenderAnalytics(c *gin.Context) {
	c.HTML(http.StatusOK, "analytics.html", gin.H{})
}

func APIPurgeDatabase(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database not initialized"})
		return
	}
	
	if err := database.TruncateDatabase(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	// Also clear in-memory logger
	if logger.GlobalBuffer != nil {
		logger.GlobalBuffer.Reset()
	}
	
	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Database and logs purged successfully"})
}
