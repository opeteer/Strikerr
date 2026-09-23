package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/logger"
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
		"ActiveMenu": "dashboard",
		"Stats": gin.H{
			"ActiveHunts": totalDomains,
			"FrozenMules": totalMules,
			"ThreatLevel": "NORMAL",
		},
		"RecentMules": recentMules,
	})
}

func RenderMuleAccounts(c *gin.Context) {
	var mules []database.MuleAccount
	var totalMules int64
	if database.DB != nil {
		database.DB.Order("first_seen_at desc").Limit(50).Find(&mules)
		database.DB.Model(&database.MuleAccount{}).Count(&totalMules)
	}
	
	c.HTML(http.StatusOK, "mules.html", gin.H{
		"ActiveMenu": "mules",
		"Stats": gin.H{
			"FrozenMules": totalMules,
		},
		"RecentMules": mules,
	})
}

func RenderLogs(c *gin.Context) {
	c.HTML(http.StatusOK, "logs.html", gin.H{
		"ActiveMenu": "logs",
	})
}

func APIGetLogs(c *gin.Context) {
	if logger.GlobalBuffer != nil {
		c.JSON(http.StatusOK, logger.GlobalBuffer.GetLogs())
	} else {
		c.JSON(http.StatusOK, []string{})
	}
}
