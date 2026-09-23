package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func APIMuleAccountsFeed(c *gin.Context) {
	// STIX 2.1 / JSON formatted threat feed
	c.JSON(http.StatusOK, gin.H{
		"type":        "bundle",
		"id":          "bundle--mock-uuid",
		"spec_version": "2.1",
		"objects": []gin.H{
			{
				"type": "indicator",
				"name": "Mule Account BCA",
				"pattern": "[bank-account:number = '1234567890']",
				"valid_from": time.Now(),
			},
		},
	})
}

func APITyposquattingFeed(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"domains": []string{"klikbca-auth.com", "bankmandiri-promo.id"},
		"status":  "ACTIVE_PHISHING",
	})
}

func APILookupAccount(c *gin.Context) {
	// e.g. check if a transfer destination is a known mule
	c.JSON(http.StatusOK, gin.H{
		"account_number": "1234567890",
		"is_flagged":     true,
		"risk_score":     85,
	})
}
