package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/opeteer/strikerr/internal/database"
)

func APIMuleAccountsFeed(c *gin.Context) {
	var mules []database.MuleAccount
	if database.DB != nil {
		database.DB.Find(&mules)
	}

	var objects []gin.H
	for _, m := range mules {
		objects = append(objects, gin.H{
			"type":       "indicator",
			"name":       m.InstitutionName + " Account",
			"pattern":    "[bank-account:number = '" + m.AccountNumber + "']",
			"valid_from": m.FirstSeenAt,
			"risk_score": m.RiskScore,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"type":         "bundle",
		"id":           "bundle--strikerr-live",
		"spec_version": "2.1",
		"objects":      objects,
	})
}

func APITyposquattingFeed(c *gin.Context) {
	var domains []database.TyposquattingDomain
	if database.DB != nil {
		database.DB.Find(&domains)
	}

	var dNames []string
	for _, d := range domains {
		dNames = append(dNames, d.DomainName)
	}

	c.JSON(http.StatusOK, gin.H{
		"domains": dNames,
		"status":  "ACTIVE_PHISHING",
	})
}

type LookupRequest struct {
	AccountNumber string `json:"account_number"`
}

func APILookupAccount(c *gin.Context) {
	var req LookupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var mule database.MuleAccount
	result := database.DB.Where("account_number = ?", req.AccountNumber).First(&mule)

	if result.Error != nil {
		c.JSON(http.StatusOK, gin.H{
			"account_number": req.AccountNumber,
			"is_flagged":     false,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"account_number": mule.AccountNumber,
		"is_flagged":     true,
		"risk_score":     mule.RiskScore,
		"institution":    mule.InstitutionName,
	})
}
