package web

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/opeteer/strikerr/internal/web/handlers"
)

type Server struct {
	router *gin.Engine
	port   string
}

func NewServer(port string) *Server {
	// Set Gin to release mode in production
	// gin.SetMode(gin.ReleaseMode)
	
	r := gin.Default()

	// 1. Setup Static assets & Templates (Mock layout for now)
	// r.Static("/static", "./internal/web/static")
	// r.LoadHTMLGlob("internal/web/templates/*")

	// 2. Setup Routes
	setupRoutes(r)

	return &Server{
		router: r,
		port:   port,
	}
}

func setupRoutes(r *gin.Engine) {
	// --- Internal SOC Dashboard ---
	dashboard := r.Group("/")
	{
		dashboard.GET("/", handlers.RenderDashboard)
		dashboard.GET("/vault/:case_id", handlers.RenderEvidenceVault)
		dashboard.GET("/mule-accounts", handlers.RenderMuleAccounts)
		dashboard.GET("/analytics", handlers.RenderAnalytics)
	}

	// --- B2B Threat Intel API ---
	// Protected by API Keys in a real scenario
	api := r.Group("/api/v1")
	{
		api.GET("/feeds/mule-accounts", handlers.APIMuleAccountsFeed)
		api.GET("/feeds/typosquatting", handlers.APITyposquattingFeed)
		api.POST("/lookup/account", handlers.APILookupAccount)
	}
}

func (s *Server) Start() error {
	log.Printf("Strikerr Web Server starting on port %s...", s.port)
	return s.router.Run(":" + s.port)
}
