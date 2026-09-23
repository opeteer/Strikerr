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
	r := gin.Default()

	r.LoadHTMLGlob("internal/web/templates/*")

	setupRoutes(r)

	return &Server{
		router: r,
		port:   port,
	}
}

func setupRoutes(r *gin.Engine) {
	dashboard := r.Group("/")
	{
		dashboard.GET("/", handlers.RenderDashboard)
		dashboard.GET("/analytics", handlers.RenderAnalytics)
		dashboard.GET("/mule-accounts", handlers.RenderMuleAccounts)
		dashboard.GET("/logs", handlers.RenderLogs)
	}

	api := r.Group("/api/v1")
	{
		api.GET("/stats", handlers.APIGetStats)
		api.GET("/metrics/details", handlers.APIGetMetricDetails)
		api.GET("/feeds/mule-accounts", handlers.APIMuleAccountsFeed)
		api.GET("/feeds/typosquatting", handlers.APITyposquattingFeed)
		api.POST("/lookup/account", handlers.APILookupAccount)
		api.GET("/logs", handlers.APIGetLogs)
	}
}

func (s *Server) Start() error {
	log.Printf("Strikerr Web Server starting on port %s...", s.port)
	return s.router.Run(":" + s.port)
}
