package main

import (
	"fmt"
	"log"

	"github.com/opeteer/strikerr/internal/config"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/web"
)

func main() {
	log.Println("Starting Strikerr - Automated Threat Hunting & Reporting Platform...")

	// 1. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Println("Configuration loaded successfully.")

	// 2. Initialize database connection
	if cfg.DatabaseURL != "" {
		if err := database.Connect(cfg.DatabaseURL); err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		if err := database.AutoMigrate(); err != nil {
			log.Fatalf("Failed to run database migrations: %v", err)
		}
	} else {
		log.Println("Warning: DATABASE_URL not set. Skipping database initialization.")
	}

	// 3. Initialize Web UI & B2B API Server
	port := "8080"
	if cfg.ServerPort != 0 {
		port = fmt.Sprintf("%d", cfg.ServerPort)
	}
	
	srv := web.NewServer(port)
	
	log.Println("Strikerr system initialized. Launching web server...")
	if err := srv.Start(); err != nil {
		log.Fatalf("Web server failed: %v", err)
	}
}
