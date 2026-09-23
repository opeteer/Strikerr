package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"
	"github.com/opeteer/strikerr/internal/config"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/ingestion"
	"github.com/opeteer/strikerr/internal/web"
	"github.com/opeteer/strikerr/internal/worker"
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
		if err := database.Seed(); err != nil {
			log.Printf("Warning: Failed to seed database: %v", err)
		}
	} else {
		log.Println("Warning: DATABASE_URL not set. Skipping database initialization.")
	}

	// 3. Initialize Task Queue Worker
	var workerServer *asynq.Server
	if cfg.RedisURL != "" {
		log.Println("Initializing Redis Task Queue...")
		redisOpt := asynq.RedisClientOpt{Addr: cfg.RedisURL}
		
		processor, err := worker.NewTaskProcessor()
		if err != nil {
			log.Fatalf("Failed to initialize task processor: %v", err)
		}

		workerServer = asynq.NewServer(
			redisOpt,
			asynq.Config{
				Concurrency: 10,
				Queues: map[string]int{
					"critical": 6,
					"default":  3,
					"low":      1,
				},
			},
		)

		mux := asynq.NewServeMux()
		mux.HandleFunc(ingestion.TypeCrawlWebsite, processor.ProcessCrawlTask)

		go func() {
			if err := workerServer.Run(mux); err != nil {
				log.Fatalf("Worker server failed: %v", err)
			}
		}()
		log.Println("Task Worker started.")
	}

	// 4. Initialize Web UI & B2B API Server
	port := "8051"
	if cfg.ServerPort != 0 {
		port = fmt.Sprintf("%d", cfg.ServerPort)
	}
	
	srv := web.NewServer(port)
	
	go func() {
		log.Printf("Strikerr Web Server starting on port %s...", port)
		if err := srv.Start(); err != nil {
			log.Fatalf("Web server failed: %v", err)
		}
	}()

	// Wait for termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	log.Println("Shutting down Strikerr...")
	if workerServer != nil {
		workerServer.Shutdown()
	}
}
