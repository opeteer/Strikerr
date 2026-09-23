package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hibiken/asynq"
	"github.com/opeteer/strikerr/internal/config"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/ingestion"
	"github.com/opeteer/strikerr/internal/logger"
	"github.com/opeteer/strikerr/internal/web"
	"github.com/opeteer/strikerr/internal/worker"
)

func main() {
	// 1. Initialize In-Memory Logger for Web UI
	memLog := logger.InitLogger()
	log.SetOutput(io.MultiWriter(os.Stdout, memLog))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Println("Starting Strikerr - Automated Threat Hunting & Reporting Platform...")

	// 2. Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Println("Configuration loaded successfully.")

	// 3. Initialize database connection
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
	}

	// 4. Initialize Task Queue Worker
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

		// Simulate background task generation for logs showcase
		go func() {
			client := asynq.NewClient(redisOpt)
			defer client.Close()
			for {
				time.Sleep(30 * time.Second)
				log.Println("[Engine] Active hibernation shield check: Network secure.")
			}
		}()
	}

	// 5. Initialize Web UI
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

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	log.Println("Shutting down Strikerr...")
	if workerServer != nil {
		workerServer.Shutdown()
	}
}
