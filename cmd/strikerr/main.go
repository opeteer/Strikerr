package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hibiken/asynq"
	"github.com/mxschmitt/playwright-go"
	"github.com/opeteer/strikerr/internal/config"
	"github.com/opeteer/strikerr/internal/database"
	"github.com/opeteer/strikerr/internal/ingestion"
	"github.com/opeteer/strikerr/internal/logger"
	"github.com/opeteer/strikerr/internal/web"
	"github.com/opeteer/strikerr/internal/worker"
)

func main() {
	installPlaywright := flag.Bool("install-playwright-only", false, "Install Playwright browsers and exit")
	flag.Parse()

	if *installPlaywright {
		log.Println("Installing Playwright browsers...")
		err := playwright.Install()
		if err != nil {
			log.Fatalf("Failed to install Playwright: %v", err)
		}
		log.Println("Playwright installed successfully.")
		os.Exit(0)
	}

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

	// 3. Initialize Web UI Server First (so port is bound immediately)
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

	// 4. Initialize database connection
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var workerServer *asynq.Server

	// 5. Start Heavy Initializers in Goroutine
	go func() {
		log.Println("Initializing Autonomous Threat Hunter Scanner Loop...")
		hunter, err := ingestion.NewActiveHunter()
		if err != nil {
			log.Printf("Warning: Hunter initialization issue: %v", err)
		} else {
			go hunter.StartHuntingLoop(ctx)
		}

		if cfg.RedisURL != "" {
			log.Println("Initializing Redis Task Queue...")
			redisOpt := asynq.RedisClientOpt{Addr: cfg.RedisURL}
			
			processor, err := worker.NewTaskProcessor()
			if err != nil {
				log.Printf("Warning: Failed to initialize task processor: %v", err)
			} else {
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
						log.Printf("Worker server stopped: %v", err)
					}
				}()
				log.Println("Task Worker started.")
			}
		}
	}()

	// Wait for termination signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	
	log.Println("Shutting down Strikerr...")
	cancel()
	if workerServer != nil {
		workerServer.Shutdown()
	}
}
