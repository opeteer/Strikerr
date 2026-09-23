package database

import (
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect(dsn string) error {
	var err error
	
	// Open database connection
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	// Configure connection pool
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	log.Println("Database connection established successfully.")
	return nil
}

func AutoMigrate() error {
	log.Println("Running database migrations...")
	return DB.AutoMigrate(
		&EvidenceVault{},
		&MuleAccount{},
		&TyposquattingDomain{},
	)
}
