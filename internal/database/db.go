package database

import (
	"log"
	"os"
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
	err := DB.AutoMigrate(
		&EvidenceVault{},
		&MuleAccount{},
		&TyposquattingDomain{},
	)
	if err != nil {
		return err
	}

	if os.Getenv("CLEAN_START_ON_BOOT") == "true" {
		log.Println("CLEAN_START_ON_BOOT is true! Truncating all tables for a fresh 0 state...")
		TruncateDatabase()
	}

	return nil
}

func TruncateDatabase() error {
	log.Println("Purging database to 0 (Truncating tables)...")
	return DB.Exec("TRUNCATE TABLE mule_accounts, typosquatting_domains, evidence_vaults RESTART IDENTITY CASCADE;").Error
}

// Seed adds some initial testing data to the DB if it is empty.
func Seed() error {
	var count int64
	if err := DB.Model(&MuleAccount{}).Count(&count).Error; err != nil {
		return err
	}

	if count == 0 {
		log.Println("Database is empty, seeding with test threat data...")
		DB.Create(&MuleAccount{
			InstitutionType: "Bank",
			InstitutionName: "BCA",
			AccountNumber:   "1234567890",
			SourceURL:       "phishing-bca-login.com",
			RiskScore:       95,
			Status:          "VERIFIED_FRAUD",
		})
		DB.Create(&MuleAccount{
			InstitutionType: "EWallet",
			InstitutionName: "DANA",
			AccountNumber:   "081234567890",
			SourceURL:       "slot-gacor-maxwin.net",
			RiskScore:       80,
			Status:          "S/MIME_REPORTED",
		})
		DB.Create(&TyposquattingDomain{
			TargetedBrand:   "Bank Mandiri",
			DomainName:      "bankmandirri-promo.com",
			MutationType:    "Typosquatting",
			SimilarityScore: 0.95,
			ThreatStatus:    "SUSPICIOUS_REGISTERED",
		})
	}
	return nil
}
