package database

import (
	"time"

	"github.com/google/uuid"
)

type EvidenceVault struct {
	ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	DOMHash   string
	SignedURL string
	CreatedAt time.Time
}

type MuleAccount struct {
	ID                uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	InstitutionType   string    `gorm:"size:32;not null"`
	InstitutionName   string    `gorm:"size:64;not null"`
	AccountNumber     string    `gorm:"size:128;not null"`
	AccountHolderName string    `gorm:"size:256"`
	RawQRISPayload    string    `gorm:"type:text"`
	CryptoAddress     string    `gorm:"size:128"`
	FirstSeenAt       time.Time `gorm:"autoCreateTime"`
	LastSeenAt        time.Time `gorm:"autoUpdateTime"`
	OccurrenceCount   int       `gorm:"default:1"`
	SourceURL         string    `gorm:"not null"`
	EvidenceVaultID   *uuid.UUID
	EvidenceVault     EvidenceVault
	RiskScore         int       `gorm:"check:risk_score >= 0 AND risk_score <= 100"`
	Status            string    `gorm:"size:32;default:'NEW_DETECTED'"`
}

type TyposquattingDomain struct {
	ID                  uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
	TargetedBrand       string    `gorm:"size:64;not null"`
	DomainName          string    `gorm:"size:255;not null;unique"`
	MutationType        string    `gorm:"size:64;not null"`
	LevenshteinDistance int       `gorm:"not null"`
	SimilarityScore     float64   `gorm:"not null"`
	RegisteredAt        *time.Time
	Registrar           string    `gorm:"size:128"`
	ResolvedIP          string    `gorm:"size:45"`
	EvidenceVaultID     *uuid.UUID
	EvidenceVault       EvidenceVault
	ThreatStatus        string    `gorm:"size:64;default:'SUSPICIOUS_REGISTERED'"`
	ReportedAt          *time.Time
	ReportRecipient     string    `gorm:"size:128"`
	SmiSignatureHash    string    `gorm:"size:255"`
}
