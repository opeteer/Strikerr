package database

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

type MuleRepository interface {
	Create(ctx context.Context, account *MuleAccount) error
	GetByAccountNumber(ctx context.Context, accountNumber string) (*MuleAccount, error)
	List(ctx context.Context, offset, limit int) ([]MuleAccount, error)
	UpdateStatus(ctx context.Context, id string, status string) error
}

type muleRepository struct {
	db *gorm.DB
}

func NewMuleRepository(db *gorm.DB) MuleRepository {
	return &muleRepository{db: db}
}

func (r *muleRepository) Create(ctx context.Context, account *MuleAccount) error {
	return r.db.WithContext(ctx).Create(account).Error
}

func (r *muleRepository) GetByAccountNumber(ctx context.Context, accountNumber string) (*MuleAccount, error) {
	var account MuleAccount
	err := r.db.WithContext(ctx).Where("account_number = ?", accountNumber).First(&account).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &account, nil
}

func (r *muleRepository) List(ctx context.Context, offset, limit int) ([]MuleAccount, error) {
	var accounts []MuleAccount
	err := r.db.WithContext(ctx).Offset(offset).Limit(limit).Order("created_at desc").Find(&accounts).Error
	return accounts, err
}

func (r *muleRepository) UpdateStatus(ctx context.Context, id string, status string) error {
	return r.db.WithContext(ctx).Model(&MuleAccount{}).Where("id = ?", id).Update("status", status).Error
}
