package store

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	cloudAccessTypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) GetAccountCloudAccess(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*cloudAccessTypes.CloudAccess, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var access []*cloudAccessTypes.CloudAccess
	result := tx.Find(&access, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get cloud access from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get cloud access from store")
	}

	return access, nil
}

func (s *SqlStore) GetCloudAccessByID(ctx context.Context, lockStrength LockingStrength, accountID, cloudAccessID string) (*cloudAccessTypes.CloudAccess, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var item *cloudAccessTypes.CloudAccess
	result := tx.Take(&item, accountAndIDQueryCondition, accountID, cloudAccessID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewCloudAccessNotFoundError(cloudAccessID)
		}

		log.WithContext(ctx).Errorf("failed to get cloud access from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get cloud access from store")
	}

	return item, nil
}

func (s *SqlStore) SaveCloudAccess(ctx context.Context, access *cloudAccessTypes.CloudAccess) error {
	result := s.db.Save(access)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save cloud access to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save cloud access to store")
	}

	return nil
}

func (s *SqlStore) DeleteCloudAccess(ctx context.Context, accountID, cloudAccessID string) error {
	result := s.db.Delete(&cloudAccessTypes.CloudAccess{}, accountAndIDQueryCondition, accountID, cloudAccessID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete cloud access from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete cloud access from store")
	}

	if result.RowsAffected == 0 {
		return status.NewCloudAccessNotFoundError(cloudAccessID)
	}

	return nil
}
