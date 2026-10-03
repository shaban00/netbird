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

func (s *SqlStore) GetAccountCloudRoles(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*cloudAccessTypes.CloudRole, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var roles []*cloudAccessTypes.CloudRole
	result := tx.Find(&roles, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get cloud roles from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get cloud roles from store")
	}

	return roles, nil
}

func (s *SqlStore) GetCloudRolesByCloudAccessID(ctx context.Context, lockStrength LockingStrength, accountID, cloudAccessID string) ([]*cloudAccessTypes.CloudRole, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var roles []*cloudAccessTypes.CloudRole
	result := tx.Find(&roles, "account_id = ? AND cloud_access_id = ?", accountID, cloudAccessID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get cloud roles by cloud access from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get cloud roles by cloud access from store")
	}

	return roles, nil
}

func (s *SqlStore) GetCloudRoleByID(ctx context.Context, lockStrength LockingStrength, accountID, roleID string) (*cloudAccessTypes.CloudRole, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var role *cloudAccessTypes.CloudRole
	result := tx.Take(&role, accountAndIDQueryCondition, accountID, roleID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewCloudRoleNotFoundError(roleID)
		}

		log.WithContext(ctx).Errorf("failed to get cloud role from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get cloud role from store")
	}

	return role, nil
}

func (s *SqlStore) SaveCloudRole(ctx context.Context, role *cloudAccessTypes.CloudRole) error {
	result := s.db.Save(role)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save cloud role to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save cloud role to store")
	}

	return nil
}

func (s *SqlStore) DeleteCloudRole(ctx context.Context, accountID, roleID string) error {
	result := s.db.Delete(&cloudAccessTypes.CloudRole{}, accountAndIDQueryCondition, accountID, roleID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete cloud role from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete cloud role from store")
	}

	if result.RowsAffected == 0 {
		return status.NewCloudRoleNotFoundError(roleID)
	}

	return nil
}
