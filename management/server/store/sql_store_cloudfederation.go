package store

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	issuerTypes "github.com/netbirdio/netbird/management/server/cloudfederation/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) GetActiveCloudFederationSigningKey(ctx context.Context, lockStrength LockingStrength) (*issuerTypes.SigningKey, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var key issuerTypes.SigningKey
	result := tx.Take(&key, "retire_at IS NULL")
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "cloud federation signing key not found")
		}
		log.WithContext(ctx).Errorf("failed to get active cloud federation signing key from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get active cloud federation signing key from store")
	}

	if err := key.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to decrypt cloud federation signing key: %v", err)
		return nil, status.Errorf(status.Internal, "failed to decrypt cloud federation signing key")
	}

	return &key, nil
}

func (s *SqlStore) GetCloudFederationJWKSKeys(ctx context.Context) ([]*issuerTypes.SigningKey, error) {
	var keys []*issuerTypes.SigningKey
	result := s.db.Find(&keys, "retire_at IS NULL OR retire_at > ?", time.Now().UTC())
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get cloud federation JWKS keys from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get cloud federation JWKS keys from store")
	}
	return keys, nil
}

func (s *SqlStore) SaveCloudFederationSigningKey(ctx context.Context, key *issuerTypes.SigningKey) error {
	keyCopy := *key
	if err := keyCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		log.WithContext(ctx).Errorf("failed to encrypt cloud federation signing key: %v", err)
		return status.Errorf(status.Internal, "failed to encrypt cloud federation signing key")
	}

	result := s.db.Save(&keyCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save cloud federation signing key to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save cloud federation signing key to store")
	}

	return nil
}
