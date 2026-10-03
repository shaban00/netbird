package types

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/util/crypt"
)

const signingKeyBits = 2048

func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, signingKeyBits)
}

type SigningKey struct {
	ID            string `gorm:"primaryKey"`
	PrivateKeyPEM string
	PublicKeyDER  []byte
	CreatedAt     time.Time
	RetireAt      *time.Time
}

func (SigningKey) TableName() string { return "cloud_federation_signing_keys" }

func GenerateSigningKey() (*SigningKey, *rsa.PrivateKey, error) {
	priv, err := generateRSAKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate rsa key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public key: %w", err)
	}

	key := &SigningKey{
		ID:            xid.New().String(),
		PrivateKeyPEM: string(privPEM),
		PublicKeyDER:  pubDER,
		CreatedAt:     time.Now().UTC(),
	}
	return key, priv, nil
}

func (k *SigningKey) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil || k.PrivateKeyPEM == "" {
		return nil
	}
	encrypted, err := enc.Encrypt(k.PrivateKeyPEM)
	if err != nil {
		return fmt.Errorf("encrypt signing key: %w", err)
	}
	k.PrivateKeyPEM = encrypted
	return nil
}

func (k *SigningKey) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil || k.PrivateKeyPEM == "" {
		return nil
	}
	decrypted, err := enc.Decrypt(k.PrivateKeyPEM)
	if err != nil {
		return fmt.Errorf("decrypt signing key: %w", err)
	}
	k.PrivateKeyPEM = decrypted
	return nil
}

func (k *SigningKey) ParsePrivateKey() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(k.PrivateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid signing key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not RSA")
	}
	return rsaKey, nil
}

func (k *SigningKey) ParsePublicKey() (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(k.PublicKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not RSA")
	}
	return rsaKey, nil
}
