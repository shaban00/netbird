package types

import (
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	ProviderAWS   = "aws"
	ProviderGCP   = "gcp"
	ProviderAzure = "azure"
)

type CloudAccessStatus string

const (
	CloudAccessStatusPending   CloudAccessStatus = "pending"
	CloudAccessStatusConnected CloudAccessStatus = "connected"
)

// CloudAccess is the trust connection between NetBird and the cloud provider account
type CloudAccess struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	Name      string
	Provider  string
	// ProviderAccountID: AWS Account ID / GCP Project Number / Azure Tenant ID
	ProviderAccountID string `gorm:"column:provider_account_id"`
	// ProviderProjectID is GCP only — the GCP Project ID string
	ProviderProjectID string `gorm:"column:provider_project_id"`
	Status            CloudAccessStatus

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (CloudAccess) TableName() string { return "cloud_access" }

func NewCloudAccess(accountID string) *CloudAccess {
	now := time.Now().UTC()
	return &CloudAccess{
		ID:        xid.New().String(),
		AccountID: accountID,
		Status:    CloudAccessStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func (a *CloudAccess) FromAPIRequest(req *api.CloudAccessRequest) {
	a.Name = req.Name
	a.Provider = req.Provider
	if req.ProviderAccountId != nil {
		a.ProviderAccountID = *req.ProviderAccountId
	}
	if req.ProviderProjectId != nil {
		a.ProviderProjectID = *req.ProviderProjectId
	}
}

// ToAPIResponse renders the API representation
func (a *CloudAccess) ToAPIResponse(status CloudAccessStatus) *api.CloudAccess {
	created := a.CreatedAt
	updated := a.UpdatedAt
	resp := &api.CloudAccess{
		Id:                a.ID,
		Name:              a.Name,
		Provider:          a.Provider,
		ProviderAccountId: &a.ProviderAccountID,
		Status:            api.CloudAccessStatus(status),
		CreatedAt:         &created,
		UpdatedAt:         &updated,
	}
	if a.ProviderProjectID != "" {
		resp.ProviderProjectId = &a.ProviderProjectID
	}
	return resp
}

// EventMeta is the audit-log payload for activity events.
func (a *CloudAccess) EventMeta() map[string]any {
	return map[string]any{
		"name":     a.Name,
		"provider": a.Provider,
	}
}
