package types

import (
	"fmt"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// MinCredentialLifetimeSecondsAWS is AWS STS's hard floor for
// AssumeRoleWithWebIdentity's DurationSeconds (15 minutes).
const MinCredentialLifetimeSecondsAWS = 900

// MinCredentialLifetimeSecondsGCP is GCP's hard floor for
// service_account_impersonation.token_lifetime_seconds (10 minutes).
const MinCredentialLifetimeSecondsGCP = 600

// MaxCredentialLifetimeSeconds caps credential lifetime well below provider
// limits so access stays subject to NetBird policy.
const MaxCredentialLifetimeSeconds = 3600

// credentialLifetimeFloors omits Azure: Entra's token endpoint has no
// per-request lifetime parameter (only tenant-side policies).
var credentialLifetimeFloors = map[string]int64{
	ProviderAWS: MinCredentialLifetimeSecondsAWS,
	ProviderGCP: MinCredentialLifetimeSecondsGCP,
}

type Status string

const (
	StatusPending   Status = "pending"
	StatusConnected Status = "connected"
	StatusError     Status = "error"
)

// CloudRole is one IAM role (or equivalent principal) under a CloudAccess
// connection. ProviderAccountID lives only on the parent CloudAccess, never
// denormalized here.
type CloudRole struct {
	ID            string `gorm:"primaryKey"`
	AccountID     string `gorm:"index"`
	CloudAccessID string `gorm:"index"`
	Name          string

	// PrincipalName is the AWS role name, GCP service account email, or Azure application (client) ID
	PrincipalName string `gorm:"column:principal_name"`

	// SetupMode is "create" or "import", set once at creation. It only picks the default CLI command in the deploy walkthrough
	SetupMode string `gorm:"column:setup_mode"`

	// CredentialLifetimeSeconds is clamped by ClampCredentialLifetime
	CredentialLifetimeSeconds int64

	Status          Status
	LastValidatedAt *time.Time

	CreatedAt time.Time
	UpdatedAt time.Time
}

func (CloudRole) TableName() string { return "cloud_roles" }

func NewCloudRole(accountID, cloudAccessID string) *CloudRole {
	now := time.Now().UTC()
	return &CloudRole{
		ID:            xid.New().String(),
		AccountID:     accountID,
		CloudAccessID: cloudAccessID,
		Status:        StatusPending,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// ClampCredentialLifetime bounds seconds into [floor(provider), MaxCredentialLifetimeSeconds]
func ClampCredentialLifetime(seconds int64, provider string) int64 {
	floor, ok := credentialLifetimeFloors[provider]
	if !ok {
		floor = MinCredentialLifetimeSecondsAWS
	}
	if seconds <= 0 {
		return floor
	}
	if seconds < floor {
		return floor
	}
	if seconds > MaxCredentialLifetimeSeconds {
		return MaxCredentialLifetimeSeconds
	}
	return seconds
}

func (r *CloudRole) FromAPIRequest(req *api.CloudRoleRequest) {
	r.Name = req.Name
	if req.PrincipalName != nil {
		r.PrincipalName = *req.PrincipalName
	}
	if req.CredentialLifetimeSeconds != nil {
		r.CredentialLifetimeSeconds = int64(*req.CredentialLifetimeSeconds)
	}
	if req.SetupMode != nil {
		r.SetupMode = string(*req.SetupMode)
	}
}

// PrincipalRef returns the full principal reference: an IAM role ARN for AWS,
// or PrincipalName as-is for GCP and Azure.
func (r *CloudRole) PrincipalRef(providerAccountID, provider string) string {
	if provider == ProviderGCP || provider == ProviderAzure {
		return r.PrincipalName
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", providerAccountID, r.PrincipalName)
}

// ToAPIResponse renders the API representation
func (r *CloudRole) ToAPIResponse(providerAccountID, provider string) *api.CloudRole {
	created := r.CreatedAt
	updated := r.UpdatedAt
	ref := r.PrincipalRef(providerAccountID, provider)
	resp := &api.CloudRole{
		Id:                        r.ID,
		CloudAccessId:             r.CloudAccessID,
		Name:                      r.Name,
		PrincipalName:             &r.PrincipalName,
		PrincipalRef:              &ref,
		CredentialLifetimeSeconds: intPtr(int(r.CredentialLifetimeSeconds)),
		Status:                    api.CloudRoleStatus(r.Status),
		CreatedAt:                 &created,
		UpdatedAt:                 &updated,
	}
	if r.LastValidatedAt != nil {
		resp.LastValidatedAt = r.LastValidatedAt
	}
	if r.SetupMode != "" {
		mode := api.CloudRoleSetupMode(r.SetupMode)
		resp.SetupMode = &mode
	}
	return resp
}

// EventMeta is the audit-log payload for activity events.
func (r *CloudRole) EventMeta(provider string) map[string]any {
	return map[string]any{
		"name":     r.Name,
		"provider": provider,
	}
}

func intPtr(v int) *int { return &v }
