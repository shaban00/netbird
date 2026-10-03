package internal

import (
	"errors"
	"fmt"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// RequestCloudCredentials requests short-lived credentials for the given
// integration from Management. provider is "aws", "gcp", or "azure".
func (e *Engine) RequestCloudCredentials(integrationID, provider string) (*mgmProto.CloudCredentialsResponse, error) {
	if integrationID == "" {
		return nil, errors.New("integration id is required")
	}
	if e.mgmClient == nil {
		return nil, errors.New("management client is not initialised")
	}

	resp, err := e.mgmClient.RequestCloudCredentials(integrationID, provider)
	if err != nil {
		return nil, fmt.Errorf("request cloud credentials from management: %w", err)
	}
	return resp, nil
}

// ListCloudIntegrations returns the peer's authorized cloud integrations.
func (e *Engine) ListCloudIntegrations() (*mgmProto.ListCloudIntegrationsResponse, error) {
	if e.mgmClient == nil {
		return nil, errors.New("management client is not initialised")
	}

	resp, err := e.mgmClient.ListCloudIntegrations()
	if err != nil {
		return nil, fmt.Errorf("list cloud integrations from management: %w", err)
	}
	return resp, nil
}
