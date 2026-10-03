package server

import (
	"context"
	"errors"

	"github.com/netbirdio/netbird/client/proto"
)

// GetCloudCredentials requests short-lived credentials for a cloud integration. Management authorizes every call
func (s *Server) GetCloudCredentials(
	ctx context.Context,
	req *proto.GetCloudCredentialsRequest,
) (*proto.GetCloudCredentialsResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	integrationID := req.GetIntegrationId()
	if integrationID == "" {
		return nil, errors.New("integration_id is required")
	}

	s.mutex.Lock()
	connectClient := s.connectClient
	s.mutex.Unlock()

	if connectClient == nil {
		return nil, errors.New("client not initialized")
	}

	engine := connectClient.Engine()
	if engine == nil {
		return nil, errors.New("engine not started")
	}

	resp, err := engine.RequestCloudCredentials(integrationID, req.GetProvider())
	if err != nil {
		return nil, err
	}

	return &proto.GetCloudCredentialsResponse{
		Allowed:          resp.GetAllowed(),
		DenyReason:       resp.GetDenyReason(),
		Credentials:      resp.GetCredentials(),
		ExpiresAt:        resp.GetExpiresAt(),
		ProviderIdentity: resp.GetProviderIdentity(),
	}, nil
}

// ListCloudIntegrations returns the peer's authorized cloud integrations
func (s *Server) ListCloudIntegrations(
	ctx context.Context,
	_ *proto.ListCloudIntegrationsRequest,
) (*proto.ListCloudIntegrationsResponse, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	s.mutex.Lock()
	connectClient := s.connectClient
	s.mutex.Unlock()

	if connectClient == nil {
		return nil, errors.New("client not initialized")
	}

	engine := connectClient.Engine()
	if engine == nil {
		return nil, errors.New("engine not started")
	}

	resp, err := engine.ListCloudIntegrations()
	if err != nil {
		return nil, err
	}

	out := &proto.ListCloudIntegrationsResponse{}
	for _, in := range resp.GetIntegrations() {
		out.Integrations = append(out.Integrations, &proto.CloudIntegrationSummary{
			Id:                        in.GetId(),
			Name:                      in.GetName(),
			Provider:                  in.GetProvider(),
			ProviderAccountId:         in.GetProviderAccountId(),
			PrincipalName:             in.GetPrincipalName(),
			CredentialLifetimeSeconds: in.GetCredentialLifetimeSeconds(),
		})
	}
	return out, nil
}
