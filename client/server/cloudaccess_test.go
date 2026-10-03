package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

func TestGetCloudCredentials_RequiresInitializedClient(t *testing.T) {
	s := newTestServer()

	_, err := s.GetCloudCredentials(context.Background(), &proto.GetCloudCredentialsRequest{
		IntegrationId: "integration1",
	})
	require.Error(t, err)
}

func TestGetCloudCredentials_RequiresStartedEngine(t *testing.T) {
	s := newTestServer()
	s.connectClient = newDummyConnectClient(context.Background())

	_, err := s.GetCloudCredentials(context.Background(), &proto.GetCloudCredentialsRequest{
		IntegrationId: "integration1",
	})
	require.Error(t, err)
}

func TestGetCloudCredentials_RequiresIntegrationID(t *testing.T) {
	s := newTestServer()
	s.connectClient = newDummyConnectClient(context.Background())

	_, err := s.GetCloudCredentials(context.Background(), &proto.GetCloudCredentialsRequest{})
	require.Error(t, err)
}

func TestListCloudIntegrations_RequiresInitializedClient(t *testing.T) {
	s := newTestServer()

	_, err := s.ListCloudIntegrations(context.Background(), &proto.ListCloudIntegrationsRequest{})
	require.Error(t, err)
}

func TestListCloudIntegrations_RequiresStartedEngine(t *testing.T) {
	s := newTestServer()
	s.connectClient = newDummyConnectClient(context.Background())

	_, err := s.ListCloudIntegrations(context.Background(), &proto.ListCloudIntegrationsRequest{})
	require.Error(t, err)
}
