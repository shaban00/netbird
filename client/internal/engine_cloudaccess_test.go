package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mgm "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestEngine_RequestCloudCredentials_RequiresIntegrationID(t *testing.T) {
	e := &Engine{mgmClient: &mgm.MockClient{}}
	_, err := e.RequestCloudCredentials("", "aws")
	require.Error(t, err)
}

func TestEngine_RequestCloudCredentials_RequiresInitializedManagementClient(t *testing.T) {
	e := &Engine{}
	_, err := e.RequestCloudCredentials("integration1", "aws")
	require.Error(t, err)
}

func TestEngine_RequestCloudCredentials_DelegatesToManagementClient(t *testing.T) {
	var capturedIntegrationID, capturedProvider string
	mock := &mgm.MockClient{
		RequestCloudCredentialsFunc: func(integrationID, provider string) (*mgmProto.CloudCredentialsResponse, error) {
			capturedIntegrationID = integrationID
			capturedProvider = provider
			return &mgmProto.CloudCredentialsResponse{
				Allowed:     true,
				Credentials: map[string]string{"AccessKeyId": "AKIA"},
			}, nil
		},
	}
	e := &Engine{mgmClient: mock}

	resp, err := e.RequestCloudCredentials("integration1", "aws")
	require.NoError(t, err)
	assert.Equal(t, "integration1", capturedIntegrationID)
	assert.Equal(t, "aws", capturedProvider)
	assert.True(t, resp.GetAllowed())
	assert.Equal(t, "AKIA", resp.GetCredentials()["AccessKeyId"])
}

func TestEngine_RequestCloudCredentials_PropagatesManagementError(t *testing.T) {
	mock := &mgm.MockClient{
		RequestCloudCredentialsFunc: func(string, string) (*mgmProto.CloudCredentialsResponse, error) {
			return nil, assert.AnError
		},
	}
	e := &Engine{mgmClient: mock}

	_, err := e.RequestCloudCredentials("integration1", "aws")
	require.Error(t, err)
}

func TestEngine_ListCloudIntegrations_RequiresInitializedManagementClient(t *testing.T) {
	e := &Engine{}
	_, err := e.ListCloudIntegrations()
	require.Error(t, err)
}

func TestEngine_ListCloudIntegrations_DelegatesToManagementClient(t *testing.T) {
	mock := &mgm.MockClient{
		ListCloudIntegrationsFunc: func() (*mgmProto.ListCloudIntegrationsResponse, error) {
			return &mgmProto.ListCloudIntegrationsResponse{
				Integrations: []*mgmProto.CloudIntegrationSummary{{Id: "integration1"}},
			}, nil
		},
	}
	e := &Engine{mgmClient: mock}

	resp, err := e.ListCloudIntegrations()
	require.NoError(t, err)
	assert.Len(t, resp.GetIntegrations(), 1)
	assert.Equal(t, "integration1", resp.GetIntegrations()[0].GetId())
}

func TestEngine_ListCloudIntegrations_PropagatesManagementError(t *testing.T) {
	mock := &mgm.MockClient{
		ListCloudIntegrationsFunc: func() (*mgmProto.ListCloudIntegrationsResponse, error) {
			return nil, assert.AnError
		},
	}
	e := &Engine{mgmClient: mock}

	_, err := e.ListCloudIntegrations()
	require.Error(t, err)
}
