package cloudauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	cloudaccesstypes "github.com/netbirdio/netbird/management/internals/modules/cloudaccess/types"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/cloudidentity"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const testPeerPubKey = "peer-pubkey-1"

type fakeProvider struct {
	name      string
	result    *cloudidentity.ExchangeIdentityResult
	err       error
	lastReq   cloudidentity.ExchangeIdentityRequest
	callCount int
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) ExchangeIdentity(_ context.Context, req cloudidentity.ExchangeIdentityRequest) (*cloudidentity.ExchangeIdentityResult, error) {
	f.lastReq = req
	f.callCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

type fakeRawAssertionProvider struct {
	name              string
	result            *cloudidentity.RawAssertionResult
	err               error
	lastReq           cloudidentity.ExchangeIdentityRequest
	callCount         int
	exchangeCallCount int
}

func (f *fakeRawAssertionProvider) Name() string { return f.name }
func (f *fakeRawAssertionProvider) ExchangeIdentity(_ context.Context, _ cloudidentity.ExchangeIdentityRequest) (*cloudidentity.ExchangeIdentityResult, error) {
	f.exchangeCallCount++
	return nil, errors.New("ExchangeIdentity must never be called on the raw-assertion path")
}
func (f *fakeRawAssertionProvider) IssueRawAssertion(_ context.Context, req cloudidentity.ExchangeIdentityRequest) (*cloudidentity.RawAssertionResult, error) {
	f.lastReq = req
	f.callCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func setupBrokerMocks(t *testing.T) (*gomock.Controller, *store.MockStore, *account.MockManager) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)
	mockAccount := account.NewMockManager(ctrl)
	mockAccount.EXPECT().StoreEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	return ctrl, mockStore, mockAccount
}

func TestCredentialBroker_AllowedRequestReturnsCredentials(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS, result: &cloudidentity.ExchangeIdentityResult{
		Credentials: map[string]string{"AccessKeyId": "AKIA"},
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.True(t, outcome.Allowed)
	require.NotNil(t, outcome.Result)
	assert.Equal(t, "AKIA", outcome.Result.Credentials["AccessKeyId"])
	assert.Equal(t, 1, provider.callCount)
	assert.Equal(t, testUserID, provider.lastReq.PrincipalID, "provider must receive the stable NetBird principal ID, not anything client-supplied")
}

func TestCredentialBroker_AuditEventsCarryRoleNameAndProvider(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)
	mockAccount := account.NewMockManager(ctrl)

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	var recordedMeta []map[string]any
	mockAccount.EXPECT().StoreEvent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Times(3). // CloudCredentialRequested, CloudAccessAllowed, CloudCredentialsIssued
		Do(func(_ context.Context, _, _, _ string, _ any, meta map[string]any) {
			snapshot := make(map[string]any, len(meta))
			for k, v := range meta {
				snapshot[k] = v
			}
			recordedMeta = append(recordedMeta, snapshot)
		})

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS, result: &cloudidentity.ExchangeIdentityResult{
		Credentials: map[string]string{"AccessKeyId": "AKIA"},
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	require.True(t, outcome.Allowed)
	require.Len(t, recordedMeta, 3)

	for _, meta := range recordedMeta {
		assert.Equal(t, testRoleID, meta["integration_id"])
		assert.Equal(t, cloudaccesstypes.ProviderAWS, meta["provider"])
		assert.Equal(t, "Developer", meta["name"])
	}
}

func TestCredentialBroker_RequestedEventDegradesGracefullyWhenRoleUnresolvable(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).
		Return(nil, errors.New("not found")).Times(2)

	broker := NewCredentialBroker(mockStore, mockAccount, nil)
	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, "")
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
	assert.Equal(t, "cloud role not found", outcome.DenyReason)
}

func TestCredentialBroker_DeniedRequestNeverCallsProvider(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{"not-the-allowed-group"}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
	assert.Nil(t, outcome.Result)
	assert.Equal(t, 0, provider.callCount, "provider must never be called on a DENY decision")
}

func TestCredentialBroker_UnrecognizedPeerDeniedBeforeAnyLookup(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), "unknown-pubkey").
		Return(nil, errors.New("not found"))

	broker := NewCredentialBroker(mockStore, mockAccount, nil)
	outcome, err := broker.RequestCredentials(context.Background(), "unknown-pubkey", "any-integration", "")
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
}

func TestCredentialBroker_ProviderFailureIsReportedAsGenericDenial(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(3)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).Return(nil)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS, err: errors.New("AWS STS rejected the assertion: AccessDenied")}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
	assert.NotContains(t, outcome.DenyReason, "AccessDenied", "the real AWS error detail must never reach the caller")
}

func TestCredentialBroker_ProviderFailureMarksRoleAsError(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(3)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	var saved *cloudaccesstypes.CloudRole
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, role *cloudaccesstypes.CloudRole) error {
			saved = role
			return nil
		},
	)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS, err: errors.New("AWS STS rejected the assertion: AccessDenied")}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
	require.NotNil(t, saved, "the role must be persisted with its new status")
	assert.Equal(t, cloudaccesstypes.StatusError, saved.Status)
}

func TestCredentialBroker_ProviderFailureSkipsWriteWhenAlreadyError(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	alreadyErrored := testRole()
	alreadyErrored.Status = cloudaccesstypes.StatusError

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(alreadyErrored, nil).Times(3)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS, err: errors.New("AWS STS rejected the assertion: AccessDenied")}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
}

func TestCredentialBroker_NoProviderRegisteredIsDeniedNotErrored(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{}) // no "aws" entry
	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
}

func TestCredentialBroker_ProviderMismatchDeniedBeforeExchange(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	gcpAccess := testCloudAccess()
	gcpAccess.Provider = cloudaccesstypes.ProviderGCP

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(gcpAccess, nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderGCP}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderGCP: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
	assert.Nil(t, outcome.Result)
	assert.Equal(t, "requested provider does not match this role's configured provider", outcome.DenyReason)
	assert.NotContains(t, outcome.DenyReason, cloudaccesstypes.ProviderGCP, "the role's actual provider must never be disclosed in the deny reason")
	assert.Equal(t, 0, provider.callCount, "provider must never be dispatched to on a provider mismatch")
}

func TestCredentialBroker_EmptyExpectedProviderSkipsMismatchCheck(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS, result: &cloudidentity.ExchangeIdentityResult{
		Credentials: map[string]string{"AccessKeyId": "AKIA"},
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, "")
	require.NoError(t, err)
	assert.True(t, outcome.Allowed)
	assert.Equal(t, 1, provider.callCount)
}

func TestCredentialBroker_MatchingExpectedProviderStillSucceeds(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(testCloudAccess(), nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	provider := &fakeProvider{name: cloudaccesstypes.ProviderAWS, result: &cloudidentity.ExchangeIdentityResult{
		Credentials: map[string]string{"AccessKeyId": "AKIA"},
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	}}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderAWS: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderAWS)
	require.NoError(t, err)
	assert.True(t, outcome.Allowed)
	assert.Equal(t, 1, provider.callCount)
}

func TestCredentialBroker_RawAssertionProviderSkipsFullExchange(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	gcpAccess := testCloudAccess()
	gcpAccess.Provider = cloudaccesstypes.ProviderGCP

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(2)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(gcpAccess, nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	expiresAt := time.Now().Add(60 * time.Second)
	provider := &fakeRawAssertionProvider{
		name: cloudaccesstypes.ProviderGCP,
		result: &cloudidentity.RawAssertionResult{
			Assertion: "fake.raw.assertion",
			ExpiresAt: expiresAt,
		},
	}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderGCP: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderGCP)
	require.NoError(t, err)
	assert.True(t, outcome.Allowed)
	require.NotNil(t, outcome.Result)
	assert.Equal(t, "fake.raw.assertion", outcome.Result.Credentials["id_token"])
	assert.Equal(t, expiresAt, outcome.Result.ExpiresAt)
	assert.Equal(t, 1, provider.callCount)
	assert.Equal(t, 0, provider.exchangeCallCount, "the full-exchange path must never be called when a raw-assertion path is available")
	assert.Equal(t, testUserID, provider.lastReq.PrincipalID, "provider must receive the stable NetBird principal ID, not anything client-supplied")
}

func TestCredentialBroker_RawAssertionFailureMarksRoleAsError(t *testing.T) {
	ctrl, mockStore, mockAccount := setupBrokerMocks(t)
	defer ctrl.Finish()

	gcpAccess := testCloudAccess()
	gcpAccess.Provider = cloudaccesstypes.ProviderGCP

	mockStore.EXPECT().GetPeerByPeerPubKey(gomock.Any(), gomock.Any(), testPeerPubKey).Return(testPeer(), nil)
	mockStore.EXPECT().GetCloudRoleByID(gomock.Any(), gomock.Any(), testAccountID, testRoleID).Return(testRole(), nil).Times(3)
	mockStore.EXPECT().GetCloudAccessByID(gomock.Any(), gomock.Any(), testAccountID, testAccessID).Return(gcpAccess, nil).Times(2)
	mockStore.EXPECT().GetPeerByID(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return(testPeer(), nil)
	mockStore.EXPECT().GetPeerGroupIDs(gomock.Any(), gomock.Any(), testAccountID, testPeerID).Return([]string{testGroupID}, nil)
	mockStore.EXPECT().GetAccountPolicies(gomock.Any(), gomock.Any(), testAccountID).Return([]*types.Policy{{
		ID: "policy1", Enabled: true, Rules: []*types.PolicyRule{allowRule()},
	}}, nil)

	var saved *cloudaccesstypes.CloudRole
	mockStore.EXPECT().SaveCloudRole(gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, role *cloudaccesstypes.CloudRole) error {
			saved = role
			return nil
		},
	)

	provider := &fakeRawAssertionProvider{name: cloudaccesstypes.ProviderGCP, err: errors.New("issuer not enabled")}
	broker := NewCredentialBroker(mockStore, mockAccount, map[string]cloudidentity.Provider{cloudaccesstypes.ProviderGCP: provider})

	outcome, err := broker.RequestCredentials(context.Background(), testPeerPubKey, testRoleID, cloudaccesstypes.ProviderGCP)
	require.NoError(t, err)
	assert.False(t, outcome.Allowed)
	assert.NotContains(t, outcome.DenyReason, "issuer not enabled", "the real error detail must never reach the caller")
	require.NotNil(t, saved, "the role must be persisted with its new status")
	assert.Equal(t, cloudaccesstypes.StatusError, saved.Status)
}
