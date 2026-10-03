package cmd

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/proto"
)

func testStdin(s string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(s))
}

func TestAWSCredentialProcessJSON_Allowed(t *testing.T) {
	expiry := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	resp := &proto.GetCloudCredentialsResponse{
		Allowed: true,
		Credentials: map[string]string{
			"AccessKeyId":     "AKIAFAKE",
			"SecretAccessKey": "secret",
			"SessionToken":    "token",
		},
		ExpiresAt: timestamppb.New(expiry),
	}

	encoded, err := awsCredentialProcessJSON(resp)
	require.NoError(t, err)

	var out map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(encoded), &out))
	assert.EqualValues(t, 1, out["Version"])
	assert.Equal(t, "AKIAFAKE", out["AccessKeyId"])
	assert.Equal(t, "secret", out["SecretAccessKey"])
	assert.Equal(t, "token", out["SessionToken"])
	assert.Equal(t, "2026-01-01T12:00:00Z", out["Expiration"])
}

func TestAWSCredentialProcessJSON_DeniedProducesErrorNotJSON(t *testing.T) {
	resp := &proto.GetCloudCredentialsResponse{
		Allowed:    false,
		DenyReason: "no enabled policy grants this peer access",
	}

	encoded, err := awsCredentialProcessJSON(resp)
	require.Error(t, err)
	assert.Empty(t, encoded)
	assert.Contains(t, err.Error(), "no enabled policy grants this peer access")
}

func TestAWSCredentialProcessJSON_DeniedWithEmptyReasonStillErrors(t *testing.T) {
	resp := &proto.GetCloudCredentialsResponse{Allowed: false}

	encoded, err := awsCredentialProcessJSON(resp)
	require.Error(t, err)
	assert.Empty(t, encoded)
}

func testIntegrations() []*proto.CloudIntegrationSummary {
	return []*proto.CloudIntegrationSummary{
		{Id: "clin_a", Name: "Production", Provider: "aws"},
		{Id: "clin_b", Name: "Staging", Provider: "aws"},
	}
}

func TestSelectCloudIntegration_EmptyListIsADenialNotAPanic(t *testing.T) {
	_, err := selectCloudIntegration(nil, "", testStdin(""), &strings.Builder{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not currently authorized for any cloud access")
}

func TestSelectCloudIntegration_SingleIsAutoSelectedWithoutPrompting(t *testing.T) {
	integrations := testIntegrations()[:1]
	out := &strings.Builder{}

	got, err := selectCloudIntegration(integrations, "", testStdin(""), out, nil)
	require.NoError(t, err)
	assert.Equal(t, "clin_a", got.GetId())
	assert.Empty(t, out.String(), "a single authorized integration must never prompt")
}

func TestSelectCloudIntegration_ExplicitIDMustBeAmongAuthorized(t *testing.T) {
	integrations := testIntegrations()

	got, err := selectCloudIntegration(integrations, "clin_b", testStdin(""), &strings.Builder{}, nil)
	require.NoError(t, err)
	assert.Equal(t, "clin_b", got.GetId())

	_, err = selectCloudIntegration(integrations, "clin_not_authorized", testStdin(""), &strings.Builder{}, nil)
	require.Error(t, err, "an ID the peer isn't actually authorized for must be rejected, not trusted")
}

func TestSelectCloudIntegration_PromptsAndReadsChoiceWhenMultiple(t *testing.T) {
	integrations := testIntegrations()
	out := &strings.Builder{}

	got, err := selectCloudIntegration(integrations, "", testStdin("2\n"), out, nil)
	require.NoError(t, err)
	assert.Equal(t, "clin_b", got.GetId())
	assert.Contains(t, out.String(), "Production")
	assert.Contains(t, out.String(), "Staging")
}

func TestSelectCloudIntegration_RendersNameAndActiveColumns(t *testing.T) {
	integrations := testIntegrations()
	out := &strings.Builder{}
	configured := map[string][]string{"clin_a": {"netbird-production", "default"}}

	got, err := selectCloudIntegration(integrations, "", testStdin("2\n"), out, configured)
	require.NoError(t, err)
	assert.Equal(t, "clin_b", got.GetId())

	printed := out.String()
	assert.Contains(t, printed, "NAME")
	assert.Contains(t, printed, "ACTIVE")
	assert.Regexp(t, `(?m)^1\)\s+Production\s+\*\s*$`, printed)
	assert.Regexp(t, `(?m)^2\)\s+Staging\s*$`, printed)
	assert.NotContains(t, printed, "configured as")
	assert.NotContains(t, printed, "default")
}

func TestSelectCloudIntegration_InvalidChoiceErrors(t *testing.T) {
	integrations := testIntegrations()

	_, err := selectCloudIntegration(integrations, "", testStdin("99\n"), &strings.Builder{}, nil)
	require.Error(t, err)

	_, err = selectCloudIntegration(integrations, "", testStdin("not-a-number\n"), &strings.Builder{}, nil)
	require.Error(t, err)
}

func TestDefaultAWSProfileName(t *testing.T) {
	cases := []struct {
		name           string
		netbirdProfile string
		in             *proto.CloudIntegrationSummary
		expected       string
	}{
		{"simple", "work", &proto.CloudIntegrationSummary{Name: "Production", Id: "clin_a"}, "netbird-work-production"},
		{"strips punctuation and spaces from both segments", "My Work!", &proto.CloudIntegrationSummary{Name: "Prod (AWS) #1!", Id: "clin_a"}, "netbird-my-work-prod-aws-1"},
		{"empty integration name falls back to ID", "work", &proto.CloudIntegrationSummary{Name: "***", Id: "clin_a"}, "netbird-work-clin_a"},
		{"empty netbird profile omits that segment entirely", "", &proto.CloudIntegrationSummary{Name: "Production", Id: "clin_a"}, "netbird-production"},
		{"netbird profile that sanitizes to empty also omits the segment", "***", &proto.CloudIntegrationSummary{Name: "Production", Id: "clin_a"}, "netbird-production"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, defaultAWSProfileName(tc.netbirdProfile, tc.in))
		})
	}
}

func TestDefaultAWSProfileName_DifferentNetBirdProfilesNeverCollide(t *testing.T) {
	integration := &proto.CloudIntegrationSummary{Name: "Developer", Id: "clin_a"}
	workName := defaultAWSProfileName("work", integration)
	personalName := defaultAWSProfileName("personal", integration)
	assert.NotEqual(t, workName, personalName)
}

func TestUpsertAWSConfigProfile_CreatesFileAndProfileWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aws", "config")

	require.NoError(t, upsertAWSConfigProfile(path, "netbird-production", "clin_a", ""))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Contains(t, body, "[profile netbird-production]")
	assert.Contains(t, body, "credential_process = netbird aws credentials clin_a")
}

func TestUpsertAWSConfigProfile_UsesDefaultSectionForReservedName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	require.NoError(t, upsertAWSConfigProfile(path, "default", "clin_a", ""))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Contains(t, body, "[default]")
	assert.NotContains(t, body, "[profile default]", "the reserved default profile must use [default], not [profile default] — AWS CLI treats them as different sections")
}

func TestUpsertAWSConfigProfile_PreservesOtherProfilesAndKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := "[default]\nregion = us-west-2\n\n[profile other]\nregion = eu-central-1\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, upsertAWSConfigProfile(path, "netbird-production", "clin_a", ""))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Contains(t, body, "[default]\nregion = us-west-2", "an unrelated existing section must survive untouched")
	assert.Contains(t, body, "[profile other]\nregion = eu-central-1", "an unrelated existing profile must survive untouched")
	assert.Contains(t, body, "[profile netbird-production]")
	assert.Contains(t, body, "credential_process = netbird aws credentials clin_a")
}

func TestUpsertAWSConfigProfile_UpdatesExistingProfileInPlaceWithoutDuplicating(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := "[profile netbird-production]\nregion = us-east-1\ncredential_process = netbird aws credentials clin_old\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, upsertAWSConfigProfile(path, "netbird-production", "clin_new", ""))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Equal(t, 1, strings.Count(body, "[profile netbird-production]"))
	assert.Contains(t, body, "region = us-east-1")
	assert.Contains(t, body, "credential_process = netbird aws credentials clin_new")
	assert.NotContains(t, body, "clin_old")
}

func TestUpsertAWSConfigProfile_HandlesLeadingUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	bom := "\xEF\xBB\xBF"
	initial := bom + "[profile netbird-production]\ncredential_process = netbird aws credentials clin_old\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, upsertAWSConfigProfile(path, "netbird-production", "clin_new", ""))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Equal(t, 1, strings.Count(body, "[profile netbird-production]"))
	assert.Contains(t, body, "credential_process = netbird aws credentials clin_new")
	assert.NotContains(t, body, "clin_old")
}

func TestConfiguredAWSProfileNames_HandlesLeadingUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	bom := "\xEF\xBB\xBF"
	initial := bom + "[profile netbird-production]\ncredential_process = netbird aws credentials clin_a\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	configured, err := configuredAWSProfileNames(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"netbird-production"}, configured["clin_a"])
}

func TestUpsertAWSConfigProfile_SetsRegionOnANewProfileWhenGiven(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	require.NoError(t, upsertAWSConfigProfile(path, "netbird-production", "clin_a", "us-east-1"))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Contains(t, body, "[profile netbird-production]")
	assert.Contains(t, body, "credential_process = netbird aws credentials clin_a")
	assert.Contains(t, body, "region = us-east-1")
}

func TestUpsertAWSConfigProfile_AppendsNewKeyBeforeTrailingBlankLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := "[profile netbird-lil-developer]\n" +
		"credential_process = netbird aws credentials clin_other\n\n" +
		"[default]\n" +
		"credential_process = netbird aws credentials clin_a\n\n" +
		"[profile netbird-developer]\n" +
		"credential_process = netbird aws credentials clin_b\n" +
		"region = us-east-2\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, upsertAWSConfigProfile(path, "default", "clin_a", "us-east-2"))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)

	assert.Contains(t, body,
		"[default]\ncredential_process = netbird aws credentials clin_a\nregion = us-east-2\n\n[profile netbird-developer]",
	)
}

func TestUpsertAWSConfigProfile_NeverInventsARegionWhenNotGiven(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := "[profile netbird-production]\nregion = eu-west-1\ncredential_process = netbird aws credentials clin_old\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, upsertAWSConfigProfile(path, "netbird-production", "clin_new", ""))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Contains(t, body, "region = eu-west-1")
	assert.Contains(t, body, "credential_process = netbird aws credentials clin_new")

	dir2 := t.TempDir()
	path2 := filepath.Join(dir2, "config")
	require.NoError(t, upsertAWSConfigProfile(path2, "netbird-production", "clin_a", ""))
	content2, err := os.ReadFile(path2)
	require.NoError(t, err)
	assert.NotContains(t, string(content2), "region")
}

func TestUpsertAWSConfigProfile_UpdatesExistingRegionInPlaceWithoutDuplicating(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := "[profile netbird-production]\nregion = us-west-2\ncredential_process = netbird aws credentials clin_a\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, upsertAWSConfigProfile(path, "netbird-production", "clin_a", "ap-southeast-1"))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Equal(t, 1, strings.Count(body, "region ="))
	assert.Contains(t, body, "region = ap-southeast-1")
	assert.NotContains(t, body, "us-west-2")
}

func authorizedList(ids ...string) []*proto.CloudIntegrationSummary {
	out := make([]*proto.CloudIntegrationSummary, len(ids))
	for i, id := range ids {
		out[i] = &proto.CloudIntegrationSummary{Id: id}
	}
	return out
}

func TestPruneNetBirdManagedAWSProfiles_Scenarios(t *testing.T) {
	cases := []struct {
		name           string
		initial        string
		authorized     []string
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:           "removes unauthorized NetBird-managed profile",
			initial:        "[profile netbird-work-developer]\ncredential_process = netbird aws credentials clin_work_dev\n",
			authorized:     []string{"clin_personal_dev"},
			mustNotContain: []string{"netbird-work-developer", "clin_work_dev"},
		},
		{
			name:        "keeps authorized NetBird-managed profile",
			initial:     "[profile netbird-work-developer]\ncredential_process = netbird aws credentials clin_work_dev\n",
			authorized:  []string{"clin_work_dev"},
			mustContain: []string{"netbird-work-developer", "clin_work_dev"},
		},
		{
			name:        "never touches a non-NetBird-managed profile",
			initial:     "[profile netbird-work-developer]\nregion = us-east-1\n\n[profile totally-unrelated]\ncredential_process = some-other-tool --whatever\n",
			authorized:  nil,
			mustContain: []string{"[profile netbird-work-developer]", "[profile totally-unrelated]"},
		},
		{
			name:        "never touches [default]",
			initial:     "[default]\ncredential_process = netbird aws credentials clin_stale\n",
			authorized:  nil,
			mustContain: []string{"[default]", "clin_stale"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			require.NoError(t, os.WriteFile(path, []byte(tc.initial), 0600))

			require.NoError(t, pruneNetBirdManagedAWSProfiles(path, authorizedList(tc.authorized...)))

			content, err := os.ReadFile(path)
			require.NoError(t, err)
			body := string(content)
			for _, s := range tc.mustContain {
				assert.Contains(t, body, s)
			}
			for _, s := range tc.mustNotContain {
				assert.NotContains(t, body, s)
			}
		})
	}
}

func TestPruneNetBirdManagedAWSProfiles_PreservesSurroundingProfilesAndOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := "[profile alpha]\nregion = us-east-1\n\n" +
		"[profile netbird-work-developer]\ncredential_process = netbird aws credentials clin_work_dev\n\n" +
		"[profile zeta]\nregion = eu-west-1\n\n" +
		"[default]\ncredential_process = netbird aws credentials clin_work_dev\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, pruneNetBirdManagedAWSProfiles(path, authorizedList())) // clin_work_dev no longer authorized

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.Contains(t, body, "[profile alpha]\nregion = us-east-1")
	assert.Contains(t, body, "[profile zeta]\nregion = eu-west-1")
	assert.Contains(t, body, "[default]\ncredential_process = netbird aws credentials clin_work_dev", "[default] must survive even referencing the same now-unauthorized role")
	assert.NotContains(t, body, "netbird-work-developer")
	assert.True(t, strings.Index(body, "[profile alpha]") < strings.Index(body, "[profile zeta]"), "surrounding sections must keep their relative order")
}

func TestPruneNetBirdManagedAWSProfiles_NoOpWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	assert.NoError(t, pruneNetBirdManagedAWSProfiles(path, authorizedList("clin_a")))
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "pruning a nonexistent file must not create one")
}

func TestNetBirdCredentialProcessLine(t *testing.T) {
	m := netbirdCredentialProcessLine.FindStringSubmatch("credential_process = netbird aws credentials clin_a")
	require.NotNil(t, m, "current positional form must match")
	assert.Equal(t, "clin_a", m[1])
}

func TestPruneOwnAWSProfileOnDenial_RemovesDefaultToo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	t.Setenv("AWS_CONFIG_FILE", path)
	initial := "[default]\ncredential_process = netbird aws credentials clin_revoked\n\n" +
		"[profile netbird-work-developer]\ncredential_process = netbird aws credentials clin_revoked\n\n" +
		"[profile netbird-work-other]\ncredential_process = netbird aws credentials clin_still_good\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	require.NoError(t, pruneAWSProfileOnDenial("clin_revoked"))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(content)
	assert.NotContains(t, body, "clin_revoked")
	assert.Contains(t, body, "netbird-work-other")
	assert.Contains(t, body, "clin_still_good")
}

func TestDefaultProfileIsForeign(t *testing.T) {
	cases := []struct {
		name     string
		content  string // empty means the file is never written
		expected bool
	}{
		{"false when no default section", "[profile other]\nregion = us-east-1\n", false},
		{"false when file missing entirely", "", false},
		{"false when already NetBird-managed", "[default]\ncredential_process = netbird aws credentials clin_a\n", false},
		{"true: region only, no credential_process at all", "[default]\nregion = us-west-2\n", true},
		{"true: a different credential_process", "[default]\ncredential_process = some-other-tool --whatever\n", true},
		{"true: SSO settings", "[default]\nsso_session = mycompany\nsso_account_id = 123456789012\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config")
			if tc.content != "" {
				require.NoError(t, os.WriteFile(path, []byte(tc.content), 0600))
			}

			foreign, err := defaultProfileIsForeign(path)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, foreign)
		})
	}
}

func TestSelectCloudIntegrationThenConfirm_SharedReaderConsumesBothAnswers(t *testing.T) {
	integrations := testIntegrations()
	out := &strings.Builder{}
	stdin := testStdin("2\ny\n")

	got, err := selectCloudIntegration(integrations, "", stdin, out, nil)
	require.NoError(t, err)
	assert.Equal(t, "clin_b", got.GetId())

	confirmed, err := confirmOverwriteForeignDefault(stdin, out)
	require.NoError(t, err)
	assert.True(t, confirmed)
}

func TestConfirmOverwriteForeignDefault(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
	}{
		{"y\n", true},
		{"yes\n", true},
		{"Y\n", true},
		{"n\n", false},
		{"\n", false},
		{"whatever\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			out := &strings.Builder{}
			confirmed, err := confirmOverwriteForeignDefault(testStdin(tc.input), out)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, confirmed)
			assert.Contains(t, out.String(), "wasn't set by NetBird")
		})
	}
}

func TestConfiguredAWSProfileNames_EmptyWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	configured, err := configuredAWSProfileNames(path)
	require.NoError(t, err)
	assert.Empty(t, configured)
}

func TestConfiguredAWSProfileNames_MapsIntegrationIDsToProfileNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	initial := "[profile harvard-lil]\nregion = us-east-1\n\n" +
		"[profile netbird-production]\ncredential_process = netbird aws credentials clin_a\n\n" +
		"[default]\ncredential_process = netbird aws credentials clin_a\n"
	require.NoError(t, os.WriteFile(path, []byte(initial), 0600))

	configured, err := configuredAWSProfileNames(path)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"netbird-production", "default"}, configured["clin_a"], "a role configured under two sections must list both by name")
	assert.Empty(t, configured["clin_b"], "an integration with no matching profile must be absent, not an empty-but-present entry")
	assert.Len(t, configured, 1, "the non-NetBird-managed [profile harvard-lil] section must never contribute an entry")
}
