package auth

import "testing"

func TestGroupsAllowed(t *testing.T) {
	tests := []struct {
		name          string
		groups        []string
		allowedGroups []string
		want          bool
	}{
		{"no allow-list configured, no groups", nil, nil, true},
		{"no allow-list configured, has groups", []string{"engineering"}, nil, true},
		{"allow-list configured, no groups claim at all", nil, []string{"security-team"}, false},
		{"allow-list configured, no intersection", []string{"engineering"}, []string{"security-team"}, false},
		{"allow-list configured, intersection", []string{"engineering", "security-team"}, []string{"security-team"}, true},
		{"allow-list configured, exact single match", []string{"security-team"}, []string{"security-team"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := groupsAllowed(tt.groups, tt.allowedGroups); got != tt.want {
				t.Errorf("groupsAllowed(%v, %v) = %v, want %v", tt.groups, tt.allowedGroups, got, tt.want)
			}
		})
	}
}

func TestTrustedEmail(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want string
	}{
		{"no email_verified claim at all", map[string]any{"email": "user@example.com"}, "user@example.com"},
		{"email_verified true", map[string]any{"email": "user@example.com", "email_verified": true}, "user@example.com"},
		{"email_verified false", map[string]any{"email": "user@example.com", "email_verified": false}, ""},
		{"no email claim", map[string]any{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trustedEmail(tt.raw); got != tt.want {
				t.Errorf("trustedEmail(%v) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestExtractGroups(t *testing.T) {
	tests := []struct {
		name      string
		raw       map[string]any
		claimName string
		want      []string
	}{
		{
			name:      "claim present as string array",
			raw:       map[string]any{"groups": []any{"a", "b"}},
			claimName: "groups",
			want:      []string{"a", "b"},
		},
		{
			name:      "claim absent",
			raw:       map[string]any{},
			claimName: "groups",
			want:      nil,
		},
		{
			name:      "claim present but wrong type",
			raw:       map[string]any{"groups": "not-an-array"},
			claimName: "groups",
			want:      nil,
		},
		{
			name:      "custom claim name",
			raw:       map[string]any{"roles": []any{"admin"}},
			claimName: "roles",
			want:      []string{"admin"},
		},
		{
			name:      "array with non-string entries are skipped",
			raw:       map[string]any{"groups": []any{"a", 42, "b"}},
			claimName: "groups",
			want:      []string{"a", "b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGroups(tt.raw, tt.claimName)
			if len(got) != len(tt.want) {
				t.Fatalf("extractGroups() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("extractGroups() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
