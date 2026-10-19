package auth

import "testing"

func TestSanitizeReturnTo(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"simple path", "/sessions/abc-123", "/sessions/abc-123"},
		{"path with query", "/sessions?status=completed", "/sessions?status=completed"},
		{"protocol-relative", "//evil.com", "/"},
		{"protocol-relative with path", "//evil.com/phish", "/"},
		{"backslash variant", "/\\evil.com", "/"},
		{"absolute url", "http://evil.com", "/"},
		{"absolute https url", "https://evil.com/path", "/"},
		{"javascript scheme", "javascript:alert(1)", "/"},
		{"no leading slash", "sessions/abc", "/"},
		{"tab before double slash", "/\t/evil.com", "/"},
		{"newline before double slash", "/\n/evil.com", "/"},
		{"carriage return before double slash", "/\r/evil.com", "/"},
		{"tab buried mid-path does not enable a bypass", "/sessions/ab\tc", "/sessions/abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeReturnTo(tt.in); got != tt.want {
				t.Errorf("sanitizeReturnTo(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
