package auth

import "strings"

// sanitizeReturnTo returns path if it's a same-origin relative path, else "/".
func sanitizeReturnTo(path string) string {
	const fallback = "/"

	path = stripTabAndNewlines(path)

	if path == "" || path[0] != '/' {
		return fallback
	}
	if len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return fallback
	}
	return path
}

func stripTabAndNewlines(s string) string {
	if !strings.ContainsAny(s, "\t\n\r") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
