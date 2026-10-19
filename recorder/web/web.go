// Package web embeds and serves the recorder's standalone web UI, a
// Next.js app (same stack, folder conventions, and theme as
// netbird-dashboard) statically exported via `next build` into out/.
// Playback uses the npm asciinema-player package (Apache-2.0).
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

// all: is required, not just out/* — Next.js's static export (since
// Next 16) puts a route's internal RSC/routing metadata into files named
// like out/_not-found/__next._tree.txt. go:embed's default directory walk
// excludes anything starting with "." or "_", which empties that
// directory out entirely and fails the build ("contains no embeddable
// files") since an explicitly-matched directory can't embed to nothing.
// The actual served content (out/_not-found.html) is an ordinary file
// right next to it and was never affected either way — this only pulls
// in a few harmless extra metadata files nothing here ever reads.
//
//go:embed all:out
var files embed.FS

var (
	webFS   fs.FS
	initErr error
)

func init() {
	webFS, initErr = fs.Sub(files, "out")
}

// Handler serves the embedded static export. The app keeps all view state
// in the "/" route's query string, so any path without a matching file
// falls back to index.html rather than a 404.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if initErr != nil {
			http.Error(w, initErr.Error(), http.StatusInternalServerError)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}

		content, err := fs.ReadFile(webFS, path)
		if err != nil {
			content, err = fs.ReadFile(webFS, "index.html")
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			path = "index.html"
		}

		setContentType(w, path)
		w.Write(content) //nolint:errcheck
	})
}

func setContentType(w http.ResponseWriter, path string) {
	switch filepath.Ext(path) {
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	}
}
