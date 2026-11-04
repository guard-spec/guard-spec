// Package web holds the admin UI, which the control plane serves at /ui/.
//
// dist is the built single-page app. The repository keeps a placeholder
// index.html there, so that go build works without Node; the Docker build
// and CI replace it with the real build (npm run build in this directory).
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built UI, with index.html at its root.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // dist is embedded at build time; fs.Sub only fails on a bad name
	}
	return sub
}
