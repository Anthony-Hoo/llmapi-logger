package web

import (
	"embed"
	"io/fs"
)

// embeddedDist holds the React/Vite build output. The build artifacts are not
// committed: `dist` is populated by `pnpm build` (see scripts/build.*) or by the
// web-build stage of the Dockerfile. Only dist/.gitkeep is tracked, which is
// what keeps this embed directive resolvable in a fresh checkout.
//
//go:embed all:dist
var embeddedDist embed.FS

// EmbeddedAssets returns the built management UI, or nil when the frontend has
// not been built in this tree. A nil result selects the small built-in fallback
// page instead of serving a shell whose script and stylesheet would 404.
func EmbeddedAssets() fs.FS {
	assets, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		return nil
	}
	return assets
}
