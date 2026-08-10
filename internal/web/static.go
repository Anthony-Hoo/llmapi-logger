package web

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const fallbackHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI API Audit Proxy</title></head>
<body><main><h1>AI API Audit Proxy</h1><p>The management UI has not been built yet.</p></main></body></html>`

func newStaticHandler(assets fs.FS) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			methodNotAllowed(writer, http.MethodGet, http.MethodHead)
			return
		}
		if request.URL.Path == "/ui" {
			http.Redirect(writer, request, "/ui/", http.StatusTemporaryRedirect)
			return
		}
		if assets == nil {
			writer.Header().Set("Content-Type", "text/html; charset=utf-8")
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.WriteHeader(http.StatusOK)
			if request.Method == http.MethodGet {
				_, _ = writer.Write([]byte(fallbackHTML))
			}
			return
		}

		relative := strings.TrimPrefix(request.URL.Path, "/ui/")
		relative = strings.TrimPrefix(path.Clean("/"+relative), "/")
		if relative == "." || relative == "" {
			relative = "index.html"
		}
		if _, err := fs.Stat(assets, relative); err != nil {
			relative = "index.html"
		}
		cloned := request.Clone(request.Context())
		if relative == "index.html" {
			cloned.URL.Path = "/"
		} else {
			cloned.URL.Path = "/" + relative
		}
		http.FileServer(http.FS(assets)).ServeHTTP(writer, cloned)
	})
}
