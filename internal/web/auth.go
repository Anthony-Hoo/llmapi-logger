package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

func newBearerAuth(adminToken string, next http.HandlerFunc) http.Handler {
	expected := sha256.Sum256([]byte(adminToken))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		provided, ok := bearerToken(request.Header.Get("Authorization"))
		actual := sha256.Sum256([]byte(provided))
		if !ok || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="audit-proxy"`)
			writer.Header().Set("Cache-Control", "no-store")
			writeError(writer, http.StatusUnauthorized, "unauthorized", "valid bearer token required")
			return
		}
		next(writer, request)
	})
}

func bearerToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" {
		return "", false
	}
	return fields[1], true
}
