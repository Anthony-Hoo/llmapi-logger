package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookieName = "llmapi_logger_session"
	sessionVersion    = "v1"
	sessionLifetime   = 7 * 24 * time.Hour
)

type managementAuth struct {
	expectedToken [sha256.Size]byte
	sessionKey    [sha256.Size]byte
	now           func() time.Time
}

func newManagementAuth(adminToken string) *managementAuth {
	return &managementAuth{
		expectedToken: sha256.Sum256([]byte(adminToken)),
		sessionKey:    sha256.Sum256([]byte("llmapi-logger/admin-session/v1\x00" + adminToken)),
		now:           time.Now,
	}
}

func (auth *managementAuth) middleware(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !auth.authorized(request) {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="audit-proxy"`)
			writer.Header().Set("Cache-Control", "no-store")
			writeError(writer, http.StatusUnauthorized, "unauthorized", "valid management session or bearer token required")
			return
		}
		next(writer, request)
	})
}

func (auth *managementAuth) authorized(request *http.Request) bool {
	if auth == nil || request == nil {
		return false
	}
	if authorization := request.Header.Get("Authorization"); authorization != "" {
		provided, ok := bearerToken(authorization)
		return ok && auth.validAdminToken(provided)
	}
	cookie, err := request.Cookie(sessionCookieName)
	return err == nil && auth.validSession(cookie.Value)
}

func (auth *managementAuth) validAdminToken(provided string) bool {
	actual := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(auth.expectedToken[:], actual[:]) == 1
}

func (auth *managementAuth) issueSessionCookie(writer http.ResponseWriter, request *http.Request) time.Time {
	expires := auth.now().Add(sessionLifetime).UTC().Truncate(time.Second)
	value := auth.sessionValue(expires.Unix())
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(sessionLifetime / time.Second),
		HttpOnly: true,
		Secure:   request != nil && request.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	return expires
}

func (auth *managementAuth) clearSessionCookie(writer http.ResponseWriter, request *http.Request) {
	http.SetCookie(writer, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   request != nil && request.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
}

func (auth *managementAuth) validSession(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != sessionVersion {
		return false
	}
	expiresUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || expiresUnix <= 0 {
		return false
	}
	now := auth.now()
	expires := time.Unix(expiresUnix, 0)
	if !now.Before(expires) || expires.After(now.Add(sessionLifetime+time.Minute)) {
		return false
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(providedMAC) != sha256.Size {
		return false
	}
	expectedMAC := auth.sessionMAC(parts[0] + "." + parts[1])
	return subtle.ConstantTimeCompare(expectedMAC, providedMAC) == 1
}

func (auth *managementAuth) sessionValue(expiresUnix int64) string {
	payload := sessionVersion + "." + strconv.FormatInt(expiresUnix, 10)
	return payload + "." + base64.RawURLEncoding.EncodeToString(auth.sessionMAC(payload))
}

func (auth *managementAuth) sessionMAC(payload string) []byte {
	mac := hmac.New(sha256.New, auth.sessionKey[:])
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func bearerToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" {
		return "", false
	}
	return fields[1], true
}
