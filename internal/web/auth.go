package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage/sqlite"
)

const (
	sessionCookieName       = "llmapi_logger_session"
	adminSessionVersion     = "v1"
	developerSessionVersion = "v2"
	sessionLifetime         = 7 * 24 * time.Hour
)

// role names the two management identities. An administrator reads everything;
// a developer reads only what their own NewAPI API key produced.
type role string

const (
	roleAdmin     role = "admin"
	roleDeveloper role = "developer"
)

// developerIdentity is the display-only ownership information NewAPI reported
// for the key at login. It never includes the key or its fingerprint.
type developerIdentity struct {
	UserID    int64  `json:"user_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenID   *int64 `json:"token_id,omitempty"`
	TokenName string `json:"token_name,omitempty"`
}

// principal is the authenticated caller of one management request.
type principal struct {
	Role      role
	ExpiresAt time.Time
	// Scope is nil for administrators and always set for developers.
	Scope    *query.Scope
	Identity developerIdentity
}

// developerSessionPayload travels inside the signed cookie. Short names keep the
// cookie small; the fingerprint is carried so a session needs no server state,
// and it is never echoed back to the browser.
type developerSessionPayload struct {
	Fingerprint []byte `json:"fpr"`
	TokenID     *int64 `json:"tid,omitempty"`
	UserID      int64  `json:"uid,omitempty"`
	Username    string `json:"usr,omitempty"`
	TokenName   string `json:"tkn,omitempty"`
}

type managementAuth struct {
	expectedToken   [sha256.Size]byte
	sessionKey      [sha256.Size]byte
	developerKey    [sha256.Size]byte
	now             func() time.Time
	developerLogins bool
}

func newManagementAuth(adminToken string, developerLogins bool) *managementAuth {
	return &managementAuth{
		expectedToken: sha256.Sum256([]byte(adminToken)),
		sessionKey:    sha256.Sum256([]byte("llmapi-logger/admin-session/v1\x00" + adminToken)),
		// A separate domain keeps a developer cookie from ever verifying as an
		// administrator cookie, and vice versa.
		developerKey:    sha256.Sum256([]byte("llmapi-logger/developer-session/v1\x00" + adminToken)),
		now:             time.Now,
		developerLogins: developerLogins,
	}
}

type principalContextKey struct{}

func withPrincipal(ctx context.Context, caller principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, caller)
}

func principalFrom(ctx context.Context) (principal, bool) {
	caller, ok := ctx.Value(principalContextKey{}).(principal)
	return caller, ok
}

// middleware authenticates the request and publishes the caller on the request
// context. Per-route role checks live in serveProtected.
func (auth *managementAuth) middleware(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		caller, ok := auth.resolve(request)
		if !ok {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="audit-proxy"`)
			writer.Header().Set("Cache-Control", "no-store")
			writeError(writer, http.StatusUnauthorized, "unauthorized", "valid management session or bearer token required")
			return
		}
		next(writer, request.WithContext(withPrincipal(request.Context(), caller)))
	})
}

// resolve identifies the caller. A present Authorization header is answered
// only as a bearer token and never falls back to the cookie, so a stale browser
// session cannot rescue a wrong CLI token.
func (auth *managementAuth) resolve(request *http.Request) (principal, bool) {
	if auth == nil || request == nil {
		return principal{}, false
	}
	if authorization := request.Header.Get("Authorization"); authorization != "" {
		provided, ok := bearerToken(authorization)
		if !ok || !auth.validAdminToken(provided) {
			return principal{}, false
		}
		return principal{Role: roleAdmin}, true
	}
	cookie, err := request.Cookie(sessionCookieName)
	if err != nil {
		return principal{}, false
	}
	return auth.validSession(cookie.Value)
}

func (auth *managementAuth) validAdminToken(provided string) bool {
	actual := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(auth.expectedToken[:], actual[:]) == 1
}

func (auth *managementAuth) issueSessionCookie(writer http.ResponseWriter, request *http.Request) time.Time {
	expires := auth.now().Add(sessionLifetime).UTC().Truncate(time.Second)
	auth.setSessionCookie(writer, request, auth.adminSessionValue(expires.Unix()), expires)
	return expires
}

// issueDeveloperCookie signs the session scope into the cookie. The scope is
// fixed at login precisely so a later request cannot widen it.
func (auth *managementAuth) issueDeveloperCookie(writer http.ResponseWriter, request *http.Request, payload developerSessionPayload) (time.Time, error) {
	expires := auth.now().Add(sessionLifetime).UTC().Truncate(time.Second)
	value, err := auth.developerSessionValue(expires.Unix(), payload)
	if err != nil {
		return time.Time{}, err
	}
	auth.setSessionCookie(writer, request, value, expires)
	return expires, nil
}

func (auth *managementAuth) setSessionCookie(writer http.ResponseWriter, request *http.Request, value string, expires time.Time) {
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

func (auth *managementAuth) validSession(value string) (principal, bool) {
	parts := strings.Split(value, ".")
	if len(parts) < 3 {
		return principal{}, false
	}
	expires, ok := auth.validSessionExpiry(parts[1])
	if !ok {
		return principal{}, false
	}
	switch {
	case parts[0] == adminSessionVersion && len(parts) == 3:
		if !verifyMAC(auth.sessionKey[:], parts[0]+"."+parts[1], parts[2]) {
			return principal{}, false
		}
		return principal{Role: roleAdmin, ExpiresAt: expires}, true
	case parts[0] == developerSessionVersion && len(parts) == 4:
		if !auth.developerLogins {
			// Disabling developer logins must invalidate cookies already out
			// there, not merely hide the login form.
			return principal{}, false
		}
		signed := parts[0] + "." + parts[1] + "." + parts[2]
		if !verifyMAC(auth.developerKey[:], signed, parts[3]) {
			return principal{}, false
		}
		payload, ok := decodeDeveloperPayload(parts[2])
		if !ok {
			return principal{}, false
		}
		return principal{
			Role:      roleDeveloper,
			ExpiresAt: expires,
			Scope:     &query.Scope{Fingerprint: payload.Fingerprint, TokenID: payload.TokenID},
			Identity: developerIdentity{
				UserID: payload.UserID, Username: payload.Username,
				TokenID: payload.TokenID, TokenName: payload.TokenName,
			},
		}, true
	default:
		return principal{}, false
	}
}

func (auth *managementAuth) validSessionExpiry(encoded string) (time.Time, bool) {
	expiresUnix, err := strconv.ParseInt(encoded, 10, 64)
	if err != nil || expiresUnix <= 0 {
		return time.Time{}, false
	}
	now := auth.now()
	expires := time.Unix(expiresUnix, 0)
	if !now.Before(expires) || expires.After(now.Add(sessionLifetime+time.Minute)) {
		return time.Time{}, false
	}
	return expires.UTC(), true
}

func decodeDeveloperPayload(encoded string) (developerSessionPayload, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return developerSessionPayload{}, false
	}
	var payload developerSessionPayload
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return developerSessionPayload{}, false
	}
	if len(payload.Fingerprint) != sqlite.APIKeyFingerprintSize {
		return developerSessionPayload{}, false
	}
	if payload.TokenID != nil && *payload.TokenID < 0 {
		return developerSessionPayload{}, false
	}
	return payload, true
}

func (auth *managementAuth) adminSessionValue(expiresUnix int64) string {
	payload := adminSessionVersion + "." + strconv.FormatInt(expiresUnix, 10)
	return payload + "." + base64.RawURLEncoding.EncodeToString(sessionMAC(auth.sessionKey[:], payload))
}

func (auth *managementAuth) developerSessionValue(expiresUnix int64, payload developerSessionPayload) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signed := developerSessionVersion + "." + strconv.FormatInt(expiresUnix, 10) + "." +
		base64.RawURLEncoding.EncodeToString(encoded)
	return signed + "." + base64.RawURLEncoding.EncodeToString(sessionMAC(auth.developerKey[:], signed)), nil
}

func sessionMAC(key []byte, payload string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

func verifyMAC(key []byte, payload, encodedMAC string) bool {
	provided, err := base64.RawURLEncoding.DecodeString(encodedMAC)
	if err != nil || len(provided) != sha256.Size {
		return false
	}
	return subtle.ConstantTimeCompare(sessionMAC(key, payload), provided) == 1
}

func bearerToken(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] == "" {
		return "", false
	}
	return fields[1], true
}
