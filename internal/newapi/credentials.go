package newapi

import (
	"net/http"
	"strings"
)

// MaskTokenKey matches NewAPI v1.0.0-rc.21's model.MaskTokenKey.
func MaskTokenKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 4 {
		return strings.Repeat("*", len(key))
	}
	if len(key) <= 8 {
		return key[:2] + "****" + key[len(key)-2:]
	}
	return key[:4] + "**********" + key[len(key)-4:]
}

// LookupRequest applies NewAPI's protocol-specific credential precedence and
// returns a token only when its masked key uniquely identifies one catalog row.
func (catalog *Catalog) LookupRequest(request *http.Request) (Token, bool) {
	key := credentialKeyFromRequest(request)
	return catalog.lookupNormalizedKey(key)
}

// LookupCredential applies NewAPI's Authorization parsing to a raw credential.
// It is useful when the caller has already selected the effective header.
func (catalog *Catalog) LookupCredential(credential string) (Token, bool) {
	return catalog.lookupNormalizedKey(normalizeAuthorization(credential))
}

func (catalog *Catalog) lookupNormalizedKey(key string) (Token, bool) {
	if catalog == nil || key == "" || strings.ContainsRune(key, '*') {
		return Token{}, false
	}
	snapshot := catalog.snapshot.Load()
	if snapshot == nil {
		return Token{}, false
	}
	token, found := snapshot.byMaskedKey[MaskTokenKey(key)]
	return token, found
}

func credentialKeyFromRequest(request *http.Request) string {
	if request == nil {
		return ""
	}

	credential := request.Header.Get("Authorization")
	syntheticBearer := false
	requestPath := ""
	if request.URL != nil {
		requestPath = request.URL.Path
	}

	// NewAPI copies Anthropic's x-api-key into Authorization for these paths.
	if strings.Contains(requestPath, "/v1/messages") || strings.Contains(requestPath, "/v1/models") {
		if anthropicKey := request.Header.Get("x-api-key"); anthropicKey != "" {
			credential = anthropicKey
			syntheticBearer = true
		}
	}

	// NewAPI then applies Gemini query/header credentials, so these override
	// both Authorization and any Anthropic-style x-api-key selected above.
	if isGeminiCredentialPath(requestPath) {
		if request.URL != nil {
			if queryKey := request.URL.Query().Get("key"); queryKey != "" {
				credential = queryKey
				syntheticBearer = true
			}
		}
		if googleKey := request.Header.Get("x-goog-api-key"); googleKey != "" {
			credential = googleKey
			syntheticBearer = true
		}
	}

	if syntheticBearer {
		return normalizeTokenKey(strings.TrimSpace(credential))
	}
	return normalizeAuthorization(credential)
}

func isGeminiCredentialPath(requestPath string) bool {
	return strings.HasPrefix(requestPath, "/v1beta/models") ||
		strings.HasPrefix(requestPath, "/v1beta/openai/models") ||
		strings.HasPrefix(requestPath, "/v1/models/")
}

func normalizeAuthorization(credential string) string {
	if strings.HasPrefix(credential, "Bearer ") || strings.HasPrefix(credential, "bearer ") {
		credential = strings.TrimSpace(credential[7:])
	}
	return normalizeTokenKey(credential)
}

func normalizeTokenKey(key string) string {
	key = strings.TrimPrefix(key, "sk-")
	if separator := strings.IndexByte(key, '-'); separator >= 0 {
		key = key[:separator]
	}
	return key
}
