package newapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ErrKeyRejected reports that NewAPI refused the submitted user API key. It is
// distinct from a transport or protocol failure so a rejected login is answered
// with 401 while an unhealthy NewAPI is answered with 502.
var ErrKeyRejected = errors.New("newapi client: token key rejected")

// TokenIdentity is the ownership metadata NewAPI reports for one user API key.
// HasIdentity is false for a valid key that has not been used yet, because the
// log endpoint is then empty and reveals no owner.
type TokenIdentity struct {
	UserID      int64
	Username    string
	TokenID     int64
	TokenName   string
	HasIdentity bool
}

// ValidateTokenKey authenticates a NewAPI user API key against the key's own
// log endpoint and reports the token it belongs to.
//
// NewAPI guards this endpoint with TokenAuthReadOnly, which refuses unknown and
// disabled tokens and banned users but deliberately skips expiry and quota
// checks. That is the behaviour this project wants: a developer whose key has
// expired or run out of quota can still audit what it did.
//
// The key is used only as the credential of this single request. It is never
// logged, stored, or forwarded anywhere else.
func ValidateTokenKey(ctx context.Context, baseURL string, httpClient *http.Client, rawKey string) (TokenIdentity, error) {
	if ctx == nil {
		return TokenIdentity{}, ErrInvalidConfig
	}
	parsed, err := parseBaseURL(baseURL)
	if err != nil {
		return TokenIdentity{}, err
	}
	key := strings.TrimSpace(rawKey)
	if key == "" || strings.ContainsAny(key, "\x00\r\n") {
		return TokenIdentity{}, ErrKeyRejected
	}
	if httpClient == nil {
		httpClient = &http.Client{Transport: directTransport(), Timeout: requestTimeout}
	}

	endpoint := *parsed
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/api/log/token"
	endpoint.RawPath = ""

	var envelope apiEnvelope[[]apiLog]
	if err := fetchJSON(ctx, httpClient, endpoint.String(), func(request *http.Request) {
		request.Header.Set("Authorization", "Bearer "+key)
	}, &envelope); err != nil {
		var status unexpectedStatusError
		if errors.As(err, &status) && (status.status == http.StatusUnauthorized || status.status == http.StatusForbidden) {
			return TokenIdentity{}, ErrKeyRejected
		}
		return TokenIdentity{}, err
	}
	if !envelope.Success {
		return TokenIdentity{}, ErrKeyRejected
	}
	return tokenIdentityFromLogs(envelope.Data)
}

// tokenIdentityFromLogs collapses the returned log page into one owner. NewAPI
// filters these rows by the resolved token id, so disagreeing owners mean the
// response cannot be trusted to identify anybody.
func tokenIdentityFromLogs(logs []apiLog) (TokenIdentity, error) {
	identity := TokenIdentity{}
	for _, item := range logs {
		if item.UserID <= 0 || item.TokenID < 0 ||
			!safeText(item.Username, 512) || !safeText(item.TokenName, 512) {
			return TokenIdentity{}, ErrInvalidResponse
		}
		candidate := TokenIdentity{
			UserID: item.UserID, Username: item.Username,
			TokenID: item.TokenID, TokenName: item.TokenName,
			HasIdentity: true,
		}
		if !identity.HasIdentity {
			identity = candidate
			continue
		}
		if identity != candidate {
			return TokenIdentity{}, ErrInvalidResponse
		}
	}
	return identity, nil
}
