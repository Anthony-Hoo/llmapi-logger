package newapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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

	var identity TokenIdentity
	if err := fetchBody(ctx, httpClient, endpoint.String(), func(request *http.Request) {
		request.Header.Set("Authorization", "Bearer "+key)
	}, func(body io.Reader) error {
		var err error
		identity, err = decodeTokenLog(body)
		return err
	}); err != nil {
		var status unexpectedStatusError
		if errors.As(err, &status) && (status.status == http.StatusUnauthorized || status.status == http.StatusForbidden) {
			return TokenIdentity{}, ErrKeyRejected
		}
		return TokenIdentity{}, err
	}
	return identity, nil
}

// maxTokenLogBodyBytes bounds the streamed token log. It is far above the
// shared buffered ceiling because this response cannot be bounded in advance:
// the endpoint ignores every paging parameter and always returns its whole
// page, whose size is driven by the logged content, so real deployments send
// several megabytes to identify one token. Streaming keeps resident memory at
// one row regardless, and this only stops a body that never ends.
const maxTokenLogBodyBytes = 64 << 20

// decodeTokenLog reads the log page as a stream and collapses it into one
// owner. It deliberately does not buffer the document: every row is still
// inspected, but only one is resident at a time, so the cost of identifying a
// token does not grow with how much that token has been used.
func decodeTokenLog(body io.Reader) (TokenIdentity, error) {
	decoder := json.NewDecoder(&ceilingReader{reader: body, remaining: maxTokenLogBodyBytes})
	// The envelope reports success in a sibling field that may arrive after
	// the rows, so the outcome is only known once the object is exhausted.
	success := false
	identity := TokenIdentity{}

	if err := expectDelim(decoder, '{'); err != nil {
		return TokenIdentity{}, err
	}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return TokenIdentity{}, decodeError(err)
		}
		field, isString := token.(string)
		if !isString {
			return TokenIdentity{}, ErrInvalidResponse
		}
		switch field {
		case "success":
			if err := decoder.Decode(&success); err != nil {
				return TokenIdentity{}, decodeError(err)
			}
		case "data":
			identity, err = decodeTokenLogRows(decoder)
			if err != nil {
				return TokenIdentity{}, err
			}
		default:
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return TokenIdentity{}, decodeError(err)
			}
		}
	}
	if err := expectDelim(decoder, '}'); err != nil {
		return TokenIdentity{}, err
	}
	if !success {
		return TokenIdentity{}, ErrKeyRejected
	}
	return identity, nil
}

// decodeTokenLogRows folds the data array into one owner. Only
// (user_id, token_id) identifies the owner: each row also carries the username
// and token name as they read when that request was served, so renaming a token
// leaves older rows holding the older label, and comparing those too would
// report every renamed token as a corrupted response. The labels are display
// text, and the one worth showing is the current one, so they come from the
// newest row by created_at rather than from whichever row arrived first.
func decodeTokenLogRows(decoder *json.Decoder) (TokenIdentity, error) {
	identity := TokenIdentity{}
	var labelledAt int64
	if err := expectDelim(decoder, '['); err != nil {
		return TokenIdentity{}, err
	}
	for decoder.More() {
		var item apiLog
		if err := decoder.Decode(&item); err != nil {
			return TokenIdentity{}, decodeError(err)
		}
		if item.UserID <= 0 || item.TokenID < 0 ||
			!safeText(item.Username, 512) || !safeText(item.TokenName, 512) {
			return TokenIdentity{}, ErrInvalidResponse
		}
		if identity.HasIdentity &&
			(identity.UserID != item.UserID || identity.TokenID != item.TokenID) {
			return TokenIdentity{}, ErrInvalidResponse
		}
		if !identity.HasIdentity || item.CreatedAt > labelledAt {
			identity.Username = item.Username
			identity.TokenName = item.TokenName
			labelledAt = item.CreatedAt
		}
		identity.UserID = item.UserID
		identity.TokenID = item.TokenID
		identity.HasIdentity = true
	}
	if err := expectDelim(decoder, ']'); err != nil {
		return TokenIdentity{}, err
	}
	return identity, nil
}

func expectDelim(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return decodeError(err)
	}
	if delim, isDelim := token.(json.Delim); !isDelim || delim != want {
		return ErrInvalidResponse
	}
	return nil
}

// decodeError keeps a body that outgrew the ceiling distinguishable from a
// body that was merely malformed; the streamed read surfaces the first as a
// read error rather than as a broken document.
func decodeError(err error) error {
	if errors.Is(err, ErrResponseTooLarge) {
		return ErrResponseTooLarge
	}
	return ErrInvalidResponse
}
