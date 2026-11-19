package agentdist

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"time"
)

// LinkLifetime is how long a signed download link is valid.
const LinkLifetime = 30 * time.Minute

// downloadKeyLabel separates the download-link key from the other keys
// derived from admin_token (token digests, session cookies).
const downloadKeyLabel = "llmapi-logger/agent-download/v1\x00"

// maxSignatureLength bounds the decoded signature: at most 20 digits, the dot
// and a 32-byte MAC. Anything longer is rejected before decoding.
const maxSignatureLength = 72

var (
	// ErrBadSignature means the signature does not verify: malformed,
	// signed with another key, or tampered with. The handler answers 404.
	ErrBadSignature = errors.New("agentdist: invalid download signature")
	// ErrLinkExpired means a correctly signed link is past its expiry. The
	// handler answers 410.
	ErrLinkExpired = errors.New("agentdist: download link expired")
)

// DownloadKey is K_dl = SHA-256("llmapi-logger/agent-download/v1\x00" +
// admin_token). Rotating admin_token invalidates every link.
func DownloadKey(adminToken string) []byte {
	sum := sha256.Sum256([]byte(downloadKeyLabel + adminToken))
	return sum[:]
}

// Signer mints and verifies signed download links. Now is injectable for
// tests; nil means time.Now.
type Signer struct {
	key []byte
	now func() time.Time
}

// NewSigner derives the download key from adminToken. An empty token is an
// error: every link would be forgeable.
func NewSigner(adminToken string, now func() time.Time) (*Signer, error) {
	if adminToken == "" {
		return nil, errors.New("agentdist: admin token is empty")
	}
	if now == nil {
		now = time.Now
	}
	return &Signer{key: DownloadKey(adminToken), now: now}, nil
}

// mac is HMAC-SHA-256(K_dl, expires_unix) over the decimal seconds.
func (signer *Signer) mac(expires string) []byte {
	hash := hmac.New(sha256.New, signer.key)
	hash.Write([]byte(expires))
	return hash.Sum(nil)
}

// Mint returns a signature valid for LinkLifetime from now, and its expiry:
// BASE64URL(expires_unix || "." || HMAC-SHA-256(K_dl, expires_unix)), with
// expires_unix in decimal seconds, the MAC as its 32 raw bytes and unpadded
// URL-safe base64.
func (signer *Signer) Mint() (string, time.Time) {
	expires := signer.now().Add(LinkLifetime).Truncate(time.Second)
	unix := strconv.FormatInt(expires.Unix(), 10)
	payload := append([]byte(unix+"."), signer.mac(unix)...)
	return base64.RawURLEncoding.EncodeToString(payload), expires.UTC()
}

// Verify checks signature and returns its expiry. ErrBadSignature covers every
// way it can be wrong; ErrLinkExpired is only returned for a signature that
// verifies, so an expired answer never confirms a guess. The MAC comparison
// is constant time.
func (signer *Signer) Verify(signature string) (time.Time, error) {
	if signature == "" || len(signature) > base64.RawURLEncoding.EncodedLen(maxSignatureLength) {
		return time.Time{}, ErrBadSignature
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil {
		return time.Time{}, ErrBadSignature
	}
	dot := bytes.IndexByte(payload, '.')
	if dot <= 0 || dot > 20 || len(payload)-dot-1 != sha256.Size {
		return time.Time{}, ErrBadSignature
	}
	unix := string(payload[:dot])
	for index := 0; index < len(unix); index++ {
		if unix[index] < '0' || unix[index] > '9' {
			return time.Time{}, ErrBadSignature
		}
	}
	if len(unix) > 1 && unix[0] == '0' {
		return time.Time{}, ErrBadSignature
	}
	if !hmac.Equal(payload[dot+1:], signer.mac(unix)) {
		return time.Time{}, ErrBadSignature
	}
	seconds, err := strconv.ParseInt(unix, 10, 64)
	if err != nil {
		return time.Time{}, ErrBadSignature
	}
	expires := time.Unix(seconds, 0).UTC()
	now := signer.now()
	if !now.Before(expires) {
		return expires, ErrLinkExpired
	}
	// A signature that expires later than a freshly minted one cannot come
	// from Mint under a sane clock; refusing it bounds the damage of a clock
	// that once jumped forward.
	if expires.Sub(now) > LinkLifetime+time.Minute {
		return time.Time{}, ErrBadSignature
	}
	return expires, nil
}
