package agentdist

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
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

// nonceSize is the random part of every link, so that two links minted in
// the same second differ and each has its own download budget.
const nonceSize = 16

// expiryDigits is the length of expires_unix in decimal: ten digits cover
// every second from 2001-09-09 to 2286-11-20, so every link Mint makes has
// exactly this many.
const expiryDigits = 10

// SignatureLength is the exact length of every signature: the unpadded
// base64url encoding of the ten digits, the dot, the nonce and the 32-byte
// MAC. A signature of any other length, or with any character outside
// [A-Za-z0-9_-], is refused before it is decoded, so one link has exactly
// one spelling (the decoder would otherwise skip CR and LF).
var SignatureLength = base64.RawURLEncoding.EncodedLen(expiryDigits + 1 + nonceSize + sha256.Size)

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

// mac is HMAC-SHA-256(K_dl, expires_unix || "." || nonce) over the decimal
// seconds and the raw nonce bytes.
func (signer *Signer) mac(expires string, nonce []byte) []byte {
	hash := hmac.New(sha256.New, signer.key)
	hash.Write([]byte(expires + "."))
	hash.Write(nonce)
	return hash.Sum(nil)
}

// Mint returns a signature valid for LinkLifetime from now, and its expiry:
// BASE64URL(expires_unix || "." || nonce || HMAC-SHA-256(K_dl, expires_unix ||
// "." || nonce)), with expires_unix in decimal seconds, a fresh 16-byte random
// nonce, the MAC as its 32 raw bytes and unpadded URL-safe base64. The nonce
// makes every link distinct, so each link has its own download budget.
func (signer *Signer) Mint() (string, time.Time) {
	expires := signer.now().Add(LinkLifetime).Truncate(time.Second)
	unix := strconv.FormatInt(expires.Unix(), 10)
	nonce := make([]byte, nonceSize)
	// crypto/rand.Read does not fail on supported platforms: it crashes the
	// program rather than return predictable bytes.
	_, _ = rand.Read(nonce)
	payload := append(append([]byte(unix+"."), nonce...), signer.mac(unix, nonce)...)
	return base64.RawURLEncoding.EncodeToString(payload), expires.UTC()
}

// Verify checks signature and returns its expiry. ErrBadSignature covers every
// way it can be wrong; ErrLinkExpired is only returned for a signature that
// verifies, so an expired answer never confirms a guess. The MAC comparison
// is constant time.
func (signer *Signer) Verify(signature string) (time.Time, error) {
	link, err := signer.VerifyLink(signature)
	return link.Expires, err
}

// VerifiedLink is what a signature that verifies stands for. Nonce is the
// link's identity: the download budget is kept per nonce, never per request
// spelling.
type VerifiedLink struct {
	Expires time.Time
	Nonce   string
}

// VerifyLink is Verify that also returns the nonce. Expires is set for
// ErrLinkExpired too; Nonce only when err is nil.
func (signer *Signer) VerifyLink(signature string) (VerifiedLink, error) {
	if len(signature) != SignatureLength {
		return VerifiedLink{}, ErrBadSignature
	}
	for index := 0; index < len(signature); index++ {
		char := signature[index]
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return VerifiedLink{}, ErrBadSignature
		}
	}
	// Strict also refuses non-zero padding bits in the last character, so
	// with the checks above the encoding is the only one of its payload.
	payload, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != signature {
		return VerifiedLink{}, ErrBadSignature
	}
	dot := bytes.IndexByte(payload, '.')
	if dot != expiryDigits || len(payload)-dot-1 != nonceSize+sha256.Size {
		return VerifiedLink{}, ErrBadSignature
	}
	unix := string(payload[:dot])
	for index := 0; index < len(unix); index++ {
		if unix[index] < '0' || unix[index] > '9' {
			return VerifiedLink{}, ErrBadSignature
		}
	}
	if unix[0] == '0' {
		return VerifiedLink{}, ErrBadSignature
	}
	nonce := payload[dot+1 : dot+1+nonceSize]
	if !hmac.Equal(payload[dot+1+nonceSize:], signer.mac(unix, nonce)) {
		return VerifiedLink{}, ErrBadSignature
	}
	seconds, err := strconv.ParseInt(unix, 10, 64)
	if err != nil {
		return VerifiedLink{}, ErrBadSignature
	}
	expires := time.Unix(seconds, 0).UTC()
	now := signer.now()
	if !now.Before(expires) {
		return VerifiedLink{Expires: expires}, ErrLinkExpired
	}
	// A signature that expires later than a freshly minted one cannot come
	// from Mint under a sane clock; refusing it bounds the damage of a clock
	// that once jumped forward.
	if expires.Sub(now) > LinkLifetime+time.Minute {
		return VerifiedLink{}, ErrBadSignature
	}
	return VerifiedLink{Expires: expires, Nonce: string(nonce)}, nil
}
