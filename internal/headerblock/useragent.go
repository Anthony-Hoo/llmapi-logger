package headerblock

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"llmapi-logger/internal/security"
)

const (
	userAgentVersion    = 0x01
	userAgentAADPurpose = "user_agent_v1"
)

// UserAgentValues selects the values user_agent_enc stores from the
// request_received Header fields (Snapshot order): every name equal to
// "user-agent" under strings.EqualFold, in name byte order, each with its
// values in order. nil means the Header is absent.
func UserAgentValues(headers []Field) []string {
	var values []string
	for _, field := range headers {
		if !strings.EqualFold(field.Name, "user-agent") {
			continue
		}
		for _, value := range field.Values {
			values = append(values, string(value))
		}
	}
	return values
}

// EncodeUserAgent returns the user_agent_enc plaintext
// 0x01 (u32be(len) bytes)+, or nil when there is no value: an absent Header is
// stored as NULL, while one empty value is a present Header.
func EncodeUserAgent(values []string) []byte {
	if len(values) == 0 {
		return nil
	}
	size := 1
	for _, value := range values {
		size += 4 + len(value)
	}
	plaintext := make([]byte, 0, size)
	plaintext = append(plaintext, userAgentVersion)
	for _, value := range values {
		plaintext = binary.BigEndian.AppendUint32(plaintext, uint32(len(value)))
		plaintext = append(plaintext, value...)
	}
	return plaintext
}

// DecodeUserAgent parses a user_agent_enc plaintext strictly: version byte, at
// least one value, no trailing bytes.
func DecodeUserAgent(plaintext []byte) ([]string, error) {
	if len(plaintext) < 1 || plaintext[0] != userAgentVersion {
		return nil, fmt.Errorf("%w: invalid user agent encoding", ErrIntegrity)
	}
	rest := plaintext[1:]
	if len(rest) == 0 {
		return nil, fmt.Errorf("%w: user agent without values", ErrIntegrity)
	}
	var values []string
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: truncated user agent", ErrIntegrity)
		}
		length := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(length) > uint64(len(rest)) {
			return nil, fmt.Errorf("%w: truncated user agent", ErrIntegrity)
		}
		values = append(values, string(rest[:length]))
		rest = rest[length:]
	}
	return values, nil
}

// UserAgentAAD is the associated data of user_agent_enc:
// security.AAD(auditID, "user_agent_v1").
func UserAgentAAD(auditID string) ([]byte, error) {
	if auditID == "" {
		return nil, errors.New("headerblock: empty audit id")
	}
	return security.AAD(auditID, userAgentAADPurpose)
}

// SealUserAgent encrypts the values without compression. It returns nil for
// an absent Header, which BeginAudit stores as NULL.
func SealUserAgent(c security.Cipher, auditID string, values []string) ([]byte, error) {
	if c == nil {
		return nil, errors.New("headerblock: nil cipher")
	}
	plaintext := EncodeUserAgent(values)
	if plaintext == nil {
		return nil, nil
	}
	defer clear(plaintext)
	aad, err := UserAgentAAD(auditID)
	if err != nil {
		return nil, err
	}
	enc, err := c.Encrypt(aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("headerblock: encrypt user agent: %w", err)
	}
	return enc, nil
}

// OpenUserAgent authenticates and decodes user_agent_enc. Empty enc (NULL)
// means the Header was absent and returns nil.
func OpenUserAgent(c security.Cipher, auditID string, enc []byte) ([]string, error) {
	if len(enc) == 0 {
		return nil, nil
	}
	if c == nil {
		return nil, errors.New("headerblock: nil cipher")
	}
	aad, err := UserAgentAAD(auditID)
	if err != nil {
		return nil, err
	}
	plaintext, err := c.Decrypt(aad, enc)
	if err != nil {
		return nil, fmt.Errorf("%w: user agent does not authenticate", ErrIntegrity)
	}
	defer clear(plaintext)
	return DecodeUserAgent(plaintext)
}
