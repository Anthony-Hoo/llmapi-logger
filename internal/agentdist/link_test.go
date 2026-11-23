package agentdist

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDownloadKeyDerivation(t *testing.T) {
	want := sha256.Sum256([]byte("llmapi-logger/agent-download/v1\x00" + testAdminToken))
	if got := DownloadKey(testAdminToken); string(got) != string(want[:]) {
		t.Fatal("DownloadKey does not follow the contract's derivation")
	}
	if string(DownloadKey("a")) == string(DownloadKey("b")) {
		t.Fatal("different tokens give the same key")
	}
}

func TestSignatureFormat(t *testing.T) {
	clk := newClock()
	signer, err := NewSigner(testAdminToken, clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	signature, expires := signer.Mint()
	if !expires.Equal(clk.now.Add(30 * time.Minute)) {
		t.Fatalf("expiry %v, want now + 30 minutes", expires)
	}
	payload, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("signature is not unpadded base64url: %v", err)
	}
	unix := strconv.FormatInt(expires.Unix(), 10)
	if len(payload) != len(unix)+1+16+32 || string(payload[:len(unix)+1]) != unix+"." {
		t.Fatalf("payload is not expires_unix || \".\" || 16-byte nonce || 32-byte MAC: %d bytes", len(payload))
	}
	nonce := payload[len(unix)+1 : len(unix)+17]
	if string(payload) != string(signWith(unix, nonce)) {
		t.Fatal("MAC is not HMAC-SHA-256(K_dl, expires_unix || \".\" || nonce)")
	}
	// Two links of the same second differ in their nonce.
	second, sameExpiry := signer.Mint()
	if second == signature || !sameExpiry.Equal(expires) {
		t.Fatalf("two links minted in one second are equal: %s", signature)
	}
}

// signWith builds a payload exactly as the contract describes it.
func signWith(unix string, nonce []byte) []byte {
	mac := hmac.New(sha256.New, DownloadKey(testAdminToken))
	mac.Write([]byte(unix + "."))
	mac.Write(nonce)
	return append(append([]byte(unix+"."), nonce...), mac.Sum(nil)...)
}

func TestVerifyRoundTripAndExpiry(t *testing.T) {
	clk := newClock()
	signer, _ := NewSigner(testAdminToken, clk.Now)
	signature, expires := signer.Mint()
	got, err := signer.Verify(signature)
	if err != nil || !got.Equal(expires) {
		t.Fatalf("fresh signature: %v, %v", got, err)
	}
	clk.advance(30*time.Minute - time.Second)
	if _, err := signer.Verify(signature); err != nil {
		t.Fatalf("signature rejected one second before expiry: %v", err)
	}
	clk.advance(time.Second)
	if _, err := signer.Verify(signature); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("signature at expiry: %v, want ErrLinkExpired", err)
	}
	clk.advance(24 * time.Hour)
	if _, err := signer.Verify(signature); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("old signature: %v, want ErrLinkExpired", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	clk := newClock()
	signer, _ := NewSigner(testAdminToken, clk.Now)
	signature, _ := signer.Mint()
	payload, _ := base64.RawURLEncoding.DecodeString(signature)
	for index := range payload {
		tampered := append([]byte(nil), payload...)
		tampered[index] ^= 0x01
		if _, err := signer.Verify(base64.RawURLEncoding.EncodeToString(tampered)); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("flipping byte %d: %v, want ErrBadSignature", index, err)
		}
	}
	other, _ := NewSigner("another-admin-token", clk.Now)
	if _, err := other.Verify(signature); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signature under another admin token: %v", err)
	}
	// An expired signature under another key must look like a bad one, not
	// like an expired one.
	clk.advance(time.Hour)
	if _, err := other.Verify(signature); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expired signature under another key: %v, want ErrBadSignature", err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	clk := newClock()
	signer, _ := NewSigner(testAdminToken, clk.Now)
	signature, _ := signer.Mint()
	nonce := make([]byte, 16)
	sign := func(unix string) string {
		return base64.RawURLEncoding.EncodeToString(signWith(unix, nonce))
	}
	// The format before nonces: expires_unix || "." || HMAC(K_dl, expires_unix).
	legacy := func(unix string) string {
		mac := hmac.New(sha256.New, DownloadKey(testAdminToken))
		mac.Write([]byte(unix))
		return base64.RawURLEncoding.EncodeToString(append([]byte(unix+"."), mac.Sum(nil)...))
	}
	expires := strconv.FormatInt(clk.now.Add(10*time.Minute).Unix(), 10)
	cases := map[string]string{
		"empty":           "",
		"padded":          signature + "=",
		"standard base64": base64.StdEncoding.EncodeToString([]byte("x")),
		"not base64":      "!!!!",
		"too long":        signature + signature,
		"no dot":          base64.RawURLEncoding.EncodeToString(make([]byte, 40)),
		"short mac":       base64.RawURLEncoding.EncodeToString([]byte(expires + ".abc")),
		"leading zero":    sign("0" + expires),
		"negative":        sign("-" + expires),
		"far future":      sign(strconv.FormatInt(clk.now.Add(48*time.Hour).Unix(), 10)),
		"non digit":       sign(expires[:5] + "a" + expires[6:]),
		"without nonce":   legacy(expires),
		"short nonce":     base64.RawURLEncoding.EncodeToString(signWith(expires, nonce[:8])),
	}
	for name, input := range cases {
		if _, err := signer.Verify(input); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v, want ErrBadSignature", name, err)
		}
	}
	// The same payload spelled with non-zero padding bits in the last
	// character is refused, so one link has one spelling and one budget.
	canonical := sign(expires)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if len(canonical)%4 == 0 {
		t.Fatal("the payload length leaves no padding bits; pick another length")
	}
	last := strings.IndexByte(alphabet, canonical[len(canonical)-1])
	respelled := canonical[:len(canonical)-1] + string(alphabet[last|1])
	if decoded, err := base64.RawURLEncoding.DecodeString(respelled); err != nil || string(decoded) != string(signWith(expires, nonce)) {
		t.Fatal("the respelling does not decode leniently to the same payload; the case tests nothing")
	}
	if _, err := signer.Verify(respelled); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("non-canonical spelling: %v, want ErrBadSignature", err)
	}
	if _, err := signer.Verify(canonical); err != nil {
		t.Fatalf("a correctly signed near expiry was rejected: %v", err)
	}
}

// TestVerifyHasOneSpellingPerLink: every re-spelling of a valid signature
// that a client can construct is refused, so one link has exactly one
// spelling (and so one download budget). The decoder alone would accept CR
// and LF anywhere.
func TestVerifyHasOneSpellingPerLink(t *testing.T) {
	clk := newClock()
	signer, _ := NewSigner(testAdminToken, clk.Now)
	signature, _ := signer.Mint()
	if len(signature) != SignatureLength {
		t.Fatalf("minted signature has %d characters, want %d", len(signature), SignatureLength)
	}
	if _, err := signer.Verify(signature); err != nil {
		t.Fatalf("canonical spelling: %v", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	variants := map[string]string{
		"padding":         signature + "=",
		"double padding":  signature + "==",
		"std alphabet":    base64.RawStdEncoding.EncodeToString(mustDecode(t, signature)),
		"std padded":      base64.StdEncoding.EncodeToString(mustDecode(t, signature)),
		"trailing data":   signature + "A",
		"trailing slash":  signature + "/",
		"leading space":   " " + signature,
		"trailing space":  signature + " ",
		"tab inside":      signature[:5] + "\t" + signature[5:],
		"NUL at end":      signature + "\x00",
		"percent escape":  signature[:3] + "%41" + signature[4:],
		"one char short":  signature[:len(signature)-1],
		"non-ASCII":       signature[:len(signature)-1] + "é",
		"last char + one": signature[:len(signature)-1] + string(alphabet[(strings.IndexByte(alphabet, signature[len(signature)-1])+1)%64]),
	}
	for index := 0; index <= len(signature); index++ {
		for _, insert := range []string{"\n", "\r", "\r\n", "\n\r"} {
			variants[fmt.Sprintf("%q at %d", insert, index)] = signature[:index] + insert + signature[index:]
		}
	}
	// Removing one character and adding a CR keeps the length.
	for index := 0; index < len(signature); index++ {
		variants[fmt.Sprintf("CR in place of %d", index)] = signature[:index] + "\r" + signature[index+1:]
	}
	for index := 0; index < len(signature); index++ {
		char := signature[index]
		switch {
		case char >= 'a' && char <= 'z':
			variants[fmt.Sprintf("upper %d", index)] = signature[:index] + string(char-32) + signature[index+1:]
		case char >= 'A' && char <= 'Z':
			variants[fmt.Sprintf("lower %d", index)] = signature[:index] + string(char+32) + signature[index+1:]
		}
	}
	for name, variant := range variants {
		if variant == signature {
			continue
		}
		if _, err := signer.Verify(variant); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v, want ErrBadSignature", name, err)
		}
	}
	// The verified link names its nonce, which is what budgets are kept by.
	link, err := signer.VerifyLink(signature)
	payload := mustDecode(t, signature)
	if err != nil || link.Nonce != string(payload[expiryDigits+1:expiryDigits+1+16]) {
		t.Fatalf("VerifyLink: %+v, %v", link, err)
	}
}

func mustDecode(t *testing.T, signature string) []byte {
	t.Helper()
	payload, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestNewSignerRequiresToken(t *testing.T) {
	if _, err := NewSigner("", nil); err == nil {
		t.Fatal("empty admin token accepted")
	}
}
