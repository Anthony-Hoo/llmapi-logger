package agentdist

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
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
	mac := hmac.New(sha256.New, DownloadKey(testAdminToken))
	mac.Write([]byte(unix))
	want := append([]byte(unix+"."), mac.Sum(nil)...)
	if string(payload) != string(want) {
		t.Fatal("payload is not expires_unix || \".\" || HMAC-SHA-256(K_dl, expires_unix)")
	}
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
	sign := func(unix string) string {
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
	}
	for name, input := range cases {
		if _, err := signer.Verify(input); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v, want ErrBadSignature", name, err)
		}
	}
	if _, err := signer.Verify(sign(expires)); err != nil {
		t.Fatalf("a correctly signed near expiry was rejected: %v", err)
	}
}

func TestNewSignerRequiresToken(t *testing.T) {
	if _, err := NewSigner("", nil); err == nil {
		t.Fatal("empty admin token accepted")
	}
}
