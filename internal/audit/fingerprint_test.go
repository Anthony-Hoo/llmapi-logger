package audit

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/routing"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

func newFingerprintTestManager(t *testing.T, fingerprints *security.CredentialFingerprinter) (*Manager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := sqlite.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cipher, err := security.NewAESGCM(make([]byte, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(store, cipher, fingerprints, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return manager, path
}

// storedFingerprint reads the column directly because no read path exposes it:
// the fingerprint is an internal scoping index and must never reach a DTO.
func storedFingerprint(t *testing.T, path, auditID string) []byte {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var fingerprint []byte
	if err := database.QueryRow(`SELECT api_key_fpr FROM audit_records WHERE audit_id = ?`, auditID).Scan(&fingerprint); err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func TestBeginTagsEveryCredentialTransportWithOneFingerprint(t *testing.T) {
	t.Parallel()
	fingerprints, err := security.NewCredentialFingerprinter(bytes.Repeat([]byte{0x44}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	want := fingerprints.Fingerprint("sk-devkey123")

	cases := []struct {
		name    string
		target  string
		headers map[string]string
	}{
		{
			name:    "authorization bearer",
			target:  "http://audit-proxy/v1/chat/completions",
			headers: map[string]string{"Authorization": "Bearer sk-devkey123"},
		},
		{
			name:    "anthropic header",
			target:  "http://audit-proxy/v1/messages",
			headers: map[string]string{"X-Api-Key": "sk-devkey123"},
		},
		{
			name:    "gemini header",
			target:  "http://audit-proxy/v1beta/models/gemini:generateContent",
			headers: map[string]string{"X-Goog-Api-Key": "sk-devkey123"},
		},
		{
			name:   "gemini query parameter",
			target: "http://audit-proxy/v1beta/models/gemini:generateContent?key=sk-devkey123",
		},
		{
			name:    "channel suffixed key",
			target:  "http://audit-proxy/v1/chat/completions",
			headers: map[string]string{"Authorization": "Bearer sk-devkey123-channel"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			manager, path := newFingerprintTestManager(t, fingerprints)
			request := httptest.NewRequest(http.MethodPost, testCase.target, http.NoBody)
			for name, value := range testCase.headers {
				request.Header.Set(name, value)
			}
			session, err := manager.Begin(context.Background(), request, routing.Match{
				RouteID: "chat", Parser: "openai.chat_completions",
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := storedFingerprint(t, path, session.ID()); !bytes.Equal(got, want) {
				t.Fatalf("stored fingerprint = %x, want %x", got, want)
			}
		})
	}
}

func TestBeginStoresNoFingerprintWithoutCredentialOrFingerprinter(t *testing.T) {
	t.Parallel()
	fingerprints, err := security.NewCredentialFingerprinter(bytes.Repeat([]byte{0x44}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("request without a credential", func(t *testing.T) {
		manager, path := newFingerprintTestManager(t, fingerprints)
		request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
		session, err := manager.Begin(context.Background(), request, routing.Match{
			RouteID: "chat", Parser: "openai.chat_completions",
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := storedFingerprint(t, path, session.ID()); got != nil {
			t.Fatalf("stored fingerprint = %x, want NULL", got)
		}
	})

	t.Run("fingerprinting disabled", func(t *testing.T) {
		manager, path := newFingerprintTestManager(t, nil)
		request := httptest.NewRequest(http.MethodPost, "http://audit-proxy/v1/chat/completions", http.NoBody)
		request.Header.Set("Authorization", "Bearer sk-devkey123")
		session, err := manager.Begin(context.Background(), request, routing.Match{
			RouteID: "chat", Parser: "openai.chat_completions",
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := storedFingerprint(t, path, session.ID()); got != nil {
			t.Fatalf("stored fingerprint = %x, want NULL", got)
		}
	})
}
