package audit

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"llmapi-logger/internal/security"
)

type noUnifiedStore struct{ Store }

func (noUnifiedStore) SupportsUnifiedWrite() bool { return false }

func optionsCipher(t *testing.T) security.Cipher {
	t.Helper()
	cipher, err := security.NewAESGCM(make([]byte, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func TestManagerOptionsDefaultToLegacy(t *testing.T) {
	manager, err := NewManager(&bufferStore{}, optionsCipher(t), nil, ModeAvailable, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if manager.WritePath() != WritePathLegacy || manager.CommitRetries() != 0 {
		t.Fatalf("write path %s, retries %d", manager.WritePath(), manager.CommitRetries())
	}
}

func TestManagerRefusesUnifiedOnAStoreThatCannotServeIt(t *testing.T) {
	_, err := NewManagerWithOptions(noUnifiedStore{}, optionsCipher(t), nil, ModeStrict, nil, Options{WritePath: WritePathUnified, CommitRetries: 3})
	if err == nil || !strings.Contains(err.Error(), "cannot serve audit.write_path unified") {
		t.Fatalf("error = %v", err)
	}
	if _, err := NewManagerWithOptions(noUnifiedStore{}, optionsCipher(t), nil, ModeStrict, nil, Options{WritePath: WritePathLegacy}); err != nil {
		t.Fatalf("legacy refused: %v", err)
	}
}

func TestManagerOptionsValidation(t *testing.T) {
	for _, options := range []Options{
		{WritePath: "fast"},
		{CommitRetries: -1},
		{CommitRetries: 6},
		{StageBytes: 1<<20 - 1},
		{StageBytes: 4 << 20, GlobalBytes: 2 << 20},
	} {
		if _, err := NewManagerWithOptions(&bufferStore{}, optionsCipher(t), nil, ModeAvailable, nil, options); err == nil {
			t.Fatalf("options %+v accepted", options)
		}
	}
}

func TestSetCommitRetriesClamps(t *testing.T) {
	manager, err := NewManagerWithOptions(&bufferStore{}, optionsCipher(t), nil, ModeAvailable, nil, Options{CommitRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if manager.CommitRetries() != 2 {
		t.Fatalf("retries = %d", manager.CommitRetries())
	}
	for value, want := range map[int]int{0: 0, 5: 5, -3: 0, 9: 5, 4: 4} {
		manager.SetCommitRetries(value)
		if manager.CommitRetries() != want {
			t.Fatalf("SetCommitRetries(%d) = %d, want %d", value, manager.CommitRetries(), want)
		}
	}
}
