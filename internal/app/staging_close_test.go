package app

import (
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/storage"
)

// Closing the application closes the stager after the store: what is still
// queued is written and synced for the next start to import, the writer
// stops, and nothing is staged afterwards.
func TestCloseDrainsTheStager(t *testing.T) {
	directory := t.TempDir()
	configuration := testConfig(t)
	configuration.DBPath = filepath.Join(directory, "audit.db")
	configuration.KeyPath = filepath.Join(directory, "key", "audit.key")
	configuration.RetentionDays = 0
	configuration.AdminToken = "synthetic-test-admin"
	application, err := newSQLiteTest(configuration, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	stager := application.auditStager
	if stager == nil || application.cipher == nil {
		_ = application.Close()
		t.Fatal("no stager assembled")
	}
	const id = "apx_staged_at_close"
	piece := make([]byte, 4096)
	for index := range piece {
		piece[index] = byte(index)
	}
	if _, err := stager.Stage(sealStageChunk(t, application.cipher, id, storage.StageRequestReceived, 0, 0, piece)); err != nil {
		t.Fatal(err)
	}
	// The commit failed: the file stays for the store or the next start.
	stager.Keep(id)
	if err := application.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stager.Stage(sealStageChunk(t, application.cipher, id, storage.StageRequestReceived, 1, 4096, piece)); !errors.Is(err, staging.ErrClosed) {
		t.Fatalf("stage after close: %v", err)
	}
	scan, err := staging.ScanFile(application.cipher, id, filepath.Join(configuration.Audit.Staging.Dir, id+staging.Suffix))
	if err != nil || len(scan.Records) != 1 || scan.TornTail || scan.Damage != "" {
		t.Fatalf("staging file after close: %d records, torn %v, damage %q, %v", len(scan.Records), scan.TornTail, scan.Damage, err)
	}
}
