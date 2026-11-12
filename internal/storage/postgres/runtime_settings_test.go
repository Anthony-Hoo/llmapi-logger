package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"

	"llmapi-logger/internal/storage"
)

func TestRuntimeSettingsStorage(t *testing.T) {
	t.Parallel()
	store, _ := openTestStore(t)
	ctx := context.Background()

	if _, err := store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("nothing saved: %v", err)
	}
	// Resetting a section that was never saved is fine.
	if err := store.DeleteRuntimeSettings(ctx, storage.SettingsSessionAnalysis); err != nil {
		t.Fatal(err)
	}
	row := storage.RuntimeSettings{Section: storage.SettingsSessionAnalysis, Settings: `{"run_at":"03:30"}`, SecretEnc: []byte{1, 2, 3}, UpdatedAtNS: 10}
	if err := store.SaveRuntimeSettings(ctx, row); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis)
	if err != nil || loaded.Settings != row.Settings || !bytes.Equal(loaded.SecretEnc, row.SecretEnc) || loaded.UpdatedAtNS != 10 || loaded.Section != row.Section {
		t.Fatalf("loaded = %+v, %v", loaded, err)
	}
	// A second save replaces the row; an empty secret stores none.
	row.Settings, row.SecretEnc, row.UpdatedAtNS = `{"run_at":"04:00"}`, nil, 20
	if err := store.SaveRuntimeSettings(ctx, row); err != nil {
		t.Fatal(err)
	}
	if loaded, err = store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis); err != nil || loaded.Settings != row.Settings || len(loaded.SecretEnc) != 0 || loaded.UpdatedAtNS != 20 {
		t.Fatalf("replaced = %+v, %v", loaded, err)
	}
	// Sections are independent.
	if err := store.SaveRuntimeSettings(ctx, storage.RuntimeSettings{Section: storage.SettingsOrgReports, Settings: `{}`, UpdatedAtNS: 30}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteRuntimeSettings(ctx, storage.SettingsSessionAnalysis); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadRuntimeSettings(ctx, storage.SettingsSessionAnalysis); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("after reset: %v", err)
	}
	if other, err := store.LoadRuntimeSettings(ctx, storage.SettingsOrgReports); err != nil || other.UpdatedAtNS != 30 {
		t.Fatalf("other section = %+v, %v", other, err)
	}

	for _, bad := range []storage.RuntimeSettings{
		{Section: "billing", Settings: `{}`, UpdatedAtNS: 1},
		{Section: storage.SettingsOrgReports, Settings: ``, UpdatedAtNS: 1},
		{Section: storage.SettingsOrgReports, Settings: `{}`},
	} {
		if err := store.SaveRuntimeSettings(ctx, bad); err == nil {
			t.Fatalf("saved %+v", bad)
		}
	}
	if _, err := store.LoadRuntimeSettings(ctx, "billing"); err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unknown section read: %v", err)
	}
	if err := store.DeleteRuntimeSettings(ctx, "billing"); err == nil {
		t.Fatal("unknown section deleted")
	}
}
