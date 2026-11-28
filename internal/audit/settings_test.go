package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/storage"
)

// settingsMemory is an in-memory SettingsStore. While fail is set every read
// fails with it.
type settingsMemory struct {
	mu   sync.Mutex
	rows map[string]storage.RuntimeSettings
	fail error
}

func (store *settingsMemory) LoadRuntimeSettings(_ context.Context, section string) (storage.RuntimeSettings, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.fail != nil {
		return storage.RuntimeSettings{}, store.fail
	}
	row, ok := store.rows[section]
	if !ok {
		return storage.RuntimeSettings{}, sql.ErrNoRows
	}
	return row, nil
}

func (store *settingsMemory) SaveRuntimeSettings(_ context.Context, row storage.RuntimeSettings) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.rows == nil {
		store.rows = map[string]storage.RuntimeSettings{}
	}
	store.rows[row.Section] = row
	return nil
}

func (store *settingsMemory) DeleteRuntimeSettings(_ context.Context, section string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.rows, section)
	return nil
}

func (store *settingsMemory) setFail(err error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.fail = err
}

func (store *settingsMemory) row() (storage.RuntimeSettings, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	row, ok := store.rows[storage.SettingsAuditCapture]
	return row, ok
}

// retryRecorder records every value handed to SetCommitRetries.
type retryRecorder struct{ values []int }

func (recorder *retryRecorder) SetCommitRetries(retries int) {
	recorder.values = append(recorder.values, retries)
}

func (recorder *retryRecorder) last() int {
	if len(recorder.values) == 0 {
		return -1
	}
	return recorder.values[len(recorder.values)-1]
}

func savedCapture(retries string, version int64) map[string]storage.RuntimeSettings {
	return map[string]storage.RuntimeSettings{storage.SettingsAuditCapture: {
		Section: storage.SettingsAuditCapture, Settings: retries, UpdatedAtNS: version,
	}}
}

func newCaptureSettings(t *testing.T, store SettingsStore, manager CommitRetrySetter, logs *bytes.Buffer) *CaptureSettings {
	t.Helper()
	options := CaptureSettingsOptions{FileRetries: 3, WritePath: WritePathUnified, Store: store, Manager: manager}
	if logs != nil {
		options.Logger = slog.New(slog.NewTextHandler(logs, nil))
	}
	service, err := NewCaptureSettings(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestCaptureSettingsSaveAndResetReachTheManager(t *testing.T) {
	ctx := context.Background()
	store := &settingsMemory{}
	manager, err := NewManagerWithOptions(&commitStore{}, optionsCipher(t), nil, ModeAvailable, nil, Options{CommitRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	service := newCaptureSettings(t, store, manager, nil)
	initial, err := service.Get(ctx)
	if err != nil || initial.Source != CaptureSettingsSourceFile || initial.Settings.CommitRetries != 3 || initial.File.CommitRetries != 3 ||
		initial.UpdatedNS != 0 || initial.WritePath != WritePathUnified || manager.CommitRetries() != 3 {
		t.Fatalf("initial = %+v, %v; manager %d", initial, err, manager.CommitRetries())
	}

	saved, err := service.Update(ctx, CaptureEditableSettings{CommitRetries: 0})
	if err != nil || saved.Source != CaptureSettingsSourceSaved || saved.Settings.CommitRetries != 0 || saved.File.CommitRetries != 3 || saved.UpdatedNS == 0 {
		t.Fatalf("saved = %+v, %v", saved, err)
	}
	if manager.CommitRetries() != 0 {
		t.Fatalf("manager after save = %d", manager.CommitRetries())
	}
	if row, ok := store.row(); !ok || row.Settings != `{"commit_retries":0}` || row.UpdatedAtNS != saved.UpdatedNS || len(row.SecretEnc) != 0 {
		t.Fatalf("stored row = %+v", row)
	}
	if view, _ := service.Get(ctx); view.Source != CaptureSettingsSourceSaved || view.Settings.CommitRetries != 0 || view.UpdatedNS != saved.UpdatedNS {
		t.Fatalf("view after save = %+v", view)
	}
	if _, err := service.Update(ctx, CaptureEditableSettings{CommitRetries: 5}); err != nil || manager.CommitRetries() != 5 {
		t.Fatalf("save 5 = %v; manager %d", err, manager.CommitRetries())
	}

	reset, err := service.Reset(ctx)
	if err != nil || reset.Source != CaptureSettingsSourceFile || reset.Settings.CommitRetries != 3 || reset.UpdatedNS != 0 {
		t.Fatalf("reset = %+v, %v", reset, err)
	}
	if _, ok := store.row(); ok || manager.CommitRetries() != 3 {
		t.Fatalf("after reset: row kept %v, manager %d", ok, manager.CommitRetries())
	}
}

func TestCaptureSettingsRejectValuesOutOfRange(t *testing.T) {
	ctx := context.Background()
	store := &settingsMemory{}
	recorder := &retryRecorder{}
	service := newCaptureSettings(t, store, recorder, nil)
	for _, retries := range []int{-1, 6, 100} {
		_, err := service.Update(ctx, CaptureEditableSettings{CommitRetries: retries})
		if !errors.Is(err, ErrInvalidSettings) || SettingsMessage(err) != "audit.commit_retries must be between 0 and 5" {
			t.Fatalf("%d: %v (%q)", retries, err, SettingsMessage(err))
		}
	}
	if _, ok := store.row(); ok || len(recorder.values) != 1 || recorder.last() != 3 {
		t.Fatalf("a rejected change was saved or applied: %v", recorder.values)
	}
	if SettingsMessage(errors.New("other")) != "" {
		t.Fatal("a foreign error has a settings message")
	}
	// The configuration file's value is validated by the configuration; the
	// service refuses one out of range rather than clamp it silently.
	if _, err := NewCaptureSettings(ctx, CaptureSettingsOptions{FileRetries: 9, Store: store, Manager: recorder}); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("file value 9 accepted: %v", err)
	}
	if _, err := NewCaptureSettings(ctx, CaptureSettingsOptions{FileRetries: 3, Store: store}); err == nil {
		t.Fatal("no manager accepted")
	}
}

func TestCaptureSettingsAreAppliedAtStartup(t *testing.T) {
	store := &settingsMemory{rows: savedCapture(`{"commit_retries":1}`, 5)}
	recorder := &retryRecorder{}
	service := newCaptureSettings(t, store, recorder, nil)
	if len(recorder.values) != 1 || recorder.last() != 1 {
		t.Fatalf("start applied %v", recorder.values)
	}
	if view, err := service.Get(context.Background()); err != nil || view.Source != CaptureSettingsSourceSaved || view.Settings.CommitRetries != 1 || view.UpdatedNS != 5 {
		t.Fatalf("view after a restart = %+v, %v", view, err)
	}
	// A saved section that no longer validates or cannot be parsed is ignored
	// with a warning: the file's value applies.
	for name, settings := range map[string]string{
		"out of range": `{"commit_retries":9}`,
		"negative":     `{"commit_retries":-1}`,
		"unknown":      `{"commit_retries":1,"write_path":"legacy"}`,
		"missing":      `{}`,
		"not a number": `{"commit_retries":"2"}`,
		"not json":     `retries`,
	} {
		store.rows = savedCapture(settings, 6)
		recorder := &retryRecorder{}
		logs := &bytes.Buffer{}
		ignored := newCaptureSettings(t, store, recorder, logs)
		if len(recorder.values) != 1 || recorder.last() != 3 {
			t.Fatalf("%s: start applied %v", name, recorder.values)
		}
		if !strings.Contains(logs.String(), "runtime_settings_invalid") {
			t.Fatalf("%s: no warning: %s", name, logs.String())
		}
		if view, err := ignored.Get(context.Background()); err != nil || view.Source != CaptureSettingsSourceFile || view.Settings.CommitRetries != 3 {
			t.Fatalf("%s: view = %+v, %v", name, view, err)
		}
		// Such a row is the file-applies state and stays writable.
		if view, err := ignored.Update(context.Background(), CaptureEditableSettings{CommitRetries: 2}); err != nil || view.Settings.CommitRetries != 2 || recorder.last() != 2 {
			t.Fatalf("%s: update over an unusable row = %+v, %v", name, view, err)
		}
	}
	// A store that cannot be read at start: the file's value applies.
	store.rows = savedCapture(`{"commit_retries":1}`, 7)
	store.setFail(errors.New("database unavailable"))
	recorder = &retryRecorder{}
	logs := &bytes.Buffer{}
	newCaptureSettings(t, store, recorder, logs)
	if recorder.last() != 3 || !strings.Contains(logs.String(), "runtime_settings_invalid") {
		t.Fatalf("store error at start applied %v: %s", recorder.values, logs.String())
	}
}

// No write starts from the configuration file because the saved row could
// not be read: Update and Reset refuse with ErrSettingsUnavailable and save
// nothing, while Get still answers with the file.
func TestCaptureSettingsWritesRefuseWhenTheSavedSectionCannotBeRead(t *testing.T) {
	ctx := context.Background()
	const saved = `{"commit_retries":1}`
	writes := map[string]func(*CaptureSettings) error{
		"update": func(service *CaptureSettings) error {
			_, err := service.Update(ctx, CaptureEditableSettings{CommitRetries: 4})
			return err
		},
		"reset": func(service *CaptureSettings) error {
			_, err := service.Reset(ctx)
			return err
		},
	}
	for name, write := range writes {
		t.Run(name, func(t *testing.T) {
			store := &settingsMemory{rows: savedCapture(saved, 5)}
			recorder := &retryRecorder{}
			service := newCaptureSettings(t, store, recorder, nil)
			store.setFail(errors.New("transient: reader pool exhausted"))
			view, err := service.Get(ctx)
			if err != nil || view.Source != CaptureSettingsSourceFile || view.Settings.CommitRetries != 3 || view.UpdatedNS != 0 {
				t.Fatalf("read during the error = %+v, %v", view, err)
			}
			if err := write(service); !errors.Is(err, ErrSettingsUnavailable) {
				t.Fatalf("write during the error = %v", err)
			}
			store.setFail(nil)
			if row, _ := store.row(); row.UpdatedAtNS != 5 || row.Settings != saved {
				t.Fatalf("a refused write changed the saved row: %+v", row)
			}
			if len(recorder.values) != 1 || recorder.last() != 1 {
				t.Fatalf("a refused write reached the manager: %v", recorder.values)
			}
		})
	}
	// Without a store (the audit storage could not be opened) reads answer
	// with the file and nothing can be written.
	recorder := &retryRecorder{}
	bare := newCaptureSettings(t, nil, recorder, nil)
	if view, err := bare.Get(ctx); err != nil || view.Source != CaptureSettingsSourceFile || view.Settings.CommitRetries != 3 {
		t.Fatalf("read without a store = %+v, %v", view, err)
	}
	if _, err := bare.Update(ctx, CaptureEditableSettings{CommitRetries: 1}); !errors.Is(err, ErrSettingsUnavailable) {
		t.Fatalf("update without a store = %v", err)
	}
	if _, err := bare.Reset(ctx); !errors.Is(err, ErrSettingsUnavailable) {
		t.Fatalf("reset without a store = %v", err)
	}
	if len(recorder.values) != 1 || recorder.last() != 3 {
		t.Fatalf("manager without a store: %v", recorder.values)
	}
}

func TestCaptureSettingsVersionsIncreaseStrictly(t *testing.T) {
	ctx := context.Background()
	// The saved row carries a version ahead of the clock, and the clock
	// stands still: every save still gets a version above the last one.
	store := &settingsMemory{rows: savedCapture(`{"commit_retries":1}`, 5_000)}
	fixed := time.Unix(0, 1_000)
	service, err := NewCaptureSettings(ctx, CaptureSettingsOptions{FileRetries: 3, Store: store, Manager: &retryRecorder{}, Now: func() time.Time { return fixed }})
	if err != nil {
		t.Fatal(err)
	}
	previous := int64(5_000)
	for _, retries := range []int{2, 2, 0} {
		view, err := service.Update(ctx, CaptureEditableSettings{CommitRetries: retries})
		if err != nil || view.UpdatedNS <= previous {
			t.Fatalf("save %d = %d after %d, %v", retries, view.UpdatedNS, previous, err)
		}
		previous = view.UpdatedNS
	}
	// After a reset and a save, the version still does not go back.
	if _, err := service.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if view, err := service.Update(ctx, CaptureEditableSettings{CommitRetries: 4}); err != nil || view.UpdatedNS <= previous {
		t.Fatalf("save after reset = %d after %d, %v", view.UpdatedNS, previous, err)
	}
	// A row another process saved with a later version is replaced by a later
	// one still.
	store.rows = savedCapture(`{"commit_retries":1}`, 9_000)
	if view, err := service.Update(ctx, CaptureEditableSettings{CommitRetries: 2}); err != nil || view.UpdatedNS <= 9_000 {
		t.Fatalf("save over a newer row = %d, %v", view.UpdatedNS, err)
	}
}
