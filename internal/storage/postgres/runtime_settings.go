package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/storage"
)

func validSettingsSection(section string) bool {
	return section == storage.SettingsSessionAnalysis || section == storage.SettingsOrgReports
}

// LoadRuntimeSettings reads the saved settings of one section; sql.ErrNoRows
// when the section was never saved or was reset.
func (store *Store) LoadRuntimeSettings(ctx context.Context, section string) (storage.RuntimeSettings, error) {
	if ctx == nil {
		return storage.RuntimeSettings{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return storage.RuntimeSettings{}, ErrClosed
	}
	if !validSettingsSection(section) {
		return storage.RuntimeSettings{}, errors.New("postgres: unknown settings section")
	}
	row := storage.RuntimeSettings{Section: section}
	err := store.readerDB.QueryRowContext(ctx, `
SELECT r.settings, r.secret_enc, r.updated_at_ns FROM runtime_settings AS r WHERE r.section = $1`, section).
		Scan(&row.Settings, &row.SecretEnc, &row.UpdatedAtNS)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.RuntimeSettings{}, sql.ErrNoRows
		}
		return storage.RuntimeSettings{}, fmt.Errorf("postgres: read runtime settings: %w", err)
	}
	return row, nil
}

// SaveRuntimeSettings replaces the saved settings of one section, secret
// included: an empty SecretEnc stores no secret.
func (store *Store) SaveRuntimeSettings(ctx context.Context, row storage.RuntimeSettings) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if !validSettingsSection(row.Section) || row.Settings == "" || row.UpdatedAtNS <= 0 {
		return errors.New("postgres: invalid runtime settings")
	}
	owned := row
	owned.SecretEnc = append([]byte(nil), row.SecretEnc...)
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		_, err := tx.Exec(`
INSERT INTO runtime_settings (section, settings, secret_enc, updated_at_ns) VALUES ($1, $2, $3, $4)
ON CONFLICT (section) DO UPDATE SET
    settings = excluded.settings, secret_enc = excluded.secret_enc, updated_at_ns = excluded.updated_at_ns`,
			owned.Section, owned.Settings, nullableBytes(owned.SecretEnc), owned.UpdatedAtNS)
		if err != nil {
			return fmt.Errorf("postgres writer: save runtime settings: %w", err)
		}
		return nil
	})})
}

// DeleteRuntimeSettings removes the saved settings of one section, so the
// configuration file applies again. Deleting a section that was never saved
// is not an error.
func (store *Store) DeleteRuntimeSettings(ctx context.Context, section string) error {
	if ctx == nil {
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	if !validSettingsSection(section) {
		return errors.New("postgres: unknown settings section")
	}
	return store.submitSync(ctx, writeRequest{kind: writeDerived, data: derivedWrite(func(tx dbTransaction) error {
		if _, err := tx.Exec(`DELETE FROM runtime_settings WHERE section = $1`, section); err != nil {
			return fmt.Errorf("postgres writer: delete runtime settings: %w", err)
		}
		return nil
	})})
}
