package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"llmapi-logger/internal/contentpolicy"
)

// Compile-time assertion that the store satisfies the domain repository.
var _ contentpolicy.Repository = (*Store)(nil)

// ListContentPolicyRules returns every persisted rule in stable ID order. An
// empty result means no interception; migration 010 installs no seed rule.
func (store *Store) ListContentPolicyRules(ctx context.Context) ([]contentpolicy.Rule, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT id, name, enabled, action, model_pattern, scan_scopes, keywords, created_at_ns, updated_at_ns
FROM content_policy_rules
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list content policy rules: %w", err)
	}
	defer rows.Close()
	rules := make([]contentpolicy.Rule, 0)
	for rows.Next() {
		var rule contentpolicy.Rule
		var enabled int
		var scanScopesJSON, keywordsJSON string
		if err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&enabled,
			&rule.Action,
			&rule.ModelPattern,
			&scanScopesJSON,
			&keywordsJSON,
			&rule.CreatedAtNS,
			&rule.UpdatedAtNS,
		); err != nil {
			return nil, fmt.Errorf("sqlite: scan content policy rule: %w", err)
		}
		rule.Enabled = enabled != 0
		if err := json.Unmarshal([]byte(scanScopesJSON), &rule.ScanScopes); err != nil {
			return nil, fmt.Errorf("sqlite: decode content policy rule %d scan scopes: %w", rule.ID, err)
		}
		if err := json.Unmarshal([]byte(keywordsJSON), &rule.Keywords); err != nil {
			return nil, fmt.Errorf("sqlite: decode content policy rule %d keywords: %w", rule.ID, err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate content policy rules: %w", err)
	}
	return rules, nil
}

// CreateContentPolicyRule inserts one rule with the service-assigned stable ID.
func (store *Store) CreateContentPolicyRule(ctx context.Context, rule contentpolicy.Rule) (contentpolicy.Rule, error) {
	if ctx == nil {
		return contentpolicy.Rule{}, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return contentpolicy.Rule{}, ErrClosed
	}
	owned := cloneContentPolicyRule(rule)
	if err := store.submitSync(ctx, writeRequest{kind: writeCreateContentPolicyRule, data: owned}); err != nil {
		return contentpolicy.Rule{}, err
	}
	return owned, nil
}

// UpdateContentPolicyRule replaces one existing rule. Creation time is
// immutable; likewise every other column except updated_at_ns is overwritten.
func (store *Store) UpdateContentPolicyRule(ctx context.Context, rule contentpolicy.Rule) (contentpolicy.Rule, error) {
	if ctx == nil {
		return contentpolicy.Rule{}, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return contentpolicy.Rule{}, ErrClosed
	}
	owned := cloneContentPolicyRule(rule)
	if err := store.submitSync(ctx, writeRequest{kind: writeUpdateContentPolicyRule, data: owned}); err != nil {
		return contentpolicy.Rule{}, err
	}
	return owned, nil
}

// DeleteContentPolicyRule removes one existing rule.
func (store *Store) DeleteContentPolicyRule(ctx context.Context, id int64) error {
	if ctx == nil {
		return errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitSync(ctx, writeRequest{kind: writeDeleteContentPolicyRule, data: id})
}

func cloneContentPolicyRule(rule contentpolicy.Rule) contentpolicy.Rule {
	rule.ScanScopes = append([]string(nil), rule.ScanScopes...)
	rule.Keywords = append([]string(nil), rule.Keywords...)
	return rule
}

func requireAffectedContentPolicyRule(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: read affected content policy rules: %w", err)
	}
	if affected == 0 {
		return contentpolicy.ErrNotFound
	}
	return nil
}

// encodeContentPolicyRule serializes the JSON array columns. A nil slice
// marshals to JSON null; the service layer always passes normalized scopes and
// keywords, and the schema bounds only the encoded length.
func encodeContentPolicyRule(rule contentpolicy.Rule) (scanScopesJSON, keywordsJSON string, err error) {
	scanScopes, err := json.Marshal(rule.ScanScopes)
	if err != nil {
		return "", "", fmt.Errorf("sqlite: encode content policy rule scan scopes: %w", err)
	}
	keywords, err := json.Marshal(rule.Keywords)
	if err != nil {
		return "", "", fmt.Errorf("sqlite: encode content policy rule keywords: %w", err)
	}
	return string(scanScopes), string(keywords), nil
}

func createContentPolicyRule(transaction *sql.Tx, rule contentpolicy.Rule) error {
	scanScopes, keywords, err := encodeContentPolicyRule(rule)
	if err != nil {
		return err
	}
	if _, err := transaction.Exec(`
INSERT INTO content_policy_rules (id, name, enabled, action, model_pattern, scan_scopes, keywords, created_at_ns, updated_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.Name, boolInt(rule.Enabled), rule.Action, rule.ModelPattern,
		scanScopes, keywords, rule.CreatedAtNS, rule.UpdatedAtNS); err != nil {
		return fmt.Errorf("sqlite writer: create content policy rule: %w", err)
	}
	return nil
}

func updateContentPolicyRule(transaction *sql.Tx, rule contentpolicy.Rule) error {
	scanScopes, keywords, err := encodeContentPolicyRule(rule)
	if err != nil {
		return err
	}
	result, err := transaction.Exec(`
UPDATE content_policy_rules
SET name = ?, enabled = ?, action = ?, model_pattern = ?, scan_scopes = ?, keywords = ?, updated_at_ns = ?
WHERE id = ?`,
		rule.Name, boolInt(rule.Enabled), rule.Action, rule.ModelPattern,
		scanScopes, keywords, rule.UpdatedAtNS, rule.ID)
	if err != nil {
		return fmt.Errorf("sqlite writer: update content policy rule: %w", err)
	}
	return requireAffectedContentPolicyRule(result)
}

func deleteContentPolicyRule(transaction *sql.Tx, id int64) error {
	result, err := transaction.Exec("DELETE FROM content_policy_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("sqlite writer: delete content policy rule: %w", err)
	}
	return requireAffectedContentPolicyRule(result)
}
