package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/uaguard"
)

// ListUserAgentRules returns every rule in stable ID order.
func (store *Store) ListUserAgentRules(ctx context.Context) ([]uaguard.Rule, error) {
	if ctx == nil {
		return nil, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT id, name, enabled, model_pattern, user_agent_pattern, created_at_ns, updated_at_ns
FROM user_agent_rules
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list user agent rules: %w", err)
	}
	defer rows.Close()
	rules := make([]uaguard.Rule, 0)
	for rows.Next() {
		var rule uaguard.Rule
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &enabled, &rule.ModelPattern, &rule.UserAgentPattern, &rule.CreatedAtNS, &rule.UpdatedAtNS); err != nil {
			return nil, fmt.Errorf("sqlite: scan user agent rule: %w", err)
		}
		rule.Enabled = enabled != 0
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: iterate user agent rules: %w", err)
	}
	return rules, nil
}

// CreateUserAgentRule inserts one rule with the service-assigned stable ID.
func (store *Store) CreateUserAgentRule(ctx context.Context, rule uaguard.Rule) (uaguard.Rule, error) {
	if ctx == nil {
		return uaguard.Rule{}, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return uaguard.Rule{}, ErrClosed
	}
	if err := store.submitSync(ctx, writeRequest{kind: writeCreateUserAgentRule, data: rule}); err != nil {
		return uaguard.Rule{}, err
	}
	return rule, nil
}

// UpdateUserAgentRule replaces one existing rule.
func (store *Store) UpdateUserAgentRule(ctx context.Context, rule uaguard.Rule) (uaguard.Rule, error) {
	if ctx == nil {
		return uaguard.Rule{}, errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return uaguard.Rule{}, ErrClosed
	}
	if err := store.submitSync(ctx, writeRequest{kind: writeUpdateUserAgentRule, data: rule}); err != nil {
		return uaguard.Rule{}, err
	}
	return rule, nil
}

// DeleteUserAgentRule removes one existing rule.
func (store *Store) DeleteUserAgentRule(ctx context.Context, id int64) error {
	if ctx == nil {
		return errors.New("sqlite: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitSync(ctx, writeRequest{kind: writeDeleteUserAgentRule, data: id})
}

func requireAffectedRule(result interface{ RowsAffected() (int64, error) }) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite: read affected user agent rules: %w", err)
	}
	if affected == 0 {
		return uaguard.ErrNotFound
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func createUserAgentRule(transaction *sql.Tx, rule uaguard.Rule) error {
	_, err := transaction.Exec(`
INSERT INTO user_agent_rules (id, name, enabled, model_pattern, user_agent_pattern, created_at_ns, updated_at_ns)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.Name, boolInt(rule.Enabled), rule.ModelPattern, rule.UserAgentPattern, rule.CreatedAtNS, rule.UpdatedAtNS)
	if err != nil {
		return fmt.Errorf("sqlite writer: create user agent rule: %w", err)
	}
	return nil
}

func updateUserAgentRule(transaction *sql.Tx, rule uaguard.Rule) error {
	result, err := transaction.Exec(`
UPDATE user_agent_rules
SET name = ?, enabled = ?, model_pattern = ?, user_agent_pattern = ?, updated_at_ns = ?
WHERE id = ?`,
		rule.Name, boolInt(rule.Enabled), rule.ModelPattern, rule.UserAgentPattern, rule.UpdatedAtNS, rule.ID)
	if err != nil {
		return fmt.Errorf("sqlite writer: update user agent rule: %w", err)
	}
	return requireAffectedRule(result)
}

func deleteUserAgentRule(transaction *sql.Tx, id int64) error {
	result, err := transaction.Exec("DELETE FROM user_agent_rules WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("sqlite writer: delete user agent rule: %w", err)
	}
	return requireAffectedRule(result)
}
