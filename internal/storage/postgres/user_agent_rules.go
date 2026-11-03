package postgres

import (
	"context"
	"errors"
	"fmt"

	"llmapi-logger/internal/uaguard"
)

// ListUserAgentRules returns every rule in stable ID order.
func (store *Store) ListUserAgentRules(ctx context.Context) ([]uaguard.Rule, error) {
	if ctx == nil {
		return nil, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return nil, ErrClosed
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT id, name, enabled, model_pattern, user_agent_pattern, created_at_ns, updated_at_ns
FROM user_agent_rules
ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list user agent rules: %w", err)
	}
	defer rows.Close()
	rules := make([]uaguard.Rule, 0)
	for rows.Next() {
		var rule uaguard.Rule
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &enabled, &rule.ModelPattern, &rule.UserAgentPattern, &rule.CreatedAtNS, &rule.UpdatedAtNS); err != nil {
			return nil, fmt.Errorf("postgres: scan user agent rule: %w", err)
		}
		rule.Enabled = enabled != 0
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate user agent rules: %w", err)
	}
	return rules, nil
}

// CreateUserAgentRule inserts one rule with the service-assigned stable ID.
func (store *Store) CreateUserAgentRule(ctx context.Context, rule uaguard.Rule) (uaguard.Rule, error) {
	if ctx == nil {
		return uaguard.Rule{}, errors.New("postgres: nil context")
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
		return uaguard.Rule{}, errors.New("postgres: nil context")
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
		return errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return ErrClosed
	}
	return store.submitSync(ctx, writeRequest{kind: writeDeleteUserAgentRule, data: id})
}

func requireAffectedRule(result interface{ RowsAffected() (int64, error) }) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: read affected user agent rules: %w", err)
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

func createUserAgentRule(transaction dbTransaction, rule uaguard.Rule) error {
	_, err := transaction.Exec(`
INSERT INTO user_agent_rules (id, name, enabled, model_pattern, user_agent_pattern, created_at_ns, updated_at_ns)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rule.ID, rule.Name, boolInt(rule.Enabled), rule.ModelPattern, rule.UserAgentPattern, rule.CreatedAtNS, rule.UpdatedAtNS)
	if err != nil {
		return fmt.Errorf("postgres writer: create user agent rule: %w", err)
	}
	return nil
}

func updateUserAgentRule(transaction dbTransaction, rule uaguard.Rule) error {
	result, err := transaction.Exec(`
UPDATE user_agent_rules
SET name = $1, enabled = $2, model_pattern = $3, user_agent_pattern = $4, updated_at_ns = $5
WHERE id = $6`,
		rule.Name, boolInt(rule.Enabled), rule.ModelPattern, rule.UserAgentPattern, rule.UpdatedAtNS, rule.ID)
	if err != nil {
		return fmt.Errorf("postgres writer: update user agent rule: %w", err)
	}
	return requireAffectedRule(result)
}

func deleteUserAgentRule(transaction dbTransaction, id int64) error {
	result, err := transaction.Exec("DELETE FROM user_agent_rules WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("postgres writer: delete user agent rule: %w", err)
	}
	return requireAffectedRule(result)
}
