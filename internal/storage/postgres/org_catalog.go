package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"llmapi-logger/internal/orgreport"
)

// Compile-time assertion that the store satisfies the org repository.
var _ orgreport.Repository = (*Store)(nil)

// LoadOrgCatalog reads every group, project, member and principal.
func (store *Store) LoadOrgCatalog(ctx context.Context) (orgreport.Catalog, error) {
	if ctx == nil {
		return orgreport.Catalog{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return orgreport.Catalog{}, ErrClosed
	}
	catalog := orgreport.Catalog{Groups: []orgreport.Group{}, Projects: []orgreport.Project{}, Members: []orgreport.Member{}, Principals: []orgreport.Principal{}}
	rows, err := store.readerDB.QueryContext(ctx, `SELECT id, name, enabled, created_at_ns, updated_at_ns FROM project_groups ORDER BY id`)
	if err != nil {
		return catalog, fmt.Errorf("postgres: list project groups: %w", err)
	}
	for rows.Next() {
		var group orgreport.Group
		var enabled int64
		if err := rows.Scan(&group.ID, &group.Name, &enabled, &group.CreatedAtNS, &group.UpdatedAtNS); err != nil {
			rows.Close()
			return catalog, fmt.Errorf("postgres: scan project group: %w", err)
		}
		group.Enabled = enabled != 0
		catalog.Groups = append(catalog.Groups, group)
	}
	if err := closeOrgRows(rows); err != nil {
		return catalog, err
	}

	rows, err = store.readerDB.QueryContext(ctx, `SELECT id, name, group_id, enabled, rules, created_at_ns, updated_at_ns FROM projects ORDER BY id`)
	if err != nil {
		return catalog, fmt.Errorf("postgres: list projects: %w", err)
	}
	for rows.Next() {
		var project orgreport.Project
		var groupID sql.NullInt64
		var enabled int64
		var rules string
		if err := rows.Scan(&project.ID, &project.Name, &groupID, &enabled, &rules, &project.CreatedAtNS, &project.UpdatedAtNS); err != nil {
			rows.Close()
			return catalog, fmt.Errorf("postgres: scan project: %w", err)
		}
		project.Enabled = enabled != 0
		if groupID.Valid {
			id := groupID.Int64
			project.GroupID = &id
		}
		if err := json.Unmarshal([]byte(rules), &project.Rules); err != nil {
			rows.Close()
			return catalog, fmt.Errorf("postgres: decode project %d rules: %w", project.ID, err)
		}
		catalog.Projects = append(catalog.Projects, project)
	}
	if err := closeOrgRows(rows); err != nil {
		return catalog, err
	}

	rows, err = store.readerDB.QueryContext(ctx, `SELECT newapi_user_id, group_id, updated_at_ns FROM group_members ORDER BY newapi_user_id`)
	if err != nil {
		return catalog, fmt.Errorf("postgres: list group members: %w", err)
	}
	for rows.Next() {
		var member orgreport.Member
		if err := rows.Scan(&member.UserID, &member.GroupID, &member.UpdatedAtNS); err != nil {
			rows.Close()
			return catalog, fmt.Errorf("postgres: scan group member: %w", err)
		}
		catalog.Members = append(catalog.Members, member)
	}
	if err := closeOrgRows(rows); err != nil {
		return catalog, err
	}

	rows, err = store.readerDB.QueryContext(ctx, `SELECT kind, principal_id, class, updated_at_ns FROM principal_class ORDER BY kind, principal_id`)
	if err != nil {
		return catalog, fmt.Errorf("postgres: list principal classes: %w", err)
	}
	for rows.Next() {
		var principal orgreport.Principal
		if err := rows.Scan(&principal.Kind, &principal.ID, &principal.Class, &principal.UpdatedAtNS); err != nil {
			rows.Close()
			return catalog, fmt.Errorf("postgres: scan principal class: %w", err)
		}
		catalog.Principals = append(catalog.Principals, principal)
	}
	return catalog, closeOrgRows(rows)
}

func closeOrgRows(rows *sql.Rows) error {
	err := rows.Err()
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("postgres: iterate org catalog: %w", err)
	}
	return nil
}

// orgAdminError maps constraint failures to the domain errors the web layer
// understands. Every other error passes through.
func orgAdminError(err error) error {
	var coded *pgconn.PgError
	if errors.As(err, &coded) {
		switch coded.Code {
		case "23505", "23503":
			return fmt.Errorf("%w: %s", orgreport.ErrConflict, coded.ConstraintName)
		case "23514", "23502":
			return fmt.Errorf("%w: %s", orgreport.ErrInvalid, coded.ConstraintName)
		}
	}
	return err
}

func requireOrgRow(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return orgreport.ErrNotFound
	}
	return nil
}

func (store *Store) orgAdmin(ctx context.Context, write orgWrite) error {
	return orgAdminError(store.submitOrgAdmin(ctx, write))
}

// CreateProjectGroup inserts a group and returns it with its id.
func (store *Store) CreateProjectGroup(ctx context.Context, group orgreport.Group) (orgreport.Group, error) {
	err := store.orgAdmin(ctx, func(transaction dbTransaction) error {
		if err := transaction.QueryRow(`INSERT INTO project_groups (name, enabled, created_at_ns, updated_at_ns) VALUES ($1, $2, $3, $4) RETURNING id`,
			group.Name, boolInt(group.Enabled), group.CreatedAtNS, group.UpdatedAtNS).Scan(&group.ID); err != nil {
			return err
		}
		countMutation(transaction)
		return nil
	})
	return group, err
}

// UpdateProjectGroup renames or toggles a group.
func (store *Store) UpdateProjectGroup(ctx context.Context, group orgreport.Group) error {
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		result, err := transaction.Exec(`UPDATE project_groups SET name = $1, enabled = $2, updated_at_ns = $3 WHERE id = $4`,
			group.Name, boolInt(group.Enabled), group.UpdatedAtNS, group.ID)
		if err != nil {
			return err
		}
		return requireOrgRow(result)
	})
}

// DeleteProjectGroup removes a group; projects and members restrict it.
func (store *Store) DeleteProjectGroup(ctx context.Context, id int64) error {
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		result, err := transaction.Exec(`DELETE FROM project_groups WHERE id = $1`, id)
		if err != nil {
			return err
		}
		return requireOrgRow(result)
	})
}

func encodeRules(rules []orgreport.Rule) (string, error) {
	if rules == nil {
		rules = []orgreport.Rule{}
	}
	encoded, err := json.Marshal(rules)
	return string(encoded), err
}

func nullableGroup(id *int64) any {
	if id == nil {
		return nil
	}
	return *id
}

// CreateProject inserts a project and returns it with its id.
func (store *Store) CreateProject(ctx context.Context, project orgreport.Project) (orgreport.Project, error) {
	rules, err := encodeRules(project.Rules)
	if err != nil {
		return orgreport.Project{}, err
	}
	err = store.orgAdmin(ctx, func(transaction dbTransaction) error {
		if err := transaction.QueryRow(`INSERT INTO projects (name, group_id, enabled, rules, created_at_ns, updated_at_ns) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
			project.Name, nullableGroup(project.GroupID), boolInt(project.Enabled), rules, project.CreatedAtNS, project.UpdatedAtNS).Scan(&project.ID); err != nil {
			return err
		}
		countMutation(transaction)
		return nil
	})
	return project, err
}

// UpdateProject replaces a project.
func (store *Store) UpdateProject(ctx context.Context, project orgreport.Project) error {
	rules, err := encodeRules(project.Rules)
	if err != nil {
		return err
	}
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		result, err := transaction.Exec(`UPDATE projects SET name = $1, group_id = $2, enabled = $3, rules = $4, updated_at_ns = $5 WHERE id = $6`,
			project.Name, nullableGroup(project.GroupID), boolInt(project.Enabled), rules, project.UpdatedAtNS, project.ID)
		if err != nil {
			return err
		}
		return requireOrgRow(result)
	})
}

// DeleteProject removes a project.
func (store *Store) DeleteProject(ctx context.Context, id int64) error {
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		result, err := transaction.Exec(`DELETE FROM projects WHERE id = $1`, id)
		if err != nil {
			return err
		}
		return requireOrgRow(result)
	})
}

// SetGroupMember upserts a user's single group.
func (store *Store) SetGroupMember(ctx context.Context, member orgreport.Member) error {
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		_, err := transaction.Exec(`INSERT INTO group_members (newapi_user_id, group_id, updated_at_ns) VALUES ($1, $2, $3)
ON CONFLICT (newapi_user_id) DO UPDATE SET group_id = EXCLUDED.group_id, updated_at_ns = EXCLUDED.updated_at_ns`,
			member.UserID, member.GroupID, member.UpdatedAtNS)
		return err
	})
}

// DeleteGroupMember removes a user from its group.
func (store *Store) DeleteGroupMember(ctx context.Context, userID int64) error {
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		result, err := transaction.Exec(`DELETE FROM group_members WHERE newapi_user_id = $1`, userID)
		if err != nil {
			return err
		}
		return requireOrgRow(result)
	})
}

// SetPrincipalClass upserts a user or token classification.
func (store *Store) SetPrincipalClass(ctx context.Context, principal orgreport.Principal) error {
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		_, err := transaction.Exec(`INSERT INTO principal_class (kind, principal_id, class, updated_at_ns) VALUES ($1, $2, $3, $4)
ON CONFLICT (kind, principal_id) DO UPDATE SET class = EXCLUDED.class, updated_at_ns = EXCLUDED.updated_at_ns`,
			principal.Kind, principal.ID, principal.Class, principal.UpdatedAtNS)
		return err
	})
}

// DeletePrincipalClass removes a classification.
func (store *Store) DeletePrincipalClass(ctx context.Context, kind string, id int64) error {
	return store.orgAdmin(ctx, func(transaction dbTransaction) error {
		result, err := transaction.Exec(`DELETE FROM principal_class WHERE kind = $1 AND principal_id = $2`, kind, id)
		if err != nil {
			return err
		}
		return requireOrgRow(result)
	})
}

// countMutation records a RETURNING insert, which Exec does not count.
func countMutation(transaction dbTransaction) {
	if tx, ok := transaction.(*countingTx); ok {
		tx.mutations++
	}
}
