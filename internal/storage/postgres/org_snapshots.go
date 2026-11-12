package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"llmapi-logger/internal/orgreport"
)

var _ orgreport.SnapshotStore = (*Store)(nil)

// SaveWeeklySnapshot replaces one week's snapshot atomically.
func (store *Store) SaveWeeklySnapshot(ctx context.Context, snapshot orgreport.WeeklySnapshot) error {
	if len(snapshot.Week) != 10 || snapshot.FrozenAtNS <= 0 || snapshot.GeneratedAtNS <= 0 {
		return localWriteError("postgres: invalid weekly snapshot")
	}
	rows, err := snapshotRows(snapshot)
	if err != nil {
		return err
	}
	return store.submitOrg(ctx, func(transaction dbTransaction) error {
		if _, err := transaction.Exec(`DELETE FROM org_weekly_snapshots WHERE week_start = $1`, snapshot.Week); err != nil {
			return fmt.Errorf("postgres writer: replace weekly snapshot: %w", err)
		}
		if _, err := transaction.Exec(`INSERT INTO org_weekly_snapshots (week_start, frozen_at_ns, generated_at_ns) VALUES ($1, $2, $3)`,
			snapshot.Week, snapshot.FrozenAtNS, snapshot.GeneratedAtNS); err != nil {
			return fmt.Errorf("postgres writer: insert weekly snapshot: %w", err)
		}
		for _, row := range rows {
			if _, err := transaction.Exec(`
INSERT INTO org_weekly_stats (
    week_start, section, newapi_user_id, newapi_token_id, project_id, group_id, project_name,
    active_ns, other_active_ns, inferred_ns, roots, single_request_roots, requests,
    identified_requests, billed_requests, u_uncached_input, u_cache_read, u_cache_write, u_output,
    cost_usd, peak_concurrency, avg_concurrency, daily_active_ns, flags
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)`,
				snapshot.Week, row.section, row.userID, row.tokenID, row.projectID, row.groupID, row.projectName,
				row.activeNS, row.otherActiveNS, row.inferredNS, row.roots, row.singleRequestRoots, row.requests,
				row.identifiedRequests, row.billedRequests, row.tokens.Uncached, row.tokens.CacheRead, row.tokens.CacheWrite, row.tokens.Output,
				row.costUSD, row.peak, row.average, row.daily, row.flags); err != nil {
				return fmt.Errorf("postgres writer: insert weekly stats: %w", err)
			}
		}
		return nil
	})
}

type snapshotRow struct {
	section            string
	userID, tokenID    int64
	projectID, groupID int64
	projectName        string
	activeNS           int64
	otherActiveNS      int64
	inferredNS         int64
	roots              int64
	singleRequestRoots int64
	requests           int64
	identifiedRequests int64
	billedRequests     int64
	tokens             orgreport.Tokens
	costUSD            float64
	peak               int64
	average            float64
	daily              string
	flags              string
}

func snapshotRows(snapshot orgreport.WeeklySnapshot) ([]snapshotRow, error) {
	rows := make([]snapshotRow, 0, 4*len(snapshot.Result.Users)+len(snapshot.Result.Service))
	for _, user := range snapshot.Result.Users {
		daily, err := json.Marshal(user.Daily)
		if err != nil {
			return nil, err
		}
		flags, err := json.Marshal(user.Flags)
		if err != nil {
			return nil, err
		}
		rows = append(rows, snapshotRow{
			section: "ranked", userID: user.UserID, groupID: user.GroupID,
			activeNS: user.ActiveNS, otherActiveNS: user.OtherActiveNS, inferredNS: user.InferredNS,
			roots: int64(user.Roots), singleRequestRoots: int64(user.SingleRequestRoots), requests: int64(user.Requests),
			identifiedRequests: int64(user.IdentifiedRequests), billedRequests: int64(user.BilledRequests),
			tokens: user.Tokens, costUSD: user.CostUSD, peak: int64(user.PeakConcurrency), average: user.AvgConcurrency,
			daily: string(daily), flags: string(flags),
		})
		for _, cell := range user.Projects {
			name := ""
			if cell.Project > 0 {
				name = snapshot.ProjectNames[int64(cell.Project)]
			}
			rows = append(rows, snapshotRow{
				section: "ranked", userID: user.UserID, groupID: user.GroupID, projectID: int64(cell.Project), projectName: name,
				activeNS: cell.ActiveNS, roots: int64(cell.Roots), requests: int64(cell.Requests), tokens: cell.Tokens, costUSD: cell.CostUSD,
				daily: "[]", flags: "[]",
			})
		}
	}
	for _, service := range snapshot.Result.Service {
		rows = append(rows, snapshotRow{
			section: "service", userID: service.UserID, tokenID: service.TokenID,
			activeNS: service.ActiveNS, roots: int64(service.Roots), requests: int64(service.Requests),
			tokens: service.Tokens, costUSD: service.CostUSD, daily: "[]", flags: "[]",
		})
	}
	return rows, nil
}

// LoadWeeklySnapshot reads one frozen week.
func (store *Store) LoadWeeklySnapshot(ctx context.Context, week string) (orgreport.WeeklySnapshot, bool, error) {
	if ctx == nil {
		return orgreport.WeeklySnapshot{}, false, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return orgreport.WeeklySnapshot{}, false, ErrClosed
	}
	snapshot := orgreport.WeeklySnapshot{Week: week, ProjectNames: map[int64]string{},
		Result: orgreport.WeekResult{Users: []orgreport.UserRow{}, Service: []orgreport.ServiceRow{}}}
	err := store.readerDB.QueryRowContext(ctx, `SELECT frozen_at_ns, generated_at_ns FROM org_weekly_snapshots WHERE week_start = $1`, week).
		Scan(&snapshot.FrozenAtNS, &snapshot.GeneratedAtNS)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return orgreport.WeeklySnapshot{}, false, nil
		}
		return orgreport.WeeklySnapshot{}, false, fmt.Errorf("postgres: load weekly snapshot: %w", err)
	}
	rows, err := store.readerDB.QueryContext(ctx, `
SELECT section, newapi_user_id, newapi_token_id, project_id, group_id, project_name,
       active_ns, other_active_ns, inferred_ns, roots, single_request_roots, requests,
       identified_requests, billed_requests, u_uncached_input, u_cache_read, u_cache_write, u_output,
       cost_usd, peak_concurrency, avg_concurrency, daily_active_ns, flags
FROM org_weekly_stats WHERE week_start = $1
ORDER BY section, newapi_user_id, newapi_token_id, project_id`, week)
	if err != nil {
		return orgreport.WeeklySnapshot{}, false, fmt.Errorf("postgres: load weekly stats: %w", err)
	}
	defer rows.Close()
	users := map[int64]*orgreport.UserRow{}
	for rows.Next() {
		var row snapshotRow
		if err := rows.Scan(&row.section, &row.userID, &row.tokenID, &row.projectID, &row.groupID, &row.projectName,
			&row.activeNS, &row.otherActiveNS, &row.inferredNS, &row.roots, &row.singleRequestRoots, &row.requests,
			&row.identifiedRequests, &row.billedRequests, &row.tokens.Uncached, &row.tokens.CacheRead, &row.tokens.CacheWrite, &row.tokens.Output,
			&row.costUSD, &row.peak, &row.average, &row.daily, &row.flags); err != nil {
			return orgreport.WeeklySnapshot{}, false, fmt.Errorf("postgres: scan weekly stats: %w", err)
		}
		if row.section == "service" {
			snapshot.Result.Service = append(snapshot.Result.Service, orgreport.ServiceRow{
				UserID: row.userID, TokenID: row.tokenID, ActiveNS: row.activeNS, Roots: int(row.roots),
				Requests: int(row.requests), Tokens: row.tokens, CostUSD: row.costUSD,
			})
			continue
		}
		user := users[row.userID]
		if user == nil {
			user = &orgreport.UserRow{UserID: row.userID, GroupID: row.groupID, Daily: []int64{}, Projects: []orgreport.ProjectCell{}, Flags: []orgreport.Flag{}}
			users[row.userID] = user
		}
		if row.projectID == 0 {
			user.ActiveNS, user.OtherActiveNS, user.InferredNS = row.activeNS, row.otherActiveNS, row.inferredNS
			user.Roots, user.SingleRequestRoots, user.Requests = int(row.roots), int(row.singleRequestRoots), int(row.requests)
			user.IdentifiedRequests, user.BilledRequests = int(row.identifiedRequests), int(row.billedRequests)
			user.Tokens, user.CostUSD = row.tokens, row.costUSD
			user.PeakConcurrency, user.AvgConcurrency = int(row.peak), row.average
			if err := json.Unmarshal([]byte(row.daily), &user.Daily); err != nil {
				return orgreport.WeeklySnapshot{}, false, fmt.Errorf("postgres: decode weekly daily: %w", err)
			}
			if err := json.Unmarshal([]byte(row.flags), &user.Flags); err != nil {
				return orgreport.WeeklySnapshot{}, false, fmt.Errorf("postgres: decode weekly flags: %w", err)
			}
			continue
		}
		user.Projects = append(user.Projects, orgreport.ProjectCell{
			Project: orgreport.ProjectKey(row.projectID), ActiveNS: row.activeNS, Roots: int(row.roots),
			Requests: int(row.requests), Tokens: row.tokens, CostUSD: row.costUSD,
		})
		if row.projectID > 0 && row.projectName != "" {
			snapshot.ProjectNames[row.projectID] = row.projectName
		}
	}
	if err := rows.Err(); err != nil {
		return orgreport.WeeklySnapshot{}, false, fmt.Errorf("postgres: iterate weekly stats: %w", err)
	}
	for _, user := range users {
		sort.Slice(user.Projects, func(i, j int) bool {
			if user.Projects[i].ActiveNS != user.Projects[j].ActiveNS {
				return user.Projects[i].ActiveNS > user.Projects[j].ActiveNS
			}
			return user.Projects[i].Project < user.Projects[j].Project
		})
		snapshot.Result.Users = append(snapshot.Result.Users, *user)
	}
	sort.Slice(snapshot.Result.Users, func(i, j int) bool {
		if snapshot.Result.Users[i].ActiveNS != snapshot.Result.Users[j].ActiveNS {
			return snapshot.Result.Users[i].ActiveNS > snapshot.Result.Users[j].ActiveNS
		}
		return snapshot.Result.Users[i].UserID < snapshot.Result.Users[j].UserID
	})
	return snapshot, true, nil
}

// CountOrgPendingAudits counts the audits of [fromNS, toNS) still waiting for
// the parser or analysed without a current project identity (Pending), and
// the parsed, ended audits without any analysis that the analysis backfill
// selects (Unanalysed). Whether an unanalysed audit will ever be analysed is
// only known to the backfill, so the caller decides how long they hold the
// week.
func (store *Store) CountOrgPendingAudits(ctx context.Context, fromNS, toNS int64, identityVersion int) (orgreport.PendingAudits, error) {
	if ctx == nil {
		return orgreport.PendingAudits{}, errors.New("postgres: nil context")
	}
	if store == nil || store.isClosed() {
		return orgreport.PendingAudits{}, ErrClosed
	}
	var counts orgreport.PendingAudits
	err := store.readerDB.QueryRowContext(ctx, `
SELECT
    COUNT(*) FILTER (WHERE ar.parse_status IN ('pending', 'processing')
                        OR (aa.audit_id IS NOT NULL AND (pi.audit_id IS NULL OR pi.identity_version < $3))),
    COUNT(*) FILTER (WHERE aa.audit_id IS NULL AND ar.ended_at_ns IS NOT NULL AND ar.parse_status IN ('ok', 'partial'))
FROM audit_records AS ar
LEFT JOIN audit_analysis AS aa ON aa.audit_id = ar.audit_id
LEFT JOIN audit_project_identity AS pi ON pi.audit_id = ar.audit_id
WHERE ar.started_at_ns >= $1 AND ar.started_at_ns < $2`, fromNS, toNS, identityVersion).Scan(&counts.Pending, &counts.Unanalysed)
	if err != nil {
		return orgreport.PendingAudits{}, fmt.Errorf("postgres: count org pending audits: %w", err)
	}
	return counts, nil
}
