package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"llmapi-logger/internal/parser"
	"llmapi-logger/internal/storage"
)

// The parser worker bounds both backfills only when the store reports a
// horizon; these assertions keep the PostgreSQL store on that path.
var (
	_ parser.BackfillStore               = (*Store)(nil)
	_ parser.BackfillHorizonStore        = (*Store)(nil)
	_ parser.ProjectBackfillStore        = (*Store)(nil)
	_ parser.ProjectBackfillHorizonStore = (*Store)(nil)
)

const seededAudits = 20000

// seedProcessedAudits inserts audits that are parsed, analysed at version 1
// and identified at version 1, started at 1000, 2000, ... and refreshes the
// planner statistics.
func seedProcessedAudits(t *testing.T, store *Store, count int) {
	t.Helper()
	ctx := context.Background()
	for _, statement := range []string{
		`INSERT INTO audit_records (audit_id, started_at_ns, ended_at_ns, route_id, protocol, parser_name, method, path,
    request_uri_enc, mode, forward_status, capture_status, parse_status)
SELECT 'seed-' || lpad(g::text, 6, '0'), g * 1000, g * 1000 + 1, 'openai-chat', 'openai', 'openai.chat_completions',
    'POST', '/v1/chat/completions', '\x102030'::bytea, 'available', 'completed', 'complete', 'ok'
FROM generate_series(1, $1::bigint) AS g`,
		`INSERT INTO audit_analysis (audit_id, analysis_version, analyzed_at_ns, protocol, started_at_ns)
SELECT audit_id, 1, 1, 'openai', started_at_ns FROM audit_records WHERE $1::bigint > 0`,
		`INSERT INTO audit_project_identity (audit_id, identity_version, extracted_at_ns, source, body_scanned)
SELECT audit_id, 1, 1, 'none', 0 FROM audit_records WHERE $1::bigint > 0`,
	} {
		if _, err := store.writerConn.ExecContext(ctx, statement, count); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"audit_records", "audit_analysis", "audit_project_identity"} {
		if _, err := store.writerConn.ExecContext(ctx, `ANALYZE `+table); err != nil {
			t.Fatal(err)
		}
	}
}

// planScan is what one EXPLAIN ANALYZE plan did to one table.
type planScan struct {
	nodeTypes []string
	// examined is every row the table's scan nodes produced or threw away,
	// over all loops.
	examined float64
}

type planNode struct {
	NodeType       string     `json:"Node Type"`
	RelationName   string     `json:"Relation Name"`
	IndexName      string     `json:"Index Name"`
	ActualRows     float64    `json:"Actual Rows"`
	ActualLoops    float64    `json:"Actual Loops"`
	RemovedFilter  float64    `json:"Rows Removed by Filter"`
	RemovedRecheck float64    `json:"Rows Removed by Index Recheck"`
	Plans          []planNode `json:"Plans"`
}

// explainScans runs query under EXPLAIN (ANALYZE, FORMAT JSON) with the same
// bound arguments the store sends and sums the work per table. Row counts do
// not depend on what is cached, unlike buffer counts.
func explainScans(t *testing.T, store *Store, query string, arguments ...any) map[string]*planScan {
	t.Helper()
	var document string
	if err := store.readerDB.QueryRowContext(context.Background(), `EXPLAIN (ANALYZE, FORMAT JSON) `+query, arguments...).Scan(&document); err != nil {
		t.Fatal(err)
	}
	var plans []struct {
		Plan planNode `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(document), &plans); err != nil || len(plans) != 1 {
		t.Fatalf("plan document: %v", err)
	}
	scans := map[string]*planScan{}
	var walk func(node planNode)
	walk = func(node planNode) {
		if node.RelationName != "" {
			scan := scans[node.RelationName]
			if scan == nil {
				scan = &planScan{}
				scans[node.RelationName] = scan
			}
			scan.nodeTypes = append(scan.nodeTypes, node.NodeType+" "+node.IndexName)
			scan.examined += (node.ActualRows + node.RemovedFilter + node.RemovedRecheck) * node.ActualLoops
		}
		for _, child := range node.Plans {
			walk(child)
		}
	}
	walk(plans[0].Plan)
	return scans
}

func assertNoSeqScan(t *testing.T, label string, scans map[string]*planScan) {
	t.Helper()
	for table, scan := range scans {
		for _, nodeType := range scan.nodeTypes {
			if strings.HasPrefix(nodeType, "Seq Scan") {
				t.Errorf("%s: sequential scan of %s: %v", label, table, scan.nodeTypes)
			}
		}
	}
}

// Once every audit is processed, the bounded queries a steady-state pass
// sends read only the rows after the watermark, through the existing
// (started_at_ns, audit_id) indexes; the unbounded ones read every row.
//
// The assertions are on the executed plan's row counts, not on timing,
// buffer or statistics counters, which depend on caching and on when the
// collector flushes. With fresh statistics on 20000 rows and a range of ten,
// an index range scan costs a few pages against hundreds for any full scan,
// so the planner's choice does not flip between runs.
func TestBackfillCandidateQueriesStayInsideTheWatermark(t *testing.T) {
	store, _ := openTestStore(t)
	seedProcessedAudits(t, store, seededAudits)
	ctx := context.Background()
	watermark := AnalysisBackfillCursor{StartedAtNS: (seededAudits - 10) * 1000, AuditID: "seed-019990"}

	// Insights: the horizon is one backward index step.
	horizon, found, err := store.AnalysisBackfillHorizon(ctx)
	if err != nil || !found || horizon.AuditID != "seed-020000" || horizon.StartedAtNS != seededAudits*1000 {
		t.Fatalf("horizon = %+v %v %v", horizon, found, err)
	}
	scans := explainScans(t, store, analysisBackfillHorizonQuery)
	assertNoSeqScan(t, "insights horizon", scans)
	if scans["audit_records"] == nil || scans["audit_records"].examined > 1 {
		t.Fatalf("insights horizon read %+v", scans["audit_records"])
	}

	query, arguments := analysisBackfillQuery(1, &watermark, 20)
	bounded := explainScans(t, store, query, arguments...)
	assertNoSeqScan(t, "bounded insights candidates", bounded)
	for _, table := range []string{"audit_records", "audit_analysis"} {
		if bounded[table] == nil || bounded[table].examined > 10 {
			t.Errorf("bounded insights candidates read %+v rows of %s", bounded[table], table)
		}
	}
	query, arguments = analysisBackfillQuery(1, nil, 20)
	full := explainScans(t, store, query, arguments...)
	if full["audit_records"] == nil || full["audit_records"].examined < seededAudits {
		t.Fatalf("unbounded insights candidates read only %+v rows", full["audit_records"])
	}
	t.Logf("insights candidates: bounded %v rows of audit_records via %v, unbounded %v rows",
		bounded["audit_records"].examined, bounded["audit_records"].nodeTypes, full["audit_records"].examined)

	// Project identity: the same against audit_analysis, walked backwards.
	projectHorizon, found, err := store.ProjectBackfillHorizon(ctx)
	if err != nil || !found || projectHorizon.AuditID != "seed-020000" {
		t.Fatalf("project horizon = %+v %v %v", projectHorizon, found, err)
	}
	scans = explainScans(t, store, projectBackfillHorizonQuery)
	assertNoSeqScan(t, "project horizon", scans)
	if scans["audit_analysis"] == nil || scans["audit_analysis"].examined > 1 {
		t.Fatalf("project horizon read %+v", scans["audit_analysis"])
	}
	after := storage.ProjectBackfillCursor(watermark)
	query, arguments = projectBackfillQuery(1, &after, nil, 50)
	bounded = explainScans(t, store, query, arguments...)
	assertNoSeqScan(t, "bounded project candidates", bounded)
	for _, table := range []string{"audit_analysis", "audit_project_identity"} {
		if bounded[table] == nil || bounded[table].examined > 10 {
			t.Errorf("bounded project candidates read %+v rows of %s", bounded[table], table)
		}
	}
	query, arguments = projectBackfillQuery(1, nil, nil, 50)
	full = explainScans(t, store, query, arguments...)
	if full["audit_analysis"] == nil || full["audit_analysis"].examined < seededAudits {
		t.Fatalf("unbounded project candidates read only %+v rows", full["audit_analysis"])
	}
	t.Logf("project candidates: bounded %v rows of audit_analysis via %v, unbounded %v rows",
		bounded["audit_analysis"].examined, bounded["audit_analysis"].nodeTypes, full["audit_analysis"].examined)
}

// The row comparisons keep the keyset order: audits that share a start time
// are split by id on both sides of a bound.
func TestBackfillBoundsSplitTiesByAuditID(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	if _, found, err := store.AnalysisBackfillHorizon(ctx); found || err != nil {
		t.Fatalf("empty store horizon: %v %v", found, err)
	}
	if _, found, err := store.ProjectBackfillHorizon(ctx); found || err != nil {
		t.Fatalf("empty store project horizon: %v %v", found, err)
	}
	for _, id := range []string{"t-a", "t-b", "t-c"} {
		finishedTestAudit(t, store, id, 500)
		if _, err := store.writerConn.ExecContext(ctx, `UPDATE audit_records SET parse_status = 'ok' WHERE audit_id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := store.writerConn.ExecContext(ctx, `INSERT INTO audit_analysis (audit_id, analysis_version, analyzed_at_ns, protocol, started_at_ns) VALUES ($1, 1, 1, 'openai', 500)`, id); err != nil {
			t.Fatal(err)
		}
	}
	horizon, found, err := store.AnalysisBackfillHorizon(ctx)
	if err != nil || !found || horizon != (AnalysisBackfillCursor{StartedAtNS: 500, AuditID: "t-c"}) {
		t.Fatalf("horizon = %+v %v %v", horizon, found, err)
	}
	candidates, err := store.ListAnalysisBackfillCandidates(ctx, 2, &AnalysisBackfillCursor{StartedAtNS: 500, AuditID: "t-a"}, 10)
	if err != nil || len(candidates) != 2 || candidates[0].AuditID != "t-b" || candidates[1].AuditID != "t-c" {
		t.Fatalf("after t-a = %+v %v", candidates, err)
	}
	// An empty id sorts below every real one: the bound a lowered watermark
	// uses to uncover a whole start time.
	candidates, err = store.ListAnalysisBackfillCandidates(ctx, 2, &AnalysisBackfillCursor{StartedAtNS: 500}, 10)
	if err != nil || len(candidates) != 3 {
		t.Fatalf("after (500, '') = %+v %v", candidates, err)
	}
	projectCandidates, err := store.ListProjectIdentityBackfillCandidates(ctx, 1,
		&storage.ProjectBackfillCursor{StartedAtNS: 500, AuditID: "t-a"}, &storage.ProjectBackfillCursor{StartedAtNS: 500, AuditID: "t-c"}, 10)
	if err != nil || len(projectCandidates) != 1 || projectCandidates[0].AuditID != "t-b" {
		t.Fatalf("between t-a and t-c = %+v %v", projectCandidates, err)
	}
}
