package auditbench

import (
	"encoding/json"
	"os"
	"sort"
	"time"
)

// FormatVersion is the version of the result file layout.
const FormatVersion = 1

// Result is everything one run measured. Sizes are bytes, durations are
// seconds or milliseconds as the field name says, and counters are counts.
type Result struct {
	Tool          string        `json:"tool"`
	FormatVersion int           `json:"format_version"`
	Build         BuildInfo     `json:"build"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Workload      Workload      `json:"workload"`
	Postgres      PostgresInfo  `json:"postgres"`
	Phases        []PhaseResult `json:"phases"`
	Total         PhaseResult   `json:"total"`
	// Write spans load and drain together. Counter statistics flush with a
	// lag of up to a second for busy sessions, so the split between load and
	// drain is approximate while their sum is not.
	Write         PhaseResult       `json:"load_and_drain"`
	Tables        []TableFinal      `json:"tables"`
	Audits        AuditSummary      `json:"audits"`
	Client        ClientSummary     `json:"client"`
	Reads         ReadSummary       `json:"reads"`
	Memory        MemorySummary     `json:"memory"`
	Logs          map[string]int64  `json:"app_log_counts"`
	Upstream      UpstreamSummary   `json:"upstream"`
	Contamination ContaminationInfo `json:"contamination"`
	Warnings      []string          `json:"warnings"`
}

// BuildInfo identifies the code that was measured.
type BuildInfo struct {
	Commit    string `json:"commit"`
	Modified  bool   `json:"modified"`
	GoVersion string `json:"go_version"`
	Source    string `json:"source"`
}

// PostgresInfo holds the settings needed to read the numbers.
type PostgresInfo struct {
	Settings       map[string]string `json:"settings"`
	VersionNumber  int               `json:"server_version_num"`
	FreshSchema    bool              `json:"fresh_schema"`
	Schema         string            `json:"schema"`
	BackendStats   bool              `json:"per_backend_stats"`
	ForceFlush     bool              `json:"force_next_flush"`
	SettleSeconds  int               `json:"settle_seconds"`
	StatsWereReset bool              `json:"stats_reset_during_run"`
}

// PhaseResult holds the differences between the snapshots that bracket one
// phase.
type PhaseResult struct {
	Name            string                `json:"name"`
	DurationSeconds float64               `json:"duration_seconds"`
	Tables          map[string]TableDelta `json:"tables"`
	WAL             WALStats              `json:"wal"`
	Writer          BackendStats          `json:"writer_backend"`
	// WALOutsideWriter is cluster WAL not written by the application's writer
	// session: reader page pruning, autovacuum, checkpoints, other sessions.
	WALOutsideWriter int64         `json:"wal_outside_writer_bytes"`
	Database         DatabaseStats `json:"database"`
	ToolCommits      int64         `json:"tool_commits"`
	AppCommits       int64         `json:"commits_excluding_tool"`
	MemoryPeakBytes  uint64        `json:"memory_peak_bytes"`
	HeapPeakBytes    uint64        `json:"heap_peak_bytes"`
	Activity         Activity      `json:"max_foreign_activity"`
	LatencyPolls     int64         `json:"tool_latency_polls"`
	DrainPolls       int64         `json:"tool_drain_polls"`
}

// TableDelta is the counter difference over a phase plus the sizes at its end.
type TableDelta struct {
	TableStats
	HeapBytesDelta  int64 `json:"heap_bytes_delta"`
	ToastBytesDelta int64 `json:"toast_bytes_delta"`
	IndexBytesDelta int64 `json:"index_bytes_delta"`
}

// TableFinal is one table at the end of the run.
type TableFinal struct {
	Name       string `json:"name"`
	Rows       int64  `json:"rows"`
	HeapBytes  int64  `json:"heap_bytes"`
	ToastBytes int64  `json:"toast_bytes"`
	IndexBytes int64  `json:"index_bytes"`
	TotalBytes int64  `json:"total_bytes"`
}

// AuditSummary describes the audits the run wrote.
type AuditSummary struct {
	Count            int64            `json:"count"`
	ByForwardStatus  map[string]int64 `json:"by_forward_status"`
	ByCaptureStatus  map[string]int64 `json:"by_capture_status"`
	ByParseStatus    map[string]int64 `json:"by_parse_status"`
	ByRetention      map[string]int64 `json:"body_streams_by_retention_state"`
	ByCallerStatus   map[string]int64 `json:"by_caller_status"`
	Turns            int64            `json:"turns"`
	Conversations    int64            `json:"conversations"`
	ExpectationOK    int64            `json:"parse_status_as_expected"`
	ExpectationMiss  int64            `json:"parse_status_unexpected"`
	ExpectationLost  int64            `json:"requests_without_audit"`
	NotForwarded     int64            `json:"requests_not_forwarded"`
	Mismatches       map[string]int64 `json:"unexpected_by_case"`
	AnalysisPending  int64            `json:"analysis_candidates_left"`
	IdentityPending  int64            `json:"project_identity_candidates_left"`
	DrainTimedOut    bool             `json:"drain_timed_out"`
	RequestBodyBytes int64            `json:"request_body_bytes_sent"`
}

// ClientSummary describes the traffic as the client saw it.
type ClientSummary struct {
	Requests        int64                     `json:"requests"`
	ByCase          map[string]int64          `json:"by_case"`
	Errors          map[string]int64          `json:"transport_errors"`
	TTFB            LatencySummary            `json:"time_to_first_byte_ms"`
	EndOfStream     LatencySummary            `json:"time_to_end_ms"`
	Queryable       LatencySummary            `json:"end_to_queryable_ms"`
	ByGroup         map[string]GroupLatencies `json:"by_protocol_and_mode"`
	QueryableMissed int64                     `json:"queryable_not_observed"`
}

// GroupLatencies are the client latencies of one protocol and mode.
type GroupLatencies struct {
	TTFB        LatencySummary `json:"time_to_first_byte_ms"`
	EndOfStream LatencySummary `json:"time_to_end_ms"`
	Queryable   LatencySummary `json:"end_to_queryable_ms"`
}

// LatencySummary are milliseconds.
type LatencySummary struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	Max   float64 `json:"max"`
}

// ReadSummary holds the management API read latencies.
type ReadSummary struct {
	Sampled        int              `json:"sampled_audits"`
	Detail         LatencySummary   `json:"detail_ms"`
	ExportRequest  LatencySummary   `json:"export_request_ms"`
	ExportResponse LatencySummary   `json:"export_response_ms"`
	Statuses       map[string]int64 `json:"statuses"`
	RawFallbacks   int64            `json:"raw_fallbacks"`
}

// MemorySummary is the process memory: the application, the fake upstream
// and the load driver share one process.
type MemorySummary struct {
	PeakTotalBytes uint64 `json:"peak_go_total_bytes"`
	PeakHeapBytes  uint64 `json:"peak_go_heap_objects_bytes"`
	PeakRSSBytes   uint64 `json:"peak_rss_bytes,omitempty"`
}

// UpstreamSummary counts what the fake upstream and fake NewAPI served.
type UpstreamSummary struct {
	Served        int64 `json:"served"`
	Unknown       int64 `json:"unknown"`
	Mismatched    int64 `json:"request_mismatched"`
	Aborted       int64 `json:"aborted"`
	Cancelled     int64 `json:"client_cancelled"`
	NewAPILookups int64 `json:"newapi_log_lookups"`
}

// ContaminationInfo reports other sessions that share the counters.
type ContaminationInfo struct {
	MaxSameDatabase  int64 `json:"max_foreign_same_database"`
	MaxOtherDatabase int64 `json:"max_other_databases"`
	Contaminated     bool  `json:"database_wide_counters_contaminated"`
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o644)
}

func readResult(path string) (Result, error) {
	var result Result
	data, err := os.ReadFile(path)
	if err != nil {
		return result, err
	}
	return result, json.Unmarshal(data, &result)
}

func summarize(values []float64) LatencySummary {
	if len(values) == 0 {
		return LatencySummary{}
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	percentile := func(fraction float64) float64 {
		index := int(fraction*float64(len(sorted)-1) + 0.5)
		return round3(sorted[min(index, len(sorted)-1)])
	}
	return LatencySummary{Count: len(sorted), P50: percentile(0.50), P95: percentile(0.95), Max: round3(sorted[len(sorted)-1])}
}

func round3(value float64) float64 {
	return float64(int64(value*1000+0.5)) / 1000
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration.Nanoseconds()) / 1e6
}

// difference computes end minus start for one phase.
func difference(name string, start, end snapshot) PhaseResult {
	phase := PhaseResult{
		Name:            name,
		DurationSeconds: round3(end.at.Sub(start.at).Seconds()),
		Tables:          make(map[string]TableDelta, len(end.tables)),
		WAL: WALStats{
			Records:  end.wal.Records - start.wal.Records,
			FPI:      end.wal.FPI - start.wal.FPI,
			Bytes:    end.wal.Bytes - start.wal.Bytes,
			LSNBytes: end.wal.LSNBytes - start.wal.LSNBytes,
		},
		Database: DatabaseStats{
			XactCommit:   end.database.XactCommit - start.database.XactCommit,
			XactRollback: end.database.XactRollback - start.database.XactRollback,
			BlocksRead:   end.database.BlocksRead - start.database.BlocksRead,
			BlocksHit:    end.database.BlocksHit - start.database.BlocksHit,
			TupInserted:  end.database.TupInserted - start.database.TupInserted,
			TupUpdated:   end.database.TupUpdated - start.database.TupUpdated,
			TupDeleted:   end.database.TupDeleted - start.database.TupDeleted,
			TempBytes:    end.database.TempBytes - start.database.TempBytes,
		},
		ToolCommits: end.transactions - start.transactions,
	}
	phase.AppCommits = phase.Database.XactCommit - phase.ToolCommits
	if start.writer.Available && end.writer.Available {
		phase.Writer = BackendStats{
			Available:     true,
			WALRecords:    end.writer.WALRecords - start.writer.WALRecords,
			WALFPI:        end.writer.WALFPI - start.writer.WALFPI,
			WALBytes:      end.writer.WALBytes - start.writer.WALBytes,
			IOReads:       end.writer.IOReads - start.writer.IOReads,
			IOReadBytes:   end.writer.IOReadBytes - start.writer.IOReadBytes,
			IOWrites:      end.writer.IOWrites - start.writer.IOWrites,
			IOWriteBytes:  end.writer.IOWriteBytes - start.writer.IOWriteBytes,
			IOExtends:     end.writer.IOExtends - start.writer.IOExtends,
			IOHits:        end.writer.IOHits - start.writer.IOHits,
			IOUnavailable: start.writer.IOUnavailable || end.writer.IOUnavailable,
		}
		phase.WALOutsideWriter = phase.WAL.Bytes - phase.Writer.WALBytes
	}
	for table, after := range end.tables {
		before := start.tables[table]
		phase.Tables[table] = TableDelta{
			TableStats: TableStats{
				HeapBytes: after.HeapBytes, ToastBytes: after.ToastBytes, IndexBytes: after.IndexBytes,
				LiveTuples: after.LiveTuples, DeadTuples: after.DeadTuples,
				Inserted: after.Inserted - before.Inserted, Updated: after.Updated - before.Updated,
				HOTUpdated: after.HOTUpdated - before.HOTUpdated, Deleted: after.Deleted - before.Deleted,
				SeqScans: after.SeqScans - before.SeqScans, SeqTupRead: after.SeqTupRead - before.SeqTupRead,
				IndexScans: after.IndexScans - before.IndexScans, IdxTupFetch: after.IdxTupFetch - before.IdxTupFetch,
				HeapBlocksRead: after.HeapBlocksRead - before.HeapBlocksRead, HeapBlocksHit: after.HeapBlocksHit - before.HeapBlocksHit,
				IndexBlocksRead: after.IndexBlocksRead - before.IndexBlocksRead, IndexBlocksHit: after.IndexBlocksHit - before.IndexBlocksHit,
				ToastBlocksRead: after.ToastBlocksRead - before.ToastBlocksRead, ToastBlocksHit: after.ToastBlocksHit - before.ToastBlocksHit,
				ToastIndexBlocksRead: after.ToastIndexBlocksRead - before.ToastIndexBlocksRead,
				ToastIndexBlocksHit:  after.ToastIndexBlocksHit - before.ToastIndexBlocksHit,
				Autovacuums:          after.Autovacuums - before.Autovacuums, Autoanalyzes: after.Autoanalyzes - before.Autoanalyzes,
			},
			HeapBytesDelta:  after.HeapBytes - before.HeapBytes,
			ToastBytesDelta: after.ToastBytes - before.ToastBytes,
			IndexBytesDelta: after.IndexBytes - before.IndexBytes,
		}
	}
	return phase
}
