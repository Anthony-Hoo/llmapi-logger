package auditbench

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"llmapi-logger/internal/config"
)

type comparedMetric struct {
	name   string
	unit   string
	a, b   float64
	digits int
	// missingA and missingB mark a value the result does not carry (an
	// older format, or statements not counted).
	missingA, missingB bool
}

// writePathWarnings flag an A/B whose write paths are not what the labels
// say, and runs whose backlog makes the queryable latency meaningless.
func writePathWarnings(a, b Result) []string {
	warnings := make([]string, 0)
	for _, run := range []struct {
		name   string
		result Result
	}{{"A", a}, {"B", b}} {
		if run.result.FormatVersion < 2 || run.result.WritePath.Effective == "" {
			warnings = append(warnings, fmt.Sprintf("%s does not record the write path the application used (result format %d)", run.name, run.result.FormatVersion))
			continue
		}
		if run.result.WritePath.Effective != run.result.WritePath.Requested {
			warnings = append(warnings, fmt.Sprintf("%s requested the %s write path but the application used %s", run.name, run.result.WritePath.Requested, run.result.WritePath.Effective))
		}
		if backlog := run.result.Client.ParseBacklog.Max; backlog > BacklogLimit {
			warnings = append(warnings, fmt.Sprintf("%s's pending parse backlog reached %d (limit %d): its end of response to queryable measures the parser's rescan, not the write path", run.name, backlog, BacklogLimit))
		}
	}
	pa, pb := a.WritePath, b.WritePath
	if pa.Effective != "" && pa.Effective == pb.Effective && pa.Requested != pb.Requested {
		warnings = append(warnings, fmt.Sprintf("the write paths differ only by label: both runs used %s", pa.Effective))
	}
	if pa.Effective == config.AuditWritePathUnified && pb.Effective == config.AuditWritePathUnified && pa.StageBytes != pb.StageBytes {
		warnings = append(warnings, fmt.Sprintf("the stage budgets differ (%d vs %d bytes)", pa.StageBytes, pb.StageBytes))
	}
	switch {
	case pa.CountStatements != pb.CountStatements:
		warnings = append(warnings, "only one run relayed its connections to count statements; the relay adds a loopback hop to every database round trip, so latencies are not comparable")
	case pa.CountStatements:
		warnings = append(warnings, "both runs relayed their connections to count statements: the latency rows include a loopback hop per database round trip, which favours the path with fewer round trips; take latencies from a pair run with --count-statements=false")
	}
	return warnings
}

func phaseByName(result Result, name string) (PhaseResult, bool) {
	if name == "total" {
		return result.Total, true
	}
	if name == "load+drain" {
		return result.Write, true
	}
	for _, phase := range result.Phases {
		if phase.Name == name {
			return phase, true
		}
	}
	return PhaseResult{}, false
}

func tableTotals(result Result) map[string]TableFinal {
	values := make(map[string]TableFinal, len(result.Tables))
	for _, table := range result.Tables {
		values[table.Name] = table
	}
	return values
}

// compareResults prints the differences of two result files as Markdown.
func compareResults(a, b Result, nameA, nameB string, output io.Writer) {
	var builder strings.Builder
	fmt.Fprintf(&builder, "# audit-bench comparison\n\n- A: `%s`, commit `%s`, write path %s\n- B: `%s`, commit `%s`, write path %s\n\n",
		nameA, a.Build.Commit, orNA(a.WritePath.Effective), nameB, b.Build.Commit, orNA(b.WritePath.Effective))
	warnings := make([]string, 0)
	workloadA, _ := json.Marshal(a.Workload)
	workloadB, _ := json.Marshal(b.Workload)
	if string(workloadA) != string(workloadB) {
		warnings = append(warnings, "the workloads differ; the comparison is not an A/B of the same traffic")
	}
	if !reflect.DeepEqual(a.Postgres.Settings, b.Postgres.Settings) {
		for _, key := range sortedKeys(a.Postgres.Settings) {
			if a.Postgres.Settings[key] != b.Postgres.Settings[key] {
				warnings = append(warnings, fmt.Sprintf("PostgreSQL setting %s differs: %q vs %q", key, a.Postgres.Settings[key], b.Postgres.Settings[key]))
			}
		}
	}
	if a.Contamination.Contaminated || b.Contamination.Contaminated {
		warnings = append(warnings, "at least one run shared the database with other sessions; compare the per-table and writer-backend rows")
	}
	warnings = append(warnings, writePathWarnings(a, b)...)
	if a.Audits.Count != b.Audits.Count {
		warnings = append(warnings, fmt.Sprintf("the runs wrote different numbers of audits (%d vs %d)", a.Audits.Count, b.Audits.Count))
	}
	for _, warning := range append(append([]string(nil), a.Warnings...), b.Warnings...) {
		warnings = append(warnings, "from a run: "+warning)
	}
	if len(warnings) > 0 {
		builder.WriteString("## Warnings\n\n")
		for _, warning := range warnings {
			builder.WriteString("- " + warning + "\n")
		}
		builder.WriteByte('\n')
	}

	metrics := make([]comparedMetric, 0, 64)
	addMB := func(name string, x, y int64) {
		metrics = append(metrics, comparedMetric{name: name, unit: "MB", a: float64(x) / 1e6, b: float64(y) / 1e6, digits: 3})
	}
	addCount := func(name, unit string, x, y float64, digits int) {
		metrics = append(metrics, comparedMetric{name: name, unit: unit, a: x, b: y, digits: digits})
	}
	addCount("audits written", "count", float64(a.Audits.Count), float64(b.Audits.Count), 0)
	for _, phaseName := range append(append([]string(nil), phaseNames...), "load+drain", "total") {
		pa, okA := phaseByName(a, phaseName)
		pb, okB := phaseByName(b, phaseName)
		if !okA || !okB {
			continue
		}
		addMB(phaseName+": WAL", pa.WAL.Bytes, pb.WAL.Bytes)
		addMB(phaseName+": WAL by LSN", pa.WAL.LSNBytes, pb.WAL.LSNBytes)
		addCount(phaseName+": full-page images", "count", float64(pa.WAL.FPI), float64(pb.WAL.FPI), 0)
		if pa.Writer.Available && pb.Writer.Available {
			addMB(phaseName+": writer backend WAL", pa.Writer.WALBytes, pb.Writer.WALBytes)
		}
		addCount(phaseName+": commits excluding the tool", "count", float64(pa.AppCommits), float64(pb.AppCommits), 0)
		var readsA, readsB int64
		for _, delta := range pa.Tables {
			readsA += delta.HeapBlocksRead + delta.HeapBlocksHit + delta.IndexBlocksRead + delta.IndexBlocksHit + delta.ToastBlocksRead + delta.ToastBlocksHit
		}
		for _, delta := range pb.Tables {
			readsB += delta.HeapBlocksRead + delta.HeapBlocksHit + delta.IndexBlocksRead + delta.IndexBlocksHit + delta.ToastBlocksRead + delta.ToastBlocksHit
		}
		addCount(phaseName+": table block accesses", "blocks", float64(readsA), float64(readsB), 0)
	}
	addCount("WAL per audit", "kB", perAudit(a.Total.WAL.Bytes, a.Audits.Count)/1e3, perAudit(b.Total.WAL.Bytes, b.Audits.Count)/1e3, 1)
	if a.Total.Writer.Available && b.Total.Writer.Available {
		addCount("writer backend WAL per audit", "kB", perAudit(a.Total.Writer.WALBytes, a.Audits.Count)/1e3, perAudit(b.Total.Writer.WALBytes, b.Audits.Count)/1e3, 1)
	}
	addCount("commits per audit, all sessions incl. reader statements", "count", perAudit(a.Total.AppCommits, a.Audits.Count), perAudit(b.Total.AppCommits, b.Audits.Count), 2)
	addWire := func(name string, value func(WireStats) int64) {
		wa, wb := a.Total.Statements, b.Total.Statements
		metrics = append(metrics, comparedMetric{name: name, unit: "count", a: perAudit(value(wa), a.Audits.Count), b: perAudit(value(wb), b.Audits.Count),
			digits: 2, missingA: !wa.Available, missingB: !wb.Available})
	}
	addWire("writer operations per audit", func(stats WireStats) int64 { return stats.Writer.Operations })
	addWire("writer commits per audit", func(stats WireStats) int64 { return stats.Writer.Commits })
	addWire("writer statements per audit", func(stats WireStats) int64 { return stats.Writer.Statements })
	addWire("reader statements per audit", func(stats WireStats) int64 { return stats.Readers.Statements })
	for _, row := range rowChanges {
		value := func(delta TableDelta) int64 {
			switch row.kind {
			case "updated":
				return delta.Updated
			case "deleted":
				return delta.Deleted
			}
			return delta.Inserted
		}
		addCount(row.table+" rows "+row.kind+" per audit", "rows", perAudit(value(a.Total.Tables[row.table]), a.Audits.Count),
			perAudit(value(b.Total.Tables[row.table]), b.Audits.Count), 2)
	}
	staged := func(name, unit string, x, y float64, digits int) {
		metrics = append(metrics, comparedMetric{name: name, unit: unit, a: x, b: y, digits: digits, missingA: a.FormatVersion < 2, missingB: b.FormatVersion < 2})
	}
	staged("staging bytes written", "MB", float64(a.Total.Staging.BytesWritten)/1e6, float64(b.Total.Staging.BytesWritten)/1e6, 3)
	staged("staged records", "count", float64(a.Total.Staging.Records), float64(b.Total.Staging.Records), 0)
	staged("staging fsyncs", "count", float64(a.Total.Staging.Fsyncs), float64(b.Total.Staging.Fsyncs), 0)
	staged("largest pending parse backlog", "audits", float64(a.Client.ParseBacklog.Max), float64(b.Client.ParseBacklog.Max), 0)
	staged("handler Finish p50", "ms", a.Client.Finish.P50, b.Client.Finish.P50, 2)
	staged("handler Finish p95", "ms", a.Client.Finish.P95, b.Client.Finish.P95, 2)
	staged("handler Finish max", "ms", a.Client.Finish.Max, b.Client.Finish.Max, 2)
	for _, idleTable := range []string{"audit_records", "audit_analysis", "audit_project_identity", "body_chunks"} {
		pa, _ := phaseByName(a, "idle")
		pb, _ := phaseByName(b, "idle")
		addCount("idle: "+idleTable+" seq scans", "count", float64(pa.Tables[idleTable].SeqScans), float64(pb.Tables[idleTable].SeqScans), 0)
		addCount("idle: "+idleTable+" blocks read+hit", "blocks",
			float64(pa.Tables[idleTable].HeapBlocksRead+pa.Tables[idleTable].HeapBlocksHit+pa.Tables[idleTable].ToastBlocksRead+pa.Tables[idleTable].ToastBlocksHit),
			float64(pb.Tables[idleTable].HeapBlocksRead+pb.Tables[idleTable].HeapBlocksHit+pb.Tables[idleTable].ToastBlocksRead+pb.Tables[idleTable].ToastBlocksHit), 0)
	}
	tablesA, tablesB := tableTotals(a), tableTotals(b)
	names := make([]string, 0, len(tablesA))
	for name := range tablesA {
		names = append(names, name)
	}
	for name := range tablesB {
		if _, ok := tablesA[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		x, y := tablesA[name], tablesB[name]
		if x.TotalBytes <= 16384 && y.TotalBytes <= 16384 && x.Rows == 0 && y.Rows == 0 {
			continue
		}
		addMB("size: "+name, x.TotalBytes, y.TotalBytes)
		da, db := a.Total.Tables[name], b.Total.Tables[name]
		addCount("rows inserted: "+name, "rows", float64(da.Inserted), float64(db.Inserted), 0)
		addCount("rows updated: "+name, "rows", float64(da.Updated), float64(db.Updated), 0)
		addCount("rows deleted: "+name, "rows", float64(da.Deleted), float64(db.Deleted), 0)
	}
	for _, latency := range []struct {
		name string
		x, y LatencySummary
	}{
		{"time to first byte", a.Client.TTFB, b.Client.TTFB},
		{"time to end of response", a.Client.EndOfStream, b.Client.EndOfStream},
		{"end of response to queryable", a.Client.Queryable, b.Client.Queryable},
		{"detail read", a.Reads.Detail, b.Reads.Detail},
		{"export request read", a.Reads.ExportRequest, b.Reads.ExportRequest},
		{"export response read", a.Reads.ExportResponse, b.Reads.ExportResponse},
	} {
		addCount(latency.name+" p50", "ms", latency.x.P50, latency.y.P50, 1)
		addCount(latency.name+" p95", "ms", latency.x.P95, latency.y.P95, 1)
	}
	addMB("Go memory peak", int64(a.Memory.PeakTotalBytes), int64(b.Memory.PeakTotalBytes))
	if a.Memory.PeakRSSBytes > 0 || b.Memory.PeakRSSBytes > 0 {
		addMB("peak resident set", int64(a.Memory.PeakRSSBytes), int64(b.Memory.PeakRSSBytes))
	}

	rows := make([][]string, 0, len(metrics))
	for _, metric := range metrics {
		format := fmt.Sprintf("%%.%df", metric.digits)
		if metric.missingA || metric.missingB {
			valueA, valueB := fmt.Sprintf(format, metric.a), fmt.Sprintf(format, metric.b)
			if metric.missingA {
				valueA = "n/a"
			}
			if metric.missingB {
				valueB = "n/a"
			}
			rows = append(rows, []string{metric.name, metric.unit, valueA, valueB, "n/a", "n/a"})
			continue
		}
		change := "n/a"
		if metric.a != 0 {
			change = fmt.Sprintf("%+.1f", (metric.b-metric.a)/metric.a*100)
		} else if metric.b == 0 {
			change = "0.0"
		}
		rows = append(rows, []string{metric.name, metric.unit, fmt.Sprintf(format, metric.a), fmt.Sprintf(format, metric.b),
			fmt.Sprintf("%+"+format[1:], metric.b-metric.a), change})
	}
	table(&builder, []string{"Metric", "Unit", "A", "B", "B - A", "Change (%)"}, rows)
	_, _ = io.WriteString(output, builder.String())
}
