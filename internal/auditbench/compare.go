package auditbench

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
)

type comparedMetric struct {
	name   string
	unit   string
	a, b   float64
	digits int
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
	fmt.Fprintf(&builder, "# audit-bench comparison\n\n- A: `%s`, commit `%s`\n- B: `%s`, commit `%s`\n\n", nameA, a.Build.Commit, nameB, b.Build.Commit)
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
	addCount("commits per audit", "count", perAudit(a.Total.AppCommits, a.Audits.Count), perAudit(b.Total.AppCommits, b.Audits.Count), 2)
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
