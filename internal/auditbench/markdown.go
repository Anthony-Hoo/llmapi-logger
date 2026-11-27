package auditbench

import (
	"fmt"
	"sort"
	"strings"
)

// Units follow appendix A.1 of the design: decimal megabytes (10^6 bytes)
// and kilobytes (10^3 bytes).
func megabytes(value int64) string   { return fmt.Sprintf("%.3f", float64(value)/1e6) }
func megabytesU(value uint64) string { return fmt.Sprintf("%.3f", float64(value)/1e6) }
func kilobytes(value float64) string { return fmt.Sprintf("%.1f", value/1e3) }

func perAudit(value, audits int64) float64 {
	if audits <= 0 {
		return 0
	}
	return float64(value) / float64(audits)
}

func table(builder *strings.Builder, header []string, rows [][]string) {
	builder.WriteString("| " + strings.Join(header, " | ") + " |\n|")
	for range header {
		builder.WriteString(" --- |")
	}
	builder.WriteByte('\n')
	for _, row := range rows {
		builder.WriteString("| " + strings.Join(row, " | ") + " |\n")
	}
	builder.WriteByte('\n')
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func latencyRow(name string, value LatencySummary) []string {
	return []string{name, fmt.Sprint(value.Count), fmt.Sprintf("%.1f", value.P50), fmt.Sprintf("%.1f", value.P95), fmt.Sprintf("%.1f", value.Max)}
}

func renderMarkdown(result Result) string {
	var builder strings.Builder
	commit := result.Build.Commit
	if result.Build.Modified {
		commit += " (modified)"
	}
	fmt.Fprintf(&builder, "# audit-bench result\n\n- Commit: `%s` (source: %s), %s\n- Started: %s, finished: %s\n- PostgreSQL schema: `%s` (fresh: %v)\n\n",
		commit, result.Build.Source, result.Build.GoVersion, result.StartedAt.Format("2006-01-02 15:04:05Z"),
		result.FinishedAt.Format("2006-01-02 15:04:05Z"), result.Postgres.Schema, result.Postgres.FreshSchema)
	if len(result.Warnings) > 0 {
		builder.WriteString("## Warnings\n\n")
		for _, warning := range result.Warnings {
			builder.WriteString("- " + warning + "\n")
		}
		builder.WriteByte('\n')
	}

	builder.WriteString("## Workload\n\n")
	workload := result.Workload
	mix := make([]string, 0, len(workload.Mix))
	for _, name := range sortedKeys(workload.Mix) {
		mix = append(mix, fmt.Sprintf("%s=%g", name, workload.Mix[name]))
	}
	table(&builder, []string{"Parameter", "Value"}, [][]string{
		{"profile", workload.Profile}, {"seed", fmt.Sprint(workload.Seed)},
		{"conversations (count)", fmt.Sprint(workload.Conversations)}, {"turns per conversation (count)", fmt.Sprint(workload.Turns)},
		{"concurrency (clients)", fmt.Sprint(workload.Concurrency)}, {"protocol mix (weights)", strings.Join(mix, ", ")},
		{"stream share (fraction)", fmt.Sprint(workload.StreamShare)}, {"abnormal share (fraction of turns)", fmt.Sprint(workload.AbnormalShare)},
		{"branch share (fraction of conversations)", fmt.Sprint(workload.BranchShare)},
		{"prior history items (count)", fmt.Sprint(workload.HistoryItems)}, {"bytes per item (bytes)", fmt.Sprint(workload.ItemBytes)},
		{"stream delta (bytes)", fmt.Sprint(workload.DeltaBytes)}, {"tool definitions (count)", fmt.Sprint(workload.ToolDefinitions)},
		{"system prompt (bytes)", fmt.Sprint(workload.SystemBytes)},
		{"upstream first byte delay (ms)", fmt.Sprint(workload.FirstByteMS)}, {"upstream chunk delay (ms)", fmt.Sprint(workload.ChunkDelayMS)},
		{"idle phase (s)", fmt.Sprint(workload.IdleSeconds)}, {"insights / org reports / caller lookups", fmt.Sprintf("%v / %v / %v", workload.Insights, workload.OrgReports, workload.CallerLookups)},
		{"request bodies sent (MB)", megabytes(result.Audits.RequestBodyBytes)},
	})

	builder.WriteString("## PostgreSQL\n\n")
	settings := make([][]string, 0, len(result.Postgres.Settings))
	for _, name := range sortedKeys(result.Postgres.Settings) {
		settings = append(settings, []string{name, result.Postgres.Settings[name]})
	}
	settings = append(settings, []string{"per-backend statistics", fmt.Sprint(result.Postgres.BackendStats)},
		[]string{"statistics settle wait (s)", fmt.Sprint(result.Postgres.SettleSeconds)},
		[]string{"max foreign sessions, this database / others (count)", fmt.Sprintf("%d / %d", result.Contamination.MaxSameDatabase, result.Contamination.MaxOtherDatabase)})
	table(&builder, []string{"Setting", "Value"}, settings)

	builder.WriteString("## Phases\n\n")
	phaseRows := make([][]string, 0, len(result.Phases)+1)
	for _, phase := range append(append([]PhaseResult(nil), result.Phases...), result.Write, result.Total) {
		var growth int64
		for _, delta := range phase.Tables {
			growth += delta.HeapBytesDelta + delta.ToastBytesDelta + delta.IndexBytesDelta
		}
		writer, outside := "n/a", "n/a"
		if phase.Writer.Available {
			writer, outside = megabytes(phase.Writer.WALBytes), megabytes(phase.WALOutsideWriter)
		}
		phaseRows = append(phaseRows, []string{phase.Name, fmt.Sprintf("%.1f", phase.DurationSeconds),
			megabytes(phase.WAL.Bytes), megabytes(phase.WAL.LSNBytes), fmt.Sprint(phase.WAL.Records), fmt.Sprint(phase.WAL.FPI),
			writer, outside, fmt.Sprint(phase.AppCommits), fmt.Sprint(phase.ToolCommits), megabytes(growth), megabytesU(phase.MemoryPeakBytes)})
	}
	table(&builder, []string{"Phase", "Duration (s)", "Cluster WAL (MB)", "WAL by LSN (MB)", "WAL records (count)", "Full-page images (count)",
		"Writer backend WAL (MB)", "WAL outside writer (MB)", "Commits excl. tool (count)", "Tool commits (count)", "Table growth (MB)", "Go memory peak (MB)"}, phaseRows)
	builder.WriteString("Cluster WAL and commits cover every session of the server; the writer-backend column is the application's own writer session only. " +
		"Counters flush with a lag of up to a second for busy sessions, so the load/drain split is approximate; WAL by LSN and load+drain are exact.\n\n")

	audits := result.Audits.Count
	total := result.Total
	fpiShare := 0.0
	if total.WAL.Records > 0 {
		fpiShare = float64(total.WAL.FPI) / float64(total.WAL.Records) * 100
	}
	builder.WriteString("## Per audit (total)\n\n")
	perAuditRows := [][]string{
		{"audits written (count)", fmt.Sprint(audits)},
		{"WAL per audit (kB)", kilobytes(perAudit(total.WAL.Bytes, audits))},
		{"WAL records per audit (count)", fmt.Sprintf("%.1f", perAudit(total.WAL.Records, audits))},
		{"full-page images per WAL record (%)", fmt.Sprintf("%.2f", fpiShare)},
		{"commits per audit, all sessions but the tool, including read-only statements (count)", fmt.Sprintf("%.2f", perAudit(total.AppCommits, audits))},
	}
	if total.Writer.Available {
		perAuditRows = append(perAuditRows,
			[]string{"writer backend WAL per audit (kB)", kilobytes(perAudit(total.Writer.WALBytes, audits))},
			[]string{"writer backend reads / hits (blocks)", fmt.Sprintf("%d / %d", total.Writer.IOReads, total.Writer.IOHits)},
			[]string{"writer backend writes / extends (blocks)", fmt.Sprintf("%d / %d", total.Writer.IOWrites, total.Writer.IOExtends)})
	}
	table(&builder, []string{"Metric", "Value"}, perAuditRows)

	builder.WriteString("## Tables at the end\n\n")
	tableRows := make([][]string, 0, len(result.Tables))
	for _, final := range result.Tables {
		if final.Rows == 0 {
			continue
		}
		tableRows = append(tableRows, []string{final.Name, fmt.Sprint(final.Rows), megabytes(final.HeapBytes), megabytes(final.ToastBytes),
			megabytes(final.IndexBytes), megabytes(final.TotalBytes)})
	}
	table(&builder, []string{"Table", "Rows (count)", "Heap (MB)", "TOAST (MB)", "Indexes (MB)", "Total (MB)"}, tableRows)
	builder.WriteString("Empty tables are omitted; the JSON result lists them.\n\n")

	for _, phase := range append(append([]PhaseResult(nil), result.Phases...), result.Total) {
		rows := make([][]string, 0)
		for _, name := range sortedKeys(phase.Tables) {
			delta := phase.Tables[name]
			// A scan of an empty table touches no block; leave those out.
			if delta.Inserted+delta.Updated+delta.Deleted+delta.SeqTupRead+delta.HeapBlocksRead+delta.HeapBlocksHit+
				delta.IndexBlocksRead+delta.IndexBlocksHit+delta.ToastBlocksRead+delta.ToastBlocksHit == 0 {
				continue
			}
			rows = append(rows, []string{name, fmt.Sprint(delta.Inserted), fmt.Sprint(delta.Updated), fmt.Sprint(delta.HOTUpdated),
				fmt.Sprint(delta.Deleted), fmt.Sprint(delta.SeqScans), fmt.Sprint(delta.SeqTupRead), fmt.Sprint(delta.IndexScans),
				fmt.Sprintf("%d / %d", delta.HeapBlocksRead, delta.HeapBlocksHit), fmt.Sprintf("%d / %d", delta.IndexBlocksRead, delta.IndexBlocksHit),
				fmt.Sprintf("%d / %d", delta.ToastBlocksRead, delta.ToastBlocksHit)})
		}
		fmt.Fprintf(&builder, "## Table activity: %s\n\n", phase.Name)
		if len(rows) == 0 {
			builder.WriteString("No table activity.\n\n")
			continue
		}
		table(&builder, []string{"Table", "Inserted (rows)", "Updated (rows)", "HOT updated (rows)", "Deleted (rows)", "Seq scans (count)",
			"Seq rows read (rows)", "Index scans (count)", "Heap read / hit (blocks)", "Index read / hit (blocks)", "TOAST read / hit (blocks)"}, rows)
		fmt.Fprintf(&builder, "Tool queries in this phase: %d latency polls, %d drain polls (indexed or counting reads of audit_records and the analysis tables).\n\n",
			phase.LatencyPolls, phase.DrainPolls)
	}

	builder.WriteString("## Client latency\n\n")
	client := result.Client
	latencyRows := [][]string{latencyRow("time to first byte", client.TTFB), latencyRow("time to end of response", client.EndOfStream),
		latencyRow("end of response to queryable", client.Queryable)}
	for _, group := range sortedKeys(client.ByGroup) {
		value := client.ByGroup[group]
		latencyRows = append(latencyRows, latencyRow(group+" first byte", value.TTFB), latencyRow(group+" end", value.EndOfStream),
			latencyRow(group+" queryable", value.Queryable))
	}
	table(&builder, []string{"Measure", "Samples (count)", "p50 (ms)", "p95 (ms)", "Max (ms)"}, latencyRows)
	builder.WriteString("Queryable means the audit row has a terminal parse status; its resolution is the poll interval.\n\n")

	builder.WriteString("## Management API reads\n\n")
	reads := result.Reads
	table(&builder, []string{"Read", "Samples (count)", "p50 (ms)", "p95 (ms)", "Max (ms)"}, [][]string{
		latencyRow("detail", reads.Detail), latencyRow("export request", reads.ExportRequest), latencyRow("export response", reads.ExportResponse),
	})
	statusRows := make([][]string, 0, len(reads.Statuses))
	for _, key := range sortedKeys(reads.Statuses) {
		statusRows = append(statusRows, []string{key, fmt.Sprint(reads.Statuses[key])})
	}
	table(&builder, []string{"Read and HTTP status", "Responses (count)"}, statusRows)

	builder.WriteString("## Requests and audits\n\n")
	caseRows := make([][]string, 0, len(client.ByCase))
	for _, key := range sortedKeys(client.ByCase) {
		caseRows = append(caseRows, []string{key, fmt.Sprint(client.ByCase[key])})
	}
	table(&builder, []string{"Protocol / scenario / mode", "Requests (count)"}, caseRows)
	statusRows = [][]string{
		{"parse status as the fixture expects (audits)", fmt.Sprint(result.Audits.ExpectationOK)},
		{"parse status unexpected (audits)", fmt.Sprint(result.Audits.ExpectationMiss)},
		{"requests without an audit (count)", fmt.Sprint(result.Audits.ExpectationLost)},
		{"requests answered by the proxy itself, not checked (count)", fmt.Sprint(result.Audits.NotForwarded)},
		{"turns (count)", fmt.Sprint(result.Audits.Turns)}, {"conversations (count)", fmt.Sprint(result.Audits.Conversations)},
		{"analysis candidates left after drain (audits)", fmt.Sprint(result.Audits.AnalysisPending)},
		{"project identity candidates left after drain (audits)", fmt.Sprint(result.Audits.IdentityPending)},
	}
	for _, group := range []struct {
		name   string
		values map[string]int64
	}{{"forward_status", result.Audits.ByForwardStatus}, {"capture_status", result.Audits.ByCaptureStatus},
		{"parse_status", result.Audits.ByParseStatus}, {"caller_status", result.Audits.ByCallerStatus},
		{"body_streams retention_state", result.Audits.ByRetention}} {
		for _, key := range sortedKeys(group.values) {
			statusRows = append(statusRows, []string{group.name + " = " + key + " (rows)", fmt.Sprint(group.values[key])})
		}
	}
	for _, key := range sortedKeys(client.Errors) {
		statusRows = append(statusRows, []string{"client: " + key + " (requests)", fmt.Sprint(client.Errors[key])})
	}
	for _, key := range sortedKeys(result.Audits.Mismatches) {
		statusRows = append(statusRows, []string{"unexpected: " + key + " (audits)", fmt.Sprint(result.Audits.Mismatches[key])})
	}
	table(&builder, []string{"Measure", "Value"}, statusRows)

	builder.WriteString("## Process\n\n")
	processRows := [][]string{
		{"Go memory peak, total (MB)", megabytesU(result.Memory.PeakTotalBytes)},
		{"Go memory peak, heap objects (MB)", megabytesU(result.Memory.PeakHeapBytes)},
	}
	if result.Memory.PeakRSSBytes > 0 {
		processRows = append(processRows, []string{"peak resident set (MB)", megabytesU(result.Memory.PeakRSSBytes)})
	}
	processRows = append(processRows,
		[]string{"upstream exchanges served (count)", fmt.Sprint(result.Upstream.Served)},
		[]string{"upstream requests with altered bytes (count)", fmt.Sprint(result.Upstream.Mismatched)},
		[]string{"upstream aborts / client cancels seen (count)", fmt.Sprintf("%d / %d", result.Upstream.Aborted, result.Upstream.Cancelled)},
		[]string{"fake NewAPI log lookups (count)", fmt.Sprint(result.Upstream.NewAPILookups)})
	for _, key := range sortedKeys(result.Logs) {
		processRows = append(processRows, []string{"app log " + key + " (records)", fmt.Sprint(result.Logs[key])})
	}
	table(&builder, []string{"Measure", "Value"}, processRows)
	builder.WriteString("Memory covers one process: the application, the fake upstream and the load driver.\n")
	return builder.String()
}
