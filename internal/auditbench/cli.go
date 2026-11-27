// Package auditbench is the A/B load tool of issue #59: it runs the real
// audit proxy against a real PostgreSQL with synthetic traffic from
// protofixture and reports the storage and IO numbers of the design's
// appendix A. cmd/audit-bench is its thin command.
package auditbench

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

const usage = `audit-bench runs the audit proxy against PostgreSQL with synthetic traffic.

Usage:
  audit-bench run [flags]       start a fake upstream and the real proxy, send a workload, report
  audit-bench compare A.json B.json
                                print the differences of two run results as Markdown
  audit-bench dist [flags]      read-only distributions of an existing audit database

The connection string is read from the environment variable ` + DatabaseEnv + `
and never from the command line. It is not printed.

Run "audit-bench <command> -h" for the flags of one command.
`

const runHelp = `Run starts, in this process, a fake provider upstream (protofixture), a fake
NewAPI management API and the real application, then sends the workload
through the proxy's listener and measures four phases:

  load   the traffic is running
  drain  until every audit has a terminal parse status, caller lookups are done
         and the insights and project-identity backfills have no candidates left
  reads  detail and export of sampled audits through the management API
  idle   no traffic, to expose the cost of the backfill loops with nothing to do

PostgreSQL statistics are snapshot at every boundary; each snapshot is one
read-only transaction of the tool, and the tool's own commits are subtracted.
Before the drain, reads and idle snapshots the tool waits --settle so the
application's sessions have flushed their pending statistics.

The idle phase only shows a backfill rescan if it is long enough. The parser
worker ticks every 30 s, and after a scan finds no candidate the insights and
project-identity backfills wait 10 minutes (backfillRescanInterval,
projectBackfillRescanInterval) before scanning again. An idle phase shorter
than about 10.5 minutes may see no rescan at all; the default is 11 minutes.

The tool refuses a schema that already holds audit tables. With --fresh-schema
it creates its own schema in the target database and leaves it in place unless
--drop-schema is given. Cluster-wide WAL and database-wide commits include
every other session; the result flags such sessions and also reports the
per-table and the writer-backend (PostgreSQL 18) figures, which are isolated.

Flags:
`

const distHelp = `Dist reads an existing audit database and prints the distributions sections
5.3 and 5.4 of the design need: turns and stored bytes per conversation
(power-of-two histograms), turns per conversation and day, audits without a
turn, and the ratio of the sum over conversations of deduplicated object
bytes to the globally deduplicated object bytes.

It reads only counts, lengths and hashes, never a content column, inside one
read-only repeatable-read transaction with a statement timeout, and prints
aggregates only.

Flags:
`

// Main runs the command line and returns the process exit code.
func Main(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "run":
		return mainRun(ctx, args[1:], getenv, stdout, stderr)
	case "compare":
		return mainCompare(args[1:], stdout, stderr)
	case "dist":
		return mainDist(ctx, args[1:], getenv, stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func mainRun(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, runHelp)
		flags.PrintDefaults()
	}
	profile := flags.String("profile", "small", "workload profile: small, or heavy (about 1 MB and 220 context items per request)")
	seed := flags.Uint64("seed", 1, "seed of all generated traffic")
	conversations := flags.Int("conversations", 0, "conversations to send (0: profile default)")
	turns := flags.Int("turns", 0, "turns per conversation (0: profile default)")
	concurrency := flags.Int("concurrency", 0, "concurrent client conversations (0: profile default)")
	mix := flags.String("mix", defaultMix, "protocol weights, name=weight separated by commas")
	streamShare := flags.Float64("stream-share", 0.8, "fraction of conversations that stream")
	abnormalShare := flags.Float64("abnormal-share", 0.1, "probability per turn of an extra abnormal request (error answer or broken stream) before it")
	branchShare := flags.Float64("branch-share", 0.15, "fraction of conversations that also send a branch")
	historyItems := flags.Int("history-items", -1, "prior context items in the first request (-1: profile default)")
	itemBytes := flags.Int("item-bytes", 0, "bytes per message or tool output (0: profile default)")
	deltaBytes := flags.Int("delta-bytes", 0, "bytes per streamed text delta (0: profile default)")
	toolDefinitions := flags.Int("tool-definitions", 0, "tool definitions per request (0: profile default)")
	systemBytes := flags.Int("system-bytes", 0, "system prompt bytes (0: profile default)")
	firstByte := flags.Duration("upstream-first-byte", 0, "fake upstream delay before the response headers")
	chunkDelay := flags.Duration("upstream-chunk-delay", 0, "fake upstream delay between two streamed events")
	idle := flags.Duration("idle", 11*time.Minute, "length of the idle phase; see above for why it should exceed 10.5 minutes")
	settle := flags.Duration("settle", 11*time.Second, "wait before a snapshot so pending statistics are flushed")
	drainTimeout := flags.Duration("drain-timeout", 15*time.Minute, "give up waiting for the drain after this long")
	pollInterval := flags.Duration("poll-interval", 100*time.Millisecond, "interval of the end-to-queryable latency poll")
	latencySample := flags.Float64("latency-sample", 1, "fraction of requests whose end-to-queryable latency is tracked")
	readSamples := flags.Int("read-samples", 50, "audits whose detail and exports are read in the reads phase")
	insightsEnabled := flags.Bool("insights", true, "enable the insights analyzer and its backfill")
	orgReports := flags.Bool("org-reports", true, "enable organisation reports and the project-identity backfill (needs caller lookups)")
	callerLookups := flags.Bool("caller-lookups", true, "configure a NewAPI management identity so caller lookups run against the fake NewAPI")
	freshSchema := flags.Bool("fresh-schema", false, "create and use a new schema in the target database")
	dropSchema := flags.Bool("drop-schema", false, "drop the schema created by --fresh-schema after the run")
	output := flags.String("output", "audit-bench-result", "output path prefix; writes <prefix>.json and <prefix>.md")
	commit := flags.String("commit", "", "commit to record when the binary carries no VCS information")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	base, ok := profiles[*profile]
	if !ok {
		fmt.Fprintf(stderr, "unknown profile %q\n", *profile)
		return 2
	}
	parsedMix, err := parseMix(*mix)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	workload := base
	workload.Profile, workload.Seed, workload.Mix = *profile, *seed, parsedMix
	override := func(target *int, value int) {
		if value > 0 {
			*target = value
		}
	}
	override(&workload.Conversations, *conversations)
	override(&workload.Turns, *turns)
	override(&workload.Concurrency, *concurrency)
	override(&workload.ItemBytes, *itemBytes)
	override(&workload.DeltaBytes, *deltaBytes)
	override(&workload.ToolDefinitions, *toolDefinitions)
	override(&workload.SystemBytes, *systemBytes)
	if *historyItems >= 0 {
		workload.HistoryItems = *historyItems
	}
	workload.StreamShare, workload.AbnormalShare, workload.BranchShare = *streamShare, *abnormalShare, *branchShare
	workload.FirstByteMS, workload.ChunkDelayMS = int(firstByte.Milliseconds()), int(chunkDelay.Milliseconds())
	workload.IdleSeconds = int(idle.Seconds())
	workload.ReadSamples, workload.LatencySample = *readSamples, *latencySample
	workload.Insights, workload.OrgReports, workload.CallerLookups = *insightsEnabled, *orgReports, *callerLookups
	if workload.OrgReports && (!workload.CallerLookups || !workload.Insights) {
		fmt.Fprintln(stderr, "--org-reports needs --caller-lookups and --insights")
		return 2
	}
	if *dropSchema && !*freshSchema {
		fmt.Fprintln(stderr, "--drop-schema only applies to a schema created with --fresh-schema")
		return 2
	}
	options := runOptions{workload: workload, output: *output, freshSchema: *freshSchema, dropSchema: *dropSchema,
		settle: *settle, drainTimeout: *drainTimeout, pollInterval: *pollInterval, commit: *commit}
	if err := runBench(ctx, options, getenv, stdout); err != nil {
		fmt.Fprintln(stderr, "audit-bench:", err)
		return 1
	}
	return 0
}

func mainCompare(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "usage: audit-bench compare A.json B.json")
		return 2
	}
	a, err := readResult(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "read", args[0]+":", err)
		return 1
	}
	b, err := readResult(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "read", args[1]+":", err)
		return 1
	}
	compareResults(a, b, args[0], args[1], stdout)
	return 0
}

func mainDist(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dist", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, distHelp)
		flags.PrintDefaults()
	}
	schema := flags.String("schema", "", "schema holding the audit tables (default: the connection's search_path)")
	timeout := flags.Duration("statement-timeout", 10*time.Minute, "statement timeout of each query")
	asJSON := flags.Bool("json", false, "print JSON instead of Markdown")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	result, err := runDist(ctx, getenv, *schema, *timeout)
	if err != nil {
		fmt.Fprintln(stderr, "audit-bench:", err)
		return 1
	}
	if *asJSON {
		encoded, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(stdout, string(encoded))
		return 0
	}
	renderDistribution(result, stdout)
	return 0
}
