package auditbench

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/newapi"
	"llmapi-logger/internal/protofixture"
)

func TestParseMix(t *testing.T) {
	t.Parallel()
	mix, err := parseMix(defaultMix)
	if err != nil || len(mix) != 4 || mix["openai.responses"] != 5 {
		t.Fatalf("mix = %v err = %v", mix, err)
	}
	for _, bad := range []string{"", "openai.responses", "unknown=1", "gemini=-1", "gemini=0"} {
		if _, err := parseMix(bad); err == nil {
			t.Errorf("parseMix(%q) accepted", bad)
		}
	}
}

func TestAssignFollowsTheMixExactly(t *testing.T) {
	t.Parallel()
	mix, _ := parseMix(defaultMix)
	workload := Workload{Mix: mix, Conversations: 10, StreamShare: 0.8}
	counts := make(map[protofixture.Protocol]int)
	streamed := 0
	for _, value := range workload.assign(rand.New(rand.NewPCG(1, 2))) {
		counts[value.protocol]++
		if value.stream {
			streamed++
		}
	}
	if counts[protofixture.OpenAIResponses] != 5 || counts[protofixture.OpenAIChat] != 1 || counts[protofixture.AnthropicMessages] != 2 || counts[protofixture.Gemini] != 2 {
		t.Fatalf("counts = %v", counts)
	}
	if streamed != 8 {
		t.Fatalf("streamed = %d, want 8", streamed)
	}
	small := Workload{Mix: mix, Conversations: 4}
	seen := make(map[protofixture.Protocol]bool)
	for _, value := range small.assign(rand.New(rand.NewPCG(1, 2))) {
		seen[value.protocol] = true
	}
	if len(seen) != 4 {
		t.Fatalf("four conversations cover %d protocols, want 4", len(seen))
	}
}
func TestHumanSetting(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ setting, unit, want string }{
		{"16384", "8kB", "128MB"}, {"1024", "MB", "1GB"}, {"300", "s", "300s"}, {"on", "", "on"}, {"262144", "8kB", "2GB"},
	} {
		if got := humanSetting(test.setting, test.unit); got != test.want {
			t.Errorf("humanSetting(%q, %q) = %q, want %q", test.setting, test.unit, got, test.want)
		}
	}
}

func TestSummarize(t *testing.T) {
	t.Parallel()
	values := make([]float64, 0, 100)
	for index := 100; index >= 1; index-- {
		values = append(values, float64(index))
	}
	summary := summarize(values)
	if summary.Count != 100 || summary.P50 != 51 || summary.P95 != 95 || summary.Max != 100 {
		t.Fatalf("summary = %+v", summary)
	}
	if empty := summarize(nil); empty.Count != 0 {
		t.Fatalf("empty summary = %+v", empty)
	}
}

func TestWithSearchPath(t *testing.T) {
	t.Parallel()
	got, err := withSearchPath("postgres://user:secret@db.example.com:5432/name?sslmode=disable", "audit_bench_x")
	if err != nil || !strings.Contains(got, "search_path=audit_bench_x") || !strings.Contains(got, "sslmode=disable") {
		t.Fatalf("url form = %q err = %v", got, err)
	}
	got, _ = withSearchPath("host=db.example.com dbname=name", "audit_bench_x")
	if !strings.HasSuffix(got, " search_path=audit_bench_x") {
		t.Fatalf("keyword form = %q", got)
	}
}

func TestSafeErrorDropsText(t *testing.T) {
	t.Parallel()
	err := safeError("connect", errorString("failed to connect to user=someone host=db.example.com"))
	if strings.Contains(err.Error(), "example.com") || strings.Contains(err.Error(), "someone") {
		t.Fatalf("error leaked connection details: %v", err)
	}
}

type errorString string

func (value errorString) Error() string { return string(value) }

func TestDifferenceSubtractsToolCommits(t *testing.T) {
	t.Parallel()
	start := snapshot{at: time.Unix(0, 0), transactions: 10, database: DatabaseStats{XactCommit: 100},
		wal: WALStats{Bytes: 1000, Records: 10}, tables: map[string]TableStats{"audit_records": {Inserted: 1, HeapBytes: 8192}}}
	end := snapshot{at: time.Unix(2, 0), transactions: 13, database: DatabaseStats{XactCommit: 150},
		wal: WALStats{Bytes: 5000, Records: 30}, tables: map[string]TableStats{"audit_records": {Inserted: 6, HeapBytes: 16384}}}
	phase := difference("load", start, end)
	if phase.ToolCommits != 3 || phase.AppCommits != 47 || phase.WAL.Bytes != 4000 || phase.DurationSeconds != 2 {
		t.Fatalf("phase = %+v", phase)
	}
	if delta := phase.Tables["audit_records"]; delta.Inserted != 5 || delta.HeapBytesDelta != 8192 || delta.HeapBytes != 16384 {
		t.Fatalf("table delta = %+v", delta)
	}
}

func TestFakeNewAPIAnswersTheRealClient(t *testing.T) {
	t.Parallel()
	fake := newFakeNewAPI()
	server := httptest.NewServer(fake)
	defer server.Close()
	exchanges, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic}, protofixture.Options{Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	fake.remember("bench-1", &exchanges[0])
	client, err := newapi.NewClient(newapi.Config{BaseURL: server.URL, AccessToken: "placeholder-token", UserID: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := client.RefreshUsers(ctx); err != nil || len(client.Snapshot().Users) != fakeNewAPIUsers {
		t.Fatalf("users: %v %d", err, len(client.Snapshot().Users))
	}
	if err := client.RefreshStatus(ctx); err != nil {
		t.Fatalf("status: %v", err)
	}
	record, found, err := client.LookupRequest(ctx, "bench-1")
	if err != nil || !found || record.UserID != int64(exchanges[0].User) || record.ConsumeRows != 1 || !record.Complete {
		t.Fatalf("lookup = %+v found=%v err=%v", record, found, err)
	}
	if _, found, err := client.LookupRequest(ctx, "bench-unknown"); err != nil || found {
		t.Fatalf("unknown lookup found=%v err=%v", found, err)
	}
}

func TestRenderingCarriesUnits(t *testing.T) {
	t.Parallel()
	result := Result{Tool: "audit-bench", Workload: profiles["small"], Total: PhaseResult{Name: "total", Tables: map[string]TableDelta{}},
		Phases: []PhaseResult{{Name: "load", Tables: map[string]TableDelta{"audit_records": {TableStats: TableStats{Inserted: 3}}}}},
		Tables: []TableFinal{{Name: "audit_records", Rows: 3, HeapBytes: 8192, TotalBytes: 40960}},
		Audits: AuditSummary{Count: 3}, Postgres: PostgresInfo{Settings: map[string]string{"fsync": "on"}}}
	markdown := renderMarkdown(result)
	for _, want := range []string{"WAL (MB)", "Rows (count)", "p95 (ms)", "WAL per audit (kB)", "audit_records"} {
		if !strings.Contains(markdown, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	var output bytes.Buffer
	other := result
	other.Workload.Seed = 99
	compareResults(result, other, "a.json", "b.json", &output)
	if !strings.Contains(output.String(), "the workloads differ") || !strings.Contains(output.String(), "| Metric | Unit |") {
		t.Fatalf("comparison = %s", output.String())
	}
}

func TestMainRejectsMissingDatabase(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := Main(context.Background(), []string{"run", "--idle", "0s"}, func(string) string { return "" }, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), DatabaseEnv) {
		t.Fatalf("code = %d stderr = %s", code, stderr.String())
	}
	code = Main(context.Background(), []string{"dist"}, func(string) string { return "" }, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("dist without database: code %d", code)
	}
}
