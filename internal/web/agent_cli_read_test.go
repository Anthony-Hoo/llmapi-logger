package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentcli"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// The real CLI against the real read facade: what a developer's agent sees.

// readCLI runs the real CLI against a read fixture's handler with token.
type readCLI struct {
	t      *testing.T
	env    *agentcli.Env
	stdout bytes.Buffer
	stderr bytes.Buffer
}

func newReadCLI(t *testing.T, fixture *readFixture, token string) *readCLI {
	t.Helper()
	server := httptest.NewServer(fixture.handler)
	t.Cleanup(server.Close)
	home := t.TempDir()
	credentials, _ := json.Marshal(map[string]string{"server": server.URL, "token": token, "expires_at": "2030-01-01T00:00:00Z", "role": "developer", "tier": "read"})
	if err := os.WriteFile(filepath.Join(home, "credentials.json"), credentials, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &readCLI{t: t}
	runner.env = &agentcli.Env{
		Stdin: strings.NewReader(""), Stdout: &runner.stdout, Stderr: &runner.stderr,
		Getenv: func(name string) string {
			if name == "LLMAUDIT_HOME" {
				return home
			}
			return ""
		},
		HomeDir:          func() (string, error) { return "", errors.New("not used") },
		Hostname:         func() (string, error) { return "test-host", nil },
		UTCOffsetMinutes: func() int { return 0 },
		Terminal:         &keyTerminal{},
	}
	return runner
}

func (runner *readCLI) run(args ...string) int {
	runner.stdout.Reset()
	runner.stderr.Reset()
	return agentcli.Run(args, runner.env)
}

// mustRun runs a command that must succeed and decodes its envelope.
func (runner *readCLI) mustRun(args ...string) cliEnvelope {
	runner.t.Helper()
	if exit := runner.run(args...); exit != 0 {
		runner.t.Fatalf("llmaudit %s = exit %d: %s", strings.Join(args, " "), exit, runner.stderr.String())
	}
	var envelope cliEnvelope
	if err := json.Unmarshal(runner.stdout.Bytes(), &envelope); err != nil {
		runner.t.Fatalf("llmaudit %s printed %q", strings.Join(args, " "), runner.stdout.String())
	}
	return envelope
}

type cliEnvelope struct {
	OK   bool            `json:"ok"`
	Data json.RawMessage `json:"data"`
	Meta struct {
		State            string `json:"state"`
		Complete         bool   `json:"complete"`
		IncompleteReason string `json:"incomplete_reason"`
	} `json:"meta"`
}

func sensitiveReads(fixture *readFixture) int {
	count := 0
	for _, entry := range fixture.store.Audit() {
		if entry.Event == agentaccess.EventSensitiveRead {
			count++
		}
	}
	return count
}

// An --out the client cannot write fails with LOCAL_FILE_ERROR before the
// server is asked: the pack is not read, so no view log and no
// sensitive_read row is written for content the client would discard.
func TestCLIUnusableOutLogsNoView(t *testing.T) {
	fixture := newReadFixture(t)
	cli := newReadCLI(t, fixture, fixture.developer)
	views, sensitive := fixture.analysis.viewCount(), sensitiveReads(fixture)
	missing := filepath.Join(t.TempDir(), "no-such-dir", "pack.json")
	for _, args := range [][]string{
		{"analysis", "session", analysisOwnID, "--pack", "--out", missing},
		{"analysis", "session", analysisOwnID, "--facet", "--out", missing},
		{"usage", "composition", "own-1", "--out", t.TempDir()},
	} {
		if exit := cli.run(args...); exit != 1 || !strings.Contains(cli.stderr.String(), "LOCAL_FILE_ERROR") {
			t.Fatalf("%v: exit %d %s", args, exit, cli.stderr.String())
		}
	}
	if fixture.analysis.viewCount() != views || sensitiveReads(fixture) != sensitive {
		t.Fatalf("view log rows %d -> %d, sensitive_read rows %d -> %d", views, fixture.analysis.viewCount(), sensitive, sensitiveReads(fixture))
	}
	// The same pack read with a usable --out is logged once.
	cli.mustRun("analysis", "session", analysisOwnID, "--pack", "--out", filepath.Join(t.TempDir(), "pack.json"))
	if fixture.analysis.viewCount() != views+1 || sensitiveReads(fixture) != sensitive+1 {
		t.Fatalf("a successful pack read was not logged")
	}
}

// addUnfinishedRecord prepends an own record whose forwarding is still in
// progress, whose parse is pending and whose capture is partial.
func addUnfinishedRecord(fixture *readFixture, id string) {
	record := fixtureAudit(id, 10*time.Second, fixture.ownFingerprint, 42, storage.ForwardInProgress, nil)
	record.detail.Audit.ParseStatus = storage.ParsePending
	record.detail.Audit.CaptureStatus = storage.CapturePartial
	record.detail.Audit.EndedAtNS = nil
	record.detail.Audit.StatusCode = nil
	fixture.audits.records = append([]auditRecord{record}, fixture.audits.records...)
}

// partialTimelines reports every stream timeline as incomplete.
type partialTimelines struct{ *scopedAudits }

func (audits partialTimelines) Timeline(ctx context.Context, auditID string, side query.Side) (query.StreamTimeline, error) {
	timeline, err := audits.scopedAudits.Timeline(ctx, auditID, side)
	timeline.Complete = false
	return timeline, err
}

type exportData struct {
	Path     string `json:"path"`
	Complete *bool  `json:"complete"`
}

// An export is complete exactly when `requests get` of the same record says
// complete (and, for a timeline or a raw body, the content is complete): an
// unfinished record's exports say complete=false with the reason get gives,
// in meta and in data.complete.
func TestCLIExportCompletenessFollowsTheRecord(t *testing.T) {
	fixture := newReadFixture(t)
	addUnfinishedRecord(fixture, "unfinished-own")
	cli := newReadCLI(t, fixture, fixture.developer)
	dir := t.TempDir()
	kinds := []string{"conversation", "headers", "request", "response", "timeline-request", "timeline-response", "raw-request", "raw-response"}

	for _, id := range []string{"unfinished-own", "own-1"} {
		detail := cli.mustRun("requests", "get", id)
		for _, what := range kinds {
			export := cli.mustRun("requests", "export", id, "--what", what, "--out", filepath.Join(dir, id+"-"+what))
			var data exportData
			_ = json.Unmarshal(export.Data, &data)
			if export.Meta.State != "exported" || export.Meta.Complete != detail.Meta.Complete ||
				export.Meta.IncompleteReason != detail.Meta.IncompleteReason || data.Complete == nil || *data.Complete != detail.Meta.Complete {
				t.Errorf("%s export %s: meta %+v data %s; requests get meta %+v", id, what, export.Meta, export.Data, detail.Meta)
			}
		}
		if id == "unfinished-own" && (detail.Meta.Complete || detail.Meta.IncompleteReason != auditIncompleteInProgress) {
			t.Fatalf("precondition: the unfinished record's detail is %+v", detail.Meta)
		}
	}

	// A complete record whose timeline is not: the timeline export says so.
	fixture.handler.query = partialTimelines{fixture.audits}
	export := cli.mustRun("requests", "export", "own-1", "--what", "timeline-response", "--out", filepath.Join(dir, "timeline.json"))
	content, _ := os.ReadFile(filepath.Join(dir, "timeline.json"))
	if export.Meta.Complete || export.Meta.IncompleteReason != exportIncompleteTimeline || !strings.Contains(string(content), `"complete":false`) {
		t.Fatalf("incomplete timeline: meta %+v, file %s", export.Meta, content)
	}
}

// The facade sends the completeness headers on every export kind, and the
// raw body's X-Audit-Complete is the web route's value only for a finished
// record.
func TestAgentExportCompletenessHeaders(t *testing.T) {
	fixture := newReadFixture(t)
	addUnfinishedRecord(fixture, "unfinished-own")
	for _, what := range agentapi.ExportKinds {
		for id, want := range map[string]string{"own-1": "true", "unfinished-own": "false"} {
			response := fixture.facade(http.MethodGet, "/requests/"+id+"/export/"+what, "", fixture.developer)
			if response.Code != http.StatusOK {
				t.Fatalf("%s %s = %d %s", id, what, response.Code, response.Body.String())
			}
			reason := response.Header().Get("X-Audit-Incomplete-Reason")
			if response.Header().Get("X-Audit-Complete") != want || (want == "true") != (reason == "") {
				t.Errorf("%s %s: X-Audit-Complete %q, reason %q", id, what, response.Header().Get("X-Audit-Complete"), reason)
			}
			if want == "false" && reason != auditIncompleteInProgress {
				t.Errorf("%s %s: reason %q, want the detail's in_progress", id, what, reason)
			}
		}
	}
}

// `requests list --pretty` shows the columns a person needs first: id, start
// time, state, status code, model and path, so a running, a blocked and a
// succeeded record are told apart.
func TestCLIPrettyRequestsListShowsState(t *testing.T) {
	fixture := newReadFixture(t)
	addUnfinishedRecord(fixture, "unfinished-own")
	cli := newReadCLI(t, fixture, fixture.developer)
	if exit := cli.run("requests", "list", "--no-collapse", "--pretty"); exit != 0 {
		t.Fatalf("exit %d %s", exit, cli.stderr.String())
	}
	output := cli.stdout.String()
	lines := strings.Split(output, "\n")
	header := ""
	for index, line := range lines {
		if strings.TrimSpace(line) == "items:" && index+1 < len(lines) {
			header = lines[index+1]
		}
	}
	columns := strings.Fields(header)
	want := []string{"audit_id", "started_at", "state", "status_code", "request_model_untrusted", "path_untrusted"}
	if len(columns) < len(want) {
		t.Fatalf("columns %v\n%s", columns, output)
	}
	for index, name := range want {
		if columns[index] != name {
			t.Fatalf("column %d is %q, want %q; columns %v", index+1, columns[index], name, columns)
		}
	}
	for _, value := range []string{"running", "succeeded", "blocked"} {
		if !strings.Contains(output, " "+value+" ") {
			t.Errorf("the table does not show the state %q:\n%s", value, output)
		}
	}
}

// The walkthrough's refused arguments, through the real client: every
// INVALID_ARGUMENT names the flag or argument the user typed, a reason and,
// in the message, what is accepted or which other argument it conflicts
// with; the server's own name stays in details.parameter.
func TestCLIInvalidArgumentsNameWhatTheUserTyped(t *testing.T) {
	fixture := newReadFixture(t)
	admin := newReadCLI(t, fixture, fixture.adminRead)
	developer := newReadCLI(t, fixture, fixture.developer)
	for _, test := range []struct {
		cli            *readCLI
		args           []string
		field, reason  string
		conflictsWith  string
		messageMention string
	}{
		{admin, []string{"requests", "list", "--forward-status", "bogus"}, "--forward-status", reasonNotAllowedValue, "", "completed"},
		{admin, []string{"requests", "list", "--protocol", "foo"}, "--protocol", reasonNotAllowedValue, "", "anthropic"},
		{admin, []string{"requests", "list", "--since", "30m", "--from", "2026-01-01"}, "--since", reasonConflict, "--from", "`--from`"},
		{admin, []string{"requests", "list", "--limit", "201"}, "--limit", reasonOutOfRange, "", "200"},
		{admin, []string{"requests", "list", "--no-collapse", "--cursor", "bogus"}, "--cursor", reasonInvalidCursor, "", "next_cursor"},
		{admin, []string{"usage", "overview", "--group-by", "bogus"}, "--group-by", reasonNotAllowedValue, "", "protocol"},
		{admin, []string{"usage", "overview", "--since", "500d"}, "--since", reasonRangeTooLong, "", "400"},
		{admin, []string{"usage", "tree", "xyz"}, "<tree>", reasonInvalidFormat, "", "24"},
		{admin, []string{"usage", "trend", "ses_123"}, "<session>", reasonInvalidFormat, "", "agt_"},
		{admin, []string{"weekly", "report", "--metric", "bogus"}, "--metric", reasonNotAllowedValue, "", "tokens"},
		{admin, []string{"analysis", "sessions", "--since", "7d", "--flags", "bogus"}, "--flags", reasonNotAllowedValue, "", "loop"},
		{admin, []string{"analysis", "sessions", "--since", "7d", "--kind", "foo"}, "--kind", reasonNotAllowedValue, "", "chat"},
		{admin, []string{"analysis", "session", "abc", "--facet"}, "<id>", reasonInvalidFormat, "", "64"},
		{admin, []string{"analysis", "overview", "--since", "500d"}, "--since", reasonRangeTooLong, "", "400"},
		{admin, []string{"analysis", "overview"}, "--since", reasonRequired, "", "`--from`"},
		{admin, []string{"analysis", "report", "--project-id", "1", "--group-id", "1"}, "--group-id", reasonConflict, "--project-id", "`--project-id`"},
		{admin, []string{"config", "preview-project", "--group-id", "null"}, "--rule", reasonRequired, "", "repo_name"},
		{admin, []string{"config", "preview-project", "--group-id", "null", "--rule", "repo_name: "}, "--rule", "empty", "", ""},
		{developer, []string{"usage", "overview", "--group-by", "caller"}, "--group-by", reasonAdministratorOnly, "", "administrators"},
		{developer, []string{"requests", "list", "--user-id", "8"}, "--user-id", reasonAdministratorOnly, "", "administrators"},
	} {
		label := strings.Join(test.args, " ")
		if exit := test.cli.run(test.args...); exit != agentapi.ExitInvalidUsage {
			t.Errorf("%s: exit %d %s", label, exit, test.cli.stderr.String())
			continue
		}
		var envelope struct {
			Error agentapi.ErrorBody `json:"error"`
		}
		if err := json.Unmarshal(test.cli.stderr.Bytes(), &envelope); err != nil {
			t.Fatalf("%s: %s", label, test.cli.stderr.String())
		}
		details := envelope.Error.Details
		if envelope.Error.Code != agentapi.CodeInvalidArgument || details["field"] != test.field || details["reason"] != test.reason ||
			details["parameter"] == nil || !strings.Contains(envelope.Error.Message, test.messageMention) {
			t.Errorf("%s: %s", label, test.cli.stderr.String())
		}
		if test.conflictsWith != "" && details["conflicts_with"] != test.conflictsWith {
			t.Errorf("%s: conflicts_with %v", label, details["conflicts_with"])
		}
	}
}
