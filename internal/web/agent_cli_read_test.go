package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentcli"
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
