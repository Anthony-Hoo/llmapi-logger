package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/config"
	"llmapi-logger/internal/protofixture"
)

// facadeFingerprint is the one field the archive's headers export adds to
// the facade's: the keyed fingerprint of an omitted credential (design D.3,
// D.4). The facade omits the value and gives its length; the archive gives
// the same and the fingerprint.
var facadeFingerprint = regexp.MustCompile(`,"value_fpr":"[0-9a-f]{64}"`)

// R.7 item 6 on PostgreSQL: audit-archive redeclares the JSON shapes of the
// Agent facade's single-audit exports, because it cannot link internal/web.
// A running application with agent access serves the exports of a handful
// of audits (a released and a kept raw body, a streamed turn with a
// timeline, an error answer, a request-only turn, a multimodal turn, an
// audit without a turn); after the archive ran on the same database, the
// reader tool's export of each kind from the bundle equals the facade's
// HTTP response body byte for byte, the headers export after removing
// value_fpr. Where the facade has no such export, the reader reports the
// error listed in the mapping, which the test prints.
func TestArchiveExportsMatchTheAgentFacade(t *testing.T) {
	upstream := protofixture.NewUpstream("fa")
	upstream.SetRequestID = false
	server := httptest.NewServer(upstream)
	defer server.Close()
	cfg := unifiedConfig(t, server.URL)
	cfg.AgentAccess.Enabled = true
	if err := config.Validate(cfg); err != nil {
		t.Fatal(err)
	}
	running := startApp(t, cfg)
	database := openAuditDatabase(t, cfg.DatabaseURL)
	defer database.Close()
	cli := agentLogin(t, running)
	token := cli.savedToken()
	client := &http.Client{Timeout: archiveClientTimeout}

	seen := []string{}
	send := func(method, path string, header http.Header, body []byte) string {
		request, err := http.NewRequest(method, running.baseURL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header = header
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		var id string
		deadline := time.Now().Add(archiveSettleTimeout)
		for id == "" && time.Now().Before(deadline) {
			_ = database.QueryRow(`SELECT audit_id FROM audit_records WHERE NOT (audit_id = ANY($1)) ORDER BY started_at_ns DESC LIMIT 1`, seen).Scan(&id)
			time.Sleep(10 * time.Millisecond)
		}
		if id == "" {
			t.Fatal("no audit")
		}
		seen = append(seen, id)
		archiveWaitFinal(t, database, id)
		return id
	}
	sendExchange := func(exchange protofixture.Exchange) string {
		exchangeID := upstream.Register(&exchange)
		header := exchange.RequestHeader.Clone()
		header.Set(protofixture.ExchangeHeader, exchangeID)
		return send(exchange.Method, exchange.Path, header, exchange.RequestBody)
	}
	labels := map[string]string{}
	for index, value := range []protofixture.Case{
		{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic, Stream: true},
		{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioError429},
		{Protocol: protofixture.OpenAIResponses, Scenario: protofixture.ScenarioToolCalls, Stream: true},
		{Protocol: protofixture.AnthropicMessages, Scenario: protofixture.ScenarioNoTerminal, Stream: true},
		{Protocol: protofixture.AnthropicMessages, Scenario: protofixture.ScenarioError500, Stream: true},
		{Protocol: protofixture.Gemini, Scenario: protofixture.ScenarioMultimodal},
		{Protocol: protofixture.Gemini, Scenario: protofixture.ScenarioUpstreamCut, Stream: true},
	} {
		built, err := protofixture.Build(value, protofixture.Options{Seed: uint64(900 + index)})
		if err != nil {
			t.Fatal(err)
		}
		for turn, exchange := range built {
			labels[sendExchange(exchange)] = fmt.Sprintf("%s turn %d", value, turn)
		}
	}
	// A body that is not JSON: no turn, raw kept.
	labels[send(http.MethodPost, "/v1/chat/completions", http.Header{"Authorization": {"Bearer sk-facade-example"}, "Content-Type": {"application/json"}},
		[]byte("not json at all"))] = "turnless"

	type served struct {
		status int
		body   []byte
		code   string
	}
	kinds := []string{"conversation", "headers", "request", "response", "raw-request", "raw-response", "timeline-request", "timeline-response"}
	if len(kinds) != len(agentapi.ExportKinds) {
		t.Fatalf("facade export kinds %v", agentapi.ExportKinds)
	}
	facade := map[string]served{}
	for id := range labels {
		for _, kind := range kinds {
			request, _ := http.NewRequest(http.MethodGet, running.adminURL+"/api/agent/v1/requests/"+id+"/export/"+kind, nil)
			request.Header.Set("Authorization", "Bearer "+token)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			result := served{status: response.StatusCode, body: body}
			if response.StatusCode != http.StatusOK {
				var envelope agentapi.Response
				if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error == nil {
					t.Fatalf("%s %s: status %d without a failure envelope: %s", labels[id], kind, response.StatusCode, body)
				}
				result.code = string(envelope.Error.Code)
			}
			facade[id+" "+kind] = result
		}
	}
	if err := running.stop(); err != nil {
		t.Fatal(err)
	}

	rig := newArchiveRig(t, archiveRigOptions{dsn: cfg.DatabaseURL, keyPath: cfg.KeyPath, encrypt: true})
	rig.due()
	result := rig.mustRun()
	rig.requireCleanRun(result, len(labels))
	reader := rig.reader(rig.dir)
	equal, stripped := 0, 0
	mapping := map[string]int{}
	for id, label := range labels {
		audit, err := reader.Audit(rig.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range kinds {
			want := facade[id+" "+kind]
			var out bytes.Buffer
			archivedErr := archivecli.ExportAudit(rig.ctx, audit, kind, &out)
			if want.status != http.StatusOK {
				mapping[fmt.Sprintf("%s: facade %d %s -> archive %s", kind, want.status, want.code, archivecli.ErrorCode(archivedErr))]++
				if archivedErr == nil {
					t.Errorf("%s %s: the facade has no export (%s), the archive gives %d bytes", label, kind, want.code, out.Len())
				}
				continue
			}
			if archivedErr != nil {
				t.Errorf("%s %s: the facade serves it, the archive fails: %v", label, kind, archivedErr)
				continue
			}
			got := out.Bytes()
			if kind == "headers" {
				before := len(got)
				got = facadeFingerprint.ReplaceAll(got, nil)
				if len(got) < before {
					stripped++
				}
			}
			if !bytes.Equal(got, want.body) {
				t.Errorf("%s %s differs\n facade  %s\n archive %s", label, kind, clip(want.body), clip(got))
				continue
			}
			equal++
		}
	}
	var lines []string
	for line, count := range mapping {
		lines = append(lines, fmt.Sprintf("%s (%d)", line, count))
	}
	sort.Strings(lines)
	t.Logf("%d audits: %d exports byte-equal (%d headers exports with value_fpr removed); unavailable exports:\n%s",
		len(labels), equal, stripped, strings.Join(lines, "\n"))
	if stripped == 0 || equal < len(labels)*4 {
		t.Fatal("too little compared")
	}
	// Every export the facade does not have is one the reader tool reports
	// with a code of the "no such export" family (exit code 3), never a
	// failed check. The reader is finer than the facade: NOT_AVAILABLE of a
	// response is no_turn_graph without a turn and not_available for a
	// request-only turn, and a missing timeline is not_found.
	for line := range mapping {
		_, archived, _ := strings.Cut(line, " -> archive ")
		switch archived {
		case "not_available", "not_retained", "not_found", "no_turn_graph":
		default:
			t.Errorf("%s: not a no-such-export code", line)
		}
	}
}
