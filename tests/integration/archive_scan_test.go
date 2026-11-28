package integration_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// scanValues are the distinctive values of one scan run: content markers
// and credential values, each unique to the run.
type scanValues struct {
	tag         string
	content     map[string]string // field -> marker
	credentials map[string]string // transport -> value
}

func newScanValues(t *testing.T) scanValues {
	t.Helper()
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	tag := hex.EncodeToString(random)
	values := scanValues{tag: tag, content: map[string]string{}, credentials: map[string]string{}}
	for _, field := range []string{"reqbody", "toolarg", "toolresult", "respbody", "stream", "errbody", "uri", "header", "useragent"} {
		values.content[field] = "MARKCONTENT" + field + tag
	}
	// Every transport agentapi.IsCredential recognises: the names of rule 1
	// (Authorization, Proxy-Authorization, Cookie, Set-Cookie, X-Api-Key,
	// X-Goog-Api-Key, Api-Key, Key), a *-token name, a name part (secret),
	// a value prefix (sk-) under an ordinary name and in the User-Agent, and
	// the query segments key and api_key that security/credential.go and the
	// projection recognise.
	for _, transport := range []string{"bearer", "proxyauth", "cookie", "setcookie", "xapikey", "googkey", "apikeyheader", "keyheader",
		"xtoken", "secret", "prefix", "useragent", "querykey"} {
		values.credentials[transport] = "CREDVALUE" + transport + tag
	}
	return values
}

func (values scanValues) contentList() []string {
	var out []string
	for _, marker := range values.content {
		out = append(out, marker)
	}
	return out
}

func (values scanValues) credentialList() []string {
	var out []string
	for _, value := range values.credentials {
		out = append(out, value)
	}
	return out
}

// scanHeader is a request carrying every credential transport and the
// header marker.
func (values scanValues) scanHeader(userAgent string) http.Header {
	c := values.credentials
	return http.Header{
		"Content-Type":        {"application/json"},
		"Authorization":       {"Bearer " + c["bearer"]},
		"Proxy-Authorization": {"Basic " + c["proxyauth"]},
		"Cookie":              {"session=" + c["cookie"]},
		"X-Api-Key":           {c["xapikey"]},
		"X-Goog-Api-Key":      {c["googkey"]},
		"Api-Key":             {c["apikeyheader"]},
		"Key":                 {c["keyheader"]},
		"X-Auth-Token":        {c["xtoken"]},
		"X-Client-Secret":     {c["secret"]},
		"X-Forward-Hint":      {"sk-" + c["prefix"]},
		"X-Trace-Note":        {values.content["header"]},
		"User-Agent":          {userAgent},
	}
}

// scanExchanges are hand-written chat exchanges that put the content
// markers in the request body, a tool call's arguments, a tool result, the
// response body, a streamed delta and an error body, the Request-URI and a
// header, with the credentials of scanHeader and in the query (the same
// value as X-Goog-Api-Key, so one known key matches two places).
func (values scanValues) scanExchanges() []protofixture.Exchange {
	m, c := values.content, values.credentials
	path := "/v1/chat/completions?trace=" + m["uri"] + "&key=" + c["googkey"] + "&api_key=" + c["querykey"]
	request := func(stream bool, text string) []byte {
		return []byte(fmt.Sprintf(`{"model":"model-example","stream":%v,"messages":[`+
			`{"role":"user","content":%q},`+
			`{"role":"assistant","content":null,"tool_calls":[{"id":"call_scan","type":"function","function":{"name":"lookup","arguments":%q}}]},`+
			`{"role":"tool","tool_call_id":"call_scan","content":%q}]}`,
			stream, text, `{"q":"`+m["toolarg"]+`"}`, m["toolresult"]))
	}
	jsonHeader := http.Header{"Content-Type": {"application/json"}}
	plain := protofixture.Exchange{Protocol: protofixture.OpenAIChat, Method: http.MethodPost, Path: path, ParserName: "openai.chat_completions",
		RequestHeader: values.scanHeader("client-example/" + m["useragent"]), RequestBody: request(false, m["reqbody"]),
		Response: protofixture.Response{Status: http.StatusOK, Header: jsonHeader, Chunks: [][]byte{[]byte(
			`{"id":"chatcmpl-scan","object":"chat.completion","created":1,"model":"model-example","choices":[{"index":0,"message":{"role":"assistant","content":"` +
				m["respbody"] + `"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)}}}
	streamed := plain
	streamed.RequestHeader = values.scanHeader("sk-" + c["useragent"])
	streamed.RequestBody = request(true, m["reqbody"]+" again")
	streamed.Response = protofixture.Response{Status: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Chunks: [][]byte{
		[]byte(`data: {"id":"chatcmpl-scan2","object":"chat.completion.chunk","created":1,"model":"model-example","choices":[{"index":0,"delta":{"role":"assistant","content":"` + m["stream"] + `"},"finish_reason":null}]}` + "\n\n"),
		[]byte(`data: {"id":"chatcmpl-scan2","object":"chat.completion.chunk","created":1,"model":"model-example","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n"),
		[]byte("data: [DONE]\n\n"),
	}}
	failed := plain
	failed.RequestBody = request(false, m["reqbody"]+" failing")
	failed.Response = protofixture.Response{Status: http.StatusInternalServerError, Header: jsonHeader, Chunks: [][]byte{[]byte(
		`{"error":{"message":"` + m["errbody"] + `","type":"server_error","code":"internal"}}`)}}
	return []protofixture.Exchange{plain, streamed, failed}
}

// withSetCookie adds a Set-Cookie credential to every provider answer.
func withSetCookie(value string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Set-Cookie", "sid="+value+"; Path=/")
			next.ServeHTTP(writer, request)
		})
	}
}

// Plan section 7 bullet 6 and the P3 gate ("归档盘上扫不到明文和凭据"), with
// bullet 7 (credential fingerprints) on the bundle the run wrote.
//
// With encryption on, no content marker appears in any file under the
// archive directory, in any of the forms a file could hold it (as is,
// percent-encoded, hex, base64 at every alignment, inside a gzip stream),
// neither in the finished bundles nor in the temporary files, which are
// scanned at every write, sync, close, link and directory sync of the
// bundle writer and at every step of the publication. With encryption on and
// off, no credential value appears in those files, in the archive catalog
// tables, in the log of the proxy, parser and runner, or in anything the
// reader tool prints (cat with objects, every export of every audit, list,
// verify, fpr). With encryption off the content markers are found in the
// gunzipped data files: the scan can find what it looks for.
func TestArchiveDiskHoldsNoPlaintextOrCredential(t *testing.T) {
	for _, encrypt := range []bool{true, false} {
		t.Run(fmt.Sprintf("encrypt=%v", encrypt), func(t *testing.T) {
			values := newScanValues(t)
			rig := newArchiveRig(t, archiveRigOptions{encrypt: encrypt, minTurns: 1, wrapUpstream: withSetCookie(values.credentials["setcookie"])})
			var ids []string
			for _, exchange := range values.scanExchanges() {
				ids = append(ids, rig.send(exchange))
			}
			if stats := rig.upstream.Stats(); stats.Mismatched != 0 || stats.Unknown != 0 {
				t.Fatalf("upstream stats %+v", stats)
			}
			// The fixtures carry what the scan looks for: the hot side serves
			// a raw error body, the tool arguments and the stream text.
			var probe bytes.Buffer
			if err := rig.hot.StreamRaw(rig.ctx, ids[2], "response", &probe); err != nil || !bytes.Contains(probe.Bytes(), []byte(values.content["errbody"])) {
				t.Fatalf("the error answer's raw body is not kept: %v", err)
			}

			var mu sync.Mutex
			scans, found := 0, map[string]bool{}
			scan := func(where string) {
				mu.Lock()
				defer mu.Unlock()
				scans++
				targets := archiveScanTargets(t, rig.dir)
				markers := values.credentialList()
				if encrypt {
					markers = append(markers, values.contentList()...)
				}
				for _, hit := range findMarkers(targets, markers) {
					found[where+": "+hit] = true
				}
			}
			fault := func(operation, path string) error {
				scan("during " + operation)
				return nil
			}
			step := func(name string) error {
				scan("at " + name)
				return nil
			}
			rig.fault.Store(&fault)
			rig.step.Store(&step)
			rig.due()
			result := rig.mustRun()
			rig.fault.Store(nil)
			rig.step.Store(nil)
			rig.requireCleanRun(result, len(ids))
			scan("after the run")
			temporary := false
			for _, target := range archiveScanTargets(t, rig.dir) {
				temporary = temporary || strings.Contains(target.name, ".tmp-")
			}
			for hit := range found {
				t.Errorf("found %s", hit)
			}
			t.Logf("%d scans of the archive directory during and after the run", scans)
			if scans < 10 {
				t.Fatalf("only %d scans", scans)
			}
			if temporary {
				t.Fatal("temporary files left after the run")
			}

			// The control: without encryption the content is there to find.
			if !encrypt {
				targets := archiveScanTargets(t, rig.dir)
				var gunzipped []scanTarget
				for _, target := range targets {
					if strings.HasSuffix(target.name, "(gunzipped)") {
						gunzipped = append(gunzipped, target)
					}
				}
				for field, marker := range values.content {
					if len(findMarkers(gunzipped, []string{marker})) == 0 {
						t.Errorf("control: the %s marker is not in the unencrypted bundle", field)
					}
				}
			}

			// The catalog tables and the log.
			catalog := rig.postgresTargets("archive_runs", "archive_deferred", "archive_segments", "archive_members", "archive_gap_members")
			logs := []scanTarget{{name: "log", data: rig.logs.Bytes()}}
			for _, hit := range findMarkers(append(catalog, logs...), values.credentialList()) {
				t.Errorf("credential in %s", hit)
			}
			for _, hit := range findMarkers(logs, values.contentList()) {
				t.Errorf("content in %s", hit)
			}

			// What the reader tool prints.
			keyFile := filepath.Join(t.TempDir(), "known-key")
			if err := os.WriteFile(keyFile, []byte(values.credentials["googkey"]+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			runs := [][]string{
				{"cat", "--dir", rig.dir, "--key", rig.keyPath, "--with-objects", "--all-revisions"},
				{"list", "--dir", rig.dir, "--key", rig.keyPath, "--json"},
				{"verify", "--dir", rig.dir, "--key", rig.keyPath, "--json"},
				{"fpr", "--dir", rig.dir, "--key", rig.keyPath, "--known-key-file", keyFile},
			}
			for _, id := range ids {
				for _, kind := range archivecli.ExportKinds {
					runs = append(runs, []string{"export", "--dir", rig.dir, "--key", rig.keyPath, "--audit", id, "--what", kind})
				}
			}
			var output []scanTarget
			for _, args := range runs {
				code, stdout, stderr := archiveCLI(rig.ctx, args...)
				if code != archivecli.ExitOK && code != archivecli.ExitNotFound {
					t.Fatalf("%v exit %d: %s", args[:1], code, stderr)
				}
				output = append(output, scanTarget{name: strings.Join(args[:1], " ") + " stdout", data: stdout}, scanTarget{name: args[0] + " stderr", data: stderr})
			}
			for _, hit := range findMarkers(output, values.credentialList()) {
				t.Errorf("credential in the output of %s", hit)
			}
			if len(findMarkers(output, []string{values.content["respbody"]})) == 0 {
				t.Fatal("control: the tool's output holds no content")
			}
			if encrypt {
				rig.requireCredentialFingerprints(values, ids)
			}
		})
	}
}

// requireCredentialFingerprints is plan section 7 bullet 7 on a real
// bundle: the same credential has the same value_fpr in the inbound and
// the outbound stage; the reader's fpr logic finds a known key where it
// was sent (two header forms, the query, api_key_fpr); a different master
// key gives different fingerprints and does not open the bundle.
func (rig *archiveRig) requireCredentialFingerprints(values scanValues, ids []string) {
	t := rig.t
	t.Helper()
	reader := rig.reader(rig.dir)
	audit, err := reader.Audit(rig.ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	byStage := map[string]map[string][32]byte{}
	for _, header := range audit.Record.Headers.Values {
		if !header.Value.Omitted {
			continue
		}
		if byStage[header.Stage] == nil {
			byStage[header.Stage] = map[string][32]byte{}
		}
		byStage[header.Stage][header.Name] = header.Value.Fingerprint
	}
	inbound, outbound := byStage[storage.StageRequestReceived], byStage[storage.StageRequestSent]
	if len(inbound) < 8 {
		t.Fatalf("only %d projected credentials inbound: %v", len(inbound), inbound)
	}
	same := 0
	for name, fpr := range inbound {
		if other, ok := outbound[name]; ok {
			if other != fpr {
				t.Fatalf("%s: inbound and outbound value_fpr differ", name)
			}
			same++
		}
	}
	if outbound["Authorization"] != inbound["Authorization"] || same < 4 {
		t.Fatalf("%d credentials compared between the stages (outbound %v)", same, outbound)
	}
	if byStage[storage.StageResponseReceived]["Set-Cookie"] == ([32]byte{}) {
		t.Fatal("the Set-Cookie credential of the answer is not projected")
	}
	keys := archiveKeysOf(t, rig.keyPath)
	known := archivecli.Fingerprints(keys, []byte(values.credentials["googkey"]))
	where := map[string]string{}
	for _, match := range archivecli.MatchRecord(audit.Record, known) {
		where[match.Where] = match.Form
	}
	if where["header "+storage.StageRequestReceived+" header X-Goog-Api-Key"] != "raw" || where["request_uri key"] != "raw" {
		t.Fatalf("known key matches %v", where)
	}
	bearer := archivecli.Fingerprints(keys, []byte(values.credentials["bearer"]))
	where = map[string]string{}
	for _, match := range archivecli.MatchRecord(audit.Record, bearer) {
		where[match.Where] = match.Form
	}
	if where["header "+storage.StageRequestReceived+" header Authorization"] != "bearer" || where["api_key_fpr"] != "api_key_fpr" {
		t.Fatalf("bearer key matches %v", where)
	}

	otherPath := filepath.Join(t.TempDir(), "other.key")
	otherKey := make([]byte, security.KeySize)
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	other := archivecli.Fingerprints(archiveKeysOf(t, otherPath), []byte(values.credentials["googkey"]))
	if other.Raw == known.Raw || other.Bearer == known.Bearer || bytes.Equal(other.APIKeyFPR, known.APIKeyFPR) {
		t.Fatal("another master key gives the same fingerprints")
	}
	if matches := archivecli.MatchRecord(audit.Record, other); len(matches) != 0 {
		t.Fatalf("the other key's fingerprints match %v", matches)
	}
	code, stdout, stderr := archiveCLI(rig.ctx, "export", "--dir", rig.dir, "--key", otherPath, "--audit", ids[0], "--what", "detail")
	if code != archivecli.ExitFailed || len(stdout) != 0 || !bytes.Contains(stderr, []byte("key_mismatch")) {
		t.Fatalf("export under another key: exit %d, %d bytes, %s", code, len(stdout), stderr)
	}
	code, _, _ = archiveCLI(rig.ctx, "verify", "--dir", rig.dir, "--key", otherPath)
	if code != archivecli.ExitFailed {
		t.Fatalf("verify under another key exit %d", code)
	}
}
