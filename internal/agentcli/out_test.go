package agentcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// The data has HTML-sensitive characters, non-ASCII text, spacing and number
// forms that a naive re-encoding would change.
const trendBody = `{"ok":true,"data":{ "steps": [ {"n": 1, "text_untrusted": "<b>&é ü", "ratio": 1.50} ] , "big": 12345678901234567890 },"meta":{"state":"succeeded","complete":false,"incomplete_reason":"truncated"},"next_actions":["a"],"notice":"n"}`

func TestOutFileEqualsDataByteForByte(t *testing.T) {
	server := newFakeServer(t, respondJSON(200, trendBody))
	h := newHarness(t)
	h.saveLogin(server.URL)
	if exit := h.run("usage", "trend", "ses_1"); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	plain := h.success()

	target := filepath.Join(t.TempDir(), "trend.json")
	writeFile(t, target, "old content that must be replaced")
	if exit := h.run("usage", "trend", "ses_1", "--out", target); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	withOut := h.success()
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	// The file is {"meta": …, "data": …}; its data is stdout's data byte for
	// byte, and its meta tells a later reader whether the data is complete.
	if want := `{"meta":` + string(plain["meta"]) + `,"data":` + string(plain["data"]) + `}`; string(content) != want {
		t.Fatalf("file %q != %q", content, want)
	}
	var stored struct {
		Meta agentapi.Meta   `json:"meta"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(content, &stored); err != nil || stored.Meta.Complete || stored.Meta.IncompleteReason != "truncated" {
		t.Fatalf("file meta %+v (%v)", stored.Meta, err)
	}
	var summary struct {
		Path   string `json:"path"`
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(withOut["data"], &summary); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if summary.Path != target || summary.Bytes != int64(len(content)) || summary.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("summary %+v", summary)
	}
	if !bytes.Equal(withOut["meta"], plain["meta"]) || !bytes.Equal(withOut["next_actions"], plain["next_actions"]) {
		t.Fatalf("meta or next_actions changed: %s vs %s", withOut["meta"], plain["meta"])
	}
	assertNoTempFiles(t, filepath.Dir(target))

	// --out to a missing directory is a local file error and nothing is written.
	missing := filepath.Join(t.TempDir(), "nope", "trend.json")
	h.expectFailure(h.run("usage", "trend", "ses_1", "--out", missing), agentapi.CodeLocalFileError, 1)
}

func TestPackRequiresOut(t *testing.T) {
	server := newFakeServer(t, respondJSON(200, `{"ok":true,"data":{"view_logged":true,"text_untrusted":"long"},"meta":`+okMeta+`}`))
	h := newHarness(t)
	h.saveLogin(server.URL)
	h.expectFailure(h.run("analysis", "session", sessionHex, "--pack"), agentapi.CodeInvalidArgument, 2)
	if len(server.recorded()) != 0 {
		t.Fatal("pack without --out reached the server")
	}
	target := filepath.Join(t.TempDir(), "pack.json")
	if exit := h.run("analysis", "session", sessionHex, "--pack", "--out", target); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	if request := server.recorded()[0]; request.Path != agentapi.PathPrefix+"/analysis/sessions/"+sessionHex+"/pack" || len(request.Query) != 0 {
		t.Fatalf("pack request %s %v", request.Path, request.Query)
	}
	content, _ := os.ReadFile(target)
	if string(content) != `{"meta":`+okMeta+`,"data":{"view_logged":true,"text_untrusted":"long"}}` {
		t.Fatalf("pack file %s", content)
	}
}

func TestExport(t *testing.T) {
	raw := []byte("\x00\x01raw body\xff")
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request, _ []byte) {
		if strings.HasSuffix(request.URL.Path, "/raw-response") {
			writer.Header().Set("Content-Type", "application/octet-stream")
			writer.Header().Set("X-Audit-Complete", "false")
			writer.Header().Set("X-Audit-Missing-Chunks", "true")
			_, _ = writer.Write(raw)
			return
		}
		if strings.HasSuffix(request.URL.Path, "/raw-request") {
			failWith(agentapi.CodeNotRetained)(writer, request, nil)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(request.URL.Path, agentapi.PathPrefix+"/requests/complete/"):
			writer.Header().Set("X-Audit-Complete", "true")
		case strings.HasPrefix(request.URL.Path, agentapi.PathPrefix+"/requests/running/"):
			writer.Header().Set("X-Audit-Complete", "false")
			writer.Header().Set("X-Audit-Incomplete-Reason", "in_progress")
		}
		_, _ = io.WriteString(writer, `{"messages":[]}`)
	})
	h := newHarness(t)
	h.saveLogin(server.URL)
	dir := t.TempDir()

	target := filepath.Join(dir, "response.bin")
	if exit := h.run("requests", "export", "77", "--what", "raw-response", "--out", target); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	content, _ := os.ReadFile(target)
	if !bytes.Equal(content, raw) {
		t.Fatalf("raw content %q", content)
	}
	envelope := h.success()
	var data struct {
		Path          string `json:"path"`
		Bytes         int64  `json:"bytes"`
		SHA256        string `json:"sha256"`
		Complete      *bool  `json:"complete"`
		MissingChunks *bool  `json:"missing_chunks"`
	}
	_ = json.Unmarshal(envelope["data"], &data)
	digest := sha256.Sum256(raw)
	if data.Path != target || data.Bytes != int64(len(raw)) || data.SHA256 != hex.EncodeToString(digest[:]) ||
		data.Complete == nil || *data.Complete || data.MissingChunks == nil || !*data.MissingChunks {
		t.Fatalf("export data %s", envelope["data"])
	}
	if !validMeta(envelope["meta"]) {
		t.Fatalf("export meta %s", envelope["meta"])
	}
	request := server.recorded()[0]
	if request.Method != "GET" || request.Path != agentapi.PathPrefix+"/requests/77/export/raw-response" || request.Header.Get(agentapi.HeaderCommand) != "requests.export" {
		t.Fatalf("export request %+v", request)
	}

	conversation := filepath.Join(dir, "conversation.json")
	if exit := h.run("requests", "export", "77", "--what", "conversation", "--out", conversation); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	if content, _ := os.ReadFile(conversation); string(content) != `{"messages":[]}` {
		t.Fatalf("conversation %s", content)
	}
	// No completeness header: the server did not say, so the export is not
	// called complete (contract 0.1 items 49(e) and 96).
	if envelope := h.success(); strings.Contains(string(envelope["data"]), "missing_chunks") || !strings.Contains(string(envelope["data"]), `"complete":false`) ||
		string(envelope["meta"]) != `{"state":"exported","complete":false,"incomplete_reason":"completeness_unknown"}` {
		t.Fatalf("json export without a header: data %s meta %s", envelope["data"], envelope["meta"])
	}
	for id, want := range map[string]string{
		"complete": `{"state":"exported","complete":true,"incomplete_reason":""}`,
		"running":  `{"state":"exported","complete":false,"incomplete_reason":"in_progress"}`,
	} {
		if exit := h.run("requests", "export", id, "--what", "conversation", "--out", conversation); exit != 0 {
			t.Fatalf("exit %d", exit)
		}
		envelope := h.success()
		if string(envelope["meta"]) != want || strings.Contains(want, "true") != strings.Contains(string(envelope["data"]), `"complete":true`) {
			t.Fatalf("%s export: data %s meta %s", id, envelope["data"], envelope["meta"])
		}
	}

	failed := filepath.Join(dir, "request.bin")
	h.expectFailure(h.run("requests", "export", "77", "--what", "raw-request", "--out", failed), agentapi.CodeNotRetained, 1)
	if _, err := os.Stat(failed); err == nil {
		t.Fatal("a failed export left a file")
	}
	assertNoTempFiles(t, dir)
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

// TestUnusableOutFailsBeforeAnyRequest: for every command that takes --out,
// an --out that cannot be written is LOCAL_FILE_ERROR and nothing reaches
// the server, so a failed command logs no sensitive view and uses no quota.
func TestUnusableOutFailsBeforeAnyRequest(t *testing.T) {
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	dir := t.TempDir()
	aFile := writeFile(t, filepath.Join(dir, "plain.txt"), "x")
	readOnly := writeFile(t, filepath.Join(dir, "read-only.json"), "keep")
	if err := os.Chmod(readOnly, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o600) })
	unusable := map[string]string{
		"missing directory":         filepath.Join(dir, "no-such-dir", "out.json"),
		"a directory":               dir,
		"parent is not a directory": filepath.Join(aFile, "out.json"),
	}
	if runtime.GOOS == "windows" {
		// Windows cannot rename over a read-only file (POSIX can, so there
		// it is a usable target).
		unusable["read-only file"] = readOnly
	} else if os.Geteuid() != 0 {
		// A directory without write permission (permission bits do not stop
		// root, so this case needs an ordinary user).
		locked := filepath.Join(t.TempDir(), "locked")
		if err := os.Mkdir(locked, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		unusable["directory not writable"] = filepath.Join(locked, "out.json")
	}
	samples := map[string][]string{
		"usage trend":       {"usage", "trend", "ses_1"},
		"usage composition": {"usage", "composition", "77"},
		"analysis session":  {"analysis", "session", sessionHex, "--pack"},
		"requests export":   {"requests", "export", "77", "--what", "conversation"},
	}
	covered := 0
	for _, spec := range allCommands() {
		if spec.flag("out") == nil {
			continue
		}
		args, ok := samples[spec.name()]
		if !ok {
			t.Errorf("%s takes --out but has no sample here", spec.name())
			continue
		}
		covered++
		for name, target := range unusable {
			server.reset()
			h.expectFailure(h.run(append(append([]string{}, args...), "--out", target)...), agentapi.CodeLocalFileError, 1)
			if len(server.recorded()) != 0 {
				t.Errorf("%s with --out %s reached the server", spec.name(), name)
			}
		}
		assertNoTempFiles(t, dir)
	}
	if covered != len(samples) {
		t.Fatalf("covered %d commands with --out", covered)
	}
	if data, _ := os.ReadFile(readOnly); string(data) != "keep" {
		t.Fatalf("read-only file changed to %q", data)
	}
}

// TestPrettyTableColumns: a command's preferred columns come first in its
// order, the rest alphabetically, eight at most; nested values are no column.
func TestPrettyTableColumns(t *testing.T) {
	items := []any{
		map[string]any{"zeta": 1, "alpha": "a", "state": "running", "audit_id": "x", "nested": map[string]any{"a": 1}, "list": []any{1}},
		map[string]any{"beta": 2, "status_code": 200, "path_untrusted": "/p", "c": 1, "d": 2, "e": 3, "f": 4},
	}
	_, columns := tableOf(items, []string{"audit_id", "missing", "state", "status_code", "path_untrusted"})
	want := []string{"audit_id", "state", "status_code", "path_untrusted", "alpha", "beta", "c", "d"}
	if strings.Join(columns, " ") != strings.Join(want, " ") {
		t.Fatalf("columns %v, want %v", columns, want)
	}
	_, columns = tableOf(items, nil)
	if strings.Join(columns, " ") != "alpha audit_id beta c d e f path_untrusted" {
		t.Fatalf("fallback columns %v", columns)
	}
}

// LOCAL_FILE_ERROR carries a hint wherever it is raised, through the shared
// error table: an unusable --out, an unreadable --file, a missing home.
func TestLocalFileErrorsCarryAHint(t *testing.T) {
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	missing := filepath.Join(t.TempDir(), "no-such-dir", "out.json")
	for _, args := range [][]string{
		{"usage", "composition", "apx_k5qwy3dfmzxw4ztsnb2xa4dqm4", "--out", missing},
		{"requests", "export", "apx_k5qwy3dfmzxw4ztsnb2xa4dqm4", "--what", "headers", "--out", t.TempDir()},
		{"analysis", "calibrate", "--file", missing},
	} {
		body := h.expectFailure(h.run(args...), agentapi.CodeLocalFileError, agentapi.ExitError)
		if body.Hint == "" || !strings.Contains(body.Hint, "details.path") {
			t.Errorf("%v: hint %q", args, body.Hint)
		}
	}
}
