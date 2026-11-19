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
	if !bytes.Equal(content, plain["data"]) {
		t.Fatalf("file %q != stdout data %q", content, plain["data"])
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
	if string(content) != `{"view_logged":true,"text_untrusted":"long"}` {
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
	if envelope := h.success(); strings.Contains(string(envelope["data"]), "missing_chunks") || !strings.Contains(string(envelope["data"]), `"complete":true`) {
		t.Fatalf("json export data %s", envelope["data"])
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
