package agentcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
		// 300 CJK characters are 905 bytes in UTF-8 and 305 UTF-16 units:
		// too long for every file system (255 bytes on Linux, 255 units on
		// NTFS), but only creating the file finds out.
		"name too long": filepath.Join(dir, strings.Repeat("审", 300)+".json"),
	}
	if runtime.GOOS != "windows" {
		// 200 CJK characters fit NTFS (205 units) but not Linux (605 bytes).
		unusable["name too long in bytes"] = filepath.Join(dir, strings.Repeat("审", 200)+".json")
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
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatalf("the checks left files behind: %v", entries)
	}
}

// TestOutNameCheckLeavesNothingBehind: the check that the --out name can be
// created neither creates nor changes the target: a missing target is still
// missing after a server failure, an existing one keeps its content, and a
// long but valid name (80 CJK characters, 245 bytes) works.
func TestOutNameCheckLeavesNothingBehind(t *testing.T) {
	server := newFakeServer(t, failWith(agentapi.CodeNotFound))
	h := newHarness(t)
	h.saveLogin(server.URL)
	dir := t.TempDir()
	existing := writeFile(t, filepath.Join(dir, "existing.json"), "precious")
	missing := filepath.Join(dir, strings.Repeat("审", 80)+".json")
	for _, args := range [][]string{{"usage", "trend", "ses_1"}, {"requests", "export", "77", "--what", "conversation"}} {
		for _, target := range []string{existing, missing} {
			h.expectFailure(h.run(append(append([]string{}, args...), "--out", target)...), agentapi.CodeNotFound, 1)
		}
		if data, _ := os.ReadFile(existing); string(data) != "precious" {
			t.Fatalf("%v: the existing target changed to %q", args, data)
		}
		if _, err := os.Lstat(missing); err == nil {
			t.Fatalf("%v: the missing target was left behind", args)
		}
		assertNoTempFiles(t, dir)
	}
	server.setResponder(nil)
	if exit := h.run("usage", "trend", "ses_1", "--out", missing); exit != 0 {
		t.Fatalf("a long but valid name: exit %d %s", exit, h.stderr.String())
	}
	if _, err := os.Stat(missing); err != nil {
		t.Fatalf("the long name was not written: %v", err)
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

// TestPrettyDepthIsBounded: --pretty output of a deeply nested object stays
// linear in the size of the response; an object at the depth cap is written
// on one line as compact JSON, and shallow data renders as before (contract
// section 0.1 item 178).
func TestPrettyDepthIsBounded(t *testing.T) {
	const levels = 2000
	data := strings.Repeat(`{"k":`, levels) + `{"v":1}` + strings.Repeat(`}`, levels)
	out := renderPrettySuccess(outEnvelope{OK: true, Data: json.RawMessage(data)}, nil)
	if len(out) > 4*len(data)+4096 {
		t.Fatalf("%d levels (%d bytes of data) rendered to %d bytes", levels, len(data), len(out))
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 1+maxPrettyDepth+1 {
		t.Fatalf("%d lines, want %d", len(lines), 1+maxPrettyDepth+1)
	}
	last := lines[len(lines)-1]
	wantLast := strings.Repeat("  ", maxPrettyDepth) + "k: " + data[len(`{"k":`)*(maxPrettyDepth+1):len(data)-(maxPrettyDepth+1)]
	if last != wantLast {
		t.Fatalf("last line %.120q, want %.120q", last, wantLast)
	}

	shallow := renderPrettySuccess(outEnvelope{OK: true, Data: json.RawMessage(`{"a":{"b":{"c":1,"d":[1,2]}},"e":"x"}`)}, nil)
	if shallow != "ok\na:\n  b:\n    c: 1\n    d: 1, 2\ne: x\n" {
		t.Fatalf("shallow output %q", shallow)
	}
}

// TestPrettyTableHeaderIsBounded (contract section 0.1 item 193): a table
// pads every row to its widest column, so a header is shortened like a cell.
// One very long key in a list of objects must not multiply into every row.
func TestPrettyTableHeaderIsBounded(t *testing.T) {
	// The long key sorts first: a table pads every column but the last.
	long := strings.Repeat("a", 10000)
	rows := []string{`{"` + long + `":1}`}
	for index := 0; index < 1000; index++ {
		rows = append(rows, `{"z":1}`)
	}
	data := `{"items":[` + strings.Join(rows, ",") + `]}`
	out := renderPrettySuccess(outEnvelope{OK: true, Data: json.RawMessage(data)}, nil)
	if len(out) > 8*len(data)+4096 {
		t.Fatalf("%d bytes of data rendered to %d bytes", len(data), len(out))
	}
	if !strings.Contains(out, strings.Repeat("a", 59)+"…") || strings.Contains(out, strings.Repeat("a", 61)) {
		t.Fatalf("the long header is not shortened to 60 characters: %.200q", out)
	}
	// A header of ordinary length is printed whole.
	short := renderPrettySuccess(outEnvelope{OK: true, Data: json.RawMessage(`{"items":[{"audit_id":"a1","state":"ok"}]}`)}, nil)
	if !strings.Contains(short, "audit_id") || !strings.Contains(short, "state") || strings.Contains(short, prettyTruncatedNote) {
		t.Fatalf("short headers %q", short)
	}
}

// TestPrettyOutputIsBounded (contract section 0.1 item 193): even with
// headers and cells shortened, a table pads a row of a few bytes to the width
// of eight columns. Rendering stops at maxPrettyBytes with a note; the meta
// line still follows.
func TestPrettyOutputIsBounded(t *testing.T) {
	wide := make([]string, 0, maxTableColumns)
	for index := 0; index < maxTableColumns; index++ {
		wide = append(wide, `"`+strings.Repeat(string(rune('a'+index)), 60)+`":"`+strings.Repeat("x", 60)+`"`)
	}
	rows := []string{"{" + strings.Join(wide, ",") + "}"}
	for index := 0; index < 200000; index++ {
		rows = append(rows, `{}`)
	}
	data := `{"items":[` + strings.Join(rows, ",") + `],"zz":"after"}`
	out := renderPrettySuccess(outEnvelope{OK: true, Data: json.RawMessage(data), Meta: json.RawMessage(`{"state":"ok","complete":true,"incomplete_reason":""}`)}, nil)
	if len(out) > maxPrettyBytes+64<<10 {
		t.Fatalf("%d bytes of data rendered to %d bytes, more than the %d limit", len(data), len(out), maxPrettyBytes)
	}
	if !strings.HasSuffix(out, "\n"+prettyTruncatedNote+"\nmeta: state=ok complete=true\n") {
		t.Fatalf("the output does not end with the note and the meta line: %.200q", out[len(out)-200:])
	}
	if strings.Contains(out, "zz: after") {
		t.Fatal("values after the limit were still rendered")
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

// TestOutPreCheckNeverTouchesTheTarget (contract section 0.1 item 166): the
// --out pre-check proves the name with a random name of the same length and
// never creates or removes anything at the target path. A file another
// writer renames onto the target at any moment of the check survives it; a
// missing target stays missing and an existing one unchanged, and nothing is
// left in the directory.
func TestOutPreCheckNeverTouchesTheTarget(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "out.json")
	inv, err := parse(h.env, []string{"usage", "trend", "ses_1", "--out", target})
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 300; round++ {
		_ = os.Remove(target)
		prepared := filepath.Join(dir, "prepared")
		if err := os.WriteFile(prepared, []byte("other writer"), 0o644); err != nil {
			t.Fatal(err)
		}
		var wait sync.WaitGroup
		var renamed bool
		wait.Add(1)
		go func(delay int) {
			defer wait.Done()
			for spin := 0; spin < delay; spin++ {
				runtime.Gosched()
			}
			renamed = os.Rename(prepared, target) == nil
		}(round % 13)
		// On Windows the check opens an existing target for writing (never
		// creating or truncating it) and may meet the rename half-way; a
		// refusal is fine, losing the other writer's file is not.
		_, _ = outPath(inv)
		wait.Wait()
		if data, err := os.ReadFile(target); renamed && (err != nil || string(data) != "other writer") {
			t.Fatalf("round %d: the other writer's file at the target is gone or changed: %v %q", round, err, data)
		}
		_ = os.Remove(prepared)
	}
	_ = os.Remove(target)
	if _, err := outPath(inv); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("the check left %v behind or created the target", entries)
	}
	writeFile(t, target, "precious")
	before, _ := os.Lstat(target)
	if _, err := outPath(inv); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Lstat(target)
	if data, _ := os.ReadFile(target); string(data) != "precious" || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the existing target changed: %q", data)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("the check left %v behind", entries)
	}
}

// TestOutPreCheckNeverCreatesTheTarget watches the target while the check
// runs again and again: it never exists, not even for an instant, also for a
// one-character name, where a random name of the same length could be the
// target's own (in any letter case).
func TestOutPreCheckNeverCreatesTheTarget(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	for _, name := range []string{"out.json", "a", "A"} {
		target := filepath.Join(dir, name)
		inv, err := parse(h.env, []string{"usage", "trend", "ses_1", "--out", target})
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		seen := make(chan bool, 1)
		go func() {
			appeared := false
			for {
				select {
				case <-stop:
					seen <- appeared
					return
				default:
				}
				if _, err := os.Lstat(target); err == nil {
					appeared = true
				}
			}
		}()
		for round := 0; round < 500; round++ {
			if _, err := outPath(inv); err != nil {
				t.Fatalf("%s round %d: %v", name, round, err)
			}
		}
		close(stop)
		if <-seen {
			t.Fatalf("the target %s existed while the check ran", name)
		}
	}
	// The random name of a one-character target is never the target itself.
	for round := 0; round < 500; round++ {
		file, path, err := createSameLength(dir, "a")
		if err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		_ = os.Remove(path)
		if base := filepath.Base(path); strings.EqualFold(base, "a") || len(base) != 1 {
			t.Fatalf("round %d: random name %q for target a", round, base)
		}
	}
}

// TestSameLengthNamesMatchTheTarget: the probe and the temporary file of an
// --out write have a fresh name exactly as long as the target's in the file
// system's unit (bytes; UTF-16 units on Windows), made of ASCII letters and
// digits, and two of them differ.
func TestSameLengthNamesMatchTheTarget(t *testing.T) {
	for _, name := range []string{"a", "ab", "out.json", strings.Repeat("审", 80) + ".json", strings.Repeat("x", 255)} {
		first, err := sameLengthName(name)
		if err != nil {
			t.Fatal(err)
		}
		second, _ := sameLengthName(name)
		if nameLength(first) != nameLength(name) || len(first) != nameLength(first) || (len(first) > 4 && first == second) {
			t.Fatalf("%q: %q and %q", name, first, second)
		}
	}
}

// TestOutAlternateDataStreamIsRefused: on Windows a ':' after the drive
// letter names an alternate data stream of another file; --out refuses it
// with LOCAL_FILE_ERROR and reason alternate_data_stream before anything is
// sent, and the base file is neither created nor changed.
func TestOutAlternateDataStreamIsRefused(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("alternate data streams are an NTFS feature")
	}
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	dir := t.TempDir()
	base := filepath.Join(dir, "out.json")
	for _, existing := range []bool{false, true} {
		if existing {
			writeFile(t, base, "precious")
		}
		for _, args := range [][]string{{"usage", "trend", "ses_1"}, {"requests", "export", "77", "--what", "conversation"}} {
			body := h.expectFailure(h.run(append(append([]string{}, args...), "--out", base+":stream")...), agentapi.CodeLocalFileError, 1)
			if body.Details["reason"] != "alternate_data_stream" || len(server.recorded()) != 0 {
				t.Fatalf("%v: %+v", args, body)
			}
		}
		data, err := os.ReadFile(base)
		if existing && string(data) != "precious" || !existing && err == nil {
			t.Fatalf("existing %v: the base file is %q, %v", existing, data, err)
		}
	}
}

// hostileText is name followed by an OSC 52 clipboard sequence (ESC … BEL),
// CR, LF, DEL and U+009B (a CSI on some terminals); cleanText is how --pretty
// must show it: every control a space, the rest as it is.
func hostileText(name string) string { return name + "\x1b]52;c;ZmFrZQ==\x07\r\n\x7f\u009bend" }
func cleanText(name string) string   { return name + " ]52;c;ZmFrZQ==     end" }

// assertTerminalSafe checks that out has exactly lines lines and no control
// character (C0, DEL, C1) other than the newlines that end them. It checks
// runes, not bytes: 0x9b is also a UTF-8 continuation byte.
func assertTerminalSafe(t *testing.T, out string, lines int) {
	t.Helper()
	if got := strings.Count(out, "\n"); got != lines || !strings.HasSuffix(out, "\n") {
		t.Fatalf("%d lines, want %d: %q", got, lines, out)
	}
	for _, char := range out {
		if char != '\n' && (char < 0x20 || (char >= 0x7f && char <= 0x9f)) {
			t.Fatalf("control character %U in %q", char, out)
		}
	}
}

// TestPrettyNeutralisesControlCharacters (contract section 0.1 item 189):
// no server-provided text --pretty prints, in a failure or a success, can
// carry a control character to the terminal or forge an output line.
func TestPrettyNeutralisesControlCharacters(t *testing.T) {
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)

	failure, _ := json.Marshal(map[string]any{"ok": false, "error": map[string]any{
		"code": hostileText("CODE"), "message": hostileText("message"), "hint": hostileText("hint"),
		"details": map[string]any{hostileText("key"): hostileText("value"), "nested": []any{hostileText("item"), map[string]any{"k": "\x7f\u009b"}}},
	}})
	server.setResponder(respondJSON(http.StatusNotFound, string(failure)))
	h.run("--pretty", "usage", "trend", "ses_1")
	out := h.stderr.String()
	assertTerminalSafe(t, out, 4)
	// The nested value is compact JSON: its C0 controls are JSON escapes,
	// its DEL and C1 spaces (checked by assertTerminalSafe).
	for _, name := range []string{"CODE", "message", "hint", "key", "value"} {
		if !strings.Contains(out, cleanText(name)) {
			t.Errorf("failure: %s is not shown as %q: %q", name, cleanText(name), out)
		}
	}

	success, _ := json.Marshal(map[string]any{
		"ok": true,
		"data": map[string]any{
			hostileText("label"): hostileText("scalar"),
			"list":               []any{hostileText("element"), map[string]any{"k": "\x7f\u009b"}},
			"rows":               []any{map[string]any{hostileText("header"): hostileText("cell")}},
		},
		"meta":         map[string]any{"state": hostileText("state"), "complete": false, "incomplete_reason": hostileText("reason")},
		"next_actions": []string{hostileText("next")},
		"web_path":     "/ui/" + hostileText("web"),
		"notice":       hostileText("notice"),
	})
	server.setResponder(respondJSON(http.StatusOK, string(success)))
	if exit := h.run("--pretty", "usage", "trend", "ses_1"); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	out = h.stdout.String()
	// ok, label, list, rows, table header, table row, meta, web, next, notice.
	assertTerminalSafe(t, out, 10)
	for _, name := range []string{"label", "scalar", "element", "header", "cell", "state", "reason", "web", "next", "notice"} {
		if !strings.Contains(out, cleanText(name)) {
			t.Errorf("success: %s is not shown as %q: %q", name, cleanText(name), out)
		}
	}
}

// TestPrettyKeepsOrdinaryText: text without control characters, Chinese,
// accented and emoji text included, renders exactly as before.
func TestPrettyKeepsOrdinaryText(t *testing.T) {
	failure := renderPrettyFailure(agentapi.ErrorBody{Code: agentapi.CodeNotFound, Message: "未找到会话 café 🙂", Hint: "检查 ID «ses_1»",
		Details: map[string]any{"路径": "/ui/审计", "list": []any{"é", map[string]any{"k": "ü 😀"}}}})
	if want := "error NOT_FOUND: 未找到会话 café 🙂\nhint: 检查 ID «ses_1»\nlist: [\"é\",{\"k\":\"ü 😀\"}]\n路径: /ui/审计\n"; failure != want {
		t.Fatalf("failure %q, want %q", failure, want)
	}
	success := renderPrettySuccess(outEnvelope{OK: true, Data: json.RawMessage(`{"名称":"naïve 🙂","rows":[{"列":"值"}]}`),
		Meta: json.RawMessage(`{"state":"succeeded","complete":false,"incomplete_reason":"truncated"}`), NextActions: []string{"下一步 →"},
		WebPath: "/ui/会话", Notice: "注意 ✓"}, nil)
	if want := "ok\nrows:\n  列\n  值\n名称: naïve 🙂\nmeta: state=succeeded complete=false incomplete_reason=truncated\nweb: /ui/会话\nnext: 下一步 →\nnotice: 注意 ✓\n"; success != want {
		t.Fatalf("success %q, want %q", success, want)
	}
}

// fullDiskWriter accepts limit bytes and then fails, like a full disk.
type fullDiskWriter struct {
	writer io.Writer
	limit  int
}

func (failing *fullDiskWriter) Write(data []byte) (int, error) {
	if len(data) > failing.limit {
		written, _ := failing.writer.Write(data[:failing.limit])
		failing.limit = 0
		return written, errors.New("no space left on device")
	}
	failing.limit -= len(data)
	return failing.writer.Write(data)
}

// exportServer answers every export with size bytes; broken cuts the body
// off after a part of it.
func exportServer(t *testing.T, size int, broken bool) *fakeServer {
	return newFakeServer(t, func(writer http.ResponseWriter, _ *http.Request, _ []byte) {
		writer.Header().Set("Content-Type", "application/octet-stream")
		writer.Header().Set("Content-Length", strconv.Itoa(size))
		writer.Header().Set("X-Audit-Complete", "true")
		writer.WriteHeader(http.StatusOK)
		if !broken {
			_, _ = writer.Write(bytes.Repeat([]byte("x"), size))
			return
		}
		_, _ = writer.Write(bytes.Repeat([]byte("x"), size/4))
		writer.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	})
}

// assertExportLeftNothing checks that a failed export left no temporary
// file, did not create a missing --out and did not change an existing one.
func assertExportLeftNothing(t *testing.T, dir, missing, existing string) {
	t.Helper()
	assertNoTempFiles(t, dir)
	if _, err := os.Lstat(missing); err == nil {
		t.Fatal("a failed export created the --out file")
	}
	if data, _ := os.ReadFile(existing); string(data) != "precious" {
		t.Fatalf("a failed export changed the existing --out file to %.40q", data)
	}
}

// TestExportWriteFailureIsLocalFileError (contract section 0.1 item 190): a
// write to the --out file that fails part way through the copy is
// LOCAL_FILE_ERROR naming --out, not a network failure, and leaves nothing
// behind.
func TestExportWriteFailureIsLocalFileError(t *testing.T) {
	server := exportServer(t, 256<<10, false)
	h := newHarness(t)
	h.saveLogin(server.URL)
	original := tempFileWriter
	tempFileWriter = func(file *os.File) io.Writer { return &fullDiskWriter{writer: file, limit: 1000} }
	t.Cleanup(func() { tempFileWriter = original })
	dir := t.TempDir()
	missing := filepath.Join(dir, "export.json")
	existing := writeFile(t, filepath.Join(dir, "existing.json"), "precious")
	for _, target := range []string{missing, existing} {
		body := h.expectFailure(h.run("requests", "export", "77", "--what", "conversation", "--out", target), agentapi.CodeLocalFileError, agentapi.ExitError)
		if body.Details["field"] != "--out" || body.Details["path"] != target {
			t.Fatalf("details %v", body.Details)
		}
		assertExportLeftNothing(t, dir, missing, existing)
	}
}

// TestExportBrokenBodyIsNetworkError: a response body that breaks off
// mid-stream is still NETWORK_ERROR, and leaves nothing behind.
func TestExportBrokenBodyIsNetworkError(t *testing.T) {
	server := exportServer(t, 256<<10, true)
	h := newHarness(t)
	h.saveLogin(server.URL)
	dir := t.TempDir()
	missing := filepath.Join(dir, "export.json")
	existing := writeFile(t, filepath.Join(dir, "existing.json"), "precious")
	for _, target := range []string{missing, existing} {
		h.expectFailure(h.run("requests", "export", "77", "--what", "conversation", "--out", target), agentapi.CodeNetworkError, agentapi.ExitError)
		assertExportLeftNothing(t, dir, missing, existing)
	}
}

// TestRawExportDigestIsVerified (contract section 0.1 item 191): a raw body
// the server calls complete must have the SHA-256 the server sent with it.
// A body that does not is EVIDENCE_UNAVAILABLE and replaces nothing; a body
// that does, and a body the server does not call complete, are written.
func TestRawExportDigestIsVerified(t *testing.T) {
	raw := []byte("\x00\x01raw body\xff")
	digest := sha256.Sum256(raw)
	good := hex.EncodeToString(digest[:])
	other := sha256.Sum256([]byte("another body"))
	bad := hex.EncodeToString(other[:])
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request, _ []byte) {
		writer.Header().Set("Content-Type", "application/octet-stream")
		switch {
		case strings.Contains(request.URL.Path, "/requests/match/"):
			writer.Header().Set("X-Audit-Complete", "true")
			writer.Header().Set("X-Audit-SHA256", strings.ToUpper(good))
		case strings.Contains(request.URL.Path, "/requests/mismatch/"):
			writer.Header().Set("X-Audit-Complete", "true")
			writer.Header().Set("X-Audit-SHA256", bad)
		case strings.Contains(request.URL.Path, "/requests/partial/"):
			// An incomplete capture: its digest is not one of the stored bytes.
			writer.Header().Set("X-Audit-Complete", "false")
			writer.Header().Set("X-Audit-SHA256", bad)
		}
		_, _ = writer.Write(raw)
	})
	h := newHarness(t)
	h.saveLogin(server.URL)
	dir := t.TempDir()
	missing := filepath.Join(dir, "raw.bin")
	existing := writeFile(t, filepath.Join(dir, "existing.json"), "precious")
	for _, target := range []string{missing, existing} {
		body := h.expectFailure(h.run("requests", "export", "mismatch", "--what", "raw-response", "--out", target), agentapi.CodeEvidenceUnavailable, agentapi.ExitError)
		if body.Details["reason"] != "digest_mismatch" || body.Details["path"] != target {
			t.Fatalf("details %v", body.Details)
		}
		assertExportLeftNothing(t, dir, missing, existing)
	}
	for _, id := range []string{"match", "partial"} {
		target := filepath.Join(dir, id+".bin")
		if exit := h.run("requests", "export", id, "--what", "raw-response", "--out", target); exit != 0 {
			t.Fatalf("%s: exit %d %s", id, exit, h.stderr.String())
		}
		if content, _ := os.ReadFile(target); !bytes.Equal(content, raw) {
			t.Fatalf("%s: content %q", id, content)
		}
		if envelope := h.success(); strings.Contains(string(envelope["data"]), `"complete":true`) != (id == "match") {
			t.Fatalf("%s: data %s", id, envelope["data"])
		}
	}
}
