package agentcli

import (
	"path/filepath"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// Contract section 0.1 item 132: a JSON object the user gives a write command
// (a --set-json value, a --patch-file object, a --file of calibration labels)
// names each key once at any depth. A repeated key is refused before
// anything is sent instead of letting the last one win. Separate --set,
// --set-json and --patch-file flags naming the same field are a different
// thing: there the later flag still wins, as the help says.
func TestWriteInputRefusesRepeatedKeys(t *testing.T) {
	server := newFakeServer(t, nil)
	dir := t.TempDir()
	const session = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	patch := writeFile(t, filepath.Join(dir, "patch.json"), `{"name":"a","enabled":true,"name":"b"}`)
	nested := writeFile(t, filepath.Join(dir, "nested.json"), `{"rules":[{"kind":"repo_name","pattern":"a","pattern":"b"}]}`)
	labels := writeFile(t, filepath.Join(dir, "labels.json"), `[{"session_id":"`+session+`","task_type":"bug_fix","task_type":"feature"}]`)
	for _, test := range []struct {
		args  []string
		field string
	}{
		{[]string{"config", "set", "--kind", "group", "--patch-file", patch}, "--patch-file"},
		{[]string{"config", "set", "--kind", "project", "--id", "3", "--patch-file", nested}, "--patch-file"},
		{[]string{"config", "set", "--kind", "content-rule", "--id", "3", "--set-json", `keywords={"a":1,"a":2}`}, "--set-json"},
		{[]string{"analysis", "calibrate", "--file", labels}, "--file"},
	} {
		h := newHarness(t)
		h.saveLogin(server.URL)
		server.reset()
		body := h.expectFailure(h.run(test.args...), agentapi.CodeInvalidArgument, agentapi.ExitInvalidUsage)
		if body.Details["field"] != test.field || body.Details["reason"] != "duplicate_key" {
			t.Errorf("%v = %v", test.args, body.Details)
		}
		if len(server.recorded()) != 0 {
			t.Errorf("%v sent a request", test.args)
		}
	}
}
