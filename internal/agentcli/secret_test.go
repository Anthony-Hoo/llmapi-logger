package agentcli

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

const testSecret = `sk-test "quoted\ value` + "\t"

func TestKeyCommandsHaveNoKeyInput(t *testing.T) {
	flags := func(name string) []string {
		var spec *commandSpec
		for _, candidate := range allCommands() {
			if candidate.name() == name {
				spec = candidate
			}
		}
		var names []string
		for _, flag := range spec.Flags {
			names = append(names, flag.Name)
		}
		if len(spec.Args) != 0 {
			t.Errorf("%s takes positional arguments", name)
		}
		sort.Strings(names)
		return names
	}
	if got := flags("config set-key"); !reflect.DeepEqual(got, []string{"clear", "kind"}) {
		t.Errorf("config set-key flags %v", got)
	}
	if got := flags("analysis test-model"); !reflect.DeepEqual(got, []string{"prompt-key", "set"}) {
		t.Errorf("analysis test-model flags %v", got)
	}
}

// TestSetKeyNeedsATerminal: with stdin a pipe (the real detection on an
// os.Pipe end) the command fails with NO_TTY before any request, and no
// argument, environment variable or file can supply the key.
func TestSetKeyNeedsATerminal(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	_, _ = writer.WriteString(testSecret + "\n")
	pipe := NewTerminal(reader)
	if pipe.IsInteractive() {
		t.Fatal("a pipe is reported as a terminal")
	}
	if _, err := pipe.ReadLineNoEcho(); err == nil {
		t.Fatal("read a key from a pipe")
	}

	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	h.env.Terminal = pipe
	h.env.Stdin = reader
	writeFile(t, filepath.Join(h.home, "api_key"), testSecret)
	for _, args := range [][]string{
		{"config", "set-key", "--kind", "analysis-settings"},
		{"analysis", "test-model", "--prompt-key"},
		{"analysis", "test-model", "--prompt-key", "--set", "llm.model=m"},
	} {
		body := h.expectFailure(h.run(args...), agentapi.CodeNoTTY, 2)
		if !strings.Contains(body.Hint, "themselves in a terminal") {
			t.Errorf("hint %q", body.Hint)
		}
	}
	for _, args := range [][]string{
		{"config", "set-key", "--kind", "analysis-settings", "--key", testSecret},
		{"config", "set-key", "--kind", "analysis-settings", "--api-key=" + testSecret},
		{"config", "set-key", "--kind", "analysis-settings", testSecret},
		{"analysis", "test-model", "--api-key", testSecret},
		{"analysis", "test-model", "--set", "api_key"},
	} {
		exit := h.run(args...)
		if exit == 0 {
			t.Errorf("%v succeeded", args[:3])
		}
	}
	if len(server.recorded()) != 0 {
		t.Fatalf("a key command reached the server without a terminal: %d requests", len(server.recorded()))
	}
	for _, name := range h.envNames {
		if name != "LLMAUDIT_HOME" {
			t.Errorf("the client read environment variable %s", name)
		}
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), "sk-test") {
		t.Fatal("key text printed")
	}
}

func TestSetKeyFromTerminal(t *testing.T) {
	server := newFakeServer(t, respondJSON(200, `{"ok":true,"data":{"api_key":"saved"}}`))
	h := newHarness(t)
	h.saveLogin(server.URL)
	h.terminal.interactive = true
	h.terminal.secret = testSecret
	if exit := h.run("config", "set-key", "--kind", "analysis-settings"); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	request := server.recorded()[0]
	if request.Method != "PUT" || request.Path != agentapi.PathPrefix+"/config/analysis-settings/api-key" ||
		!jsonEqual(t, request.Body, `{"api_key":"sk-test \"quoted\\ value\t"}`) || request.Header.Get(agentapi.HeaderCommand) != "config.set-key" {
		t.Fatalf("request %s %s %s", request.Method, request.Path, request.Body)
	}
	assertSecretNowhere(t, h)

	// The key is never in an error either.
	server.setResponder(respondJSON(400, `{"ok":false,"error":{"code":"INVALID_ARGUMENT","message":"bad key","details":{"field":"api_key"}}}`))
	h.expectFailure(h.run("config", "set-key", "--kind", "analysis-settings"), agentapi.CodeInvalidArgument, 2)
	assertSecretNowhere(t, h)

	// An empty line sends nothing.
	h.terminal.secret = ""
	server.reset()
	h.expectFailure(h.run("config", "set-key", "--kind", "analysis-settings"), agentapi.CodeInvalidArgument, 2)
	if len(server.recorded()) != 0 {
		t.Fatal("an empty key was sent")
	}

	// --clear reads nothing.
	h.terminal.interactive = false
	h.terminal.reads = 0
	server.setResponder(respondJSON(200, `{"ok":true,"data":{"api_key":"none"}}`))
	if exit := h.run("config", "set-key", "--kind", "analysis-settings", "--clear"); exit != 0 || h.terminal.reads != 0 {
		t.Fatalf("clear: exit %d reads %d", exit, h.terminal.reads)
	}
}

func TestTestModelPromptKeyAndExitSix(t *testing.T) {
	server := newFakeServer(t, respondJSON(200, `{"ok":true,"data":{"ok":false,"stage":"connect","message":"refused"}}`))
	h := newHarness(t)
	h.saveLogin(server.URL)
	h.terminal.interactive = true
	h.terminal.secret = testSecret
	exit := h.run("analysis", "test-model", "--set", "llm.base_url=https://llm.example.com/v1", "--prompt-key")
	if exit != agentapi.ExitOperationFails {
		t.Fatalf("exit %d, want 6", exit)
	}
	h.success()
	request := server.recorded()[0]
	if !jsonEqual(t, request.Body, `{"set":{"llm.base_url":"https://llm.example.com/v1"},"api_key":"sk-test \"quoted\\ value\t"}`) {
		t.Fatalf("body %s", request.Body)
	}
	assertSecretNowhere(t, h)

	server.setResponder(respondJSON(200, `{"ok":true,"data":{"ok":true}}`))
	if exit := h.run("analysis", "test-model"); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
}

func assertSecretNowhere(t *testing.T, h *harness) {
	t.Helper()
	if strings.Contains(h.stdout.String()+h.stderr.String(), "sk-test") {
		t.Fatalf("the key was printed: %q %q", h.stdout.String(), h.stderr.String())
	}
	_ = filepath.WalkDir(h.home, func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			if data, _ := os.ReadFile(path); strings.Contains(string(data), "sk-test") && filepath.Base(path) != "api_key" {
				t.Fatalf("the key was written to %s", filepath.Base(path))
			}
		}
		return nil
	})
}

func TestBodyWithSecretIsValidJSON(t *testing.T) {
	body, err := bodyWithSecret(map[string]any{}, "api_key", []byte("a\"b\\c\x01\n"))
	if err != nil || !jsonEqual(t, body, `{"api_key":"a\"b\\c\u0001\n"}`) {
		t.Fatalf("body %s %v", body, err)
	}
}
