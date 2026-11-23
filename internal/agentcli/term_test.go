package agentcli

import (
	"os"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// TestNonTerminalStdinIsNoTTY runs on every platform with the real terminal
// wrapper: a pipe and a regular file are not interactive, reading a secret
// from them fails, and a command that needs a typed key stops with NO_TTY
// before anything is sent.
func TestNonTerminalStdinIsNoTTY(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	_, _ = writer.WriteString("sk-not-a-terminal-key\n")
	writer.Close()
	file, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for name, source := range map[string]*os.File{"pipe": reader, "file": file} {
		terminal := NewTerminal(source)
		if terminal.IsInteractive() {
			t.Fatalf("%s is reported as a terminal", name)
		}
		if line, err := terminal.ReadLineNoEcho(); err == nil || line != nil {
			t.Fatalf("%s: read %q without a terminal", name, line)
		}
	}
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	h.env.Terminal = NewTerminal(reader)
	h.expectFailure(h.run("analysis", "test-model", "--prompt-key"), agentapi.CodeNoTTY, 2)
	if len(server.recorded()) != 0 {
		t.Fatal("a request was sent without a key")
	}
	if NewTerminal(nil).IsInteractive() {
		t.Fatal("a nil file is a terminal")
	}
}
