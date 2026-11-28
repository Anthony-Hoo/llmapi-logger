package termio

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A pipe and a regular file are not interactive, and reading a line from
// them without echo fails without returning anything.
func TestNonTerminalIsNotInteractive(t *testing.T) {
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
	if NewTerminal(nil).IsInteractive() {
		t.Fatal("a nil file is a terminal")
	}
}

// readLine stops at the newline, drops a trailing CR and leaves what follows
// unread; Wipe clears a buffer.
func TestReadLineAndWipe(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	_, _ = writer.WriteString("first\r\nsecond\n")
	writer.Close()
	if line, err := readLine(reader); err != nil || string(line) != "first" {
		t.Fatalf("line %q, %v", line, err)
	}
	if line, err := readLine(reader); err != nil || string(line) != "second" {
		t.Fatalf("second line %q, %v", line, err)
	}
	secret := []byte("sk-wipe-me")
	Wipe(secret)
	for _, b := range secret {
		if b != 0 {
			t.Fatal("not wiped")
		}
	}
}

// The package stays on the standard library, so llmaudit keeps its
// standard-library-only rule.
func TestStandardLibraryOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fileSet, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			if strings.Contains(strings.SplitN(path, "/", 2)[0], ".") || strings.HasPrefix(path, "llmapi-logger/") {
				t.Errorf("%s imports %s", file, path)
			}
		}
	}
}
