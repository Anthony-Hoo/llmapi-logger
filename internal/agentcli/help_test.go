package agentcli

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// placeholders stand in for the <...> parts of commands written in help
// text and hints, so the command can be parsed for real.
var placeholders = strings.NewReplacer(
	"<url>", "https://audit.example.com",
	"<kind>", "ua-rule",
	"<pattern>", "example",
	"<week>", "2026-01-05",
	"<plan-id>", "pln_1",
	"<id>", "1",
	"<file>", "out.json",
)

// shellSplit splits a command line with single and double quotes.
func shellSplit(t *testing.T, line string) []string {
	var words []string
	var current strings.Builder
	inWord, quote := false, rune(0)
	for _, char := range line {
		switch {
		case quote != 0 && char == quote:
			quote = 0
		case quote != 0:
			current.WriteRune(char)
		case char == '\'' || char == '"':
			quote, inWord = char, true
		case char == ' ':
			if inWord {
				words = append(words, current.String())
				current.Reset()
				inWord = false
			}
		default:
			current.WriteRune(char)
			inWord = true
		}
	}
	if quote != 0 {
		t.Fatalf("unbalanced quote in %q", line)
	}
	if inWord {
		words = append(words, current.String())
	}
	return words
}

func assertParses(t *testing.T, source, line string) {
	t.Helper()
	expanded := placeholders.Replace(line)
	if strings.Contains(expanded, "<") {
		t.Errorf("%s: unknown placeholder in %q", source, line)
		return
	}
	words := shellSplit(t, expanded)
	if len(words) == 0 || words[0] != "llmaudit" {
		t.Errorf("%s: %q does not start with llmaudit", source, line)
		return
	}
	_, err := parse(&Env{}, words[1:])
	var help *errHelp
	if err != nil && !errors.As(err, &help) {
		t.Errorf("%s: %q does not parse: %v", source, line, err)
	}
}

var inlineCommand = regexp.MustCompile("`(llmaudit[^`]*)`")

// TestEveryCommandInHelpParses: examples, commands quoted in any help text,
// in the shared error table's hints and in this package's source.
func TestEveryCommandInHelpParses(t *testing.T) {
	texts := map[string]string{"top help": topHelp()}
	for _, group := range groupOrder {
		texts[group.Name+" help"] = groupHelp(group.Name)
	}
	for _, spec := range allCommands() {
		if len(spec.Examples) == 0 {
			t.Errorf("%s has no example", spec.name())
		}
		for _, example := range spec.Examples {
			assertParses(t, spec.name()+" example", example)
		}
		texts[spec.name()+" help"] = commandHelp(spec)
	}
	for _, spec := range agentapi.Codes() {
		texts["hint of "+string(spec.Code)] = spec.Hint + " " + spec.Message
	}
	files, _ := filepath.Glob("*.go")
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		texts[file] = string(data)
	}
	count := 0
	for source, text := range texts {
		for _, match := range inlineCommand.FindAllStringSubmatch(text, -1) {
			if strings.Contains(match[1], "%s") {
				continue // a format string in an error message, filled with a real command name
			}
			assertParses(t, source, match[1])
			count++
		}
		for _, line := range strings.Split(text, "\n") {
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(line, "  llmaudit ") && !strings.Contains(trimmed, "`") {
				assertParses(t, source+" example line", trimmed)
				count++
			}
		}
	}
	if count < 50 {
		t.Fatalf("only %d commands found in help texts", count)
	}
}

func TestHelpOutput(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{}, {"--help"}, {"help"}, {"requests"}, {"requests", "--help"}, {"requests", "list", "--help"}, {"apply", "-h"}, {"config", "set-key", "--help"}} {
		if exit := h.run(args...); exit != 0 || h.stdout.Len() == 0 || h.stderr.Len() != 0 {
			t.Errorf("%v: exit %d", args, exit)
		}
	}
	// Every flag's help names a default or says it is required.
	for _, spec := range allCommands() {
		for _, flag := range spec.Flags {
			if !strings.Contains(flag.Help, "Default") && !strings.Contains(flag.Help, "Required") && !strings.Contains(flag.Help, "required") {
				t.Errorf("%s --%s: help states no default", spec.name(), flag.Name)
			}
		}
	}
	h.run("requests", "list", "--help")
	for _, want := range []string{"--since <duration>", "--no-collapse", "1-200", "Default: 50", "Timeout: 15s"} {
		if !strings.Contains(h.stdout.String(), want) {
			t.Errorf("requests list help lacks %q", want)
		}
	}
}

// TestStandardLibraryOnly: the client imports nothing but the standard
// library and the shared agentapi package.
func TestStandardLibraryOnly(t *testing.T) {
	var files []string
	for _, pattern := range []string{"*.go", filepath.Join("..", "..", "cmd", "llmaudit", "*.go")} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	if len(files) < 10 {
		t.Fatalf("found only %d files", len(files))
	}
	fileSet := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fileSet, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range parsed.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			first := strings.SplitN(path, "/", 2)[0]
			allowed := path == "llmapi-logger/internal/agentapi" || path == "llmapi-logger/internal/agentcli" && strings.Contains(file, "llmaudit")
			if !allowed && strings.Contains(first, ".") || !allowed && strings.HasPrefix(path, "llmapi-logger/") {
				t.Errorf("%s imports %s", file, path)
			}
		}
	}
}
