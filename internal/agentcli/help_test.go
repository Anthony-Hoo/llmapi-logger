package agentcli

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

// placeholders stand in for the <...> parts of commands written in help
// text and hints, so the command can be parsed for real.
var placeholders = strings.NewReplacer(
	"<url>", "https://audit.example.com",
	"<server>", "https://audit.example.com",
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
	if err := CheckCommand(words[1:]); err != nil {
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
	// A group alone is an INVALID_ARGUMENT envelope (TestGroupWithoutASubcommandIsAnEnvelope);
	// with --help it prints the group's help.
	for _, args := range [][]string{{}, {"--help"}, {"help"}, {"requests", "--help"}, {"requests", "list", "--help"}, {"apply", "-h"}, {"config", "set-key", "--help"}} {
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

// Contract section 0.1 item 111: callers list lists users only, and its help
// says where a token id for a principal comes from.
func TestCallersHelpSaysWhereTokenIDsAre(t *testing.T) {
	h := newHarness(t)
	if exit := h.run("callers", "list", "--help"); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	help := h.stdout.String()
	if strings.Contains(help, "users and tokens") || !strings.Contains(help, "token_id") || !strings.Contains(help, "--token-id") || !strings.Contains(help, "token:<id>") {
		t.Fatalf("callers list help = %q", help)
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

// TestHelpStatesTheTimeoutApplied: the timeout each command's help prints is
// the one its requests run under, and login's help also names the wait for
// the browser or the pasted code (the same constant the wait uses).
func TestHelpStatesTheTimeoutApplied(t *testing.T) {
	for _, spec := range allCommands() {
		help := commandHelp(spec)
		inv := &invocation{env: &Env{}, spec: spec}
		ctx, cancel := inv.context()
		deadline, _ := ctx.Deadline()
		cancel()
		if applied := time.Until(deadline); applied > spec.timeout() || applied < spec.timeout()-time.Second {
			t.Errorf("%s: requests run under %s, spec says %s", spec.name(), applied, spec.timeout())
		}
		if !strings.Contains(help, spec.timeout().String()) {
			t.Errorf("%s: help does not print the request timeout %s", spec.name(), spec.timeout())
		}
		if spec.Wait > 0 && !strings.Contains(help, "Timeout: up to "+spec.Wait.String()) {
			t.Errorf("%s: help does not print the wait %s", spec.name(), spec.Wait)
		}
	}
	login, _, _ := findCommand(allCommands(), []string{"login"})
	if login.Wait != (&Env{}).loginTimeout() || login.Wait != 5*time.Minute {
		t.Fatalf("login help wait %s, real wait %s", login.Wait, (&Env{}).loginTimeout())
	}
	if help := commandHelp(login); !strings.Contains(help, "Timeout: up to 5m0s waiting for the browser approval or the pasted code, then 15s") ||
		!strings.Contains(strings.Join(strings.Fields(help), " "), "waits up to "+loginWaitText) {
		t.Fatalf("login help:\n%s", help)
	}
}

// TestHelpOnNull: no help text says null means empty; where --set is
// documented, null is JSON null that only a project's group_id accepts.
func TestHelpOnNull(t *testing.T) {
	for _, spec := range allCommands() {
		help := strings.Join(strings.Fields(commandHelp(spec)), " ")
		if strings.Contains(help, "null is empty") {
			t.Errorf("%s help says null is empty", spec.name())
		}
		if spec.flag("set") != nil && !strings.Contains(help, "null is JSON null") {
			t.Errorf("%s help does not say what null is", spec.name())
		}
	}
}

// TestLoginHintsWorkWithoutSavedCredentials: the hint of a client without
// credentials names a login command that works on a first login, i.e. one
// that carries --server (a bare `llmaudit login` fails there with
// INVALID_ARGUMENT), and so do the hints of the server's credential codes.
func TestLoginHintsWorkWithoutSavedCredentials(t *testing.T) {
	h := newHarness(t)
	body := h.expectFailure(h.run("whoami"), agentapi.CodeNotLoggedIn, 4)
	hints := []string{body.Hint}
	for _, code := range []agentapi.Code{agentapi.CodeUnauthenticated, agentapi.CodeTokenExpired, agentapi.CodeTokenRevoked,
		agentapi.CodeInvalidGrant, agentapi.CodeReadOnlyToken, agentapi.CodeNotLoggedIn} {
		spec, _ := agentapi.Lookup(code)
		hints = append(hints, spec.Hint)
	}
	for _, hint := range hints {
		commands := inlineCommand.FindAllStringSubmatch(hint, -1)
		if len(commands) == 0 {
			t.Errorf("hint %q names no command", hint)
		}
		for _, match := range commands {
			words := strings.Fields(placeholders.Replace(match[1]))
			if err := CheckCommand(words[1:]); err != nil {
				t.Errorf("hint %q: %v", hint, err)
			}
			if words[1] == "login" {
				// Without saved credentials the command line itself must get past
				// the --server check (it then fails only for want of a browser).
				inv, err := parse(h.env, words[1:])
				if err != nil || inv.value("server") == "" {
					t.Errorf("hint %q: login without --server", hint)
				}
			}
		}
	}
	if CheckCommand([]string{"login"}) == nil || CheckCommand([]string{"login", "--write"}) == nil {
		t.Fatal("CheckCommand accepts a login that fails on a first login")
	}
}

// A group without a subcommand prints one JSON envelope, as every command
// does: INVALID_ARGUMENT naming the missing subcommand and the available
// ones, exit 2. Plain help is only for an explicit --help.
func TestGroupWithoutASubcommandIsAnEnvelope(t *testing.T) {
	h := newHarness(t)
	for _, group := range groupOrder {
		body := h.expectFailure(h.run(group.Name), agentapi.CodeInvalidArgument, agentapi.ExitInvalidUsage)
		available, _ := body.Details["available"].([]any)
		if body.Details["field"] != "command" || body.Details["reason"] != "missing_subcommand" || len(available) == 0 || h.stdout.Len() != 0 {
			t.Errorf("llmaudit %s: %+v", group.Name, body)
		}
		for _, name := range available {
			if !strings.Contains(body.Message, name.(string)) {
				t.Errorf("llmaudit %s: message %q does not list %v", group.Name, body.Message, name)
			}
		}
	}
	body := h.expectFailure(h.run("requests", "lst"), agentapi.CodeInvalidArgument, agentapi.ExitInvalidUsage)
	if body.Details["reason"] != "unknown_command" || !strings.Contains(body.Message, "list") {
		t.Errorf("llmaudit requests lst: %+v", body)
	}
	if exit := h.run("callers", "--help"); exit != 0 || !strings.Contains(h.stdout.String(), "callers list") {
		t.Errorf("callers --help: exit %d %s", exit, h.stdout.String())
	}
}

// Global flags are accepted before the command as well as after it.
func TestGlobalFlagsBeforeTheCommand(t *testing.T) {
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	for _, args := range [][]string{{"--pretty", "whoami"}, {"whoami", "--pretty"}, {"-pretty", "whoami"}, {"--pretty=true", "whoami"}} {
		if exit := h.run(args...); exit != 0 || strings.HasPrefix(strings.TrimSpace(h.stdout.String()), "{") {
			t.Errorf("%v: exit %d, output %q (want the pretty form)", args, exit, h.stdout.String())
		}
	}
	if exit := h.run("--pretty=false", "whoami"); exit != 0 || !strings.HasPrefix(h.stdout.String(), "{") {
		t.Errorf("--pretty=false whoami: exit %d %q", exit, h.stdout.String())
	}
	if exit := h.run("--pretty=maybe", "whoami"); exit != agentapi.ExitInvalidUsage {
		t.Errorf("--pretty=maybe whoami: exit %d", exit)
	}
}
