package agentdist

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentcli"
)

// skillFiles reads every file of the repository's Skill, by slash path.
func skillFiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(realSkillDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(realSkillDir, path)
		files[filepath.ToSlash(relative)] = strings.ReplaceAll(string(data), "\r\n", "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSkillFrontmatter(t *testing.T) {
	content := skillFiles(t)["SKILL.md"]
	if !strings.HasPrefix(content, "---\n") {
		t.Fatal("SKILL.md does not start with YAML frontmatter")
	}
	end := strings.Index(content[4:], "\n---\n")
	if end < 0 {
		t.Fatal("SKILL.md frontmatter is not closed")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(content[4:4+end], "\n") {
		key, value, ok := strings.Cut(line, ": ")
		if !ok || strings.HasPrefix(line, " ") {
			t.Fatalf("frontmatter line is not a simple key: value pair: %q", line)
		}
		if _, dup := fields[key]; dup {
			t.Fatalf("frontmatter key %s repeated", key)
		}
		fields[key] = value
	}
	if len(fields) != 2 {
		t.Fatalf("frontmatter keys %v, want name and description", fields)
	}
	name := fields["name"]
	if !regexp.MustCompile(`^[a-z0-9-]{1,64}$`).MatchString(name) || name != SkillName || strings.Contains(name, "claude") || strings.Contains(name, "anthropic") {
		t.Fatalf("name %q", name)
	}
	description := fields["description"]
	if description == "" || len(description) > 1024 || strings.ContainsAny(description, "<>") {
		t.Fatalf("description is empty, longer than 1024 characters or contains angle brackets (%d characters)", len(description))
	}
	if strings.HasPrefix(description, "I ") || strings.HasPrefix(description, "You ") || strings.HasPrefix(description, "Use this") {
		t.Fatal("description is not written in the third person")
	}
	if !strings.Contains(description, "Use when") {
		t.Fatal("description does not say when to use the Skill")
	}
	// A YAML plain scalar must not contain ": " or start with a special character.
	if strings.Contains(description, ": ") || strings.ContainsAny(description[:1], "&*!|>'\"%@`{[") {
		t.Fatal("description is not a safe YAML plain scalar")
	}
	if lines := strings.Count(content, "\n"); lines >= 500 {
		t.Fatalf("SKILL.md has %d lines; keep it under 500", lines)
	}
}

func TestSkillVersionMatchesClient(t *testing.T) {
	if version := strings.TrimSpace(skillFiles(t)["VERSION"]); version != agentapi.LatestVersion || version != agentcli.Version {
		t.Fatalf("VERSION %q, client %q, latest %q", version, agentcli.Version, agentapi.LatestVersion)
	}
}

func TestSkillLayoutAndLinks(t *testing.T) {
	files := skillFiles(t)
	want := []string{"SKILL.md", "VERSION", "references/analysis.md", "references/config.md", "references/requests.md",
		"references/troubleshooting.md", "references/usage.md", "references/weekly.md"}
	if len(files) != len(want) {
		t.Fatalf("Skill files %d, want %v", len(files), want)
	}
	for _, name := range want {
		if _, ok := files[name]; !ok {
			t.Fatalf("missing %s", name)
		}
	}
	for _, link := range regexp.MustCompile(`\]\((references/[a-z-]+\.md)\)`).FindAllStringSubmatch(files["SKILL.md"], -1) {
		if _, ok := files[link[1]]; !ok {
			t.Errorf("SKILL.md links to missing %s", link[1])
		}
	}
	for _, reference := range want[2:] {
		if !strings.Contains(files["SKILL.md"], "("+reference+")") {
			t.Errorf("SKILL.md does not link %s", reference)
		}
	}
}

// TestSkillPublicContent keeps the Skill free of real environment data: the
// only hosts are example.com names.
func TestSkillPublicContent(t *testing.T) {
	hostPattern := regexp.MustCompile(`https?://([^/\s"'` + "`" + `)]+)`)
	for name, content := range skillFiles(t) {
		for _, match := range hostPattern.FindAllStringSubmatch(content, -1) {
			if host := match[1]; host != "example.com" && !strings.HasSuffix(host, ".example.com") {
				t.Errorf("%s names host %q", name, host)
			}
		}
		for _, forbidden := range []string{`C:\Users\`, "/home/", "/Users/", "BEGIN "} {
			if strings.Contains(content, forbidden) {
				t.Errorf("%s contains %q", name, forbidden)
			}
		}
		if secret := regexp.MustCompile(`(lla_|sk-)[A-Za-z0-9_-]{8,}`).FindString(content); secret != "" {
			t.Errorf("%s contains something shaped like a credential: %q", name, secret)
		}
	}
}

func TestTroubleshootingCoversEveryCode(t *testing.T) {
	content := skillFiles(t)["references/troubleshooting.md"]
	for _, spec := range agentapi.Codes() {
		row := regexp.MustCompile("(?m)^\\| `" + string(spec.Code) + "` \\| ([0-9]) \\|")
		match := row.FindStringSubmatch(content)
		if match == nil {
			t.Errorf("troubleshooting.md has no row for %s", spec.Code)
			continue
		}
		if match[1] != string(rune('0'+spec.ExitCode)) {
			t.Errorf("troubleshooting.md gives %s exit %s, the table says %d", spec.Code, match[1], spec.ExitCode)
		}
	}
}

// placeholders stand in for the <name> placeholders of command lines in the
// Skill. An unknown placeholder fails the test, so a new one is added here on
// purpose.
var placeholders = map[string]string{
	"id":            "12345",
	"audit-id":      "apx_k5qwy3dfmzxw4ztsnb2xa4dqm4",
	"session-id":    "agt_0123456789abcdef01234567",
	"tree-id":       "0123456789abcdef01234567",
	"analysis-id":   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	"plan-id":       "pln_0123456789abcdef",
	"kind":          "content-rule",
	"server":        "https://audit.example.com",
	"suggestion-id": "42",
	"pattern":       "example",
	"session":       "ses_123",
	"version":       "1763500000000000000",
}

var placeholderPattern = regexp.MustCompile(`<([a-z-]+)>`)

// skillCommands extracts every llmaudit command line from the Skill: lines in
// fenced code blocks and inline code spans that start with "llmaudit ".
func skillCommands(t *testing.T) map[string][]string {
	t.Helper()
	commands := map[string][]string{}
	spanPattern := regexp.MustCompile("`([^`]+)`")
	for name, content := range skillFiles(t) {
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		fenced := false
		scanner := bufio.NewScanner(strings.NewReader(content))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				fenced = !fenced
				continue
			}
			if fenced {
				if strings.HasPrefix(strings.TrimSpace(line), "llmaudit ") {
					commands[name] = append(commands[name], strings.TrimSpace(line))
				}
				continue
			}
			for _, span := range spanPattern.FindAllStringSubmatch(line, -1) {
				if strings.HasPrefix(span[1], "llmaudit ") {
					commands[name] = append(commands[name], span[1])
				}
			}
		}
	}
	return commands
}

// shellWords splits a command line like a POSIX shell for the subset the
// Skill uses: blanks, single and double quotes.
func shellWords(line string) ([]string, error) {
	var words []string
	var current strings.Builder
	inWord, quote := false, rune(0)
	for _, char := range line {
		switch {
		case quote != 0:
			if char == quote {
				quote = 0
			} else {
				current.WriteRune(char)
			}
		case char == '\'' || char == '"':
			quote, inWord = char, true
		case char == ' ' || char == '\t':
			if inWord {
				words = append(words, current.String())
				current.Reset()
				inWord = false
			}
		case strings.ContainsRune("|&;<>()$`\\*?[]#~", char):
			return nil, errors.New("unquoted shell metacharacter " + string(char))
		default:
			current.WriteRune(char)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if inWord {
		words = append(words, current.String())
	}
	return words, nil
}

// commandRunner runs command lines through the real client against a fake
// server that answers everything successfully.
type commandRunner struct {
	t           *testing.T
	home        string
	credentials string
}

func newCommandRunner(t *testing.T) *commandRunner {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(fakeFacade))
	t.Cleanup(server.Close)
	work := t.TempDir()
	t.Chdir(work)
	writeTestFile(t, filepath.Join(work, "settings.json"), `{}`)
	writeTestFile(t, filepath.Join(work, "labels.json"), `{"labels":[]}`)
	return &commandRunner{
		t:    t,
		home: filepath.Join(t.TempDir(), "state"),
		credentials: `{"server":"` + server.URL + `","token":"` + agentapi.TokenPrefix + strings.Repeat("A", agentapi.TokenEncodedChars) +
			`","expires_at":"2030-01-01T00:00:00Z","role":"admin","tier":"write"}`,
	}
}

// check reports why line is not accepted by llmaudit, or nil. A command the
// parser or the local validation rejects fails with INVALID_ARGUMENT before
// any request; every other outcome (success, NO_TTY for the key prompt,
// LOGIN_TIMEOUT for a login nobody approves) means the line was accepted.
func (runner *commandRunner) check(line string) error {
	for _, match := range placeholderPattern.FindAllStringSubmatch(line, -1) {
		if _, ok := placeholders[match[1]]; !ok {
			return errors.New("unknown placeholder <" + match[1] + ">")
		}
	}
	expanded := placeholderPattern.ReplaceAllStringFunc(line, func(match string) string {
		return placeholders[match[1:len(match)-1]]
	})
	words, err := shellWords(expanded)
	if err != nil {
		return err
	}
	if len(words) == 0 || words[0] != "llmaudit" {
		return errors.New("does not start with llmaudit")
	}
	// Fresh credentials every time: a logout line removes them.
	writeTestFile(runner.t, filepath.Join(runner.home, "credentials.json"), runner.credentials)
	var stdout, stderr bytes.Buffer
	env := &agentcli.Env{
		Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr,
		Getenv: func(name string) string {
			if name == "LLMAUDIT_HOME" {
				return runner.home
			}
			return ""
		},
		HomeDir:          func() (string, error) { return "", errors.New("no home directory in tests") },
		Hostname:         func() (string, error) { return "test-host", nil },
		OpenBrowser:      func(string) error { return nil },
		LoginTimeout:     50 * time.Millisecond,
		UTCOffsetMinutes: func() int { return 0 },
	}
	exit := agentcli.Run(words[1:], env)
	if exit == agentapi.ExitOK {
		return nil
	}
	last := strings.TrimSpace(stderr.String())
	if index := strings.LastIndex(last, "\n"); index >= 0 {
		last = last[index+1:]
	}
	var failure agentapi.ErrorEnvelope
	if err := json.Unmarshal([]byte(last), &failure); err != nil {
		return errors.New("exit " + strconv.Itoa(exit) + " without a failure envelope")
	}
	if failure.Error.Code == agentapi.CodeInvalidArgument {
		return errors.New("rejected by llmaudit: " + failure.Error.Message)
	}
	return nil
}

// TestSkillCommandsParse checks that every command line of the Skill is
// accepted by the client's parser and local validation.
func TestSkillCommandsParse(t *testing.T) {
	commands := skillCommands(t)
	total := 0
	for _, lines := range commands {
		total += len(lines)
	}
	if total < 60 {
		t.Fatalf("found only %d command lines in the Skill; the extraction is broken", total)
	}
	runner := newCommandRunner(t)
	for file, lines := range commands {
		for _, line := range lines {
			if err := runner.check(line); err != nil {
				t.Errorf("%s: %q: %v", file, line, err)
			}
		}
	}
}

// TestCommandRunnerDetectsBadLines makes sure the check above can fail.
func TestCommandRunnerDetectsBadLines(t *testing.T) {
	runner := newCommandRunner(t)
	for _, line := range []string{
		"llmaudit requests list --bogus",
		"llmaudit requests lists",
		"llmaudit config show --kind nope",
		"llmaudit requests export 12345 --what everything --out x.json",
		"llmaudit requests get",
		"llmaudit analysis session 0123 --pack",
		"llmaudit config set --kind content-rule --set api_key=x",
		"llmaudit apply <unknown>",
	} {
		if runner.check(line) == nil {
			t.Errorf("%q passed the check", line)
		}
	}
	if err := runner.check("llmaudit requests list --since 2h"); err != nil {
		t.Fatalf("a valid line failed: %v", err)
	}
}

// fakeFacade answers every facade request successfully: reads with a
// read envelope, exports with content, everything else with a plain success.
func fakeFacade(writer http.ResponseWriter, request *http.Request) {
	_, _ = io.Copy(io.Discard, request.Body)
	writer.Header().Set(agentapi.HeaderLatest, agentapi.LatestVersion)
	writer.Header().Set(agentapi.HeaderMin, agentapi.MinVersion)
	switch {
	case strings.Contains(request.URL.Path, "/export/"):
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(writer, "exported content")
	case request.Method == http.MethodGet:
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"ok":true,"data":{"items":[],"next_cursor":""},"meta":{"state":"ok","complete":true,"incomplete_reason":""}}`)
	case strings.HasSuffix(request.URL.Path, "/test-model"):
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"ok":true,"data":{"ok":true}}`)
	default:
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"ok":true,"data":{"plan_id":"pln_1","applied":true}}`)
	}
}

func TestShellWords(t *testing.T) {
	words, err := shellWords(`llmaudit config set --set-json keywords='["a b"]' --set "x=y z"`)
	if err != nil || strings.Join(words, "|") != `llmaudit|config|set|--set-json|keywords=["a b"]|--set|x=y z` {
		t.Fatalf("%q, %v", words, err)
	}
	for _, line := range []string{"llmaudit a; rm", "llmaudit $(x)", "llmaudit 'open", "llmaudit *.json"} {
		if _, err := shellWords(line); err == nil {
			t.Errorf("%q accepted", line)
		}
	}
}
