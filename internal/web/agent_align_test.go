package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentcli"
	"llmapi-logger/internal/orgreport"
)

// The CLI ↔ server alignment (plan section 12, "对齐"). The CLI was written
// against the contract; these tests hold it to the server that exists:
//
//   - every route a command can call is a registered facade endpoint with the
//     same method, and every query parameter and body field the command can
//     send is one the endpoint's handler reads (agentQueryParams is what each
//     handler checks its query against; agentBodyFields is what the decoders
//     accept);
//   - the other way round, every parameter and field a handler reads can be
//     produced by some command (capability parity);
//   - real CLI invocations against the real handler succeed for every value
//     shape the contract fixes (flat dotted set keys, add/remove lists, rules
//     as {kind, pattern}, string ids and versions, numeric suggestion ids);
//   - every command written into a server hint, next_actions or plan effect
//     parses with the CLI's own parser.
//
// What they cannot prove: that a value the CLI sends is one the server will
// accept for every possible input (only the shapes exercised end to end), or
// that a command in a hint is the right advice.

// endpointsWithoutCommand are facade endpoints no llmaudit command calls,
// with the reason. They are exempt from the parity and unknown-parameter
// checks; the signed package download of phase 5 belongs here (it is fetched
// by the install prompt, not by a command).
var endpointsWithoutCommand = map[string]string{}

// cliSamplePath fills a CLI route's {name} segments.
func cliSamplePath(path string) string {
	segments := strings.Split(path, "/")
	for index, segment := range segments {
		if strings.HasPrefix(segment, "{") {
			segments[index] = "sample1"
		}
	}
	return strings.Join(segments, "/")
}

func TestCLIRoutesMatchTheFacade(t *testing.T) {
	registry := agentapi.NewRegistry(agentapi.Endpoints)
	bodies := agentBodyFields()
	sentQuery := map[string]map[string]bool{}
	sentBody := map[string]map[string]bool{}
	reached := map[string]bool{}
	for _, route := range agentcli.Routes() {
		endpoint, params, ok := registry.Match(route.Method, agentapi.PathPrefix+cliSamplePath(route.Path))
		if !ok {
			t.Errorf("%s: %s %s is not a facade endpoint", route.Command, route.Method, route.Path)
			continue
		}
		if endpoint.ID == "config.show" && !contains(agentapi.ConfigKinds, params["kind"]) {
			t.Errorf("%s: config kind %q is not served", route.Command, params["kind"])
		}
		reached[endpoint.ID] = true
		if sentQuery[endpoint.ID] == nil {
			sentQuery[endpoint.ID], sentBody[endpoint.ID] = map[string]bool{}, map[string]bool{}
		}
		for _, name := range route.Query {
			sentQuery[endpoint.ID][name] = true
			if !contains(agentQueryParams[endpoint.ID], name) {
				t.Errorf("%s sends query parameter %q, which %s does not read", route.Command, name, endpoint.ID)
			}
		}
		for _, name := range route.Body {
			sentBody[endpoint.ID][name] = true
			if !contains(bodies[endpoint.ID], name) {
				t.Errorf("%s sends body field %q, which %s does not accept", route.Command, name, endpoint.ID)
			}
		}
	}
	// Parity: what the server reads, some command can send.
	for _, endpoint := range agentapi.Endpoints {
		if _, exempt := endpointsWithoutCommand[endpoint.ID]; exempt {
			continue
		}
		if !reached[endpoint.ID] {
			t.Errorf("no command calls %s %s (%s)", endpoint.Method, endpoint.Pattern, endpoint.ID)
		}
		for _, name := range agentQueryParams[endpoint.ID] {
			if !sentQuery[endpoint.ID][name] {
				t.Errorf("%s reads query parameter %q but no command sends it", endpoint.ID, name)
			}
		}
		for _, name := range bodies[endpoint.ID] {
			if !sentBody[endpoint.ID][name] {
				t.Errorf("%s accepts body field %q but no command sends it", endpoint.ID, name)
			}
		}
	}
	// The table has exactly one row per endpoint.
	if len(agentQueryParams) != len(agentapi.Endpoints) {
		t.Errorf("agentQueryParams has %d rows for %d endpoints", len(agentQueryParams), len(agentapi.Endpoints))
	}
	for _, endpoint := range agentapi.Endpoints {
		if _, ok := agentQueryParams[endpoint.ID]; !ok {
			t.Errorf("agentQueryParams has no row for %s", endpoint.ID)
		}
	}
	// The preview row is the web route's body type.
	var preview []string
	for _, field := range reflect.VisibleFields(reflect.TypeOf(orgreport.PreviewInput{})) {
		preview = append(preview, strings.Split(field.Tag.Get("json"), ",")[0])
	}
	sort.Strings(preview)
	listed := append([]string(nil), bodies["config.project-preview"]...)
	sort.Strings(listed)
	if !reflect.DeepEqual(preview, listed) {
		t.Errorf("preview body fields %v, PreviewInput has %v", listed, preview)
	}
}

// Every handler checks its query string: a parameter outside its row is
// refused with the parameter named, before anything else.
func TestEveryFacadeEndpointRefusesUnknownParameters(t *testing.T) {
	// Optional modules are checked before parameters (section 0.1 item 26),
	// so reads go to the read fixture, which has every module on.
	writes, reads := newWriteFixture(t), newReadFixture(t)
	for _, endpoint := range agentapi.Endpoints {
		if _, exempt := endpointsWithoutCommand[endpoint.ID]; exempt {
			continue
		}
		path := agentapi.PathPrefix + cliSamplePath(strings.ReplaceAll(endpoint.Pattern, "{kind}", "ua-rule")) + "?zz_unknown=1"
		env, token := writes.agentEnv, writes.adminWrite
		if endpoint.Tier == agentapi.TierRead {
			env, token = reads.agentEnv, reads.adminRead
		}
		response := env.do(endpoint.Method, path, "{}", agentCaller{bearer: token})
		body := decodeAgent(t, response)
		if body.OK || body.Error.Code != agentapi.CodeInvalidArgument || body.Error.Details["field"] != "zz_unknown" {
			t.Errorf("%s %s with an unknown parameter = %d %s", endpoint.Method, endpoint.Pattern, response.Code, response.Body.String())
		}
	}
}

// cliRunner runs the real CLI against a fixture's handler.
type cliRunner struct {
	t        *testing.T
	env      *agentcli.Env
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	terminal *keyTerminal
}

// keyTerminal is an interactive terminal where the user types key.
type keyTerminal struct {
	key string
}

func (terminal *keyTerminal) IsInteractive() bool { return true }

func (terminal *keyTerminal) ReadLineNoEcho() ([]byte, error) { return []byte(terminal.key), nil }

func newCLIRunner(t *testing.T, fixture *writeFixture, token string) *cliRunner {
	t.Helper()
	server := httptest.NewServer(fixture.handler)
	t.Cleanup(server.Close)
	home := t.TempDir()
	credentials, _ := json.Marshal(map[string]string{"server": server.URL, "token": token, "expires_at": "2030-01-01T00:00:00Z", "role": "admin", "tier": "write"})
	if err := os.WriteFile(filepath.Join(home, "credentials.json"), credentials, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &cliRunner{t: t, terminal: &keyTerminal{}}
	runner.env = &agentcli.Env{
		Stdin: strings.NewReader(""), Stdout: &runner.stdout, Stderr: &runner.stderr,
		Getenv: func(name string) string {
			if name == "LLMAUDIT_HOME" {
				return home
			}
			return ""
		},
		HomeDir:          func() (string, error) { return "", errors.New("not used") },
		Hostname:         func() (string, error) { return "test-host", nil },
		UTCOffsetMinutes: func() int { return 0 },
		Terminal:         runner.terminal,
	}
	return runner
}

// run runs one command, requires exit 0 and returns data.
func (runner *cliRunner) run(args ...string) map[string]any {
	runner.t.Helper()
	runner.stdout.Reset()
	runner.stderr.Reset()
	if exit := agentcli.Run(args, runner.env); exit != 0 {
		runner.t.Fatalf("llmaudit %s = exit %d: %s", strings.Join(args, " "), exit, runner.stderr.String())
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(runner.stdout.Bytes(), &envelope); err != nil {
		runner.t.Fatalf("llmaudit %s printed %q", strings.Join(args, " "), runner.stdout.String())
	}
	return envelope.Data
}

// plan runs a plan-creating command and applies the plan with `apply`.
func (runner *cliRunner) planAndApply(args ...string) map[string]any {
	runner.t.Helper()
	plan := runner.run(args...)
	id, _ := plan["plan_id"].(string)
	if !strings.HasPrefix(id, "pln_") {
		runner.t.Fatalf("llmaudit %s printed no plan: %v", strings.Join(args, " "), plan)
	}
	return runner.run("apply", id)
}

// The value shapes of contract section 0.1 (F.2), end to end: the real CLI
// against the real handler.
func TestRealCLIAgainstTheFacade(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	cli := newCLIRunner(t, fixture, fixture.adminWrite)

	// Flat dotted set keys and numbers.
	cli.planAndApply("config", "set", "--kind", "analysis-settings", "--set", "llm.model=cli-model", "--set", "llm.max_concurrency=2", "--set", "run_at=05:30")
	settings := fixture.show(t, "analysis-settings")["settings"].(map[string]any)
	if llm := settings["llm"].(map[string]any); llm["model"] != "cli-model" || llm["max_concurrency"] != float64(2) || settings["run_at"] != "05:30" {
		t.Fatalf("analysis settings = %v", settings)
	}
	// add/remove lists and a string expected version.
	version := item(t, fixture.show(t, "content-rule"), "items", "id", ids.contentRule)["version"].(string)
	cli.planAndApply("config", "set", "--kind", "content-rule", "--id", ids.contentRule, "--add", "keywords=gamma", "--remove", "keywords=beta", "--if-version", version)
	if keywords := item(t, fixture.show(t, "content-rule"), "items", "id", ids.contentRule)["keywords_untrusted"]; !jsonEqual(keywords, []string{"alpha", "gamma"}) {
		t.Fatalf("keywords = %v", keywords)
	}
	// Project rules as {kind, pattern}, a create with group_id null and a JSON list.
	cli.planAndApply("config", "set", "--kind", "project", "--id", ids.project, "--add", "rules=repo_url:git.example.com/team/demo")
	created := cli.planAndApply("config", "set", "--kind", "project", "--set", "name=cli project", "--set", "group_id=null", "--set", "enabled=true", "--set-json", `rules=[{"kind":"repo_name","pattern":"cli"}]`)
	if project := item(t, fixture.show(t, "org"), "projects", "id", created["id"].(string)); project == nil || project["group_id"] != nil {
		t.Fatalf("created project = %v (%v)", project, created)
	}
	cli.planAndApply("config", "set", "--kind", "member", "--id", "7", "--set", "group_id="+ids.otherGroup)
	cli.planAndApply("config", "set", "--kind", "principal", "--id", "user:7", "--set", "class=human")
	uaVersion := item(t, fixture.show(t, "ua-rule"), "items", "id", ids.uaRule)["version"].(string)
	cli.planAndApply("config", "remove", "--kind", "ua-rule", "--id", ids.uaRule, "--if-version", uaVersion)
	cli.planAndApply("config", "reset", "--kind", "analysis-settings")
	cli.run("config", "preview-project", "--group-id", ids.group, "--rule", "repo_name:demo")
	// Operations: a numeric suggestion id, a week, labels from a file.
	if plan := cli.run("analysis", "dismiss", "42"); plan["target"].(map[string]any)["id"] != "42" {
		t.Fatalf("dismiss plan = %v", plan)
	}
	cli.planAndApply("weekly", "regenerate", "--week", "2026-11-02")
	labels := filepath.Join(t.TempDir(), "labels.json")
	if err := os.WriteFile(labels, []byte(`{"labels":[{"session_id":"`+analysisOwnID+`","task_type":"feature"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cli.planAndApply("analysis", "calibrate", "--file", labels)
	cli.planAndApply("analysis", "run")
	cli.run("analysis", "test-model", "--set", "llm.model=probe")
	// The key typed at the no-echo prompt, with the characters the CLI must
	// escape by hand.
	saved, unsaved := `sk-"typed"\key-0042`, `probe"only\key-0043`
	cli.terminal.key = saved
	if set := cli.run("config", "set-key", "--kind", "analysis-settings"); set["api_key"] != "saved" {
		t.Fatalf("set-key = %v", set)
	}
	cli.run("analysis", "test-model")
	if !fixture.model.sawKey(saved) {
		t.Fatal("the model did not receive the key typed for set-key")
	}
	cli.terminal.key = unsaved
	cli.run("analysis", "test-model", "--prompt-key", "--set", "llm.model=probe")
	if !fixture.model.sawKey(unsaved) {
		t.Fatal("the model did not receive the key typed for --prompt-key")
	}
	if strings.Contains(cli.stdout.String()+cli.stderr.String()+fixture.logs.String(), "key-004") {
		t.Fatal("a typed key appears in the CLI output or the server log")
	}
	if cleared := cli.run("config", "set-key", "--kind", "analysis-settings", "--clear"); cleared["api_key"] != "none" {
		t.Fatalf("clear = %v", cleared)
	}
	cli.run("whoami")
}

// dynamicSamples are example values for the non-constant parts of server
// strings that contain a command. A new dynamic part fails the test until it
// has a sample here.
var dynamicSamples = map[string]string{
	"request.Kind": "ua-rule",
	"state.Week":   "2026-11-02",
	"stored.ID":    "pln_example",
	"strings.Join(agentTestModelBodyFields, \", \")": "set, api_key",
	"nearest.Format(orgreport.WeekLayout)":           "2026-11-02",
}

// serverCommandTexts returns every string the server code of internal/web
// and internal/agentapi builds that holds a command: the backquoted
// `llmaudit …` parts of hints, next_actions and effects, and the plain
// "llmaudit …" verify commands.
func serverCommandTexts(t *testing.T) map[string]string {
	t.Helper()
	texts := map[string]string{}
	for _, dir := range []string{".", "../agentapi"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		fileSet := token.NewFileSet()
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fileSet, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			var evaluate func(ast.Expr) (string, bool)
			evaluate = func(expr ast.Expr) (string, bool) {
				switch typed := expr.(type) {
				case *ast.BasicLit:
					if typed.Kind != token.STRING {
						return "", false
					}
					text, err := strconv.Unquote(typed.Value)
					return text, err == nil
				case *ast.BinaryExpr:
					if typed.Op != token.ADD {
						return "", false
					}
					left, leftOK := evaluate(typed.X)
					right, rightOK := evaluate(typed.Y)
					return left + right, leftOK && rightOK
				case *ast.ParenExpr:
					return evaluate(typed.X)
				}
				source := types.ExprString(expr)
				if sample, ok := dynamicSamples[source]; ok {
					return sample, true
				}
				return "\x00" + source + "\x00", true
			}
			ast.Inspect(file, func(node ast.Node) bool {
				expr, ok := node.(ast.Expr)
				if !ok {
					return true
				}
				if _, isLiteral := expr.(*ast.BasicLit); !isLiteral {
					if _, isBinary := expr.(*ast.BinaryExpr); !isBinary {
						return true
					}
				}
				text, ok := evaluate(expr)
				if !ok || !strings.Contains(text, "llmaudit ") {
					return true
				}
				texts[text] = fileSet.Position(expr.Pos()).String()
				return false
			})
		}
	}
	return texts
}

// commandsIn extracts the commands of one server string.
func commandsIn(text string) []string {
	if strings.HasPrefix(text, "llmaudit ") {
		return []string{text}
	}
	var commands []string
	parts := strings.Split(text, "`")
	for index := 1; index < len(parts); index += 2 {
		if strings.HasPrefix(parts[index], "llmaudit ") {
			commands = append(commands, parts[index])
		}
	}
	return commands
}

func TestServerCommandsParseWithTheCLI(t *testing.T) {
	texts := serverCommandTexts(t)
	checked := 0
	for text, position := range texts {
		if strings.Contains(text, "\x00") {
			t.Errorf("%s: %q has a dynamic part without a sample in dynamicSamples", position, text)
			continue
		}
		for _, command := range commandsIn(text) {
			checked++
			args := strings.Fields(strings.TrimPrefix(command, "llmaudit "))
			if err := agentcli.CheckCommand(args); err != nil {
				t.Errorf("%s: `%s` does not parse: %v", position, command, err)
			}
		}
	}
	// The scan sees the hints it must see, so it is not vacuous.
	if checked < 20 {
		t.Fatalf("only %d commands found; the scan is probably broken", checked)
	}
	for _, want := range []string{"llmaudit login", "llmaudit apply pln_example", "llmaudit config show --kind ua-rule", "llmaudit weekly report --week 2026-11-02"} {
		found := false
		for text := range texts {
			for _, command := range commandsIn(text) {
				found = found || command == want
			}
		}
		if !found {
			t.Errorf("scan missed %q", want)
		}
	}
}

// The commands in plans and apply results as the server actually writes
// them, for every kind: next_actions and effects.
func TestPlanAndApplyTextsParseWithTheCLI(t *testing.T) {
	fixture := newWriteFixture(t)
	ids := fixture.seed(t)
	check := func(response *httptest.ResponseRecorder) {
		t.Helper()
		var envelope struct {
			Data struct {
				Effects []string `json:"effects"`
			} `json:"data"`
			NextActions []string `json:"next_actions"`
			Error       *struct {
				Hint string `json:"hint"`
			} `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &envelope)
		texts := append(append([]string{}, envelope.Data.Effects...), envelope.NextActions...)
		if envelope.Error != nil {
			texts = append(texts, envelope.Error.Hint)
		}
		for _, text := range texts {
			for _, command := range commandsIn(text) {
				if err := agentcli.CheckCommand(strings.Fields(strings.TrimPrefix(command, "llmaudit "))); err != nil {
					t.Errorf("`%s` does not parse: %v", command, err)
				}
			}
		}
	}
	for _, body := range []map[string]any{
		{"op": "config.set", "kind": "ua-rule", "id": ids.uaRule, "set": map[string]any{"enabled": false}},
		{"op": "config.set", "kind": "content-rule", "id": ids.contentRule, "set": map[string]any{"enabled": false}},
		{"op": "config.set", "kind": "project", "id": ids.project, "set": map[string]any{"enabled": false}},
		{"op": "config.set", "kind": "weekly-settings", "set": map[string]any{"idle_gap_seconds": 60}},
		{"op": "config.set", "kind": "analysis-settings", "set": map[string]any{"llm.model": "other"}},
		{"op": "config.remove", "kind": "ua-rule", "id": ids.uaRule},
		{"op": "config.reset", "kind": "weekly-settings"},
		{"op": "analysis.run"},
		{"op": "weekly.regenerate", "args": map[string]any{"week": "2026-11-02"}},
		{"op": "analysis.dismiss", "args": map[string]any{"suggestion_id": 9}},
	} {
		response := fixture.facade(http.MethodPost, "/plans", body, fixture.adminWrite)
		check(response)
		var plan struct {
			Data struct {
				PlanID string `json:"plan_id"`
			} `json:"data"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &plan)
		check(fixture.facade(http.MethodPost, "/plans/"+plan.Data.PlanID+"/apply", nil, fixture.adminWrite))
	}
	check(fixture.facade(http.MethodPut, "/config/analysis-settings/api-key", map[string]any{"api_key": plantedModelKey}, fixture.adminWrite))
}
