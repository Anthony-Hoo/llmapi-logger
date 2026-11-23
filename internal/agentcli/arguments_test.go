package agentcli

import (
	"errors"
	"testing"

	"llmapi-logger/internal/agentapi"
)

func commandByName(t *testing.T, name string) *commandSpec {
	t.Helper()
	for _, spec := range allCommands() {
		if spec.name() == name {
			return spec
		}
	}
	t.Fatalf("no command %q", name)
	return nil
}

// Every query parameter, path segment and body field a read command sends
// has a command-line name, so a refused one can always be named as typed.
func TestEveryReadParameterHasACommandLineName(t *testing.T) {
	for _, spec := range allCommands() {
		if !readCommand(spec) {
			continue
		}
		for _, route := range Routes() {
			if route.Command != spec.name() {
				continue
			}
			names := append(append([]string{}, route.Query...), route.Body...)
			for _, segment := range splitPath(route.Path) {
				if len(segment) > 2 && segment[0] == '{' {
					names = append(names, segment[1:len(segment)-1])
				}
			}
			for _, wire := range names {
				if argumentName(spec, wire) == "" {
					t.Errorf("%s: %s has no command-line name", spec.name(), wire)
				}
			}
		}
	}
}

func splitPath(path string) []string {
	var segments []string
	start := 0
	for index := 0; index <= len(path); index++ {
		if index == len(path) || path[index] == '/' {
			if index > start {
				segments = append(segments, path[start:index])
			}
			start = index + 1
		}
	}
	return segments
}

func TestRenameArgumentOnlyForServerReadErrors(t *testing.T) {
	failure := func() *cliError {
		return &cliError{Code: agentapi.CodeInvalidArgument, Status: 400, Message: "`since` cannot be combined with `from`; give only one of them",
			Details: map[string]any{"field": "since", "reason": "conflicts_with_other_argument", "conflicts_with": "from"}}
	}
	read := failure()
	renameArgument(commandByName(t, "requests list"), read)
	if read.Details["field"] != "--since" || read.Details["conflicts_with"] != "--from" || read.Details["parameter"] != "since" ||
		read.Message != "`--since` cannot be combined with `--from`; give only one of them" {
		t.Fatalf("read command: %+v", read)
	}
	positional := &cliError{Code: agentapi.CodeInvalidArgument, Status: 400, Message: "`id` must be a tree_id", Details: map[string]any{"field": "id", "reason": "invalid_format"}}
	renameArgument(commandByName(t, "usage tree"), positional)
	if positional.Details["field"] != "<tree>" || positional.Message != "`<tree>` must be a tree_id" {
		t.Fatalf("positional: %+v", positional)
	}
	// A write command keeps the settable field names of the plan.
	write := &cliError{Code: agentapi.CodeInvalidArgument, Status: 400, Details: map[string]any{"field": "kind"}}
	renameArgument(commandByName(t, "config set"), write)
	if write.Details["field"] != "kind" {
		t.Fatalf("write command renamed: %+v", write)
	}
	// A local usage error is already in the client's names.
	local := &cliError{Code: agentapi.CodeInvalidArgument, Details: map[string]any{"field": "--since"}}
	renameArgument(commandByName(t, "requests list"), local)
	if local.Details["parameter"] != nil {
		t.Fatalf("local error renamed: %+v", local)
	}
}

// Every local INVALID_ARGUMENT carries details.field and details.reason too.
func TestLocalUsageErrorsNameFieldAndReason(t *testing.T) {
	h := newHarness(t)
	for _, test := range []struct {
		args          []string
		field, reason string
	}{
		{[]string{"nosuchcommand"}, "command", "unknown_command"},
		{[]string{"usage", "tree"}, "arguments", "wrong_argument_count"},
		{[]string{"requests", "list", "--bogus"}, "--bogus", "unknown_flag"},
		{[]string{"requests", "list", "--since"}, "--since", "missing_value"},
		{[]string{"requests", "list", "--since", "1d", "--since", "2d"}, "--since", "repeated_parameter"},
		{[]string{"config", "show"}, "--kind", "required"},
		{[]string{"config", "show", "--kind", "bogus"}, "--kind", "not_allowed_value"},
		{[]string{"requests", "list", "--no-collapse=maybe"}, "--no-collapse", "not_allowed_value"},
		{[]string{"requests", "get", ".."}, "<id>", "invalid_format"},
		{[]string{"analysis", "session", "0123", "--pack", "--facet"}, "--pack", "required"},
	} {
		body := h.expectFailure(h.run(test.args...), agentapi.CodeInvalidArgument, agentapi.ExitInvalidUsage)
		if body.Details["field"] != test.field || body.Details["reason"] != test.reason {
			t.Errorf("%v: details %v, want field %q reason %q", test.args, body.Details, test.field, test.reason)
		}
	}
}

// TestRepeatedBooleanFlagIsRefused: a command's boolean flag given twice is
// refused whatever its values, so --write --write=false or --clear
// --clear=false never keeps one of them silently; a single --flag=false still
// means false (contract section 0.1 item 181).
func TestRepeatedBooleanFlagIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{
		{"login", "--server", "https://audit.example.com", "--write", "--write=false"},
		{"login", "--server", "https://audit.example.com", "--write=false", "--write"},
		{"login", "--server", "https://audit.example.com", "--write", "-write"},
		{"login", "--server", "https://audit.example.com", "--write=false", "--write=false"},
	} {
		inv, err := parse(h.env, args)
		var failure *cliError
		if !errors.As(err, &failure) || failure.Code != agentapi.CodeInvalidArgument || failure.Details["field"] != "--write" || failure.Details["reason"] != "repeated_parameter" {
			t.Errorf("%v: invocation %v error %v", args, inv != nil, err)
		}
	}
	if inv, err := parse(h.env, []string{"login", "--server", "https://audit.example.com", "--write=false"}); err != nil || inv.has("write") {
		t.Fatalf("single --write=false: error %v", err)
	}
	// The global --pretty keeps "the last one wins".
	if inv, err := parse(h.env, []string{"whoami", "--pretty", "--pretty=false"}); err != nil || inv.pretty {
		t.Fatalf("repeated --pretty: error %v", err)
	}

	server := newFakeServer(t, nil)
	h.saveLogin(server.URL)
	h.terminal.interactive = true
	h.terminal.secret = "sk-test-not-a-key"
	for _, args := range [][]string{
		{"config", "set-key", "--kind", "analysis-settings", "--clear", "--clear=false"},
		{"config", "set-key", "--kind", "analysis-settings", "--clear=false", "--clear"},
	} {
		body := h.expectFailure(h.run(args...), agentapi.CodeInvalidArgument, agentapi.ExitInvalidUsage)
		if body.Details["field"] != "--clear" || body.Details["reason"] != "repeated_parameter" {
			t.Errorf("%v: details %v", args, body.Details)
		}
	}
	if requests := server.recorded(); len(requests) != 0 {
		t.Fatalf("a repeated --clear reached the server: %+v", requests)
	}
	// A single --clear=false sets the key from the terminal; nothing is cleared.
	if exit := h.run("config", "set-key", "--kind", "analysis-settings", "--clear=false"); exit != 0 {
		t.Fatalf("--clear=false: exit %d %s", exit, h.stderr.String())
	}
	if requests := server.recorded(); len(requests) != 1 || requests[0].Method != "PUT" || h.terminal.reads != 1 {
		t.Fatalf("--clear=false requests %+v reads %d", requests, h.terminal.reads)
	}
}

// A refused element of a repeatable flag keeps its position: rules[1].pattern
// of config preview-project becomes --rule with details.index 1, the
// server's name stays in details.parameter, and the message names the
// second --rule.
func TestRenameArgumentKeepsTheIndex(t *testing.T) {
	for _, test := range []struct {
		wire, message string
		index         int
		want          string
	}{
		{"rules[0].pattern", "`rules[0].pattern` must not be empty", 0, "the first `--rule` (its pattern) must not be empty"},
		{"rules[1].pattern", "`rules[1].pattern` is not a valid glob", 1, "the second `--rule` (its pattern) is not a valid glob"},
		{"rules[11]", "`rules[11]` is not <kind>:<pattern>", 11, "`--rule` number 12 is not <kind>:<pattern>"},
	} {
		failure := &cliError{Code: agentapi.CodeInvalidArgument, Status: 400, Message: test.message,
			Details: map[string]any{"field": test.wire, "reason": "invalid_format"}}
		renameArgument(commandByName(t, "config preview-project"), failure)
		if failure.Details["field"] != "--rule" || failure.Details["index"] != test.index || failure.Details["parameter"] != test.wire ||
			failure.Message != test.want {
			t.Errorf("%s: %+v %q", test.wire, failure.Details, failure.Message)
		}
	}
	// A field without an index has none.
	plain := &cliError{Code: agentapi.CodeInvalidArgument, Status: 400, Message: "`group_id` is required", Details: map[string]any{"field": "group_id"}}
	renameArgument(commandByName(t, "config preview-project"), plain)
	if _, ok := plain.Details["index"]; ok || plain.Details["field"] != "--group-id" {
		t.Fatalf("plain field: %+v", plain.Details)
	}
}
