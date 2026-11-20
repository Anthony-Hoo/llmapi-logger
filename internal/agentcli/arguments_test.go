package agentcli

import (
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
