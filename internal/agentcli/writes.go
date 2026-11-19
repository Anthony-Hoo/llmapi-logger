package agentcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"llmapi-logger/internal/agentapi"
)

var decimalPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// scalarValue is the --set rule: true/false are booleans, decimal numbers
// are numbers, null is JSON null, anything else is a string.
func scalarValue(raw string) any {
	switch raw {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	if decimalPattern.MatchString(raw) {
		return json.Number(raw)
	}
	return raw
}

func splitAssignment(flag, value string) (string, string, error) {
	field, raw, ok := strings.Cut(value, "=")
	if !ok || strings.TrimSpace(field) == "" {
		return "", "", usageError("--"+flag, fmt.Sprintf("--%s takes <field>=<value>", flag))
	}
	if err := refuseKeyField(field); err != nil {
		return "", "", err
	}
	return field, raw, nil
}

// refuseKeyField keeps the API key out of every value a command line or
// file can carry: it only enters through the no-echo terminal prompt.
func refuseKeyField(field string) error {
	if strings.EqualFold(strings.TrimSpace(field), "api_key") {
		return &cliError{Code: agentapi.CodeInvalidArgument, Message: "api_key cannot be given as a value; nothing was sent",
			Hint:    "Ask the user to run `llmaudit config set-key --kind analysis-settings` themselves in a terminal.",
			Details: map[string]any{"field": "api_key"}}
	}
	return nil
}

// strictJSON decodes exactly one JSON value.
func strictJSON(data []byte) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	return value, nil
}

func parseRule(flag, value string) (map[string]any, error) {
	kind, pattern, ok := strings.Cut(value, ":")
	if !ok || kind == "" {
		return nil, usageError("--"+flag, fmt.Sprintf("--%s takes a rule as <kind>:<pattern>", flag))
	}
	return map[string]any{"kind": kind, "pattern": pattern}, nil
}

// setValues merges --set, --set-json and --patch-file in command-line order;
// a later occurrence of a field replaces an earlier one.
func setValues(inv *invocation) (map[string]any, error) {
	set := map[string]any{}
	for _, given := range inv.ordered("set", "set-json", "patch-file") {
		switch given.flag.Name {
		case "set":
			field, raw, err := splitAssignment("set", given.value)
			if err != nil {
				return nil, err
			}
			set[field] = scalarValue(raw)
		case "set-json":
			field, raw, err := splitAssignment("set-json", given.value)
			if err != nil {
				return nil, err
			}
			value, err := strictJSON([]byte(raw))
			if err != nil {
				return nil, usageError("--set-json", fmt.Sprintf("--set-json %s: the value is not one valid JSON value", field))
			}
			set[field] = value
		case "patch-file":
			data, err := os.ReadFile(given.value)
			if err != nil {
				return nil, localFileError("cannot read the --patch-file file", map[string]any{"field": "--patch-file", "path": given.value})
			}
			value, err := strictJSON(data)
			var fields map[string]json.RawMessage
			if err != nil || json.Unmarshal(value, &fields) != nil || fields == nil {
				return nil, usageError("--patch-file", "--patch-file must hold one JSON object whose keys are field names")
			}
			for field, raw := range fields {
				if err := refuseKeyField(field); err != nil {
					return nil, err
				}
				set[field] = raw
			}
		}
	}
	return set, nil
}

// listChanges collects --add or --remove as {field: [values]}.
func listChanges(inv *invocation, flag string) (map[string]any, error) {
	changes := map[string][]any{}
	for _, value := range inv.values(flag) {
		field, raw, err := splitAssignment(flag, value)
		if err != nil {
			return nil, err
		}
		var element any = raw
		if field == "rules" {
			rule, err := parseRule(flag, raw)
			if err != nil {
				return nil, err
			}
			element = rule
		}
		changes[field] = append(changes[field], element)
	}
	if len(changes) == 0 {
		return nil, nil
	}
	result := make(map[string]any, len(changes))
	for field, values := range changes {
		result[field] = values
	}
	return result, nil
}

// planBody builds the POST /plans body of a plan-creating command.
func planBody(inv *invocation, op string) (map[string]any, error) {
	body := map[string]any{"op": op}
	args := map[string]any{}
	switch op {
	case "config.set":
		body["kind"] = inv.value("kind")
		if inv.has("id") {
			body["id"] = inv.value("id")
		}
		set, err := setValues(inv)
		if err != nil {
			return nil, err
		}
		if len(set) > 0 {
			body["set"] = set
		}
		for _, flag := range []string{"add", "remove"} {
			changes, err := listChanges(inv, flag)
			if err != nil {
				return nil, err
			}
			if changes != nil {
				body[flag] = changes
			}
		}
		if inv.has("if-version") {
			body["expected_version"] = inv.value("if-version")
		}
	case "config.remove":
		body["kind"], body["id"] = inv.value("kind"), inv.value("id")
		if inv.has("if-version") {
			body["expected_version"] = inv.value("if-version")
		}
	case "config.reset":
		body["kind"] = inv.value("kind")
	case "analysis.run":
	case "analysis.calibrate":
		labels, err := readLabels(inv.value("file"))
		if err != nil {
			return nil, err
		}
		args["labels"] = labels
	case "analysis.dismiss":
		id := inv.arg("suggestion-id")
		if !decimalPattern.MatchString(id) || strings.ContainsAny(id, "-.") {
			return nil, usageError("suggestion-id", "<suggestion-id> must be a positive integer")
		}
		args["suggestion_id"] = json.Number(id)
	case "weekly.regenerate":
		args["week"] = inv.value("week")
	default:
		return nil, internalError("unknown plan op")
	}
	if len(args) > 0 {
		body["args"] = args
	}
	return body, nil
}

// readLabels accepts {"labels": [...]} or a bare array.
func readLabels(path string) (json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, localFileError("cannot read the --file file", map[string]any{"field": "--file", "path": path})
	}
	value, err := strictJSON(data)
	if err != nil {
		return nil, usageError("--file", "--file must hold one JSON value: {\"labels\": [...]} or an array")
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return value, nil
	}
	var wrapper map[string]json.RawMessage
	if json.Unmarshal(value, &wrapper) != nil || len(wrapper) != 1 || wrapper["labels"] == nil {
		return nil, usageError("--file", "--file must hold {\"labels\": [...]} or an array of labels")
	}
	return wrapper["labels"], nil
}

func runPlan(op string) func(*invocation) (*result, error) {
	return func(inv *invocation) (*result, error) {
		body, err := planBody(inv, op)
		if err != nil {
			return nil, err
		}
		c, err := inv.client()
		if err != nil {
			return nil, err
		}
		ctx, cancel := inv.context()
		defer cancel()
		route := &inv.spec.Routes[0]
		envelope, err := c.call(ctx, inv, route, route.Path, nil, body)
		if err != nil {
			return nil, err
		}
		return &result{envelope: envelope, server: c.server}, nil
	}
}

const applyUncertainHint = "Do not apply the plan again: it may have been executed. First check whether the change took effect with the matching read command " +
	"(`llmaudit config show --kind <kind>` for configuration, `llmaudit analysis overview --since 1d` for an analysis run, `llmaudit weekly report --week <week>` for a regenerated week)."

func runApply(inv *invocation) (*result, error) {
	route := &inv.spec.Routes[0]
	path, err := inv.path(route)
	if err != nil {
		return nil, err
	}
	c, err := inv.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := inv.context()
	defer cancel()
	envelope, err := c.call(ctx, inv, route, path, nil, nil)
	if err != nil {
		var cliErr *cliError
		if errors.As(err, &cliErr) && (cliErr.Code == agentapi.CodeTimeout || cliErr.Code == agentapi.CodeNetworkError) {
			cliErr.Hint = applyUncertainHint
		}
		return nil, err
	}
	return &result{envelope: envelope, server: c.server}, nil
}

func runPreview(inv *invocation) (*result, error) {
	body := map[string]any{}
	group := inv.value("group-id")
	switch {
	case group == "null":
		body["group_id"] = nil
	case decimalPattern.MatchString(group) && !strings.Contains(group, "."):
		body["group_id"] = json.Number(group)
	default:
		return nil, usageError("--group-id", "--group-id takes a project group ID or null")
	}
	rules := []any{}
	for _, value := range inv.values("rule") {
		rule, err := parseRule("rule", value)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	body["rules"] = rules
	if inv.has("week") {
		body["week"] = inv.value("week")
	}
	if inv.has("project-id") {
		id := inv.value("project-id")
		if !decimalPattern.MatchString(id) || strings.Contains(id, ".") {
			return nil, usageError("--project-id", "--project-id takes a project ID")
		}
		body["project_id"] = json.Number(id)
	}
	c, err := inv.client()
	if err != nil {
		return nil, err
	}
	ctx, cancel := inv.context()
	defer cancel()
	route := &inv.spec.Routes[0]
	envelope, err := c.call(ctx, inv, route, route.Path, nil, body)
	if err != nil {
		return nil, err
	}
	return &result{envelope: envelope, server: c.server}, nil
}

// readKey reads an API key from the interactive terminal without echo. It
// fails with NO_TTY when standard input is not a terminal: there is no other
// source for a key.
func readKey(inv *invocation, prompt string) ([]byte, error) {
	terminal := inv.env.Terminal
	if terminal == nil || !terminal.IsInteractive() {
		return nil, &cliError{Code: agentapi.CodeNoTTY,
			Hint: "Ask the user to run this command themselves in a terminal; the key is typed by the user and never passed by an agent."}
	}
	fmt.Fprint(inv.env.Stderr, prompt)
	key, err := terminal.ReadLineNoEcho()
	fmt.Fprintln(inv.env.Stderr)
	if err != nil {
		wipe(key)
		return nil, &cliError{Code: agentapi.CodeNoTTY, Message: "could not read the key from the terminal"}
	}
	if len(key) == 0 {
		return nil, usageError("api_key", "the key is empty; nothing was sent")
	}
	return key, nil
}

// bodyWithSecret encodes fields plus "<name>": secret without turning the
// secret into a Go string, so the buffer can be wiped after use.
func bodyWithSecret(fields map[string]any, name string, secret []byte) ([]byte, error) {
	base, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	buffer := make([]byte, 0, len(base)+len(name)+len(secret)*2+8)
	buffer = append(buffer, base[:len(base)-1]...)
	if len(fields) > 0 {
		buffer = append(buffer, ',')
	}
	buffer = append(buffer, '"')
	buffer = append(buffer, name...)
	buffer = append(buffer, '"', ':', '"')
	const hexDigits = "0123456789abcdef"
	for _, char := range secret {
		switch {
		case char == '"' || char == '\\':
			buffer = append(buffer, '\\', char)
		case char < 0x20:
			buffer = append(buffer, '\\', 'u', '0', '0', hexDigits[char>>4], hexDigits[char&0xf])
		default:
			buffer = append(buffer, char)
		}
	}
	return append(buffer, '"', '}'), nil
}

func runSetKey(inv *invocation) (*result, error) {
	if inv.value("kind") != "analysis-settings" {
		return nil, usageError("--kind", "--kind accepts only analysis-settings")
	}
	c, err := inv.client()
	if err != nil {
		return nil, err
	}
	put, remove := &inv.spec.Routes[0], &inv.spec.Routes[1]
	if inv.has("clear") {
		ctx, cancel := inv.context()
		defer cancel()
		envelope, err := c.call(ctx, inv, remove, remove.Path, nil, nil)
		if err != nil {
			return nil, err
		}
		return &result{envelope: envelope, server: c.server}, nil
	}
	if err := inv.checkDeclared(put, nil, []string{"api_key"}); err != nil {
		return nil, err
	}
	key, err := readKey(inv, "API key for the session analysis model (input is hidden): ")
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	body, err := bodyWithSecret(map[string]any{}, "api_key", key)
	if err != nil {
		return nil, internalError("cannot encode the request")
	}
	defer wipe(body)
	ctx, cancel := inv.context()
	defer cancel()
	envelope, err := c.callRaw(ctx, put, put.Path, nil, body)
	if err != nil {
		return nil, err
	}
	return &result{envelope: envelope, server: c.server}, nil
}

func runTestModel(inv *invocation) (*result, error) {
	route := &inv.spec.Routes[0]
	fields := map[string]any{}
	set := map[string]any{}
	for _, value := range inv.values("set") {
		field, raw, err := splitAssignment("set", value)
		if err != nil {
			return nil, err
		}
		set[field] = scalarValue(raw)
	}
	if len(set) > 0 {
		fields["set"] = set
	}
	c, err := inv.client()
	if err != nil {
		return nil, err
	}
	declared := bodyFieldsOf(fields)
	if inv.has("prompt-key") {
		declared = append(declared, "api_key")
	}
	if err := inv.checkDeclared(route, nil, declared); err != nil {
		return nil, err
	}
	var body []byte
	if inv.has("prompt-key") {
		key, err := readKey(inv, "API key to test (input is hidden; it is not saved): ")
		if err != nil {
			return nil, err
		}
		defer wipe(key)
		body, err = bodyWithSecret(fields, "api_key", key)
		if err != nil {
			return nil, internalError("cannot encode the request")
		}
		defer wipe(body)
	} else {
		body, err = json.Marshal(fields)
		if err != nil {
			return nil, internalError("cannot encode the request")
		}
	}
	ctx, cancel := inv.context()
	defer cancel()
	envelope, err := c.callRaw(ctx, route, route.Path, nil, body)
	if err != nil {
		return nil, err
	}
	outcome := &result{envelope: envelope, server: c.server}
	var probe struct {
		OK *bool `json:"ok"`
	}
	if json.Unmarshal(envelope.Data, &probe) == nil && probe.OK != nil && !*probe.OK {
		outcome.exit = agentapi.ExitOperationFails
	}
	return outcome, nil
}
