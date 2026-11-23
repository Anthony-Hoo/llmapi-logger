package agentcli

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"llmapi-logger/internal/agentapi"
)

// occurrence is one flag as given on the command line, in order.
type occurrence struct {
	flag  *flagSpec
	value string
}

// invocation is one parsed command line.
type invocation struct {
	env    *Env
	spec   *commandSpec
	given  []occurrence
	args   []string
	pretty bool
	// hasPrettyFlag is set when --pretty was given after the command; it
	// then wins over one given before.
	hasPrettyFlag bool

	// filled while running
	creds *credentials
}

// errHelp asks for the help of a command (or of a group when spec is nil).
type errHelp struct {
	spec  *commandSpec
	group string
}

func (err *errHelp) Error() string { return "help requested" }

// usageError is a local INVALID_ARGUMENT: field names the flag or argument
// as typed, and details.reason is invalid_usage unless a caller sets a more
// specific one (usageErrorWith), so every exit-2 envelope carries both
// (contract section 0.1 item 115).
func usageError(field, message string) *cliError {
	return usageErrorWith(field, "invalid_usage", message)
}

func usageErrorWith(field, reason, message string) *cliError {
	details := map[string]any{"reason": reason}
	if field != "" {
		details["field"] = field
	}
	return &cliError{Code: agentapi.CodeInvalidArgument, Message: message, Hint: "Run `llmaudit --help` or add --help to the command to see its arguments.", Details: details}
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "--help" || arg == "-help"
}

func isGroup(name string) bool {
	for _, group := range groupOrder {
		if group.Name == name {
			return true
		}
	}
	return false
}

// findCommand resolves the command words at the start of args.
func findCommand(commands []*commandSpec, args []string) (*commandSpec, []string, error) {
	if len(args) == 0 || isHelpFlag(args[0]) || args[0] == "help" {
		return nil, nil, &errHelp{}
	}
	for _, spec := range commands {
		if len(args) >= len(spec.Path) && len(spec.Path) == 2 && args[0] == spec.Path[0] && args[1] == spec.Path[1] {
			return spec, args[2:], nil
		}
	}
	for _, spec := range commands {
		if len(spec.Path) == 1 && args[0] == spec.Path[0] {
			return spec, args[1:], nil
		}
	}
	if isGroup(args[0]) {
		if len(args) > 1 && isHelpFlag(args[1]) {
			return nil, nil, &errHelp{group: args[0]}
		}
		// A group alone is not a command (contract section 0.1 item 123): one
		// JSON envelope naming the missing subcommand and the available ones;
		// plain help only for an explicit --help.
		available := groupCommands(commands, args[0])
		failure := usageErrorWith("command", "missing_subcommand", fmt.Sprintf("`llmaudit %s` needs a subcommand: %s", args[0], strings.Join(available, ", ")))
		if len(args) > 1 {
			failure = usageErrorWith("command", "unknown_command", fmt.Sprintf("unknown command %q; `llmaudit %s` has: %s", args[0]+" "+args[1], args[0], strings.Join(available, ", ")))
		}
		failure.Details["available"] = available
		return nil, nil, failure
	}
	var available []string
	for _, spec := range commands {
		if len(spec.Path) == 1 {
			available = append(available, spec.Path[0])
		}
	}
	for _, group := range groupOrder {
		available = append(available, group.Name)
	}
	failure := usageErrorWith("command", "unknown_command", fmt.Sprintf("unknown command %q; the commands and groups are: %s", args[0], strings.Join(available, ", ")))
	failure.Details["available"] = available
	return nil, nil, failure
}

// groupCommands lists the subcommands of group in table order.
func groupCommands(commands []*commandSpec, group string) []string {
	var names []string
	for _, spec := range commands {
		if len(spec.Path) == 2 && spec.Path[0] == group {
			names = append(names, spec.Path[1])
		}
	}
	return names
}

// parse parses a full command line (without the program name). Global flags
// (--pretty in each of its forms) are accepted before the command, between a
// group and its command (llmaudit requests --pretty list), and after the
// command; one after the command wins over one before it.
func parse(env *Env, args []string) (*invocation, error) {
	leadingPretty, args, err := takePretty(false, args)
	if err != nil {
		return nil, err
	}
	if len(args) > 0 && isGroup(args[0]) {
		var rest []string
		if leadingPretty, rest, err = takePretty(leadingPretty, args[1:]); err != nil {
			return nil, err
		}
		args = append([]string{args[0]}, rest...)
	}
	spec, rest, err := findCommand(allCommands(), args)
	if err != nil {
		return nil, err
	}
	inv, err := parseFlags(env, spec, rest)
	if err != nil {
		return nil, err
	}
	if leadingPretty && !inv.hasPrettyFlag {
		inv.pretty = true
	}
	return inv, nil
}

// takePretty consumes the --pretty flags at the start of args; the last one
// wins over current.
func takePretty(current bool, args []string) (bool, []string, error) {
	for len(args) > 0 && isPrettyFlag(args[0]) {
		set, err := prettyValue(args[0])
		if err != nil {
			return false, nil, err
		}
		current = set
		args = args[1:]
	}
	return current, args, nil
}

// prettyValue is the value of one --pretty flag.
func prettyValue(arg string) (bool, error) {
	name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
	return boolValue("--"+name, value, hasValue)
}

// isPrettyFlag reports whether arg is the global --pretty flag in any of
// its forms (--pretty, -pretty, --pretty=true|false).
func isPrettyFlag(arg string) bool {
	name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
	return strings.HasPrefix(arg, "-") && name == "pretty"
}

func isNegativeNumber(arg string) bool {
	if len(arg) < 2 || arg[0] != '-' {
		return false
	}
	for _, char := range arg[1:] {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

// parseFlags accepts flags and positional arguments in any order, flags as
// --name value, --name=value (single dash also works), bool flags as --name
// or --name=true|false. "--" ends the flags. A negative number such as -1 is
// a positional argument.
func parseFlags(env *Env, spec *commandSpec, args []string) (*invocation, error) {
	inv := &invocation{env: env, spec: spec}
	// seenBool records each boolean flag given, false occurrences included:
	// inv.given keeps only the true ones, so it cannot tell that
	// --clear --clear=false repeats --clear.
	seenBool := map[string]bool{}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			inv.args = append(inv.args, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" || isNegativeNumber(arg) {
			inv.args = append(inv.args, arg)
			continue
		}
		name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
		value, hasValue := "", false
		if cut := strings.IndexByte(name, '='); cut >= 0 {
			name, value, hasValue = name[:cut], name[cut+1:], true
		}
		switch name {
		case "h", "help":
			return nil, &errHelp{spec: spec}
		case "pretty":
			pretty, err := boolValue("--pretty", value, hasValue)
			if err != nil {
				return nil, err
			}
			inv.pretty, inv.hasPrettyFlag = pretty, true
			continue
		}
		flag := spec.flag(name)
		if flag == nil {
			return nil, usageErrorWith("--"+name, "unknown_flag", fmt.Sprintf("unknown flag --%s for `llmaudit %s`", name, spec.name()))
		}
		if flag.Kind == boolFlag {
			set, err := boolValue("--"+name, value, hasValue)
			if err != nil {
				return nil, err
			}
			// A boolean flag given twice is refused like a repeated string
			// flag, whatever its values: --write --write=false must not
			// silently keep one of them (contract section 0.1 item 181). The
			// global --pretty, handled above, keeps "the last one wins".
			if seenBool[flag.Name] {
				return nil, usageErrorWith("--"+name, "repeated_parameter", fmt.Sprintf("flag --%s given more than once", name))
			}
			seenBool[flag.Name] = true
			if set {
				inv.given = append(inv.given, occurrence{flag: flag, value: "true"})
			}
			continue
		}
		if !hasValue {
			if index+1 >= len(args) {
				return nil, usageErrorWith("--"+name, "missing_value", fmt.Sprintf("flag --%s needs a value", name))
			}
			index++
			value = args[index]
		}
		if flag.Kind == stringFlag && inv.has(name) {
			return nil, usageErrorWith("--"+name, "repeated_parameter", fmt.Sprintf("flag --%s given more than once", name))
		}
		inv.given = append(inv.given, occurrence{flag: flag, value: value})
	}
	if len(inv.args) != len(spec.Args) {
		names := make([]string, 0, len(spec.Args))
		for _, arg := range spec.Args {
			names = append(names, "<"+arg.Name+">")
		}
		expected := "no positional arguments"
		if len(names) > 0 {
			expected = "exactly " + strings.Join(names, " ")
		}
		failure := usageErrorWith("arguments", "wrong_argument_count", fmt.Sprintf("`llmaudit %s` takes %s; got %d", spec.name(), expected, len(inv.args)))
		failure.Details["expected"] = names
		return nil, failure
	}
	for index, arg := range inv.args {
		if arg == "" || arg == "." || arg == ".." {
			return nil, usageErrorWith("<"+spec.Args[index].Name+">", "invalid_format", fmt.Sprintf("<%s> is not a valid value", spec.Args[index].Name))
		}
	}
	for _, flag := range spec.Flags {
		if flag.Required && !inv.has(flag.Name) {
			return nil, usageErrorWith("--"+flag.Name, "required", fmt.Sprintf("flag --%s is required", flag.Name))
		}
	}
	return inv, nil
}

func boolValue(name, value string, hasValue bool) (bool, error) {
	if !hasValue {
		return true, nil
	}
	switch value {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, usageErrorWith(name, "not_allowed_value", fmt.Sprintf("flag %s takes true or false", name))
}

func (inv *invocation) has(name string) bool {
	for _, given := range inv.given {
		if given.flag.Name == name {
			return true
		}
	}
	return false
}

// value is the last value of a flag.
func (inv *invocation) value(name string) string {
	value := ""
	for _, given := range inv.given {
		if given.flag.Name == name {
			value = given.value
		}
	}
	return value
}

func (inv *invocation) values(name string) []string {
	var values []string
	for _, given := range inv.given {
		if given.flag.Name == name {
			values = append(values, given.value)
		}
	}
	return values
}

// ordered returns the occurrences of the named flags in command-line order.
func (inv *invocation) ordered(names ...string) []occurrence {
	var list []occurrence
	for _, given := range inv.given {
		for _, name := range names {
			if given.flag.Name == name {
				list = append(list, given)
			}
		}
	}
	return list
}

func (inv *invocation) arg(name string) string {
	for index, arg := range inv.spec.Args {
		if arg.Name == name {
			return inv.args[index]
		}
	}
	return ""
}

func (inv *invocation) context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), inv.spec.timeout())
}

func (inv *invocation) route() (*routeSpec, error) {
	if inv.spec.Select != nil {
		return inv.spec.Select(inv)
	}
	return &inv.spec.Routes[0], nil
}

// path fills the route's {name} segments from arguments and flags.
func (inv *invocation) path(route *routeSpec) (string, error) {
	values := map[string]string{}
	for index, arg := range inv.spec.Args {
		if arg.PathParam != "" {
			values[arg.PathParam] = inv.args[index]
		}
	}
	for _, flag := range inv.spec.Flags {
		if flag.PathParam != "" && inv.has(flag.Name) {
			values[flag.PathParam] = inv.value(flag.Name)
		}
	}
	segments := strings.Split(route.Path, "/")
	for index, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			value, ok := values[segment[1:len(segment)-1]]
			if !ok {
				return "", internalError("route parameter without a value")
			}
			segments[index] = url.PathEscape(value)
		}
	}
	return strings.Join(segments, "/"), nil
}

// query builds the query string from the flags that declare a parameter.
func (inv *invocation) query() url.Values {
	query := url.Values{}
	for index := range inv.spec.Flags {
		flag := &inv.spec.Flags[index]
		if flag.Query == "" {
			continue
		}
		switch {
		case inv.has(flag.Name) && flag.Kind == boolFlag:
			query.Set(flag.Query, flag.QueryValue)
		case inv.has(flag.Name):
			query.Set(flag.Query, inv.value(flag.Name))
		case flag.Default != nil:
			query.Set(flag.Query, flag.Default(inv.env))
		}
	}
	return query
}

func selectByFlag(inv *invocation, flag string, pathOf func(string) string) (*routeSpec, error) {
	value := inv.value(flag)
	for index := range inv.spec.Routes {
		if inv.spec.Routes[index].Path == pathOf(value) {
			return &inv.spec.Routes[index], nil
		}
	}
	return nil, usageErrorWith("--"+flag, "not_allowed_value", fmt.Sprintf("--%s %q is not one of the accepted values; see `llmaudit %s --help`", flag, value, inv.spec.name()))
}

func selectConfigShow(inv *invocation) (*routeSpec, error) {
	return selectByFlag(inv, "kind", func(kind string) string { return "/config/" + kind })
}

var exportWhat = []string{"conversation", "headers", "request", "response", "raw-request", "raw-response", "timeline-request", "timeline-response"}

func selectExport(inv *invocation) (*routeSpec, error) {
	what := inv.value("what")
	for _, allowed := range exportWhat {
		if what == allowed {
			return &inv.spec.Routes[0], nil
		}
	}
	return nil, usageErrorWith("--what", "not_allowed_value", fmt.Sprintf("--what %q is not one of %s", what, strings.Join(exportWhat, ", ")))
}

func selectAnalysisSession(inv *invocation) (*routeSpec, error) {
	pack, facet := inv.has("pack"), inv.has("facet")
	switch {
	case pack == facet:
		return nil, usageErrorWith("--pack", "required", "exactly one of --pack or --facet is required")
	case pack && !inv.has("out"):
		return nil, usageErrorWith("--out", "required", "--pack requires --out <file>")
	case pack:
		return &inv.spec.Routes[0], nil
	default:
		return &inv.spec.Routes[1], nil
	}
}
