package agentcli

import (
	"strings"

	"llmapi-logger/internal/agentapi"
)

// The server names a refused argument by its wire name: the query
// parameter, path segment or body field (details.field, and
// details.conflicts_with or details.alternatives for the other arguments
// involved; contract section 0.1 item 115). The user of this client typed a
// flag or a positional argument, so for a read command the client rewrites
// those names into the flag (--group-by) or argument (<session>) of the
// command, keeps the server's name in details.parameter, and rewrites the
// backticked names in the message the same way. Write commands keep the
// server's names: their fields are the settable field names the plan uses.

// argumentName is the command-line name of the wire parameter, or "" when
// the command has none (an unknown parameter, the body as a whole).
func argumentName(spec *commandSpec, wire string) string {
	base := wire
	if cut := strings.IndexAny(wire, "[."); cut > 0 {
		base = wire[:cut]
	}
	for _, arg := range spec.Args {
		if arg.PathParam == base || arg.Body == base {
			return "<" + arg.Name + ">"
		}
	}
	for _, flag := range spec.Flags {
		if flag.Query == base || flag.Body == base || flag.PathParam == base {
			return "--" + flag.Name
		}
	}
	// A path segment the command fills through Select (config show --kind).
	for _, flag := range spec.Flags {
		if flag.Name == strings.ReplaceAll(base, "_", "-") {
			return "--" + flag.Name
		}
	}
	return ""
}

// readCommand reports whether every route of spec is a read (or an export).
// A route whose result carries meta is still not a read when its endpoint
// needs the write tier (the connection test): its refused fields are the
// settable names of the settings, not flags of the command.
func readCommand(spec *commandSpec) bool {
	if len(spec.Routes) == 0 {
		return false
	}
	for _, route := range spec.Routes {
		if !route.Meta && !route.Raw {
			return false
		}
		if endpoint, _, ok := endpointRegistry.Match(route.Method, agentapi.PathPrefix+route.Path); ok && endpoint.Tier != agentapi.TierRead {
			return false
		}
	}
	return true
}

var endpointRegistry = agentapi.NewRegistry(agentapi.Endpoints)

// renameArgument rewrites a server INVALID_ARGUMENT of a read command into
// the command's own names.
func renameArgument(spec *commandSpec, failure *cliError) {
	if spec == nil || failure == nil || failure.Status == 0 || failure.Code != agentapi.CodeInvalidArgument || !readCommand(spec) {
		return
	}
	wire, ok := failure.Details["field"].(string)
	if !ok || wire == "" {
		return
	}
	name := argumentName(spec, wire)
	if name == "" {
		return
	}
	details := make(map[string]any, len(failure.Details)+1)
	for key, value := range failure.Details {
		details[key] = value
	}
	details["field"] = name
	details["parameter"] = wire
	message := renameInMessage(failure.Message, wire, name)
	if other, ok := details["conflicts_with"].(string); ok {
		if renamed := argumentName(spec, other); renamed != "" {
			details["conflicts_with"] = renamed
			message = renameInMessage(message, other, renamed)
		}
	}
	if alternatives, ok := details["alternatives"].([]any); ok {
		renamed := make([]any, 0, len(alternatives))
		for _, alternative := range alternatives {
			text, _ := alternative.(string)
			if cli := argumentName(spec, text); cli != "" {
				renamed = append(renamed, cli)
				message = renameInMessage(message, text, cli)
				continue
			}
			renamed = append(renamed, alternative)
		}
		details["alternatives"] = renamed
	}
	failure.Details = details
	failure.Message = message
}

// renameInMessage replaces the backticked wire name in message.
func renameInMessage(message, wire, name string) string {
	return strings.ReplaceAll(message, "`"+wire+"`", "`"+name+"`")
}
