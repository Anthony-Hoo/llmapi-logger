package agentcli

import (
	"errors"
	"fmt"
)

// CheckCommand parses one command line (without the program name) exactly
// as Run does, including the route choice that depends on flag values, and
// sends nothing. A help request is a valid command line. It exists for the
// tests: every command written into a hint, next_actions, notice or plan
// effect must be one this client accepts (doc/features/25-agent-access.md
// section 12). Such a command is read by someone whose local state the
// writer does not know, so it must also carry the flags a command needs in
// some state (StateFlags: login's --server before anything is saved).
func CheckCommand(args []string) error {
	inv, err := parse(&Env{}, args)
	var help *errHelp
	if errors.As(err, &help) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, name := range inv.spec.StateFlags {
		if !inv.has(name) {
			return usageError("--"+name, fmt.Sprintf("`llmaudit %s` without --%s fails when nothing is saved locally", inv.spec.name(), name))
		}
	}
	_, err = inv.route()
	return err
}
