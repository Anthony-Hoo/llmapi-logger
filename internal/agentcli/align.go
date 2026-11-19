package agentcli

import "errors"

// CheckCommand parses one command line (without the program name) exactly
// as Run does, including the route choice that depends on flag values, and
// sends nothing. A help request is a valid command line. It exists for the
// server's tests: every command written into a hint, next_actions or plan
// effect must be one this client accepts (doc/features/25-agent-access.md
// section 12).
func CheckCommand(args []string) error {
	inv, err := parse(&Env{}, args)
	var help *errHelp
	if errors.As(err, &help) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = inv.route()
	return err
}
