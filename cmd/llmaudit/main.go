// Command llmaudit is the agent access command-line client of the audit
// proxy. All logic lives in internal/agentcli.
package main

import (
	"os"

	"llmapi-logger/internal/agentcli"
)

func main() {
	os.Exit(agentcli.Main(os.Args[1:]))
}
