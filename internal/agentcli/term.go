package agentcli

import (
	"os"

	"llmapi-logger/internal/termio"
)

// Terminal is standard input seen as a terminal. It is the only way an API
// key enters the client: there is no flag, environment variable or file for
// it. Tests replace it; the real one is NewTerminal. The implementation is
// internal/termio, shared with audit-archive.
type Terminal = termio.Terminal

// NewTerminal wraps a file, normally os.Stdin.
func NewTerminal(file *os.File) Terminal {
	return termio.NewTerminal(file)
}

// wipe overwrites a secret once it is no longer needed.
func wipe(data []byte) { termio.Wipe(data) }
