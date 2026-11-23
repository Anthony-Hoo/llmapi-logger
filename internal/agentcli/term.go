package agentcli

import (
	"errors"
	"os"
	"os/signal"
)

// Terminal is standard input seen as a terminal. It is the only way an API
// key enters the client: there is no flag, environment variable or file for
// it. Tests replace it; the real one is NewTerminal.
type Terminal interface {
	// IsInteractive reports whether standard input is an interactive
	// terminal (not a pipe, file or null device).
	IsInteractive() bool
	// ReadLineNoEcho reads one line with echo turned off and restores the
	// terminal afterwards. The line ending is not included.
	ReadLineNoEcho() ([]byte, error)
}

// NewTerminal wraps a file, normally os.Stdin. The platform files implement
// isTerminal and disableEcho with the syscall package.
func NewTerminal(file *os.File) Terminal {
	return fileTerminal{file: file}
}

type fileTerminal struct{ file *os.File }

func (terminal fileTerminal) IsInteractive() bool {
	return terminal.file != nil && isTerminal(terminal.file.Fd())
}

const maxSecretLine = 64 << 10

var errInterrupted = errors.New("interrupted")

func (terminal fileTerminal) ReadLineNoEcho() ([]byte, error) {
	if !terminal.IsInteractive() {
		return nil, errors.New("not a terminal")
	}
	restore, err := disableEcho(terminal.file.Fd())
	if err != nil {
		return nil, err
	}
	defer restore()
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	type lineResult struct {
		line []byte
		err  error
	}
	done := make(chan lineResult, 1)
	go func() {
		line, err := readLine(terminal.file)
		done <- lineResult{line, err}
	}()
	select {
	case result := <-done:
		return result.line, result.err
	case <-interrupts:
		// The deferred restore turns echo back on before the caller exits.
		return nil, errInterrupted
	}
}

// wipe overwrites a secret once it is no longer needed.
func wipe(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

// readLine reads up to a newline one byte at a time, so nothing after the
// line is consumed; a trailing CR is dropped.
func readLine(file *os.File) ([]byte, error) {
	var line []byte
	var buffer [1]byte
	for {
		count, err := file.Read(buffer[:])
		if count == 1 {
			if buffer[0] == '\n' {
				break
			}
			if len(line) >= maxSecretLine {
				wipe(line)
				return nil, errors.New("line too long")
			}
			line = append(line, buffer[0])
		}
		if err != nil {
			if len(line) > 0 {
				break
			}
			return nil, err
		}
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	return line, nil
}
