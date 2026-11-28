package archivecli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeTerminal is an interactive terminal that returns one typed line.
type fakeTerminal struct {
	line  []byte
	reads int
}

func (terminal *fakeTerminal) IsInteractive() bool { return terminal.line != nil }

func (terminal *fakeTerminal) ReadLineNoEcho() ([]byte, error) {
	terminal.reads++
	if terminal.line == nil {
		return nil, errors.New("not a terminal")
	}
	return bytes.Clone(terminal.line), nil
}

// result is one run of the tool.
type result struct {
	exit           int
	stdout, stderr string
}

func runWith(t *testing.T, stdin string, terminal *fakeTerminal, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env := &Env{Stdin: strings.NewReader(stdin), Stdout: &stdout, Stderr: &stderr}
	if terminal != nil {
		env.Terminal = terminal
	} else {
		env.Terminal = &fakeTerminal{}
	}
	exit := Run(context.Background(), args, env)
	out := result{exit: exit, stdout: stdout.String(), stderr: stderr.String()}
	// The credential scan: the archive holds no credential value, so no
	// output of any command, success or failure, may carry one. Every
	// synthetic credential starts with credentialMarker.
	for name, output := range map[string]string{"stdout": out.stdout, "stderr": out.stderr} {
		if strings.Contains(output, credentialMarker) {
			t.Fatalf("%s of %q carries a credential value", name, args)
		}
	}
	return out
}

func run(t *testing.T, args ...string) result {
	t.Helper()
	return runWith(t, "", nil, args...)
}

func (r result) want(t *testing.T, exit int) result {
	t.Helper()
	if r.exit != exit {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.exit, exit, r.stdout, r.stderr)
	}
	return r
}

func (r result) lines() []string {
	trimmed := strings.TrimSuffix(r.stdout, "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}
