// Package archivecli is the stand-alone reader of the cold archive,
// audit-archive (doc/design/issue-59-stage4-cold-archive.md section K). It
// reads an archive directory through its manifests only: it never connects to
// a database and links no store (a test checks its dependencies). Every
// bundle is fully verified before anything is read from it, and everything
// it prints comes from the bundle through the query layer's plaintext half,
// with credentials only in their projected form: the archive holds no
// credential value, so no flag can print one. cmd/audit-archive is its thin
// command.
package archivecli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"llmapi-logger/internal/termio"
)

// Env is everything the tool takes from its surroundings, so tests can
// replace it.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Terminal is standard input as a terminal, for fpr's no-echo read.
	Terminal termio.Terminal
}

// DefaultEnv is the real process environment.
func DefaultEnv() *Env {
	return &Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Terminal: termio.NewTerminal(os.Stdin)}
}

// Main runs the tool with the real environment and returns the exit code.
func Main(ctx context.Context, args []string) int {
	return Run(ctx, args, DefaultEnv())
}

// command is one sub-command.
type command struct {
	name    string
	summary string
	usage   string
	help    string
	run     func(ctx context.Context, env *Env, args []string) error
}

func commands() []command {
	return []command{
		{"list", "list the bundles, their conversations and time ranges", listUsage, listHelp, runList},
		{"verify", "verify one bundle or the whole archive directory", verifyUsage, verifyHelp, runVerify},
		{"cat", "print decrypted archive lines (JSON Lines)", catUsage, catHelp, runCat},
		{"export", "export one audit or one conversation in the single-audit export forms", exportUsage, exportHelp, runExport},
		{"fpr", "print the fingerprints of a known API key and find it in the archive", fprUsage, fprHelp, runFpr},
	}
}

// Run executes one command line and returns the exit code.
func Run(ctx context.Context, args []string, env *Env) int {
	if env == nil {
		env = DefaultEnv()
	}
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, topHelp())
		return ExitUsage
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		fmt.Fprint(env.Stdout, topHelp())
		return ExitOK
	}
	for _, cmd := range commands() {
		if cmd.name != args[0] {
			continue
		}
		err := cmd.run(ctx, env, args[1:])
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(env.Stdout, commandHelp(cmd))
			return ExitOK
		}
		return report(env, err)
	}
	fmt.Fprintf(env.Stderr, "audit-archive: usage: unknown command %q\n\n%s", printable(args[0]), topHelp())
	return ExitUsage
}

// report prints a failure on standard error and returns its exit code.
func report(env *Env, err error) int {
	if err == nil {
		return ExitOK
	}
	var exit *exitStatus
	if errors.As(err, &exit) {
		return exit.code
	}
	code, message := describe(err)
	fmt.Fprintf(env.Stderr, "audit-archive: %s: %s\n", code, message)
	if code == codeUsage {
		fmt.Fprintln(env.Stderr, "Run \"audit-archive <command> --help\" for its flags.")
	}
	return exitCode(code)
}

// exitStatus ends a command whose result and diagnostics are already
// printed (verify, or cat after skipping a bundle) with an exit code.
type exitStatus struct{ code int }

func (status *exitStatus) Error() string { return fmt.Sprintf("exit status %d", status.code) }

func usageError(format string, arguments ...any) error {
	return &cliError{code: codeUsage, message: fmt.Sprintf(format, arguments...)}
}

// flagSet is a flag set that reports errors as usage errors and --help as
// flag.ErrHelp.
func flagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	return flags
}

func parseFlags(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		// Only the flag's name is repeated, never a value.
		message := err.Error()
		switch {
		case strings.HasPrefix(message, "flag provided but not defined: "):
			return usageError("unknown flag %s", printable(strings.TrimPrefix(message, "flag provided but not defined: ")))
		case strings.HasPrefix(message, "flag needs an argument: "):
			return usageError("%s needs a value", printable(strings.TrimPrefix(message, "flag needs an argument: ")))
		default:
			return usageError("invalid flag value")
		}
	}
	if flags.NArg() > 0 {
		return usageError("unexpected argument %q; every input is a flag", printable(flags.Arg(0)))
	}
	return nil
}

// common holds the flags several commands share.
type common struct {
	dir             string
	keyPath         string
	unauthenticated bool
	skipEventMAC    bool
}

func (c *common) archiveFlags(flags *flag.FlagSet) {
	flags.StringVar(&c.dir, "dir", "", "")
	flags.StringVar(&c.keyPath, "key", "", "")
}

func (c *common) readFlags(flags *flag.FlagSet) {
	c.archiveFlags(flags)
	flags.BoolVar(&c.unauthenticated, "unauthenticated", false, "")
	flags.BoolVar(&c.skipEventMAC, "skip-event-mac", false, "")
}

func (c *common) requireDir() error {
	if c.dir == "" {
		return usageError("--dir <archive directory> is required")
	}
	return nil
}

// keys loads the master key file when --key was given.
func (c *common) keys() (*Keys, error) {
	if c.keyPath == "" {
		return nil, nil
	}
	return LoadKeys(c.keyPath)
}

// openReader opens the reader for cat and export: with --key, or with
// --unauthenticated (and then says so on standard error).
func (c *common) openReader(ctx context.Context, env *Env) (*Reader, error) {
	if err := c.requireDir(); err != nil {
		return nil, err
	}
	keys, err := c.keys()
	if err != nil {
		return nil, err
	}
	if keys == nil && !c.unauthenticated {
		return nil, &cliError{code: codeKeyRequired, message: messages[codeKeyRequired]}
	}
	reader, err := OpenReader(ctx, c.dir, ReaderOptions{Keys: keys, Unauthenticated: c.unauthenticated, SkipEventMAC: c.skipEventMAC})
	if err != nil {
		return nil, err
	}
	if keys == nil {
		fmt.Fprintln(env.Stderr, "audit-archive: warning: --unauthenticated: manifest signatures are not checked and the output is not authenticated; encrypted bundles cannot be read")
	} else if c.skipEventMAC {
		fmt.Fprintln(env.Stderr, "audit-archive: warning: --skip-event-mac: the copied integrity events' MACs are not checked")
	}
	for _, problem := range reader.Index().Problems() {
		fmt.Fprintf(env.Stderr, "audit-archive: skipped %s: %s\n", c.relative(problem.Path), problemText(problem))
	}
	return reader, nil
}

// relative shows a path under the archive directory relative to it, with
// forward slashes; the directory is the one the user passed.
func (c *common) relative(path string) string {
	if c.dir != "" {
		if relative, err := filepath.Rel(c.dir, path); err == nil && !strings.HasPrefix(relative, "..") {
			return filepath.ToSlash(relative)
		}
	}
	return path
}

// printable quotes text from audited traffic or the command line when it
// holds anything but printable ASCII without spaces.
func printable(text string) string {
	for _, r := range text {
		if r <= ' ' || r > '~' || r == '"' || r == '\\' {
			return fmt.Sprintf("%q", text)
		}
	}
	return text
}

// output buffers standard output; a failed write is write_failed.
type output struct {
	writer *bufio.Writer
	err    error
}

func newOutput(destination io.Writer) *output {
	return &output{writer: bufio.NewWriterSize(destination, 64<<10)}
}

func (out *output) Write(data []byte) (int, error) {
	if out.err != nil {
		return 0, out.err
	}
	n, err := out.writer.Write(data)
	if err != nil {
		out.err = &cliError{code: codeWriteFailed, message: messages[codeWriteFailed]}
		return n, out.err
	}
	return n, nil
}

func (out *output) line(data []byte) error {
	if _, err := out.Write(data); err != nil {
		return err
	}
	_, err := out.Write([]byte{'\n'})
	return err
}

func (out *output) printf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(out, format, arguments...)
}

func (out *output) flush() error {
	if out.err != nil {
		return out.err
	}
	if err := out.writer.Flush(); err != nil {
		out.err = &cliError{code: codeWriteFailed, message: messages[codeWriteFailed]}
	}
	return out.err
}
