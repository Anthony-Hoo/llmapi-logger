package agentcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"llmapi-logger/internal/agentapi"
)

// Env is everything the client takes from its surroundings, so tests can
// replace it. A nil field falls back to the real process environment.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Getenv reads LLMAUDIT_HOME.
	Getenv   func(string) string
	HomeDir  func() (string, error)
	Hostname func() (string, error)
	// Terminal is standard input as a terminal: the only source of an API key.
	Terminal Terminal
	// OpenBrowser opens the authorization page.
	OpenBrowser func(string) error
	Now         func() time.Time
	// LoginTimeout bounds the wait for the browser or the pasted code.
	LoginTimeout time.Duration
	// DialContext replaces the network dialer (and disables proxies).
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	// UTCOffsetMinutes is the default of --tz-offset-min.
	UTCOffsetMinutes func() int
}

// DefaultEnv is the real process environment.
func DefaultEnv() *Env {
	return &Env{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Getenv: os.Getenv, HomeDir: os.UserHomeDir, Hostname: os.Hostname,
		Terminal:    NewTerminal(os.Stdin),
		OpenBrowser: openBrowser,
		Now:         time.Now,
	}
}

func (env *Env) now() time.Time {
	if env.Now != nil {
		return env.Now()
	}
	return time.Now()
}

func (env *Env) loginTimeout() time.Duration {
	if env.LoginTimeout > 0 {
		return env.LoginTimeout
	}
	return loginWait
}

// loginWait is how long login waits for the browser approval or the pasted
// code; the help, the description and the hints quote it.
const loginWait = 5 * time.Minute

// loginWaitText is loginWait in words, for hints.
const loginWaitText = "5 minutes"

func (env *Env) utcOffsetMinutes() int {
	if env.UTCOffsetMinutes != nil {
		return env.UTCOffsetMinutes()
	}
	_, seconds := env.now().Zone()
	return seconds / 60
}

func (env *Env) getenv(name string) string {
	if env.Getenv != nil {
		return env.Getenv(name)
	}
	return os.Getenv(name)
}

// stateDir is $LLMAUDIT_HOME or ~/.llmaudit.
func (env *Env) stateDir() (string, error) {
	if dir := env.getenv("LLMAUDIT_HOME"); dir != "" {
		return filepath.Abs(dir)
	}
	home := env.HomeDir
	if home == nil {
		home = os.UserHomeDir
	}
	dir, err := home()
	if err != nil || dir == "" {
		return "", &cliError{Code: agentapi.CodeLocalFileError, Message: "cannot find the home directory; set LLMAUDIT_HOME"}
	}
	return filepath.Join(dir, ".llmaudit"), nil
}

// Main runs the client with the real environment and returns the exit code.
func Main(args []string) int {
	return Run(args, DefaultEnv())
}

// result is a successful command: the envelope for stdout and its exit code
// (0, or 6 when the operation ran but failed).
type result struct {
	envelope *serverEnvelope
	exit     int
	server   string // for web_url
}

// cliError is a failure envelope. Status is the HTTP status of a server
// error and zero for a local one.
type cliError struct {
	Code    agentapi.Code
	Message string
	Hint    string
	Details map[string]any
	Status  int
}

func (err *cliError) Error() string { return string(err.Code) + ": " + err.Message }

func internalError(message string) *cliError {
	return &cliError{Code: agentapi.CodeInternal, Message: "llmaudit internal error: " + message}
}

// exitCode follows the shared error table. A code the table does not know as
// a server code falls back on the HTTP status.
func (err *cliError) exitCode() int {
	spec, known := agentapi.Lookup(err.Code)
	if err.Status == 0 {
		return spec.ExitCode
	}
	if known && !spec.Local {
		return spec.ExitCode
	}
	switch err.Status {
	case 400:
		return agentapi.ExitInvalidUsage
	case 401:
		return agentapi.ExitUnauthorized
	case 403:
		return agentapi.ExitForbidden
	}
	return agentapi.ExitError
}

// Run executes one command line and returns the exit code.
func Run(args []string, env *Env) int {
	if env == nil {
		env = DefaultEnv()
	}
	inv, err := parse(env, args)
	if err != nil {
		var help *errHelp
		if errors.As(err, &help) {
			switch {
			case help.spec != nil:
				fmt.Fprint(env.Stdout, commandHelp(help.spec))
			case help.group != "":
				fmt.Fprint(env.Stdout, groupHelp(help.group))
			default:
				fmt.Fprint(env.Stdout, topHelp())
			}
			return agentapi.ExitOK
		}
		return writeFailure(env, pretty(args), asCLIError(err))
	}
	outcome, err := inv.spec.Run(inv)
	if err != nil {
		failure := asCLIError(err)
		renameArgument(inv.spec, failure)
		return writeFailure(env, inv.pretty, failure)
	}
	if err := writeSuccess(env, inv.pretty, outcome, inv.spec.Columns); err != nil {
		return writeFailure(env, inv.pretty, asCLIError(err))
	}
	return outcome.exit
}

// pretty is the --pretty a command line that did not parse asked for, so
// that its failure is rendered as asked: every form (--pretty, -pretty,
// --pretty=true|false, -pretty=…), the last valid one winning.
func pretty(args []string) bool {
	set := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if isPrettyFlag(arg) {
			if value, err := prettyValue(arg); err == nil {
				set = value
			}
		}
	}
	return set
}

func asCLIError(err error) *cliError {
	var coded *cliError
	if errors.As(err, &coded) {
		return coded
	}
	return internalError("unexpected error")
}

// outEnvelope is the success envelope as printed.
type outEnvelope struct {
	OK          bool            `json:"ok"`
	Data        json.RawMessage `json:"data"`
	Meta        json.RawMessage `json:"meta,omitempty"`
	NextActions []string        `json:"next_actions,omitempty"`
	WebPath     string          `json:"web_path,omitempty"`
	WebURL      string          `json:"web_url,omitempty"`
	Notice      string          `json:"notice,omitempty"`
}

func writeSuccess(env *Env, prettyOutput bool, outcome *result, columns []string) error {
	source := outcome.envelope
	envelope := outEnvelope{OK: true, Data: source.Data, Meta: source.Meta, WebPath: source.WebPath, Notice: source.Notice}
	for _, action := range source.NextActions {
		envelope.NextActions = append(envelope.NextActions, maskTokens(action))
	}
	if source.WebPath != "" && outcome.server != "" && len(source.WebPath) > 0 && source.WebPath[0] == '/' {
		envelope.WebURL = strings.TrimRight(outcome.server, "/") + source.WebPath
	}
	if prettyOutput {
		_, err := io.WriteString(env.Stdout, renderPrettySuccess(envelope, columns))
		return err
	}
	encoded, err := encodeJSON(envelope)
	if err != nil {
		return internalError("cannot encode the output")
	}
	_, _ = env.Stdout.Write(encoded)
	return nil
}

func writeFailure(env *Env, prettyOutput bool, err *cliError) int {
	spec, _ := agentapi.Lookup(err.Code)
	message, hint := err.Message, err.Hint
	if message == "" {
		message = spec.Message
	}
	if hint == "" {
		hint = spec.Hint
	}
	body := agentapi.ErrorBody{Code: err.Code, Message: maskTokens(message), Hint: maskTokens(hint), Details: err.Details}
	if len(body.Details) == 0 {
		body.Details = nil
	}
	envelope := agentapi.ErrorEnvelope{OK: false, Error: body}
	if prettyOutput {
		_, _ = io.WriteString(env.Stderr, renderPrettyFailure(body))
	} else if encoded, encodeErr := encodeJSON(envelope); encodeErr == nil {
		_, _ = env.Stderr.Write(encoded)
	}
	return err.exitCode()
}

// encodeJSON encodes compactly without HTML escaping, so raw data passes
// through byte for byte (after compaction), followed by a newline.
func encodeJSON(value any) ([]byte, error) {
	var buffer bytesBuffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.data, nil
}

type bytesBuffer struct{ data []byte }

func (buffer *bytesBuffer) Write(data []byte) (int, error) {
	buffer.data = append(buffer.data, data...)
	return len(data), nil
}
