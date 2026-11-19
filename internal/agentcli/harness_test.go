package agentcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"llmapi-logger/internal/agentapi"
)

// testToken has the exact token shape; it is not a real token.
var testToken = agentapi.TokenPrefix + strings.Repeat("A", agentapi.TokenEncodedChars)

type recordedRequest struct {
	Method string
	Path   string
	Query  map[string][]string
	Body   []byte
	Header http.Header
}

type responder func(writer http.ResponseWriter, request *http.Request, body []byte)

type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
	respond  responder
}

func newFakeServer(t *testing.T, respond responder) *fakeServer {
	t.Helper()
	fake := &fakeServer{respond: respond}
	fake.Server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		fake.mu.Lock()
		fake.requests = append(fake.requests, recordedRequest{Method: request.Method, Path: request.URL.EscapedPath(), Query: request.URL.Query(), Body: body, Header: request.Header.Clone()})
		respond := fake.respond
		fake.mu.Unlock()
		writer.Header().Set(agentapi.HeaderLatest, agentapi.LatestVersion)
		writer.Header().Set(agentapi.HeaderMin, agentapi.MinVersion)
		if respond == nil {
			respond = defaultResponder
		}
		respond(writer, request, body)
	}))
	t.Cleanup(fake.Close)
	return fake
}

func (fake *fakeServer) setResponder(respond responder) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.respond = respond
}

func (fake *fakeServer) recorded() []recordedRequest {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]recordedRequest(nil), fake.requests...)
}

func (fake *fakeServer) reset() {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.requests = nil
}

const okMeta = `{"state":"succeeded","complete":true,"incomplete_reason":""}`

// defaultResponder answers a GET with a read result and anything else with
// a plain success.
func defaultResponder(writer http.ResponseWriter, request *http.Request, _ []byte) {
	writer.Header().Set("Content-Type", "application/json")
	if request.Method == http.MethodGet {
		_, _ = io.WriteString(writer, `{"ok":true,"data":{"items":[{"id":1,"name_untrusted":"x"}],"next_cursor":""},"meta":`+okMeta+`}`)
		return
	}
	_, _ = io.WriteString(writer, `{"ok":true,"data":{"plan_id":"pln_1","op":"x"}}`)
}

func failWith(code agentapi.Code) responder {
	return func(writer http.ResponseWriter, _ *http.Request, _ []byte) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(agentapi.HTTPStatus(code))
		envelope, _ := json.Marshal(agentapi.Failure(code, "", "", map[string]any{"field": "x"}))
		_, _ = writer.Write(envelope)
	}
}

func respondJSON(status int, body string) responder {
	return func(writer http.ResponseWriter, _ *http.Request, _ []byte) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, body)
	}
}

// fakeTerminal stands in for stdin as a terminal.
type fakeTerminal struct {
	interactive bool
	secret      string
	reads       int
}

func (terminal *fakeTerminal) IsInteractive() bool { return terminal.interactive }

func (terminal *fakeTerminal) ReadLineNoEcho() ([]byte, error) {
	terminal.reads++
	if !terminal.interactive {
		return nil, errors.New("not a terminal")
	}
	return []byte(terminal.secret), nil
}

type harness struct {
	t        *testing.T
	home     string
	env      *Env
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	terminal *fakeTerminal
	envNames []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, home: filepath.Join(t.TempDir(), "state"), terminal: &fakeTerminal{}}
	h.env = &Env{
		Stdin:  strings.NewReader(""),
		Stdout: &h.stdout,
		Stderr: &h.stderr,
		Getenv: func(name string) string {
			h.envNames = append(h.envNames, name)
			if name == "LLMAUDIT_HOME" {
				return h.home
			}
			return ""
		},
		HomeDir:          func() (string, error) { return "", errors.New("tests never use the real home directory") },
		Hostname:         func() (string, error) { return "test-host", nil },
		Terminal:         h.terminal,
		UTCOffsetMinutes: func() int { return 480 },
	}
	return h
}

func (h *harness) saveLogin(server string) {
	h.t.Helper()
	if err := saveCredentials(h.env, &credentials{Server: server, Token: testToken, ExpiresAt: "2030-01-01T00:00:00Z", Role: "admin", Tier: "write"}); err != nil {
		h.t.Fatalf("save credentials: %v", err)
	}
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	return Run(args, h.env)
}

// success decodes stdout as one success envelope.
func (h *harness) success() map[string]json.RawMessage {
	h.t.Helper()
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(h.stdout.Bytes()))
	if err := decoder.Decode(&envelope); err != nil || decoder.More() {
		h.t.Fatalf("stdout is not one JSON envelope: %q", h.stdout.String())
	}
	if string(envelope["ok"]) != "true" {
		h.t.Fatalf("stdout envelope is not ok: %s", h.stdout.String())
	}
	return envelope
}

// failure decodes stderr as one failure envelope and checks stdout is empty.
func (h *harness) failure() agentapi.ErrorBody {
	h.t.Helper()
	if h.stdout.Len() != 0 {
		h.t.Fatalf("stdout not empty on failure: %q", h.stdout.String())
	}
	lines := strings.Split(strings.TrimRight(h.stderr.String(), "\n"), "\n")
	var envelope struct {
		OK    *bool              `json:"ok"`
		Error agentapi.ErrorBody `json:"error"`
	}
	last := lines[len(lines)-1]
	if err := json.Unmarshal([]byte(last), &envelope); err != nil || envelope.OK == nil || *envelope.OK {
		h.t.Fatalf("stderr does not end with a failure envelope: %q", h.stderr.String())
	}
	return envelope.Error
}

func (h *harness) expectFailure(exit int, code agentapi.Code, wantExit int) agentapi.ErrorBody {
	h.t.Helper()
	body := h.failure()
	if body.Code != code || exit != wantExit {
		h.t.Fatalf("got exit %d code %s, want exit %d code %s; stderr %q", exit, body.Code, wantExit, code, h.stderr.String())
	}
	return body
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
