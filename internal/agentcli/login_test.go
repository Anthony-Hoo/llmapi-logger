package agentcli

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

// tokenServer answers the code exchange: it checks the verifier against the
// challenge the browser saw and returns testToken.
func tokenServer(t *testing.T, wantCode string, challenge *string) *fakeServer {
	return newFakeServer(t, func(writer http.ResponseWriter, request *http.Request, body []byte) {
		var exchange map[string]string
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		if request.URL.Path != agentapi.PathPrefix+"/token" || request.Method != "POST" || request.Header.Get("Authorization") != "" ||
			decoder.Decode(&exchange) != nil || len(exchange) != 2 || exchange["code"] != wantCode ||
			pkceChallenge(exchange["code_verifier"]) != *challenge || len(exchange["code_verifier"]) < 43 {
			failWith(agentapi.CodeInvalidGrant)(writer, request, body)
			return
		}
		respondJSON(200, `{"ok":true,"data":{"token":"`+testToken+`","role":"admin","tier":"write","expires_at":"2030-01-01T00:00:00Z"}}`)(writer, request, body)
	})
}

type browserVisit struct {
	params url.Values
}

// browser returns an OpenBrowser that records the URL and runs act.
func browser(t *testing.T, server string, visit *browserVisit, act func(port string, state string)) func(string) error {
	return func(target string) error {
		parsed, err := url.Parse(target)
		if err != nil || !strings.HasPrefix(target, server+"/ui/?") {
			t.Errorf("authorize URL %q", target)
			return nil
		}
		visit.params = parsed.Query()
		go act(visit.params.Get("port"), visit.params.Get("state"))
		return nil
	}
}

func callback(t *testing.T, port, path, query string) int {
	// Errors are not reported: a callback may race the end of the wait.
	response, err := http.Get("http://127.0.0.1:" + port + path + "?" + query)
	if err != nil {
		return 0
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	return response.StatusCode
}

func assertTokenNotPrinted(t *testing.T, h *harness) {
	t.Helper()
	if strings.Contains(h.stdout.String(), testToken) || strings.Contains(h.stderr.String(), testToken) {
		t.Fatalf("the token was printed: stdout %q stderr %q", h.stdout.String(), h.stderr.String())
	}
}

func TestLoginLoopback(t *testing.T) {
	var challenge string
	server := tokenServer(t, "the-code", &challenge)
	h := newHarness(t)
	visit := &browserVisit{}
	statuses := make(chan []int, 1)
	h.env.OpenBrowser = browser(t, server.URL, visit, func(port, state string) {
		challenge = visit.params.Get("challenge")
		statuses <- []int{
			callback(t, port, "/other", "code=x&state="+url.QueryEscape(state)),
			callback(t, port, "/callback", "code=stolen&state=wrong"),
			callback(t, port, "/callback", "code=the-code&state="+url.QueryEscape(state)),
		}
	})
	exit := h.run("login", "--server", server.URL+"/", "--device", "laptop\x07 one")
	if exit != 0 {
		t.Fatalf("exit %d stderr %q", exit, h.stderr.String())
	}
	got := <-statuses
	if got[0] != http.StatusNotFound || got[1] != http.StatusBadRequest || got[2] != http.StatusOK {
		t.Fatalf("callback statuses %v", got)
	}
	params := visit.params
	port := params.Get("port")
	if params.Get("agent_authorize") != "1" || params.Get("mode") != "" || params.Get("device") != "laptop one" ||
		params.Get("cli") != Version || params.Get("tier") != "" || len(params.Get("challenge")) != 43 || params.Get("state") == "" || port == "" {
		t.Fatalf("authorize params %v", params)
	}
	if !strings.Contains(h.stderr.String(), server.URL+"/ui/?") {
		t.Fatalf("the URL was not printed: %q", h.stderr.String())
	}
	assertTokenNotPrinted(t, h)
	envelope := h.success()
	var data map[string]any
	_ = json.Unmarshal(envelope["data"], &data)
	if _, has := data["token"]; has || data["role"] != "admin" || data["server"] != server.URL || data["credentials_saved"] != true {
		t.Fatalf("login data %v", data)
	}
	creds, err := loadCredentials(h.env, true)
	if err != nil || creds.Token != testToken || creds.Server != server.URL || creds.ExpiresAt != "2030-01-01T00:00:00Z" {
		t.Fatalf("credentials %+v %v", creds, err)
	}
	if strings.Contains(h.stderr.String(), "warning") {
		t.Fatalf("loopback server got the plain-HTTP warning: %q", h.stderr.String())
	}
	// The listener is closed after login.
	if _, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second); err == nil {
		t.Fatal("the callback listener is still open")
	}
}

func TestLoginWriteAndDefaults(t *testing.T) {
	var challenge string
	server := tokenServer(t, "c2", &challenge)
	h := newHarness(t)
	visit := &browserVisit{}
	h.env.OpenBrowser = browser(t, server.URL, visit, func(port, state string) {
		challenge = visit.params.Get("challenge")
		callback(t, port, "/callback", "code=c2&state="+url.QueryEscape(state))
	})
	h.saveLogin(server.URL) // a previous login supplies the server
	if exit := h.run("login", "--write"); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	if visit.params.Get("tier") != "write" || visit.params.Get("device") != "test-host" {
		t.Fatalf("params %v", visit.params)
	}
	if !strings.Contains(h.stdout.String(), `"requested_tier":"write"`) {
		t.Fatalf("stdout %s", h.stdout.String())
	}
	h2 := newHarness(t)
	h2.expectFailure(h2.run("login"), agentapi.CodeInvalidArgument, 2)
}

func TestLoginDenied(t *testing.T) {
	challenge := ""
	server := tokenServer(t, "x", &challenge)
	h := newHarness(t)
	visit := &browserVisit{}
	h.env.OpenBrowser = browser(t, server.URL, visit, func(port, state string) {
		callback(t, port, "/callback", "error=access_denied&state=other")
		callback(t, port, "/callback", "error=access_denied&state="+url.QueryEscape(state))
	})
	h.expectFailure(h.run("login", "--server", server.URL), agentapi.CodeLoginDenied, 4)
	if len(server.recorded()) != 0 {
		t.Fatal("a denied login exchanged a code")
	}
	if _, err := loadCredentials(h.env, true); err == nil {
		t.Fatal("credentials saved after denial")
	}
}

func TestLoginTimeout(t *testing.T) {
	challenge := ""
	server := tokenServer(t, "x", &challenge)
	h := newHarness(t)
	h.env.LoginTimeout = 300 * time.Millisecond
	visit := &browserVisit{}
	h.env.OpenBrowser = browser(t, server.URL, visit, func(port, _ string) {
		callback(t, port, "/callback", "code=x&state=wrong")
	})
	started := time.Now()
	h.expectFailure(h.run("login", "--server", server.URL), agentapi.CodeLoginTimeout, 4)
	if time.Since(started) > 5*time.Second {
		t.Fatal("the timeout was not honoured")
	}
	if (&Env{}).loginTimeout() != 5*time.Minute {
		t.Fatal("the default login wait must be 5 minutes")
	}
}

func TestLoginPasteMode(t *testing.T) {
	var challenge string
	server := tokenServer(t, "pasted-code", &challenge)
	h := newHarness(t)
	h.env.OpenBrowser = func(string) error { t.Error("paste mode opened a browser"); return nil }
	reader, writer := io.Pipe()
	h.env.Stdin = reader
	go func() {
		// Wait for the URL, then "paste" the code shown by the page.
		for !strings.Contains(h.stderrSnapshot(), "/ui/?") {
			time.Sleep(10 * time.Millisecond)
		}
		parsed, _ := url.Parse(strings.Fields(h.stderrSnapshot()[strings.Index(h.stderrSnapshot(), "http"):])[0])
		challenge = parsed.Query().Get("challenge")
		if parsed.Query().Get("mode") != "paste" || parsed.Query().Get("port") != "" {
			t.Errorf("paste URL %s", parsed)
		}
		_, _ = io.WriteString(writer, "\n   pasted-code  \n")
	}()
	h.env.Stderr = &lockedBuffer{buffer: &h.stderr}
	exit := Run([]string{"login", "--server", server.URL, "--no-browser"}, h.env)
	if exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	assertTokenNotPrinted(t, h)
	if creds, err := loadCredentials(h.env, true); err != nil || creds.Token != testToken {
		t.Fatalf("credentials %v", err)
	}

	// End of input without a code.
	h2 := newHarness(t)
	h2.env.Stdin = strings.NewReader("\n\n")
	h2.expectFailure(h2.run("login", "--server", server.URL, "--no-browser"), agentapi.CodeNoTTY, 2)
	// A wrong code is INVALID_GRANT from the server.
	h3 := newHarness(t)
	h3.env.Stdin = strings.NewReader("wrong\n")
	h3.expectFailure(h3.run("login", "--server", server.URL, "--no-browser"), agentapi.CodeInvalidGrant, 4)
}

// TestPlainHTTPWarning: only a non-loopback http:// server gets the warning.
func TestPlainHTTPWarning(t *testing.T) {
	var challenge string
	server := tokenServer(t, "c", &challenge)
	listener := server.Listener.Addr().String()
	h := newHarness(t)
	h.env.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, listener)
	}
	visit := &browserVisit{}
	h.env.OpenBrowser = browser(t, "http://audit.example.com", visit, func(port, state string) {
		challenge = visit.params.Get("challenge")
		callback(t, port, "/callback", "code=c&state="+url.QueryEscape(state))
	})
	if exit := h.run("login", "--server", "http://audit.example.com"); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	if strings.Count(h.stderr.String(), "warning: the server address uses plain HTTP") != 1 {
		t.Fatalf("stderr %q", h.stderr.String())
	}
	for _, server := range []string{"https://audit.example.com", "http://127.0.0.1:8080", "http://localhost", "http://[::1]:9"} {
		if !strings.HasPrefix(server, "https") && !isLoopbackHost(server) {
			t.Errorf("%s should be loopback", server)
		}
	}
	if isLoopbackHost("http://192.0.2.10") || isLoopbackHost("http://audit.example.com") {
		t.Error("non-loopback host reported as loopback")
	}
}

func TestNormalizeServer(t *testing.T) {
	cases := map[string]string{
		"https://audit.example.com":            "https://audit.example.com",
		"https://audit.example.com/":           "https://audit.example.com",
		"https://audit.example.com/audit/":     "https://audit.example.com/audit",
		"http://192.0.2.10:8080":               "http://192.0.2.10:8080",
		" https://audit.example.com/prefix/x ": "https://audit.example.com/prefix/x",
	}
	for input, want := range cases {
		if got, err := normalizeServer(input); err != nil || got != want {
			t.Errorf("%q: got %q %v, want %q", input, got, err, want)
		}
	}
	for _, bad := range []string{"", "audit.example.com", "ftp://audit.example.com", "https://u:p@audit.example.com", "https://audit.example.com/?a=1", "https://audit.example.com/#f", "https://"} {
		if _, err := normalizeServer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// lockedBuffer lets a goroutine read stderr while the command writes it.
type lockedBuffer struct {
	buffer interface {
		Write([]byte) (int, error)
		String() string
	}
}

var stderrMutex = make(chan struct{}, 1)

func (locked *lockedBuffer) Write(data []byte) (int, error) {
	stderrMutex <- struct{}{}
	defer func() { <-stderrMutex }()
	return locked.buffer.Write(data)
}

func (h *harness) stderrSnapshot() string {
	stderrMutex <- struct{}{}
	defer func() { <-stderrMutex }()
	return h.stderr.String()
}

func TestStateDirectory(t *testing.T) {
	h := newHarness(t)
	dir, err := h.env.stateDir()
	if err != nil || dir != h.home {
		t.Fatalf("LLMAUDIT_HOME: %q %v", dir, err)
	}
	home := t.TempDir()
	env := &Env{Getenv: func(string) string { return "" }, HomeDir: func() (string, error) { return home, nil }}
	if dir, err := env.stateDir(); err != nil || dir != filepath.Join(home, ".llmaudit") {
		t.Fatalf("default: %q %v", dir, err)
	}
	// config.json: a CA file that does not exist is a local file error.
	if err := os.MkdirAll(h.home, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(h.home, configFile), `{"ca_file":"`+filepath.ToSlash(filepath.Join(t.TempDir(), "missing.pem"))+`"}`)
	h.saveLogin("https://audit.example.com")
	h.expectFailure(h.run("whoami"), agentapi.CodeLocalFileError, 1)
	writeFile(t, filepath.Join(h.home, configFile), `{"unknown":1}`)
	h.expectFailure(h.run("whoami"), agentapi.CodeLocalFileError, 1)
}
