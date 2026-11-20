package agentcli

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"

	"llmapi-logger/internal/agentapi"
)

// normalizeServer checks a server address: http or https, a host, no user
// info, query or fragment; a path is allowed (a reverse-proxy prefix). The
// result has no trailing slash.
func normalizeServer(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", usageError("--server", "--server must be an http:// or https:// address with a host and no user info, query or fragment")
	}
	return strings.TrimRight(parsed.Scheme+"://"+parsed.Host+parsed.EscapedPath(), "/"), nil
}

// isLoopbackHost reports whether a server host is this machine.
func isLoopbackHost(server string) bool {
	parsed, err := url.Parse(server)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// cleanDeviceName drops control characters and caps the name at 64
// characters, as the server and the page do.
func cleanDeviceName(name string) string {
	name = strings.TrimSpace(strings.Map(func(char rune) rune {
		if unicode.IsControl(char) || unicode.Is(unicode.Cf, char) {
			return -1
		}
		return char
	}, name))
	runes := []rune(name)
	if len(runes) > 64 {
		runes = runes[:64]
	}
	return strings.TrimSpace(string(runes))
}

func randomURLSafe(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

// pkceChallenge is BASE64URL(SHA-256(verifier)) without padding.
func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func runLogin(inv *invocation) (*result, error) {
	env := inv.env
	server := inv.value("server")
	if server == "" {
		creds, err := loadCredentials(env, true)
		var cliErr *cliError
		switch {
		case err == nil:
			server = creds.Server
		case errors.As(err, &cliErr) && cliErr.Code == agentapi.CodeLocalFileError:
			return nil, err
		default:
			return nil, usageError("--server", "--server is required on the first login")
		}
	}
	server, err := normalizeServer(server)
	if err != nil {
		return nil, err
	}
	device := inv.value("device")
	if !inv.has("device") && env.Hostname != nil {
		device, _ = env.Hostname()
	}
	device = cleanDeviceName(device)
	exchange, err := newClient(env, server, "", inv.spec.header())
	if err != nil {
		return nil, err
	}

	verifier, err := randomURLSafe(32)
	if err != nil {
		return nil, internalError("no randomness")
	}
	state, err := randomURLSafe(16)
	if err != nil {
		return nil, internalError("no randomness")
	}
	params := url.Values{}
	params.Set("agent_authorize", "1")
	params.Set("challenge", pkceChallenge(verifier))
	params.Set("state", state)
	params.Set("device", device)
	params.Set("cli", Version)
	if inv.has("write") {
		// The tier is chosen on the page; this only asks for read-write.
		params.Set("tier", "write")
	}

	ctx, cancel := context.WithTimeout(context.Background(), env.loginTimeout())
	defer cancel()
	var code string
	if inv.has("no-browser") {
		params.Set("mode", "paste")
		authorizeURL := server + "/ui/?" + params.Encode()
		fmt.Fprintf(env.Stderr, "Open this address in a browser, sign in and approve:\n\n  %s\n\n", authorizeURL)
		code, err = readPastedCode(ctx, env, server)
	} else {
		listener, port, listenErr := listenLoopback()
		if listenErr != nil {
			return nil, &cliError{Code: agentapi.CodeNetworkError, Message: "cannot listen on 127.0.0.1 for the browser callback; try `llmaudit login --server " + server + " --no-browser`"}
		}
		params.Set("port", strconv.Itoa(port))
		authorizeURL := server + "/ui/?" + params.Encode()
		fmt.Fprintf(env.Stderr, "Opening the authorization page in the browser. If it does not open, visit:\n\n  %s\n\nWaiting for approval (up to %s)...\n", authorizeURL, env.loginTimeout())
		if env.OpenBrowser != nil {
			_ = env.OpenBrowser(authorizeURL)
		}
		code, err = waitForCallback(ctx, listener, port, state, server)
	}
	if err != nil {
		return nil, err
	}

	route := &inv.spec.Routes[0]
	body := map[string]any{"code": code, "code_verifier": verifier}
	exchangeCtx, exchangeCancel := inv.context()
	defer exchangeCancel()
	envelope, err := exchange.call(exchangeCtx, inv, route, route.Path, nil, body)
	if err != nil {
		return nil, err
	}
	var issued map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Data, &issued); err != nil {
		return nil, invalidResponse(http.StatusOK, "the token response is not an object")
	}
	var token, expiresAt, role, tier string
	_ = json.Unmarshal(issued["token"], &token)
	_ = json.Unmarshal(issued["expires_at"], &expiresAt)
	_ = json.Unmarshal(issued["role"], &role)
	_ = json.Unmarshal(issued["tier"], &tier)
	if !agentapi.ValidTokenFormat(token) {
		return nil, invalidResponse(http.StatusOK, "the token response has no valid token")
	}
	if err := saveCredentials(env, &credentials{Server: server, Token: token, ExpiresAt: expiresAt, Role: role, Tier: tier}); err != nil {
		return nil, err
	}
	// The token itself never reaches the output.
	delete(issued, "token")
	issued["server"], _ = json.Marshal(server)
	issued["device_name"], _ = json.Marshal(device)
	issued["credentials_saved"] = json.RawMessage("true")
	if inv.has("write") {
		issued["requested_tier"] = json.RawMessage(`"write"`)
	}
	envelope.Data, _ = json.Marshal(issued)
	if strings.HasPrefix(server, "http://") && !isLoopbackHost(server) {
		fmt.Fprintln(env.Stderr, "warning: the server address uses plain HTTP and is not this machine; the agent token and all data travel unencrypted.")
	}
	return &result{envelope: envelope, server: server}, nil
}

// listenLoopback listens on a random port of 127.0.0.1 (never another
// address); the port must be 1024 or above.
func listenLoopback() (net.Listener, int, error) {
	for attempt := 0; attempt < 5; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, 0, err
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if port >= 1024 {
			return listener, port, nil
		}
		listener.Close()
	}
	return nil, 0, errors.New("no usable port")
}

type callbackResult struct {
	code   string
	denied bool
}

// waitForCallback serves http://127.0.0.1:<port>/callback until a request
// with the right state arrives. Other paths, hosts and states are ignored and
// the wait goes on, up to the context deadline.
func waitForCallback(ctx context.Context, listener net.Listener, port int, state, server string) (string, error) {
	results := make(chan callbackResult, 1)
	expectedHost := "127.0.0.1:" + strconv.Itoa(port)
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if request.Method != http.MethodGet || request.URL.Path != "/callback" || request.Host != expectedHost {
			http.NotFound(writer, request)
			return
		}
		query := request.URL.Query()
		if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1 {
			http.Error(writer, "This authorization does not belong to the waiting llmaudit login.", http.StatusBadRequest)
			return
		}
		var outcome callbackResult
		switch {
		case query.Get("error") != "":
			outcome.denied = true
			_, _ = io.WriteString(writer, "Authorization denied. You can close this window.\n")
		case query.Get("code") != "":
			outcome.code = query.Get("code")
			_, _ = io.WriteString(writer, "Authorization received. You can close this window and return to the terminal.\n")
		default:
			http.Error(writer, "The callback has neither a code nor an error.", http.StatusBadRequest)
			return
		}
		select {
		case results <- outcome:
		default:
		}
	})
	callback := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = callback.Serve(listener) }()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = callback.Shutdown(shutdownCtx)
	}()
	select {
	case outcome := <-results:
		if outcome.denied {
			return "", &cliError{Code: agentapi.CodeLoginDenied}
		}
		return outcome.code, nil
	case <-ctx.Done():
		return "", &cliError{Code: agentapi.CodeLoginTimeout, Hint: "Ask the user to run `llmaudit login --server " + server + "` again and approve within " + loginWaitText + "."}
	}
}

// readPastedCode reads the one-time code the page shows. Empty lines are
// skipped; end of input without a code is NO_TTY.
func readPastedCode(ctx context.Context, env *Env, server string) (string, error) {
	lines := make(chan string)
	failed := make(chan struct{})
	go func() {
		reader := bufio.NewReader(env.Stdin)
		for {
			line, err := reader.ReadString('\n')
			if strings.TrimSpace(line) != "" {
				select {
				case lines <- strings.TrimSpace(line):
				case <-ctx.Done():
				}
				return
			}
			if err != nil {
				close(failed)
				return
			}
			fmt.Fprint(env.Stderr, "Authorization code: ")
		}
	}()
	fmt.Fprint(env.Stderr, "Authorization code: ")
	select {
	case code := <-lines:
		if env.Terminal == nil || !env.Terminal.IsInteractive() {
			// Piped input is not echoed: end the prompt line ourselves.
			fmt.Fprintln(env.Stderr)
		}
		return code, nil
	case <-failed:
		fmt.Fprintln(env.Stderr)
		return "", &cliError{Code: agentapi.CodeNoTTY, Message: "no authorization code was entered",
			Hint: "Ask the user to run `llmaudit login --server " + server + " --no-browser` themselves in a terminal and paste the code the page shows."}
	case <-ctx.Done():
		return "", &cliError{Code: agentapi.CodeLoginTimeout, Hint: "Ask the user to run `llmaudit login --server " + server + " --no-browser` again and paste the code within " + loginWaitText + "."}
	}
}

// openBrowser uses the platform's standard opener, without a shell.
func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.Command("open", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}
