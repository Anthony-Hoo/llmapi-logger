package agentcli

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

// TestExitCodesFollowTheSharedTable runs one command against every code of
// the shared table: a server code with its HTTP status, and every local code
// through the client's own error path.
func TestExitCodesFollowTheSharedTable(t *testing.T) {
	server := newFakeServer(t, nil)
	for _, spec := range agentapi.Codes() {
		t.Run(string(spec.Code), func(t *testing.T) {
			if spec.Local {
				err := &cliError{Code: spec.Code}
				h := newHarness(t)
				if exit := writeFailure(h.env, false, err); exit != spec.ExitCode {
					t.Fatalf("local %s exit %d, want %d", spec.Code, exit, spec.ExitCode)
				}
				return
			}
			h := newHarness(t)
			h.saveLogin(server.URL)
			server.setResponder(failWith(spec.Code))
			exit := h.run("whoami")
			body := h.expectFailure(exit, spec.Code, spec.ExitCode)
			if body.Message == "" {
				t.Fatal("failure without a message")
			}
		})
	}
}

func TestUnknownServerCodeFallsBackOnHTTPStatus(t *testing.T) {
	server := newFakeServer(t, nil)
	cases := map[int]int{400: 2, 401: 4, 403: 5, 404: 1, 409: 1, 500: 1, 503: 1}
	for status, want := range cases {
		h := newHarness(t)
		h.saveLogin(server.URL)
		server.setResponder(respondJSON(status, `{"ok":false,"error":{"code":"SOMETHING_NEW","message":"m"}}`))
		exit := h.run("whoami")
		body := h.failure()
		if body.Code != "SOMETHING_NEW" || exit != want {
			t.Errorf("status %d: exit %d code %s, want exit %d", status, exit, body.Code, want)
		}
	}
	// A local code sent by a server is not trusted as local either.
	h := newHarness(t)
	h.saveLogin(server.URL)
	server.setResponder(respondJSON(403, `{"ok":false,"error":{"code":"NO_TTY","message":"m"}}`))
	if exit := h.run("whoami"); exit != 5 {
		t.Errorf("server-sent local code: exit %d, want 5", exit)
	}
}

func TestReadResultsRequireMeta(t *testing.T) {
	server := newFakeServer(t, nil)
	bodies := map[string]string{
		"no meta":          `{"ok":true,"data":{}}`,
		"null meta":        `{"ok":true,"data":{},"meta":null}`,
		"missing state":    `{"ok":true,"data":{},"meta":{"complete":true,"incomplete_reason":""}}`,
		"missing complete": `{"ok":true,"data":{},"meta":{"state":"x","incomplete_reason":""}}`,
		"missing reason":   `{"ok":true,"data":{},"meta":{"state":"x","complete":true}}`,
		"wrong type":       `{"ok":true,"data":{},"meta":{"state":"x","complete":"yes","incomplete_reason":""}}`,
		"no data":          `{"ok":true,"meta":` + okMeta + `}`,
		"not json":         `<html>proxy error</html>`,
		"no ok":            `{"data":{},"meta":` + okMeta + `}`,
		"trailing data":    `{"ok":true,"data":{},"meta":` + okMeta + `}{}`,
		"failure no code":  `{"ok":false,"error":{"message":"m"}}`,
	}
	for name, body := range bodies {
		h := newHarness(t)
		h.saveLogin(server.URL)
		server.setResponder(respondJSON(200, body))
		exit := h.run("requests", "list")
		if got := h.failure(); got.Code != agentapi.CodeInvalidResponse || exit != 1 {
			t.Errorf("%s: exit %d code %s, want INVALID_RESPONSE", name, exit, got.Code)
		}
	}
	// A plan (POST) result has no meta and is fine.
	h := newHarness(t)
	h.saveLogin(server.URL)
	server.setResponder(respondJSON(200, `{"ok":true,"data":{"plan_id":"pln_1"}}`))
	if exit := h.run("analysis", "run"); exit != 0 {
		t.Fatalf("plan without meta: exit %d %s", exit, h.stderr.String())
	}
	// Zero values are present values.
	server.setResponder(respondJSON(200, `{"ok":true,"data":{},"meta":{"state":"","complete":false,"incomplete_reason":""}}`))
	if exit := h.run("requests", "list"); exit != 0 {
		t.Fatalf("zero-valued meta: exit %d %s", exit, h.stderr.String())
	}
}

func TestRedirectIsRefused(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request, _ []byte) {
		http.Redirect(writer, request, "https://audit.example.com/elsewhere", http.StatusFound)
	})
	h := newHarness(t)
	h.saveLogin(server.URL)
	exit := h.run("whoami")
	body := h.expectFailure(exit, agentapi.CodeRedirectRefused, 1)
	if body.Details["location"] != "https://audit.example.com/elsewhere" {
		t.Fatalf("details %v", body.Details)
	}
	if len(server.recorded()) != 1 {
		t.Fatalf("the redirect was followed: %d requests", len(server.recorded()))
	}
}

func TestNotLoggedIn(t *testing.T) {
	h := newHarness(t)
	h.expectFailure(h.run("whoami"), agentapi.CodeNotLoggedIn, 4)
	h.expectFailure(h.run("apply", "pln_1"), agentapi.CodeNotLoggedIn, 4)
}

func TestNetworkErrorAndApplyHint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := "http://" + listener.Addr().String()
	listener.Close()
	h := newHarness(t)
	h.saveLogin(address)
	h.expectFailure(h.run("whoami"), agentapi.CodeNetworkError, 1)
	body := h.expectFailure(h.run("apply", "pln_1"), agentapi.CodeNetworkError, 1)
	if !strings.Contains(body.Hint, "Do not apply the plan again") || !strings.Contains(body.Hint, "llmaudit config show --kind") {
		t.Fatalf("apply hint %q", body.Hint)
	}

	server := newFakeServer(t, failWith(agentapi.CodeTimeout))
	h.saveLogin(server.URL)
	body = h.expectFailure(h.run("apply", "pln_1"), agentapi.CodeTimeout, 1)
	if !strings.Contains(body.Hint, "Do not apply the plan again") {
		t.Fatalf("apply timeout hint %q", body.Hint)
	}
	if len(server.recorded()) != 1 {
		t.Fatalf("apply was retried: %d requests", len(server.recorded()))
	}
}

func TestClientTimeoutIsTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if got := transportError(ctx, ctx.Err()); got.Code != agentapi.CodeTimeout {
		t.Fatalf("got %s", got.Code)
	}
	if got := transportError(context.Background(), errors.New("connection refused")); got.Code != agentapi.CodeNetworkError {
		t.Fatalf("got %s", got.Code)
	}
}

func TestClientTooOld(t *testing.T) {
	server := newFakeServer(t, func(writer http.ResponseWriter, _ *http.Request, _ []byte) {
		writer.Header().Set(agentapi.HeaderMin, "99.0.0")
		failWith(agentapi.CodeClientTooOld)(writer, nil, nil)
	})
	h := newHarness(t)
	h.saveLogin(server.URL)
	h.expectFailure(h.run("whoami"), agentapi.CodeClientTooOld, 1)

	if _, ok := agentapi.ParseVersion(Version); !ok || agentapi.ClientTooOld(Version) {
		t.Fatalf("Version %q must parse and be accepted by this server", Version)
	}
}

func TestMaskingTouchesOnlyExplanatoryText(t *testing.T) {
	other := agentapi.TokenPrefix + strings.Repeat("B", agentapi.TokenEncodedChars)
	server := newFakeServer(t, respondJSON(200, `{"ok":true,"data":{"value_untrusted":"`+other+`"},"meta":`+okMeta+`,"next_actions":["token `+other+` seen"]}`))
	h := newHarness(t)
	h.saveLogin(server.URL)
	if exit := h.run("requests", "get", "1"); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	envelope := h.success()
	if !strings.Contains(string(envelope["data"]), other) {
		t.Fatalf("business data was changed: %s", envelope["data"])
	}
	var actions []string
	_ = json.Unmarshal(envelope["next_actions"], &actions)
	if len(actions) != 1 || actions[0] != "token lla_*** seen" {
		t.Fatalf("next_actions %v", actions)
	}

	server.setResponder(respondJSON(404, `{"ok":false,"error":{"code":"NOT_FOUND","message":"no `+other+`","hint":"try `+other+`","details":{"value":"`+other+`"}}}`))
	body := h.expectFailure(h.run("requests", "get", "1"), agentapi.CodeNotFound, 1)
	if body.Message != "no lla_***" || body.Hint != "try lla_***" || body.Details["value"] != other {
		t.Fatalf("masking %+v", body)
	}
}

func TestWebURLAndPretty(t *testing.T) {
	server := newFakeServer(t, respondJSON(200, `{"ok":true,"data":{"items":[{"id":1,"name":"a"}],"total":2},"meta":`+okMeta+`,"web_path":"/ui/?audit=1"}`))
	h := newHarness(t)
	h.saveLogin(server.URL + "/")
	if exit := h.run("requests", "list"); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	envelope := h.success()
	var webURL string
	_ = json.Unmarshal(envelope["web_url"], &webURL)
	if webURL != server.URL+"/ui/?audit=1" {
		t.Fatalf("web_url %q", webURL)
	}
	if exit := h.run("requests", "list", "--pretty"); exit != 0 || !strings.HasPrefix(h.stdout.String(), "ok\n") || !strings.Contains(h.stdout.String(), "total: 2") {
		t.Fatalf("pretty output %q", h.stdout.String())
	}
	server.setResponder(failWith(agentapi.CodeNotFound))
	if exit := h.run("requests", "list", "--pretty"); exit != 1 || !strings.HasPrefix(h.stderr.String(), "error NOT_FOUND") {
		t.Fatalf("pretty failure %q", h.stderr.String())
	}
}

func TestUsageErrors(t *testing.T) {
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	cases := [][]string{
		{"nope"},
		{"requests", "nope"},
		{"requests", "list", "--bogus", "1"},
		{"requests", "list", "--limit"},
		{"requests", "get"},
		{"requests", "get", "1", "2"},
		{"requests", "get", ".."},
		{"requests", "export", "1", "--out", "x.json"},
		{"requests", "export", "1", "--what", "everything", "--out", "x.json"},
		{"config", "show"},
		{"config", "show", "--kind", "member"},
		{"config", "show", "--kind", "org", "--kind", "org"},
		{"analysis", "session", sessionHex},
		{"analysis", "session", sessionHex, "--pack", "--facet"},
		{"analysis", "session", sessionHex, "--pack"},
		{"analysis", "dismiss", "x1"},
		{"config", "set", "--kind", "ua-rule", "--set", "novalue"},
		{"config", "set", "--kind", "ua-rule", "--set-json", "a={"},
		{"config", "set", "--kind", "project", "--add", "rules=nocolon"},
		{"config", "set-key", "--kind", "ua-rule", "--clear"},
		{"config", "preview-project", "--group-id", "x"},
		{"weekly", "regenerate"},
		{"apply"},
		{"apply", "pln_1", "--force"},
		{"apply", "pln_1", "extra"},
		{"login", "--server", "ftp://audit.example.com"},
		{"login", "--server", "https://user@audit.example.com"},
		{"login", "--server", "https://audit.example.com/?q=1"},
		{"whoami", "--pretty=maybe"},
	}
	for _, args := range cases {
		exit := h.run(args...)
		body := h.failure()
		if exit != 2 || body.Code != agentapi.CodeInvalidArgument {
			t.Errorf("%v: exit %d code %s, want 2 INVALID_ARGUMENT", args, exit, body.Code)
		}
	}
	if len(server.recorded()) != 0 {
		t.Fatalf("usage errors reached the server: %+v", server.recorded())
	}
}

func TestLogout(t *testing.T) {
	server := newFakeServer(t, respondJSON(200, `{"ok":true,"data":{"revoked":true}}`))
	h := newHarness(t)
	h.saveLogin(server.URL)
	if exit := h.run("logout"); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	if _, err := loadCredentials(h.env); err == nil {
		t.Fatal("credentials still present after logout")
	}
	request := server.recorded()[0]
	if request.Method != "POST" || request.Path != agentapi.PathPrefix+"/logout" {
		t.Fatalf("logout request %s %s", request.Method, request.Path)
	}

	// An already invalid token: local credentials go anyway.
	server.setResponder(failWith(agentapi.CodeTokenRevoked))
	h.saveLogin(server.URL)
	if exit := h.run("logout"); exit != 0 {
		t.Fatalf("exit %d %s", exit, h.stderr.String())
	}
	if _, err := loadCredentials(h.env); err == nil {
		t.Fatal("credentials still present")
	}
	// FEATURE_DISABLED keeps them (contract: do not clear local credentials).
	server.setResponder(failWith(agentapi.CodeFeatureDisabled))
	h.saveLogin(server.URL)
	h.expectFailure(h.run("logout"), agentapi.CodeFeatureDisabled, 1)
	if _, err := loadCredentials(h.env); err != nil {
		t.Fatal("credentials removed on FEATURE_DISABLED")
	}
}

func TestVersion(t *testing.T) {
	h := newHarness(t)
	if exit := h.run("version"); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	envelope := h.success()
	if !strings.Contains(string(envelope["meta"]), `"incomplete_reason":"not_logged_in"`) || !strings.Contains(string(envelope["data"]), `"cli_version":"`+Version+`"`) {
		t.Fatalf("version without login: %s", h.stdout.String())
	}

	server := newFakeServer(t, func(writer http.ResponseWriter, request *http.Request, body []byte) {
		writer.Header().Set(agentapi.HeaderLatest, "99.1.0")
		defaultResponder(writer, request, body)
	})
	h.saveLogin(server.URL)
	if exit := h.run("version"); exit != 0 {
		t.Fatalf("exit %d", exit)
	}
	envelope = h.success()
	var data struct {
		Server struct {
			Latest          string `json:"api_latest"`
			Minimum         string `json:"api_min"`
			UpdateAvailable bool   `json:"update_available"`
			Compatible      bool   `json:"compatible"`
		} `json:"server"`
	}
	_ = json.Unmarshal(envelope["data"], &data)
	if data.Server.Latest != "99.1.0" || data.Server.Minimum != agentapi.MinVersion || !data.Server.UpdateAvailable || !data.Server.Compatible {
		t.Fatalf("version data %s", envelope["data"])
	}
	if request := server.recorded()[0]; request.Path != agentapi.PathPrefix+"/whoami" || request.Header.Get(agentapi.HeaderCommand) != "version" {
		t.Fatalf("version request %+v", request)
	}

	// An unreachable server is not an error.
	h.saveLogin("http://127.0.0.1:1")
	if exit := h.run("version"); exit != 0 || !strings.Contains(h.stdout.String(), "server_unreachable") {
		t.Fatalf("unreachable: exit %d %s %s", exit, h.stdout.String(), h.stderr.String())
	}
}
