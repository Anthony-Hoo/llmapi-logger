package agentapi

import (
	"encoding/json"
	"go/build"
	"net/http"
	"strings"
	"testing"
)

// The command-line client builds against this package alone, so it must stay
// on the standard library.
func TestPackageImportsOnlyTheStandardLibrary(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imported := range append(append([]string{}, pkg.Imports...), pkg.TestImports...) {
		if strings.Contains(strings.Split(imported, "/")[0], ".") || strings.HasPrefix(imported, "llmapi-logger/") {
			t.Errorf("agentapi imports %q", imported)
		}
	}
}

// The full error table of contract section 2.3, server and client codes.
func TestErrorTableMatchesTheContract(t *testing.T) {
	server := map[Code][2]int{
		CodeFeatureDisabled: {404, 1}, CodeUnauthenticated: {401, 4}, CodeTokenExpired: {401, 4},
		CodeTokenRevoked: {401, 4}, CodeRoleUnavailable: {401, 4}, CodeClientTooOld: {426, 1},
		CodeForbiddenRole: {403, 5}, CodeReadOnlyToken: {403, 5}, CodeWriteDisabled: {403, 5},
		CodeModuleDisabled: {404, 1}, CodeInvalidArgument: {400, 2}, CodeNotFound: {404, 1},
		CodeAlreadyExists: {409, 1}, CodeConflict: {409, 1}, CodeVersionConflict: {409, 1},
		CodePlanNotFound: {404, 1}, CodePlanExpired: {410, 1}, CodeLinkExpired: {410, 1}, CodeRunInProgress: {409, 1},
		CodeNotReady: {409, 1}, CodeNotAvailable: {404, 1}, CodeNotRetained: {410, 1}, CodeEvidenceUnavailable: {500, 1},
		CodeRateLimited: {429, 1}, CodeUpstreamUnavailable: {502, 1}, CodeTimeout: {503, 1},
		CodeInvalidGrant: {400, 4}, CodeInternal: {500, 1},
	}
	local := map[Code]int{
		CodeNotLoggedIn: 4, CodeNetworkError: 1, CodeInvalidResponse: 1, CodeRedirectRefused: 1,
		CodeLoginTimeout: 4, CodeLoginDenied: 4, CodeNoTTY: 2, CodeLocalFileError: 1,
	}
	if got := len(Codes()); got != len(server)+len(local) {
		t.Fatalf("table has %d codes, contract has %d", got, len(server)+len(local))
	}
	for code, want := range server {
		spec, ok := Lookup(code)
		if !ok || spec.Local || spec.HTTPStatus != want[0] || spec.ExitCode != want[1] || HTTPStatus(code) != want[0] || ExitCode(code) != want[1] {
			t.Errorf("%s = %+v, want status %d exit %d", code, spec, want[0], want[1])
		}
		if spec.Message == "" {
			t.Errorf("%s has no default message", code)
		}
	}
	for code, exit := range local {
		spec, ok := Lookup(code)
		if !ok || !spec.Local || spec.HTTPStatus != 0 || spec.ExitCode != exit {
			t.Errorf("%s = %+v, want local exit %d", code, spec, exit)
		}
		if HTTPStatus(code) != http.StatusInternalServerError {
			t.Errorf("local code %s has a server status", code)
		}
	}
	for _, spec := range Codes() {
		if spec.ExitCode == 3 {
			t.Errorf("%s uses the reserved exit code 3", spec.Code)
		}
		if strings.Contains(spec.Hint, "llmaudit ") && !strings.Contains(spec.Hint, "`llmaudit ") {
			t.Errorf("%s hint names a command outside backquotes", spec.Code)
		}
	}
	if spec, ok := Lookup("NOPE"); ok || spec.Code != CodeInternal || HTTPStatus("NOPE") != 500 || ExitCode("NOPE") != 1 {
		t.Fatalf("unknown code = %+v, %v", spec, ok)
	}
}

func TestEnvelopesHaveTheContractShape(t *testing.T) {
	encoded, err := json.Marshal(ReadSuccess(map[string]int{"n": 1}, Meta{State: "ok", Complete: true}))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"ok":true,"data":{"n":1},"meta":{"state":"ok","complete":true,"incomplete_reason":""}}` {
		t.Fatalf("read success = %s", encoded)
	}
	encoded, _ = json.Marshal(Success(map[string]bool{"revoked": true}))
	if string(encoded) != `{"ok":true,"data":{"revoked":true}}` {
		t.Fatalf("success = %s", encoded)
	}
	encoded, _ = json.Marshal(Failure(CodeInvalidArgument, "", "", map[string]any{"field": "tier"}))
	var decoded Response
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.OK || decoded.Error == nil || decoded.Error.Code != CodeInvalidArgument || decoded.Error.Message == "" ||
		decoded.Error.Hint == "" || decoded.Error.Details["field"] != "tier" || !strings.HasPrefix(string(encoded), `{"ok":false,"error":{`) {
		t.Fatalf("failure = %s", encoded)
	}
}

func TestRegistryMatch(t *testing.T) {
	registry := NewRegistry(Endpoints)
	cases := []struct {
		method, path, id string
		params           map[string]string
	}{
		{"GET", "/api/agent/v1/whoami", "whoami", nil},
		{"POST", "/api/agent/v1/token", "token.exchange", nil},
		{"POST", "/api/agent/v1/logout", "logout", nil},
		{"GET", "/api/agent/v1/requests/a1", "requests.get", map[string]string{"id": "a1"}},
		{"GET", "/api/agent/v1/requests/a1/export/headers", "requests.export", map[string]string{"id": "a1", "what": "headers"}},
		{"GET", "/api/agent/v1/dl/c2ln/manifest.json", EndpointDownload, map[string]string{"signature": "c2ln", "file": "manifest.json"}},
		{"GET", "/api/agent/v1/dl/c2ln/", "", nil},
		{"GET", "/api/agent/v1/dl/c2ln/a/b", "", nil},
		{"POST", "/api/agent/v1/dl/c2ln/manifest.json", "", nil},
		{"POST", "/api/agent/v1/whoami", "", nil},
		{"GET", "/api/agent/v1/whoami/", "", nil},
		{"GET", "/api/agent/v1/requests/", "", nil},
		{"GET", "/api/agent/v1//whoami", "", nil},
		{"GET", "/api/agent/v1", "", nil},
		{"GET", "/api/agent/v2/whoami", "", nil},
		{"GET", "/api/v1/whoami", "", nil},
	}
	for _, test := range cases {
		endpoint, params, ok := registry.Match(test.method, test.path)
		if ok != (test.id != "") || endpoint.ID != test.id || len(params) != len(test.params) {
			t.Errorf("%s %s = %+v %v %v", test.method, test.path, endpoint, params, ok)
			continue
		}
		for key, value := range test.params {
			if params[key] != value {
				t.Errorf("%s %s param %s = %q", test.method, test.path, key, params[key])
			}
		}
	}
	var nilRegistry *Registry
	if _, _, ok := nilRegistry.Match("GET", "/api/agent/v1/whoami"); ok {
		t.Fatal("nil registry matched")
	}
	seen := map[string]bool{}
	for _, endpoint := range Endpoints {
		if seen[endpoint.ID] || !endpoint.Tier.Valid() || endpoint.Access == "" {
			t.Errorf("bad registry row %+v", endpoint)
		}
		seen[endpoint.ID] = true
	}
}

func TestVersionNegotiation(t *testing.T) {
	if _, ok := ParseVersion(LatestVersion); !ok {
		t.Fatal("latest version does not parse")
	}
	latest, _ := ParseVersion(LatestVersion)
	minimum, _ := ParseVersion(MinVersion)
	if CompareVersions(minimum, latest) > 0 {
		t.Fatal("minimum is newer than latest")
	}
	for _, test := range []struct {
		header string
		tooOld bool
	}{
		{"", false}, {MinVersion, false}, {LatestVersion, false}, {"9.0.0", false}, {MinVersion + "-dev+abc", false},
		{"0.0.9", true}, {"0.0.0", true}, {"garbage", true}, {"1.2", true}, {"1.2.3.4", true}, {"v1.0.0", true}, {"1.-1.0", true},
	} {
		if got := ClientTooOld(test.header); got != test.tooOld {
			t.Errorf("ClientTooOld(%q) = %v, want %v", test.header, got, test.tooOld)
		}
	}
}

func TestTokenFormat(t *testing.T) {
	good := TokenPrefix + strings.Repeat("A", 42) + "_"
	if !ValidTokenFormat(good) {
		t.Fatal("well-formed token rejected")
	}
	for _, bad := range []string{
		"", "lla_", good[:len(good)-1], good + "A", "llb_" + good[4:], strings.Replace(good, "A", "=", 1),
		strings.Replace(good, "A", "+", 1), strings.Replace(good, "A", "/", 1), "LLA_" + good[4:],
	} {
		if ValidTokenFormat(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

// Contract section 4.3.2, first group: the four credential transports never
// leave the facade with their value.
func TestMaskingHidesEveryCredentialTransport(t *testing.T) {
	cases := [][2]string{
		{"Authorization", "Bearer sk-live-placeholder"},
		{"authorization", "raw-key-without-scheme"},
		{"AUTHORIZATION", "Basic dXNlcjpwYXNz"},
		{"X-Api-Key", "plain-anthropic-style-key"},
		{"x-goog-api-key", "plain-gemini-style-key"},
		{"key", "plain-query-key"},
		{"Key", "plain-query-key"},
		// The other names and shapes of rule 1 to rule 3.
		{"Proxy-Authorization", "anything"},
		{"Cookie", "session=1"},
		{"Set-Cookie", "session=1"},
		{"api-key", "x"},
		{"token", "x"},
		{"X-Auth-Token", "x"},
		{"refresh_token", "x"},
		{"X-Client-Secret", "x"},
		{"password", "x"},
		{"db_passwd", "x"},
		{"X-Credential-Id", "x"},
		{"X-Amz-Signature", "x"},
		{"X-My-ApiKey", "x"},
		{"my_api_key", "x"},
		{"X-Forwarded-Note", "  bearer abc"},
		{"X-Custom", "sk-abc"},
		{"X-Custom", "SK-abc"},
		{"X-Custom", "lla_abc"},
		{"X-Custom", "\tBasic abc"},
	}
	for _, test := range cases {
		masked := MaskValue(test[0], test[1])
		encoded, _ := json.Marshal(masked)
		if masked.ValueUntrusted != nil || masked.ValueOmitted != OmittedCredential || masked.Length != len(test[1]) ||
			strings.Contains(string(encoded), test[1]) {
			t.Errorf("%s: %q leaked as %s", test[0], test[1], encoded)
		}
	}
}

// Contract section 4.3.2, second group: agent identification and ordinary
// headers keep their values.
func TestMaskingKeepsAgentAndOrdinaryHeaders(t *testing.T) {
	cases := [][2]string{
		{"X-Agent-Session-Id", "ses_0001"},
		{"X-Agent-Id", "agt_0001"},
		{"X-Agent-Parent-Id", "agt_0000"},
		{"X-Agent-Role", "worker"},
		{"X-Agent-Name", "reviewer"},
		{"X-Agent-Project", "example-project"},
		{"User-Agent", "codex-tui/1.0"},
		{"X-Oneapi-Request-Id", "20261119000000000000"},
		{"X-Ratelimit-Remaining-Tokens", "1000"},
		{"Content-Type", "application/json"},
		{"tokens", "12"},
		{"tokenizer", "cl100k"},
	}
	for _, test := range cases {
		masked := MaskValue(test[0], test[1])
		if masked.ValueUntrusted == nil || *masked.ValueUntrusted != test[1] || masked.ValueOmitted != "" || masked.Length != len(test[1]) {
			t.Errorf("%s = %+v", test[0], masked)
		}
	}
}

// The API key is one field under every name the server and the client accept
// (contract section 0.1 item 177).
func TestIsKeyField(t *testing.T) {
	for _, field := range []string{"api_key", "API_KEY", " api_key ", "llm.api_key", "LLM.Api_Key", " llm.api_key\t", "a.b.api_key", "llm. api_key"} {
		if !IsKeyField(field) {
			t.Errorf("%q is not a key field", field)
		}
	}
	for _, field := range []string{"", "llm", "llm.model", "api_key.llm", "api_keys", "my_api_key", "llm.api_key_source", "apikey", "api-key"} {
		if IsKeyField(field) {
			t.Errorf("%q is a key field", field)
		}
	}
}

// Everything addressed to the agent is English: the notice and every default
// message and hint of the error table carry no CJK text.
func TestAgentFacingTextIsEnglish(t *testing.T) {
	texts := map[string]string{"notice": UntrustedNotice}
	for _, spec := range Codes() {
		texts[string(spec.Code)+" message"] = spec.Message
		texts[string(spec.Code)+" hint"] = spec.Hint
	}
	for name, text := range texts {
		for _, char := range text {
			if char >= 0x2E80 && char <= 0x9FFF || char >= 0xFF00 && char <= 0xFFEF {
				t.Errorf("%s is not English: %q", name, text)
				break
			}
		}
	}
}
