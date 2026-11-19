package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentaccess"
	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentdist"
)

// distClock is an adjustable clock for the download signer.
type distClock struct{ now time.Time }

func (clock *distClock) Now() time.Time { return clock.now }

// packTestPackages builds a real package directory with the packer from a
// minimal Skill and placeholder binaries.
func packTestPackages(t *testing.T) (string, *agentdist.Manifest) {
	t.Helper()
	root := t.TempDir()
	skill := filepath.Join(root, "skill")
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(skill, "SKILL.md"), "---\nname: llmapi-audit\ndescription: test\n---\nbody\n")
	write(filepath.Join(skill, "VERSION"), agentapi.LatestVersion+"\n")
	binaries := map[agentdist.Platform]string{}
	for _, platform := range agentdist.Platforms {
		path := filepath.Join(root, "bin", "llmaudit-"+platform.String())
		write(path, "placeholder client for "+platform.String()+"\n")
		binaries[platform] = path
	}
	out := filepath.Join(root, agentdist.PackageDirName)
	manifest, err := agentdist.Pack(agentdist.PackOptions{SkillDir: skill, Binaries: binaries, OutDir: out})
	if err != nil {
		t.Fatal(err)
	}
	return out, manifest
}

// withDist gives env a distribution service over dir.
func withDist(t *testing.T, env agentEnv, dir string, clock *distClock) *agentdist.Service {
	t.Helper()
	service, err := agentdist.New(agentdist.Options{PackageDir: dir, AdminToken: testAdminToken, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	env.handler.agentDist = service
	return service
}

var linkPattern = regexp.MustCompile(`"(https?://[^"]+/api/agent/v1/dl/([A-Za-z0-9_-]+)/)([A-Za-z0-9._-]+)"`)

type installLink struct {
	Prompt    string `json:"prompt"`
	ExpiresAt string `json:"expires_at"`
}

func requestInstallLink(t *testing.T, env agentEnv, caller agentCaller, body string) (installLink, string, string) {
	t.Helper()
	response := env.do(http.MethodPost, agentInstallLinksPath, body, caller)
	if response.Code != http.StatusOK {
		t.Fatalf("install-links = %d %s", response.Code, response.Body.String())
	}
	var link installLink
	decoder := json.NewDecoder(strings.NewReader(response.Body.String()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&link); err != nil || link.Prompt == "" || link.ExpiresAt == "" {
		t.Fatalf("install-links body = %s", response.Body.String())
	}
	match := linkPattern.FindStringSubmatch(link.Prompt)
	if match == nil {
		t.Fatalf("no download link in the prompt:\n%s", link.Prompt)
	}
	return link, match[1], match[2]
}

func TestAgentInstallLinkAndDownload(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	dir, manifest := packTestPackages(t)
	clock := &distClock{now: time.Now()}
	withDist(t, env, dir, clock)

	link, prefix, signature := requestInstallLink(t, env, agentCaller{bearer: testAdminToken}, `{"agent":"claude-code","platform":"linux-amd64"}`)
	// httptest requests are addressed to example.com: the browser's address.
	if !strings.HasPrefix(prefix, "http://example.com/api/agent/v1/dl/") {
		t.Fatalf("link prefix %q", prefix)
	}
	expires, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil || expires.Sub(clock.now) > agentdist.LinkLifetime || expires.Sub(clock.now) < agentdist.LinkLifetime-2*time.Second {
		t.Fatalf("expires_at %q", link.ExpiresAt)
	}
	pkg, _ := manifest.Find(agentdist.Platform{OS: "linux", Arch: "amd64"})
	if !strings.Contains(link.Prompt, pkg.File) || !strings.Contains(link.Prompt, pkg.SHA256) {
		t.Fatal("the prompt does not name the linux-amd64 package and its digest")
	}

	path := strings.TrimPrefix(prefix, "http://example.com")
	response := env.do(http.MethodGet, path+pkg.File, "", agentCaller{})
	sum := sha256.Sum256(response.Body.Bytes())
	if response.Code != http.StatusOK || int64(response.Body.Len()) != pkg.Size || hex.EncodeToString(sum[:]) != pkg.SHA256 {
		t.Fatalf("download = %d, %d bytes", response.Code, response.Body.Len())
	}
	if response.Header().Get(agentapi.HeaderLatest) != agentapi.LatestVersion || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("download headers %v", response.Header())
	}
	if response := env.do(http.MethodGet, path+agentdist.ManifestFile, "", agentCaller{}); response.Code != http.StatusOK {
		t.Fatalf("manifest download = %d", response.Code)
	}

	// Refusals: a query parameter, another signature, an unlisted file, a
	// wrong method; none of them is audited.
	cases := []struct {
		method, path string
		code         agentapi.Code
	}{
		{http.MethodGet, path + pkg.File + "?x=1", agentapi.CodeInvalidArgument},
		{http.MethodGet, "/api/agent/v1/dl/" + strings.Repeat("A", len(signature)) + "/" + pkg.File, agentapi.CodeNotFound},
		{http.MethodGet, path + "SKILL.md", agentapi.CodeNotFound},
		{http.MethodPost, path + pkg.File, agentapi.CodeNotFound},
	}
	for _, test := range cases {
		if got := agentErrorCode(t, env.do(test.method, test.path, "", agentCaller{})); got != test.code {
			t.Errorf("%s %s = %s, want %s", test.method, test.path, got, test.code)
		}
	}
	clock.now = clock.now.Add(agentdist.LinkLifetime)
	if got := agentErrorCode(t, env.do(http.MethodGet, path+pkg.File, "", agentCaller{})); got != agentapi.CodeLinkExpired {
		t.Fatalf("expired link = %s", got)
	}

	var issued, downloaded int
	for _, entry := range env.store.Audit() {
		encoded, _ := json.Marshal(entry)
		if strings.Contains(string(encoded), signature) || strings.Contains(string(encoded), testAdminToken) {
			t.Fatalf("audit row carries the link signature or the admin token: %s", encoded)
		}
		switch entry.Event {
		case agentaccess.EventLinkIssued:
			issued++
			if entry.Role != "admin" || entry.Command != "web" || entry.ObjectKind != agentPackageObject || entry.ObjectID != pkg.File || entry.TokenID != nil {
				t.Errorf("link_issued row %+v", entry)
			}
		case agentaccess.EventPackageDownloaded:
			downloaded++
			if entry.ObjectKind != agentPackageObject || entry.Outcome != agentaccess.OutcomeOK || entry.TokenID != nil || entry.Role != "" {
				t.Errorf("package_downloaded row %+v", entry)
			}
		}
	}
	if issued != 1 || downloaded != 2 {
		t.Fatalf("audit has %d link_issued and %d package_downloaded rows, want 1 and 2", issued, downloaded)
	}
}

func TestAgentInstallLinkInputs(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	dir, _ := packTestPackages(t)
	withDist(t, env, dir, &distClock{now: time.Now()})
	admin := agentCaller{bearer: testAdminToken}
	fieldOf := func(response *httptest.ResponseRecorder) (string, string) {
		var body struct {
			Error struct{ Code, Field string } `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		return body.Error.Code, body.Error.Field
	}
	for body, field := range map[string]string{
		`{"agent":"robot","platform":"linux-amd64"}`:                            "agent",
		`{"agent":"codex","platform":"plan9-amd64"}`:                            "platform",
		`{"agent":"other","platform":"linux-amd64"}`:                            "skills_dir",
		`{"agent":"other","platform":"linux-amd64","skills_dir":"/tmp/../etc"}`: "skills_dir",
		`{"agent":"other","platform":"linux-amd64","skills_dir":"/a/$(id)"}`:    "skills_dir",
		`{"agent":"codex","platform":"linux-amd64","state":"x"}`:                "body",
		`{"agent":"codex","platform":"linux-amd64"} {}`:                         "body",
		`not json`: "body",
	} {
		response := env.do(http.MethodPost, agentInstallLinksPath, body, admin)
		if code, got := fieldOf(response); response.Code != http.StatusBadRequest || code != "invalid_argument" || got != field {
			t.Errorf("%s = %d %s", body, response.Code, response.Body.String())
		}
	}
	if response := env.do(http.MethodGet, agentInstallLinksPath, "", admin); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET install-links = %d", response.Code)
	}

	// A developer may create links too; a custom skills directory is used.
	cookie := developerSignIn(t, env.handler)
	link, _, _ := requestInstallLink(t, env, agentCaller{cookie: cookie}, `{"agent":"other","platform":"darwin-arm64","skills_dir":"/opt/agent/skills"}`)
	if !strings.Contains(link.Prompt, "/opt/agent/skills/llmapi-audit") {
		t.Fatal("the prompt does not install into the given skills directory")
	}
	rows := env.store.Audit()
	if last := rows[len(rows)-1]; last.Event != agentaccess.EventLinkIssued || last.Role != "developer" {
		t.Fatalf("developer link row %+v", last)
	}

	// A browser address that cannot go into a shell command is refused with
	// a stable code instead of a 500.
	request := httptest.NewRequest(http.MethodPost, agentInstallLinksPath, strings.NewReader(`{"agent":"codex","platform":"linux-amd64"}`))
	request.Host = "audit.example.com:80$(id)"
	request.Header.Set("Authorization", "Bearer "+testAdminToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	env.handler.ServeHTTP(response, request)
	if code, _ := fieldOf(response); response.Code != http.StatusBadRequest || code != "server_url_unusable" || !strings.Contains(response.Body.String(), "agent_access.public_url") {
		t.Fatalf("unusable host = %d %s", response.Code, response.Body.String())
	}
}

// public_url wins over the browser's address, and forwarded headers are
// never read.
func TestAgentInstallLinkUsesPublicURL(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	dir, _ := packTestPackages(t)
	withDist(t, env, dir, &distClock{now: time.Now()})
	_, prefix, _ := requestInstallLink(t, env, agentCaller{bearer: testAdminToken}, `{"agent":"codex","platform":"windows-amd64"}`)
	if !strings.HasPrefix(prefix, "http://example.com/") {
		t.Fatalf("prefix without public_url %q", prefix)
	}
	request := func() string {
		response := env.do(http.MethodPost, agentInstallLinksPath, `{"agent":"codex","platform":"windows-amd64"}`, agentCaller{bearer: testAdminToken},
			"X-Forwarded-Host", "attacker.example.net", "X-Forwarded-Proto", "https", "Forwarded", "host=attacker.example.net")
		return response.Body.String()
	}
	if strings.Contains(request(), "attacker") {
		t.Fatal("a forwarded header reached the prompt")
	}
	env.handler.agentPublicURL = "https://audit.example.com/admin"
	if body := request(); !strings.Contains(body, "https://audit.example.com/admin/api/agent/v1/dl/") || strings.Contains(body, "attacker") {
		t.Fatalf("public_url not used: %s", body)
	}
}

// Without packages both endpoints answer cleanly: install-links with the
// stable message the page shows, the download with NOT_FOUND.
func TestAgentDistributionWithoutPackages(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	admin := agentCaller{bearer: testAdminToken}
	check := func(label string) {
		t.Helper()
		response := env.do(http.MethodPost, agentInstallLinksPath, `{"agent":"codex","platform":"linux-amd64"}`, admin)
		var body struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &body)
		if response.Code != http.StatusServiceUnavailable || body.Error.Code != "packages_unavailable" || body.Error.Message != agentPackagesMissingMessage {
			t.Fatalf("%s: install-links = %d %s", label, response.Code, response.Body.String())
		}
		if got := agentErrorCode(t, env.do(http.MethodGet, "/api/agent/v1/dl/c2ln/manifest.json", "", agentCaller{})); got != agentapi.CodeNotFound {
			t.Fatalf("%s: download = %s", label, got)
		}
	}
	check("no service")
	withDist(t, env, filepath.Join(t.TempDir(), "missing"), &distClock{now: time.Now()})
	check("missing directory")
	for _, entry := range env.store.Audit() {
		if entry.Event == agentaccess.EventLinkIssued || entry.Event == agentaccess.EventPackageDownloaded {
			t.Fatalf("a refused request was audited: %+v", entry)
		}
	}
}

// TestInstallLinksAreLimitedPerSession: 20 install links per web session
// identity in 10 minutes; the 21st is 429 too_many_requests with Retry-After
// and writes no link_issued row. A developer's budget is separate from the
// administrator's, and the window reopens after 10 minutes.
func TestInstallLinksAreLimitedPerSession(t *testing.T) {
	env := newAgentEnv(t, agentEnvOptions{})
	dir, _ := packTestPackages(t)
	clock := &distClock{now: time.Now()}
	withDist(t, env, dir, clock)
	issued := func() int {
		count := 0
		for _, entry := range env.store.Audit() {
			if entry.Event == agentaccess.EventLinkIssued {
				count++
			}
		}
		return count
	}
	admin := agentCaller{bearer: testAdminToken}
	body := `{"agent":"codex","platform":"windows-amd64"}`
	for index := 0; index < agentdist.InstallLinksPerWindow; index++ {
		if response := env.do(http.MethodPost, agentInstallLinksPath, body, admin); response.Code != http.StatusOK {
			t.Fatalf("link %d = %d %s", index+1, response.Code, response.Body.String())
		}
	}
	for index := 0; index < 180; index++ {
		response := env.do(http.MethodPost, agentInstallLinksPath, body, admin)
		var refused struct {
			Error struct{ Code string } `json:"error"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &refused)
		if response.Code != http.StatusTooManyRequests || refused.Error.Code != "too_many_requests" || response.Header().Get("Retry-After") != "600" {
			t.Fatalf("link beyond the limit = %d %s Retry-After %q", response.Code, response.Body.String(), response.Header().Get("Retry-After"))
		}
	}
	if got := issued(); got != agentdist.InstallLinksPerWindow {
		t.Fatalf("link_issued rows = %d after 200 requests, want %d", got, agentdist.InstallLinksPerWindow)
	}
	// The administrator's web session shares the administrator's budget; a
	// developer has its own.
	if response := env.do(http.MethodPost, agentInstallLinksPath, body, agentCaller{cookie: adminSignIn(t, env.handler)}); response.Code != http.StatusTooManyRequests {
		t.Fatalf("admin cookie after the admin token's 20 = %d", response.Code)
	}
	_, developer := issueAgentDeveloper(t, env)
	if response := env.do(http.MethodPost, agentInstallLinksPath, body, agentCaller{cookie: developer}); response.Code != http.StatusOK {
		t.Fatalf("developer's first link = %d %s", response.Code, response.Body.String())
	}
	clock.now = clock.now.Add(10 * time.Minute)
	if response := env.do(http.MethodPost, agentInstallLinksPath, body, admin); response.Code != http.StatusOK {
		t.Fatalf("after the window = %d", response.Code)
	}
}
