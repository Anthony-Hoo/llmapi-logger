package integration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/agentcli"
	"llmapi-logger/internal/agentdist"
	"llmapi-logger/internal/app"
	"llmapi-logger/internal/config"
)

// The agent access journeys of doc/features/25-agent-access.md, end to end:
// the real assembled application on PostgreSQL, the real llmaudit code run
// in-process against it over loopback HTTP, the web session of a person
// approving in the browser (driven here by plain HTTP calls the page would
// make), and real packages built by the packer.

const journeyAdminToken = "integration-admin-token"

var (
	authorizeURLPattern = regexp.MustCompile(`https?://\S+/ui/\?\S+`)
	installLinkPattern  = regexp.MustCompile(`"(https?://[^"]+/api/agent/v1/dl/([A-Za-z0-9_-]+)/)([A-Za-z0-9._-]+)"`)
)

// journeyConfig is the integration configuration with agent access and
// every optional read module on.
func journeyConfig(t *testing.T, upstreamURL string) config.Config {
	t.Helper()
	cfg := loadConfig(t, upstreamURL, "/v1/chat/completions", false)
	cfg.Insights.Enabled = true
	// Weekly reports need the NewAPI management identity; the fake gateway
	// does not answer its caller lookups, which leaves callers unresolved.
	cfg.NewAPI.AccessToken = "integration-newapi-access-token"
	cfg.NewAPI.UserID = 1
	cfg.OrgReports.Enabled = true
	cfg.SessionAnalysis.Enabled = true
	cfg.AgentAccess.Enabled = true
	cfg.AgentAccess.AllowWrite = true
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("journey configuration: %v", err)
	}
	return cfg
}

// packJourneyPackages builds a package directory with the packer's library
// functions from a minimal Skill and placeholder binaries.
func packJourneyPackages(t *testing.T) (string, *agentdist.Manifest) {
	t.Helper()
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	skill := filepath.Join(root, "skill")
	write(filepath.Join(skill, "SKILL.md"), "---\nname: llmapi-audit\ndescription: journey test\n---\nbody\n")
	write(filepath.Join(skill, "VERSION"), agentapi.LatestVersion+"\n")
	write(filepath.Join(skill, "references", "requests.md"), "# requests\n")
	binaries := map[agentdist.Platform]string{}
	for _, platform := range agentdist.Platforms {
		path := filepath.Join(root, "bin", "llmaudit-"+platform.String())
		write(path, "placeholder client for "+platform.String()+"\n")
		binaries[platform] = path
	}
	out := filepath.Join(root, agentdist.PackageDirName)
	manifest, err := agentdist.Pack(agentdist.PackOptions{SkillDir: skill, Binaries: binaries, OutDir: out})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return out, manifest
}

// webCall is one management API call with a web session cookie.
func webCall(t *testing.T, client *http.Client, method, target string, cookie *http.Cookie, body string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

// adminWebSession signs in to the web UI with the admin token, as the sign-in
// page does.
func adminWebSession(t *testing.T, client *http.Client, adminURL string) *http.Cookie {
	t.Helper()
	response, err := client.Post(adminURL+"/api/v1/session", "application/json", strings.NewReader(`{"token":"`+journeyAdminToken+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || len(response.Cookies()) != 1 {
		t.Fatalf("admin web sign-in = %d, cookies %d", response.StatusCode, len(response.Cookies()))
	}
	return response.Cookies()[0]
}

// journeyCLI is llmaudit with its own state directory.
type journeyCLI struct {
	t      *testing.T
	home   string
	stdout *synchronizedLogBuffer
	stderr *synchronizedLogBuffer
}

func newJourneyCLI(t *testing.T) *journeyCLI {
	return &journeyCLI{t: t, home: filepath.Join(t.TempDir(), "llmaudit-home")}
}

func (cli *journeyCLI) env(stdin io.Reader) *agentcli.Env {
	cli.stdout, cli.stderr = &synchronizedLogBuffer{}, &synchronizedLogBuffer{}
	return &agentcli.Env{
		Stdin: stdin, Stdout: cli.stdout, Stderr: cli.stderr,
		Getenv: func(name string) string {
			if name == "LLMAUDIT_HOME" {
				return cli.home
			}
			return ""
		},
		HomeDir:          func() (string, error) { return "", errors.New("LLMAUDIT_HOME is set") },
		Hostname:         func() (string, error) { return "journey-host", nil },
		UTCOffsetMinutes: func() int { return 0 },
		Now:              time.Now,
	}
}

// journeyEnvelope is what llmaudit printed: the success envelope on stdout or
// the failure envelope on stderr.
type journeyEnvelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Meta  *agentapi.Meta  `json:"meta"`
	Error *struct {
		Code    agentapi.Code  `json:"code"`
		Details map[string]any `json:"details"`
	} `json:"error"`
}

func (cli *journeyCLI) run(args ...string) (int, journeyEnvelope) {
	cli.t.Helper()
	exit := agentcli.Run(args, cli.env(strings.NewReader("")))
	return exit, cli.envelope(exit, args)
}

func (cli *journeyCLI) envelope(exit int, args []string) journeyEnvelope {
	cli.t.Helper()
	output := cli.stdout.snapshot()
	if exit != 0 {
		output = cli.stderr.snapshot()
	}
	var envelope journeyEnvelope
	if err := json.Unmarshal(lastLine(output), &envelope); err != nil {
		cli.t.Fatalf("llmaudit %s (exit %d) printed no envelope: stdout %q stderr %q", strings.Join(args, " "), exit, cli.stdout.snapshot(), cli.stderr.snapshot())
	}
	return envelope
}

func lastLine(output []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(output), []byte("\n"))
	return lines[len(lines)-1]
}

// ok runs a command that must succeed and returns its data.
func (cli *journeyCLI) ok(args ...string) map[string]any {
	cli.t.Helper()
	exit, envelope := cli.run(args...)
	if exit != 0 || !envelope.OK {
		cli.t.Fatalf("llmaudit %s = exit %d: %s", strings.Join(args, " "), exit, cli.stderr.snapshot())
	}
	var data map[string]any
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		cli.t.Fatalf("llmaudit %s data = %s", strings.Join(args, " "), envelope.Data)
	}
	return data
}

// read runs a read command: it must succeed and carry the three meta fields.
func (cli *journeyCLI) read(args ...string) map[string]any {
	cli.t.Helper()
	data := cli.ok(args...)
	if !bytes.Contains(cli.stdout.snapshot(), []byte(`"incomplete_reason"`)) {
		cli.t.Fatalf("llmaudit %s returned no meta: %s", strings.Join(args, " "), cli.stdout.snapshot())
	}
	return data
}

// fails runs a command that must fail with code and exit.
func (cli *journeyCLI) fails(code agentapi.Code, args ...string) {
	cli.t.Helper()
	exit, envelope := cli.run(args...)
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != code || exit != agentapi.ExitCode(code) {
		cli.t.Fatalf("llmaudit %s = exit %d %s, want %s (exit %d)", strings.Join(args, " "), exit, cli.stderr.snapshot(), code, agentapi.ExitCode(code))
	}
}

// approval is what the person in the browser decides for one login.
type approval func(authorize url.Values) (code string)

// login runs `llmaudit login --no-browser` and answers it like a person: the
// page is opened at the printed address, approve decides, and the one-time
// code is typed into the terminal (here: a pipe).
func (cli *journeyCLI) login(server string, approve approval, extra ...string) map[string]any {
	cli.t.Helper()
	reader, writer := io.Pipe()
	defer writer.Close()
	args := append([]string{"login", "--server", server, "--no-browser"}, extra...)
	env := cli.env(reader)
	done := make(chan int, 1)
	go func() { done <- agentcli.Run(args, env) }()

	deadline := time.Now().Add(integrationTimeout)
	var address string
	for address == "" {
		address = authorizeURLPattern.FindString(string(cli.stderr.snapshot()))
		if address != "" {
			break
		}
		select {
		case exit := <-done:
			cli.t.Fatalf("login exited %d before printing the address: %s", exit, cli.stderr.snapshot())
		default:
		}
		if time.Now().After(deadline) {
			cli.t.Fatalf("login printed no address: %s", cli.stderr.snapshot())
		}
		time.Sleep(10 * time.Millisecond)
	}
	parsed, err := url.Parse(address)
	if err != nil || !strings.HasPrefix(address, server+"/ui/?") {
		cli.t.Fatalf("authorization address %q", address)
	}
	code := approve(parsed.Query())
	if _, err := io.WriteString(writer, code+"\n"); err != nil {
		cli.t.Fatal(err)
	}
	var exit int
	select {
	case exit = <-done:
	case <-time.After(integrationTimeout):
		cli.t.Fatal("login did not finish")
	}
	envelope := cli.envelope(exit, args)
	if exit != 0 || !envelope.OK {
		cli.t.Fatalf("login = exit %d %s", exit, cli.stderr.snapshot())
	}
	if bytes.Contains(cli.stdout.snapshot(), []byte(agentapi.TokenPrefix)) {
		cli.t.Fatal("login printed the token")
	}
	var data map[string]any
	_ = json.Unmarshal(envelope.Data, &data)
	return data
}

// savedToken is the token llmaudit stored. Only the test reads it: it proves
// below that the server refuses the token itself after logout.
func (cli *journeyCLI) savedToken() string {
	cli.t.Helper()
	data, err := os.ReadFile(filepath.Join(cli.home, "credentials.json"))
	if err != nil {
		cli.t.Fatal(err)
	}
	var credentials struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(data, &credentials); err != nil || !agentapi.ValidTokenFormat(credentials.Token) {
		cli.t.Fatal("credentials.json holds no token")
	}
	return credentials.Token
}

// pageApproval approves a paste-mode login from a web session with tier,
// posting exactly what the authorization page posts, and remembers the code.
func pageApproval(t *testing.T, client *http.Client, adminURL string, cookie *http.Cookie, tier string, codes *[]string) approval {
	return func(authorize url.Values) string {
		t.Helper()
		if authorize.Get("agent_authorize") != "1" || authorize.Get("mode") != "paste" || authorize.Has("port") {
			t.Fatalf("authorization parameters %v", authorize)
		}
		body, _ := json.Marshal(map[string]any{
			"challenge": authorize.Get("challenge"), "mode": "paste", "device_name": authorize.Get("device"),
			"cli_version": authorize.Get("cli"), "tier": tier, "decision": "approve",
		})
		status, response := webCall(t, client, http.MethodPost, adminURL+"/api/v1/agent-access/authorizations", cookie, string(body))
		var approved struct {
			Code        string `json:"code"`
			ExpiresIn   int    `json:"expires_in"`
			RedirectURI string `json:"redirect_uri"`
		}
		if status != http.StatusOK || json.Unmarshal(response, &approved) != nil || approved.Code == "" || approved.ExpiresIn != 300 || approved.RedirectURI != "" {
			t.Fatalf("approval = %d %s", status, response)
		}
		*codes = append(*codes, approved.Code)
		return approved.Code
	}
}

// facadeCall sends one raw facade request with a bearer token.
func facadeCall(t *testing.T, client *http.Client, method, target, token string) (int, agentapi.Response) {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope agentapi.Response
	_ = json.NewDecoder(response.Body).Decode(&envelope)
	return response.StatusCode, envelope
}

func download(t *testing.T, client *http.Client, target string) (int, []byte) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatalf("download %s: %v", target, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

type journeyAuditRow struct {
	event, role, command, objectKind, objectID, changedKeys, outcome, errorCode string
	tokenID                                                                     *int64
}

func journeyAuditRows(t *testing.T, dsn string) []journeyAuditRow {
	t.Helper()
	db := openAuditDatabase(t, dsn)
	defer db.Close()
	rows, err := db.Query(`SELECT event, token_id, coalesce(role, ''), coalesce(command, ''), coalesce(object_kind, ''), coalesce(object_id, ''),
		coalesce(changed_keys, ''), outcome, coalesce(error_code, '') FROM agent_audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []journeyAuditRow
	for rows.Next() {
		var row journeyAuditRow
		if err := rows.Scan(&row.event, &row.tokenID, &row.role, &row.command, &row.objectKind, &row.objectID, &row.changedKeys, &row.outcome, &row.errorCode); err != nil {
			t.Fatal(err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAgentJourneyAdministrator(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-local","model":"model-result","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	upstream := newAPIWithTokenLogin(t, responseBody)
	cfg := journeyConfig(t, upstream.URL)
	packageDir, manifest := packJourneyPackages(t)
	running := startApp(t, cfg, app.WithAgentPackageDir(packageDir))
	client := &http.Client{Timeout: integrationTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// A record for the reads, as the neighbouring tests create them.
	proxyChatRequest(t, client, running.baseURL, developerKeyAlpha, "model-journey")
	audits := waitForParsedAudits(t, client, running.adminURL, 1)

	// The administrator signs in to the web UI and approves a read-write
	// login in paste mode; the code goes to llmaudit through a pipe.
	cookie := adminWebSession(t, client, running.adminURL)
	var codes []string
	cli := newJourneyCLI(t)
	approve := pageApproval(t, client, running.adminURL, cookie, "write", &codes)
	login := cli.login(running.adminURL, func(authorize url.Values) string {
		// login --write only preselects the tier on the page.
		if authorize.Get("tier") != "write" || authorize.Get("device") != "journey-host" || authorize.Get("cli") != agentcli.Version {
			t.Fatalf("authorization parameters %v", authorize)
		}
		return approve(authorize)
	}, "--write")
	if login["role"] != "admin" || login["tier"] != "write" || login["credentials_saved"] != true || login["server"] != running.adminURL {
		t.Fatalf("login data %v", login)
	}
	token := cli.savedToken()

	whoami := cli.read("whoami")
	features, _ := whoami["features"].(map[string]any)
	if whoami["role"] != "admin" || whoami["tier"] != "write" || whoami["device_name"] != "journey-host" ||
		features["insights"] != true || features["org_reports"] != true || features["session_analysis"] != true || features["write_allowed"] != true {
		t.Fatalf("whoami %v", whoami)
	}

	// One read from each group.
	list := cli.read("requests", "list", "--since", "1h")
	items, _ := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["audit_id"] != audits[0].AuditID {
		t.Fatalf("requests list %v", list)
	}
	if record := cli.read("requests", "get", audits[0].AuditID); record["audit_id"] != audits[0].AuditID {
		t.Fatalf("requests get %v", record)
	} else {
		assertDetailMatchesListItem(t, items[0].(map[string]any), record)
	}
	cli.read("usage", "overview", "--since", "1d", "--group-by", "model")
	cli.read("weekly", "trend")
	cli.read("analysis", "overview", "--since", "7d")
	cli.read("config", "show", "--kind", "ua-rule")

	// A disabled user-agent rule: plan, apply, read back.
	plan := cli.ok("config", "set", "--kind", "ua-rule", "--set", "name=journey rule", "--set", "enabled=false",
		"--set", "model_pattern=^journey-", "--set", "user_agent_pattern=^journey/")
	planID, _ := plan["plan_id"].(string)
	if !strings.HasPrefix(planID, "pln_") {
		t.Fatalf("plan %v", plan)
	}
	applied := cli.ok("apply", planID)
	ruleID, _ := applied["id"].(string)
	target, _ := applied["target"].(map[string]any)
	version, _ := target["version"].(string)
	if applied["applied"] != true || ruleID == "" || version == "" {
		t.Fatalf("apply %v", applied)
	}
	findRule := func() map[string]any {
		t.Helper()
		shown := cli.read("config", "show", "--kind", "ua-rule")
		rules, _ := shown["items"].([]any)
		for _, rule := range rules {
			if entry := rule.(map[string]any); fmt.Sprint(entry["id"]) == ruleID {
				return entry
			}
		}
		t.Fatalf("rule %s not in %v", ruleID, shown)
		return nil
	}
	if rule := findRule(); rule["enabled"] != false || rule["version"] != version {
		t.Fatalf("rule after apply %v, want version %s", rule, version)
	}

	// A change planned against that version, then made stale by an edit on
	// the web route, is refused when applied.
	stale := cli.ok("config", "set", "--kind", "ua-rule", "--id", ruleID, "--set", "name=journey rule renamed")
	status, body := webCall(t, client, http.MethodPut, running.adminURL+"/api/v1/user-agent-rules/"+ruleID, cookie,
		`{"name":"journey rule edited on the web","enabled":false,"model_pattern":"^journey-","user_agent_pattern":"^journey/"}`)
	if status != http.StatusOK {
		t.Fatalf("web edit = %d %s", status, body)
	}
	cli.fails(agentapi.CodeVersionConflict, "apply", stale["plan_id"].(string))
	if rule := findRule(); rule["name_untrusted"] != "journey rule edited on the web" && rule["name"] != "journey rule edited on the web" {
		t.Fatalf("rule after the refused apply %v", rule)
	}

	// Install links from the web session, then the signed downloads.
	status, body = webCall(t, client, http.MethodPost, running.adminURL+"/api/v1/agent-access/install-links", cookie, `{"agent":"claude-code","platform":"linux-amd64"}`)
	var link struct {
		Prompt    string `json:"prompt"`
		ExpiresAt string `json:"expires_at"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &link) != nil {
		t.Fatalf("install-links = %d %s", status, body)
	}
	match := installLinkPattern.FindStringSubmatch(link.Prompt)
	if match == nil || !strings.HasPrefix(match[1], running.adminURL+"/api/agent/v1/dl/") {
		t.Fatalf("no download link for %s in the prompt:\n%s", running.adminURL, link.Prompt)
	}
	prefix, signature := match[1], match[2]
	status, served := download(t, client, prefix+agentdist.ManifestFile)
	servedManifest, err := agentdist.ParseManifest(served)
	if status != http.StatusOK || err != nil || servedManifest.Version != manifest.Version || len(servedManifest.Packages) != len(manifest.Packages) {
		t.Fatalf("manifest download = %d %v", status, err)
	}
	pkg, ok := servedManifest.Find(agentdist.Platform{OS: "linux", Arch: "amd64"})
	if !ok || pkg.File != match[3] {
		t.Fatalf("manifest has no linux-amd64 package named %s", match[3])
	}
	status, archive := download(t, client, prefix+pkg.File)
	digest := sha256.Sum256(archive)
	if status != http.StatusOK || int64(len(archive)) != pkg.Size || hex.EncodeToString(digest[:]) != pkg.SHA256 {
		t.Fatalf("package download = %d, %d bytes, digest %x", status, len(archive), digest)
	}
	// A link signed with this deployment's key that has expired.
	signer, err := agentdist.NewSigner(journeyAdminToken, func() time.Time { return time.Now().Add(-time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	expired, _ := signer.Mint()
	if status, envelope := facadeCall(t, client, http.MethodGet, running.adminURL+"/api/agent/v1/dl/"+expired+"/"+agentdist.ManifestFile, ""); status != http.StatusGone ||
		envelope.Error == nil || envelope.Error.Code != agentapi.CodeLinkExpired {
		t.Fatalf("expired link = %d %+v", status, envelope.Error)
	}

	// Logout revokes the token on the server, not only locally.
	if out := cli.ok("logout"); out["revoked"] != true {
		t.Fatalf("logout %v", out)
	}
	if status, envelope := facadeCall(t, client, http.MethodGet, running.adminURL+"/api/agent/v1/whoami", token); status != http.StatusUnauthorized ||
		envelope.Error == nil || envelope.Error.Code != agentapi.CodeTokenRevoked {
		t.Fatalf("whoami with the revoked token = %d %+v", status, envelope.Error)
	}
	cli.fails(agentapi.CodeNotLoggedIn, "whoami")

	// The journey's audit rows exist and hold no token, code, link or key.
	counts := map[string]int{}
	for _, row := range journeyAuditRows(t, cfg.DatabaseURL) {
		counts[row.event]++
		switch row.event {
		case "write_applied":
			if row.objectKind != "ua-rule" || row.objectID != ruleID || row.outcome != "ok" {
				t.Errorf("write_applied row %+v", row)
			}
		case "write_failed":
			if row.objectKind != "ua-rule" || row.objectID != ruleID || row.errorCode != string(agentapi.CodeVersionConflict) || row.outcome != "failed" {
				t.Errorf("write_failed row %+v", row)
			}
		case "link_issued":
			if row.role != "admin" || row.command != "web" || row.objectID != pkg.File || row.tokenID != nil {
				t.Errorf("link_issued row %+v", row)
			}
		case "package_downloaded":
			if row.objectID != pkg.File && row.objectID != agentdist.ManifestFile {
				t.Errorf("package_downloaded row %+v", row)
			}
		}
	}
	for event, want := range map[string]int{
		"authorize_approved": 1, "token_issued": 1, "write_applied": 1, "write_failed": 1,
		"link_issued": 1, "package_downloaded": 2, "token_revoked": 1,
	} {
		if counts[event] != want {
			t.Errorf("%d %s rows, want %d (all: %v)", counts[event], event, want, counts)
		}
	}
	secrets := [][]byte{[]byte(token), []byte(signature), []byte(expired), []byte(journeyAdminToken)}
	for _, code := range codes {
		secrets = append(secrets, []byte(code))
	}
	assertPostgresRowsDoNotContain(t, cfg.DatabaseURL, secrets)
	logs := running.logs.snapshot()
	for _, secret := range secrets {
		if bytes.Contains(logs, secret) {
			t.Fatal("the server log holds a token, code, link signature or the admin token")
		}
	}
}

func TestAgentJourneyDeveloper(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-local","model":"model-result","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	upstream := newAPIWithTokenLogin(t, responseBody)
	cfg := journeyConfig(t, upstream.URL)
	cfg.DeveloperLogin.Enabled = true
	packageDir, _ := packJourneyPackages(t)
	running := startApp(t, cfg, app.WithAgentPackageDir(packageDir))
	client := &http.Client{Timeout: integrationTimeout}

	proxyChatRequest(t, client, running.baseURL, developerKeyAlpha, "model-alpha")
	proxyChatRequest(t, client, running.baseURL, developerKeyBeta, "model-beta")
	var own, foreign string
	for _, item := range waitForParsedAudits(t, client, running.adminURL, 2) {
		switch *item.RequestModel {
		case "model-alpha":
			own = item.AuditID
		case "model-beta":
			foreign = item.AuditID
		}
	}
	if own == "" || foreign == "" {
		t.Fatal("the two records were not found")
	}

	cookie, status := developerLogin(t, client, running.adminURL, developerKeyAlpha)
	if cookie == nil {
		t.Fatalf("developer sign-in = %d", status)
	}
	// A developer cannot be granted the write tier, even though this
	// deployment allows writes.
	status, body := webCall(t, client, http.MethodPost, running.adminURL+"/api/v1/agent-access/authorizations", cookie,
		`{"challenge":"`+strings.Repeat("A", 43)+`","mode":"paste","device_name":"journey-host","cli_version":"`+agentcli.Version+`","tier":"write","decision":"approve"}`)
	if status != http.StatusBadRequest || !strings.Contains(string(body), `"field":"tier"`) {
		t.Fatalf("developer write-tier approval = %d %s", status, body)
	}

	var codes []string
	cli := newJourneyCLI(t)
	login := cli.login(running.adminURL, pageApproval(t, client, running.adminURL, cookie, "read", &codes))
	if login["role"] != "developer" || login["tier"] != "read" {
		t.Fatalf("developer login %v", login)
	}
	token := cli.savedToken()
	whoami := cli.read("whoami")
	identity, _ := whoami["identity"].(map[string]any)
	if whoami["role"] != "developer" || whoami["tier"] != "read" || identity["username"] != "alpha" {
		t.Fatalf("developer whoami %v", whoami)
	}

	list := cli.read("requests", "list", "--since", "1h")
	items, _ := list["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["audit_id"] != own {
		t.Fatalf("developer list %v", list)
	}
	if record := cli.read("requests", "get", own); record["audit_id"] != own {
		t.Fatalf("own record %v", record)
	} else {
		assertDetailMatchesListItem(t, items[0].(map[string]any), record)
	}
	cli.fails(agentapi.CodeNotFound, "requests", "get", foreign)
	cli.fails(agentapi.CodeForbiddenRole, "config", "set", "--kind", "ua-rule", "--set", "name=developer rule", "--set", "enabled=false",
		"--set", "model_pattern=^x-", "--set", "user_agent_pattern=^x/")

	cli.ok("logout")
	if status, envelope := facadeCall(t, client, http.MethodGet, running.adminURL+"/api/agent/v1/whoami", token); status != http.StatusUnauthorized ||
		envelope.Error == nil || envelope.Error.Code != agentapi.CodeTokenRevoked {
		t.Fatalf("developer token after logout = %d %+v", status, envelope.Error)
	}
	secrets := [][]byte{[]byte(token)}
	for _, code := range codes {
		secrets = append(secrets, []byte(code))
	}
	assertPostgresRowsDoNotContain(t, cfg.DatabaseURL, secrets)
}

// assertDetailMatchesListItem: on the real query service every field the
// list item and the detail share has the same value, and the User-Agent the
// list shows is in the detail too (it was once always null there).
func assertDetailMatchesListItem(t *testing.T, item, detail map[string]any) {
	t.Helper()
	for key, want := range item {
		if got, ok := detail[key]; !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("requests get %s = %v, requests list has %v", key, got, want)
		}
	}
	if item["user_agent_untrusted"] == nil {
		t.Errorf("the journey record has no User-Agent in the list: %v", item)
	}
}
