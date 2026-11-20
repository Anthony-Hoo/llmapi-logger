//go:build !windows

package agentcli

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// TestLooseCredentialStoreIsTightened: a state directory or credentials.json
// that group or others can access is made private (0700, 0600) before the
// credentials are read or replaced; the content is never printed.
func TestLooseCredentialStoreIsTightened(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(h.home, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.home, 0o777); err != nil {
		t.Fatal(err)
	}
	server := newFakeServer(t, nil)
	h.saveLogin(server.URL)
	assertPrivateDir(t, h.home)
	path := filepath.Join(h.home, credentialsFile)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.home, 0o755); err != nil {
		t.Fatal(err)
	}
	creds, err := loadCredentials(h.env, true)
	if err != nil || creds.Token != testToken {
		t.Fatalf("load after tightening: %v", err)
	}
	assertPrivate(t, path)
	assertPrivateDir(t, h.home)

	// Through a command: whoami tightens before it reads the token, and
	// neither stream shows the token.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	h.run("whoami")
	assertPrivate(t, path)
	if strings.Contains(h.stdout.String()+h.stderr.String(), testToken) {
		t.Fatal("the token was printed")
	}
}

// TestSecurePrivateStateFailureNamesPathAndModes: when tightening an entry
// the user owns fails, the command stops with LOCAL_FILE_ERROR naming the
// path and the modes. A kernel file others can read whose mode cannot be
// changed, not even by root, stands for it; it must be owned by the test's
// user (the container runs as root), because an entry of another user is
// refused before any change is tried.
func TestSecurePrivateStateFailureNamesPathAndModes(t *testing.T) {
	target := ""
	for _, candidate := range []string{"/proc/version", "/proc/sys/kernel/osrelease", "/sys/kernel/uevent_seqnum", "/sys/class/net/lo/address"} {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 == 0 {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
			continue
		}
		if os.Chmod(candidate, info.Mode().Perm()) != nil {
			target = candidate
			break
		}
	}
	if target == "" {
		t.Skip("no file of this user readable by others whose mode cannot be changed; the failure cannot be forced here")
	}
	exists, problem := inspectPrivate(target, false, 0o600, true)
	if !exists || problem != problemMode {
		t.Fatalf("inspectPrivate(%s) = %v, %q", target, exists, problem)
	}
	cliErr := storeError(target, problem, 0o600)
	if cliErr.Code != "LOCAL_FILE_ERROR" || cliErr.Details["path"] != target || cliErr.Details["required_mode"] != "0600" ||
		cliErr.Details["reason"] != problemMode || !strings.Contains(cliErr.Hint, "0600") || !strings.Contains(cliErr.Hint, "0700") {
		t.Fatalf("err %#v", cliErr)
	}
	if strings.Contains(cliErr.Message+cliErr.Hint, "Linux version") {
		t.Fatal("the file's content was printed")
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode() & (os.ModePerm | os.ModeSticky)
}

// TestCredentialStoreLinksAreRefused: a state directory or credentials.json
// that is a symbolic link is refused with LOCAL_FILE_ERROR (reason symlink,
// hint to point LLMAUDIT_HOME at a real directory), and the link's target
// keeps its mode: nothing is followed, read or changed.
func TestCredentialStoreLinksAreRefused(t *testing.T) {
	server := newFakeServer(t, nil)

	// The state directory is a link to another directory.
	h := newHarness(t)
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(shared, 0o755)
	writeFile(t, filepath.Join(shared, credentialsFile), `{"server":"`+server.URL+`","token":"`+testToken+`"}`)
	_ = os.Chmod(filepath.Join(shared, credentialsFile), 0o644)
	if err := os.Symlink(shared, h.home); err != nil {
		t.Fatal(err)
	}
	assertVersionDegrades(t, h)
	for _, args := range [][]string{{"whoami"}, {"login", "--no-browser"}, {"login", "--server", server.URL, "--no-browser"}} {
		body := h.expectFailure(h.run(args...), "LOCAL_FILE_ERROR", 1)
		if body.Details["reason"] != problemSymlink || body.Details["path"] != h.home || !strings.Contains(body.Hint, "LLMAUDIT_HOME") {
			t.Fatalf("%v: %+v", args, body)
		}
	}
	if err := saveCredentials(h.env, &credentials{Server: server.URL, Token: testToken}); err == nil {
		t.Fatal("credentials were saved through a linked state directory")
	}
	if modeOf(t, shared) != 0o755 || modeOf(t, filepath.Join(shared, credentialsFile)) != 0o644 || len(server.recorded()) != 0 {
		t.Fatalf("the link's target changed (%v, %v) or the server was asked", modeOf(t, shared), modeOf(t, filepath.Join(shared, credentialsFile)))
	}

	// credentials.json is a link to a file of the user.
	h = newHarness(t)
	if err := os.Mkdir(h.home, 0o700); err != nil {
		t.Fatal(err)
	}
	other := writeFile(t, filepath.Join(t.TempDir(), "public.txt"), "public notes")
	_ = os.Chmod(other, 0o644)
	if err := os.Symlink(other, filepath.Join(h.home, credentialsFile)); err != nil {
		t.Fatal(err)
	}
	body := h.expectFailure(h.run("whoami"), "LOCAL_FILE_ERROR", 1)
	if body.Details["reason"] != problemSymlink || body.Details["path"] != filepath.Join(h.home, credentialsFile) {
		t.Fatalf("%+v", body)
	}
	if err := saveCredentials(h.env, &credentials{Server: server.URL, Token: testToken}); err == nil {
		t.Fatal("credentials were written over a link")
	}
	if data, _ := os.ReadFile(other); modeOf(t, other) != 0o644 || string(data) != "public notes" {
		t.Fatalf("the link's target changed: mode %v, %q", modeOf(t, other), data)
	}
}

// TestSharedStateDirectoryIsRefused: LLMAUDIT_HOME naming a sticky shared
// directory (as /tmp is) is refused, never changed; with nothing saved a
// read command answers NOT_LOGGED_IN and changes nothing either.
func TestSharedStateDirectoryIsRefused(t *testing.T) {
	h := newHarness(t)
	if err := os.Mkdir(h.home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.home, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	h.expectFailure(h.run("whoami"), "NOT_LOGGED_IN", 4)
	server := newFakeServer(t, nil)
	if err := saveCredentials(h.env, &credentials{Server: server.URL, Token: testToken}); err == nil {
		t.Fatal("credentials were saved into a shared directory")
	} else if cliErr, ok := err.(*cliError); !ok || cliErr.Details["reason"] != problemShared {
		t.Fatalf("err %#v", err)
	}
	if modeOf(t, h.home) != 0o777|os.ModeSticky {
		t.Fatalf("the shared directory changed to %v", modeOf(t, h.home))
	}
	if _, err := os.Lstat(filepath.Join(h.home, credentialsFile)); err == nil {
		t.Fatal("a credentials file was written")
	}
	// Credentials someone placed there are not used either.
	writeFile(t, filepath.Join(h.home, credentialsFile), `{"server":"`+server.URL+`","token":"`+testToken+`"}`)
	body := h.expectFailure(h.run("whoami"), "LOCAL_FILE_ERROR", 1)
	if body.Details["reason"] != problemShared || modeOf(t, h.home) != 0o777|os.ModeSticky || len(server.recorded()) != 0 {
		t.Fatalf("%+v, mode %v", body, modeOf(t, h.home))
	}
}

// TestStateDirectoryOfAnotherUserIsRefused: a state directory owned by
// another user is refused and not changed. Creating one needs root (the
// Linux test container).
func TestStateDirectoryOfAnotherUserIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a directory to another user")
	}
	h := newHarness(t)
	if err := os.Mkdir(h.home, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(h.home, 0o755)
	server := newFakeServer(t, nil)
	writeFile(t, filepath.Join(h.home, credentialsFile), `{"server":"`+server.URL+`","token":"`+testToken+`"}`)
	if err := os.Chown(h.home, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	body := h.expectFailure(h.run("whoami"), "LOCAL_FILE_ERROR", 1)
	if body.Details["reason"] != problemNotOwned || modeOf(t, h.home) != 0o755 || len(server.recorded()) != 0 {
		t.Fatalf("%+v, mode %v", body, modeOf(t, h.home))
	}
}

// TestConfigFileIsCheckedLikeCredentials (contract section 0.1 item 164):
// config.json names the CA the client trusts with the token, so a link, an
// entry that is not a regular file, or a file of another user is refused
// with LOCAL_FILE_ERROR naming the path and reason, is never read, and no
// request is sent; a loose mode of the user's own file is tightened by a
// command that uses the token and only reported by version.
func TestConfigFileIsCheckedLikeCredentials(t *testing.T) {
	server := newFakeServer(t, nil)
	config := `{"ca_file":"/nonexistent-test-ca.pem"}`
	refused := func(h *harness, reason string, args ...string) {
		t.Helper()
		body := h.expectFailure(h.run(args...), "LOCAL_FILE_ERROR", 1)
		if body.Details["reason"] != reason || body.Details["path"] != filepath.Join(h.home, configFile) ||
			strings.Contains(body.Message, "CA file") || len(server.recorded()) != 0 {
			t.Fatalf("%v: %+v, %d requests", args, body, len(server.recorded()))
		}
	}

	// A link to a file elsewhere.
	h := newHarness(t)
	h.saveLogin(server.URL)
	elsewhere := writeFile(t, filepath.Join(t.TempDir(), "elsewhere.json"), config)
	_ = os.Chmod(elsewhere, 0o644)
	if err := os.Symlink(elsewhere, filepath.Join(h.home, configFile)); err != nil {
		t.Fatal(err)
	}
	refused(h, problemSymlink, "whoami")
	refused(h, problemSymlink, "login", "--server", server.URL, "--no-browser")
	if modeOf(t, elsewhere) != 0o644 {
		t.Fatalf("the link's target changed to %v", modeOf(t, elsewhere))
	}

	// A directory.
	h = newHarness(t)
	h.saveLogin(server.URL)
	if err := os.Mkdir(filepath.Join(h.home, configFile), 0o700); err != nil {
		t.Fatal(err)
	}
	refused(h, problemNotFile, "whoami")

	// The user's own config.json naming a CA file in the state directory
	// that is a link: the CA file gets the same checks.
	h = newHarness(t)
	h.saveLogin(server.URL)
	caLink := filepath.Join(h.home, "ca.pem")
	if err := os.Symlink(elsewhere, caLink); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(h.home, configFile), `{"ca_file":"`+caLink+`"}`)
	body := h.expectFailure(h.run("whoami"), "LOCAL_FILE_ERROR", 1)
	if body.Details["reason"] != problemSymlink || body.Details["path"] != caLink || strings.Contains(body.Message, "PEM") || len(server.recorded()) != 0 {
		t.Fatalf("CA file link: %+v", body)
	}

	// The user's own file others can write: tightened by whoami, reported
	// (not changed) by version.
	h = newHarness(t)
	h.saveLogin(server.URL)
	own := writeFile(t, filepath.Join(h.home, configFile), `{}`)
	_ = os.Chmod(own, 0o666)
	assertVersionDegrades(t, h)
	if modeOf(t, own) != 0o666 || len(server.recorded()) != 0 {
		t.Fatalf("version changed config.json (%v) or asked the server", modeOf(t, own))
	}
	if exit := h.run("whoami"); exit != 0 {
		t.Fatalf("whoami with the user's own loose config.json: exit %d %s", exit, h.stderr.String())
	}
	assertPrivate(t, own)
}

// TestConfigFileOfAnotherUserIsNotTrusted is the end-to-end case: another
// user who can write to a loose state directory plants config.json naming
// their own CA. whoami tightens the directory, refuses config.json
// (not_owned) and never sends the token to the server that CA vouches for;
// login refuses it before anyone is asked to approve. Needs root to give a
// file to another user (the Linux test container).
func TestConfigFileOfAnotherUserIsNotTrusted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give a file to another user")
	}
	var mu sync.Mutex
	var authorizations []string
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		authorizations = append(authorizations, request.Header.Get("Authorization"))
		mu.Unlock()
		defaultResponder(writer, request, nil)
	}))
	t.Cleanup(tlsServer.Close)
	caFile := writeFile(t, filepath.Join(t.TempDir(), "other-ca.pem"), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw})))

	h := newHarness(t)
	h.saveLogin(tlsServer.URL)
	_ = os.Chmod(h.home, 0o777)
	planted := writeFile(t, filepath.Join(h.home, configFile), `{"ca_file":"`+caFile+`"}`)
	if err := os.Chown(planted, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		body := h.expectFailure(h.run("whoami"), "LOCAL_FILE_ERROR", 1)
		if body.Details["reason"] != problemNotOwned || body.Details["path"] != planted {
			t.Fatalf("whoami %d: %+v", run, body)
		}
	}
	assertPrivateDir(t, h.home)
	opened := false
	h.env.OpenBrowser = func(string) error { opened = true; return nil }
	body := h.expectFailure(h.run("login", "--server", tlsServer.URL), "LOCAL_FILE_ERROR", 1)
	if body.Details["reason"] != problemNotOwned || opened {
		t.Fatalf("login: %+v, browser opened %v", body, opened)
	}
	asked := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(authorizations)
	}
	if asked() != 0 {
		t.Fatalf("the server trusted through the planted CA was asked %d times", asked())
	}
	if info, err := os.Lstat(planted); err != nil || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Uid != 4242 {
		t.Fatalf("the planted file changed: %v %v", info, err)
	}

	// The user's own config.json names ca.pem in the state directory, and
	// another user plants that file while the directory is loose.
	h = newHarness(t)
	h.saveLogin(tlsServer.URL)
	_ = os.Chmod(h.home, 0o777)
	plantedCA := filepath.Join(h.home, "ca.pem")
	data, _ := os.ReadFile(caFile)
	writeFile(t, plantedCA, string(data))
	if err := os.Chown(plantedCA, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(h.home, configFile), `{"ca_file":"`+plantedCA+`"}`)
	body = h.expectFailure(h.run("whoami"), "LOCAL_FILE_ERROR", 1)
	if body.Details["reason"] != problemNotOwned || body.Details["path"] != plantedCA {
		t.Fatalf("planted CA file: %+v", body)
	}
	if asked() != 0 {
		t.Fatalf("the server trusted through the planted CA file was asked %d times", asked())
	}
}

// TestOnlyCredentialCommandsTighten: version and --help change nothing; a
// command that uses the token tightens the user's own loose store; the
// parent of the state directory is never created or changed.
func TestOnlyCredentialCommandsTighten(t *testing.T) {
	server := newFakeServer(t, nil)
	h := newHarness(t)
	h.saveLogin(server.URL)
	path := filepath.Join(h.home, credentialsFile)
	_ = os.Chmod(h.home, 0o755)
	_ = os.Chmod(path, 0o644)
	for _, args := range [][]string{{"version"}, {"--help"}, {"whoami", "--help"}, {"requests", "list", "--help"}} {
		h.run(args...)
		if modeOf(t, h.home) != 0o755 || modeOf(t, path) != 0o644 {
			t.Fatalf("%v changed the store: %v %v", args, modeOf(t, h.home), modeOf(t, path))
		}
	}
	// version reports the loose store instead of using it.
	assertVersionDegrades(t, h)
	if modeOf(t, h.home) != 0o755 || modeOf(t, path) != 0o644 || len(server.recorded()) != 0 {
		t.Fatalf("version changed the store or asked the server: %v %v", modeOf(t, h.home), modeOf(t, path))
	}
	if exit := h.run("whoami"); exit != 0 {
		t.Fatalf("whoami exit %d: %s", exit, h.stderr.String())
	}
	assertPrivateDir(t, h.home)
	assertPrivate(t, path)
	if exit := h.run("version"); exit != 0 {
		t.Fatalf("version after tightening: exit %d %s", exit, h.stderr.String())
	}

	// The parent of a missing state directory is not created.
	h = newHarness(t)
	parent := filepath.Join(t.TempDir(), "missing")
	h.home = filepath.Join(parent, "state")
	if err := saveCredentials(h.env, &credentials{Server: server.URL, Token: testToken}); err == nil {
		t.Fatal("saved under a missing parent")
	}
	if _, err := os.Lstat(parent); err == nil {
		t.Fatal("the parent of the state directory was created")
	}
}

// assertVersionDegrades: version with a credential store it may not use
// still exits 0 with the client version, does not ask the server, and says
// why in meta.
func assertVersionDegrades(t *testing.T, h *harness) {
	t.Helper()
	if exit := h.run("version"); exit != 0 {
		t.Fatalf("version: exit %d %s", exit, h.stderr.String())
	}
	envelope := h.success()
	var data struct {
		Client string           `json:"cli_version"`
		Server *json.RawMessage `json:"server"`
	}
	var meta struct {
		Complete bool   `json:"complete"`
		Reason   string `json:"incomplete_reason"`
	}
	_ = json.Unmarshal(envelope["data"], &data)
	_ = json.Unmarshal(envelope["meta"], &meta)
	if data.Client != Version || data.Server != nil || meta.Complete || meta.Reason != versionLocalStateUnusable ||
		!strings.Contains(string(envelope["next_actions"]), "llmaudit whoami") {
		t.Fatalf("version: %s", h.stdout.String())
	}
}
