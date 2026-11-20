//go:build !windows

package agentcli

import (
	"os"
	"path/filepath"
	"strings"
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
	for _, args := range [][]string{{"whoami"}, {"version"}, {"login", "--no-browser"}} {
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
	body := h.expectFailure(h.run("version"), "LOCAL_FILE_ERROR", 1)
	if body.Details["reason"] != problemMode || body.Details["path"] != h.home {
		t.Fatalf("%+v", body)
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
