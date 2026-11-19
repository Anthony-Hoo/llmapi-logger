//go:build !windows

package agentcli

import (
	"os"
	"path/filepath"
	"strings"
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
	creds, err := loadCredentials(h.env)
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

// TestSecurePrivateStateFailureNamesPathAndModes: when tightening fails the
// command stops with LOCAL_FILE_ERROR naming the path and the modes.
func TestSecurePrivateStateFailureNamesPathAndModes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can change the mode of any file; the failure needs an ordinary user")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A credentials.json owned by someone else cannot be chmod-ed; the
	// closest an ordinary user gets is a symlink to a file it does not own.
	target := "/etc/hostname"
	if _, err := os.Stat(target); err != nil {
		t.Skip("no file owned by another user to point at")
	}
	info, _ := os.Stat(target)
	if info.Mode().Perm()&0o077 == 0 {
		t.Skip(target + " is not readable by others")
	}
	if err := os.Symlink(target, filepath.Join(dir, credentialsFile)); err != nil {
		t.Fatal(err)
	}
	err := securePrivateState(dir)
	cliErr, ok := err.(*cliError)
	if !ok || cliErr.Code != "LOCAL_FILE_ERROR" || cliErr.Details["path"] != filepath.Join(dir, credentialsFile) ||
		cliErr.Details["required_mode"] != "0600" || !strings.Contains(cliErr.Hint, "0600") || !strings.Contains(cliErr.Hint, "0700") {
		t.Fatalf("err %#v", err)
	}
}
