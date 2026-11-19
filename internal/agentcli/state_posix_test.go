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
// command stops with LOCAL_FILE_ERROR naming the path and the modes. A
// credentials.json that is a link to a kernel file others can read cannot be
// made private, not even by root.
func TestSecurePrivateStateFailureNamesPathAndModes(t *testing.T) {
	// A file others can read whose mode cannot be changed, not even by
	// root: kernel files on read-only or chmod-refusing mounts. Probing with
	// the file's own mode changes nothing when chmod does succeed.
	target := ""
	for _, candidate := range []string{"/proc/version", "/proc/sys/kernel/osrelease", "/sys/kernel/uevent_seqnum", "/sys/class/net/lo/address"} {
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().Perm()&0o077 != 0 && os.Chmod(candidate, info.Mode().Perm()) != nil {
			target = candidate
			break
		}
	}
	if target == "" {
		t.Skip("no file readable by others whose mode cannot be changed; the failure cannot be forced here")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
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
	if strings.Contains(cliErr.Message+cliErr.Hint, "Linux version") {
		t.Fatal("the file's content was printed")
	}
}
