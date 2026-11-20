package agentdist

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPosixWorkRemovalInShell runs the work-directory removal of the POSIX
// prompt in /bin/sh with every path under t.TempDir(): a directory of
// mktemp's shape is removed, and anything else is refused and left alone,
// including paths whose last characters contain a slash or a .. segment.
// It runs where /bin/sh exists (the Linux test container).
func TestPosixWorkRemovalInShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh; runs in the Linux test container")
	}
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	sandbox := t.TempDir()
	run := func(value string) bool {
		command := exec.Command("/bin/sh", "-c", posixWorkRemoval(quote(value)))
		command.Dir = sandbox
		command.Env = []string{"HOME=" + sandbox, "TMPDIR=" + sandbox, "PATH=/usr/bin:/bin"}
		return command.Run() == nil
	}
	mustDir := func(path string) {
		t.Helper()
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(path string) bool {
		_, err := os.Lstat(path)
		return err == nil
	}

	work := filepath.Join(sandbox, "llmapi-audit-install.Ab12Cd34")
	mustDir(filepath.Join(work, "extract", "llmapi-audit"))
	if !run(work) || exists(work) {
		t.Fatalf("the work directory was not removed")
	}

	keep := filepath.Join(sandbox, "x", "keep")
	mustDir(filepath.Join(keep, "data"))
	mustDir(filepath.Join(sandbox, "x", "llmapi-audit-install."))
	mustDir(filepath.Join(sandbox, "x", "llmapi-audit-install.Ab12Cd34", "inner"))
	refused := []string{
		"", "LLMAPI_WORK_DIR", "/", sandbox, keep, "$HOME",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install./../keep",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install.Ab12Cd34/../keep",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install.Ab12Cd34/./",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install.Ab12Cd34/",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install.Ab12Cd34/..",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install.Ab12Cd3",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install.Ab12Cd345",
		filepath.Join(sandbox, "x") + "/llmapi-audit-install.Ab12-d34",
		filepath.Join(sandbox, "x") + "//llmapi-audit-install.Ab12Cd34",
		"x/llmapi-audit-install.Ab12Cd34",
		"llmapi-audit-install.Ab12Cd34",
		"/tmp/llmapi-audit-install.XXXXXXX?",
	}
	for _, value := range refused {
		if run(value) {
			t.Errorf("%q was accepted", value)
		}
	}
	if !exists(filepath.Join(keep, "data")) || !exists(filepath.Join(sandbox, "x", "llmapi-audit-install.Ab12Cd34", "inner")) {
		t.Fatal("a refused path was removed")
	}
	if strings.Contains(posixWorkRemoval(`"x"`), "?") {
		t.Fatal("the guard uses ?, which matches a slash")
	}
}
