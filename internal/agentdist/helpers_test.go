package agentdist

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

// realSkillDir is the Skill source in this repository.
var realSkillDir = filepath.Join("..", "..", "skill", SkillName)

// testAdminToken is a placeholder, not a real token.
const testAdminToken = "test-admin-token-0123456789abcdef"

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fakeSkill writes a minimal Skill source with the client's version.
func fakeSkill(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "skill")
	writeTestFile(t, filepath.Join(dir, "SKILL.md"), "---\r\nname: llmapi-audit\r\ndescription: test\r\n---\r\nbody\r\n")
	writeTestFile(t, filepath.Join(dir, "VERSION"), agentapi.LatestVersion+"\n")
	writeTestFile(t, filepath.Join(dir, "references", "requests.md"), "# requests\n")
	return dir
}

// fakeBinaries writes one placeholder binary per platform.
func fakeBinaries(t *testing.T) map[Platform]string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bin")
	binaries := map[Platform]string{}
	for _, platform := range Platforms {
		path := filepath.Join(dir, "llmaudit-"+platform.String())
		writeTestFile(t, path, "fake client binary for "+platform.String()+"\n")
		binaries[platform] = path
	}
	return binaries
}

// packedDir packs the fake Skill into a fresh directory.
func packedDir(t *testing.T) (string, *Manifest) {
	t.Helper()
	out := filepath.Join(t.TempDir(), PackageDirName)
	manifest, err := Pack(PackOptions{SkillDir: fakeSkill(t), Binaries: fakeBinaries(t), OutDir: out})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return out, manifest
}

// clock is an adjustable test clock.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time             { return c.now }
func (c *clock) advance(step time.Duration) { c.now = c.now.Add(step) }

func newClock() *clock {
	return &clock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
}
