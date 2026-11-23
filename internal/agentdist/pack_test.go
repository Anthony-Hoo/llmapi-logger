package agentdist

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"llmapi-logger/internal/agentapi"
)

func TestPackIsReproducible(t *testing.T) {
	skill, binaries := fakeSkill(t), fakeBinaries(t)
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	if _, err := Pack(PackOptions{SkillDir: skill, Binaries: binaries, OutDir: first}); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(PackOptions{SkillDir: skill, Binaries: binaries, OutDir: second}); err != nil {
		t.Fatal(err)
	}
	names := listFiles(t, first)
	if strings.Join(names, ",") != strings.Join(listFiles(t, second), ",") {
		t.Fatal("the two runs wrote different file sets")
	}
	if len(names) != len(Platforms)+1 {
		t.Fatalf("wrote %v", names)
	}
	for _, name := range names {
		left, _ := os.ReadFile(filepath.Join(first, name))
		right, _ := os.ReadFile(filepath.Join(second, name))
		if !bytes.Equal(left, right) {
			t.Fatalf("%s differs between two runs", name)
		}
	}
}

func listFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func TestPackManifestMatchesFiles(t *testing.T) {
	dir, manifest := packedDir(t)
	data, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(data)
	if err != nil {
		t.Fatalf("written manifest is invalid: %v", err)
	}
	if parsed.Version != agentapi.LatestVersion || parsed.MinCompatible != agentapi.MinVersion {
		t.Fatalf("versions %s/%s", parsed.Version, parsed.MinCompatible)
	}
	if len(parsed.Packages) != len(Platforms) {
		t.Fatalf("%d packages", len(parsed.Packages))
	}
	for index, pkg := range parsed.Packages {
		if pkg != manifest.Packages[index] {
			t.Fatalf("returned and written manifests differ at %d", index)
		}
		if pkg.Platform() != Platforms[index] || pkg.File != PackageFileName(agentapi.LatestVersion, Platforms[index]) {
			t.Fatalf("package %d is %+v", index, pkg)
		}
		archive, err := os.ReadFile(filepath.Join(dir, pkg.File))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(archive)
		if hex.EncodeToString(sum[:]) != pkg.SHA256 || int64(len(archive)) != pkg.Size {
			t.Fatalf("%s: digest or size does not match the manifest", pkg.File)
		}
	}
}

func TestPackArchiveLayout(t *testing.T) {
	dir, manifest := packedDir(t)
	for _, pkg := range manifest.Packages {
		reader, err := zip.OpenReader(filepath.Join(dir, pkg.File))
		if err != nil {
			t.Fatal(err)
		}
		binary := "llmapi-audit/scripts/" + pkg.Platform().BinaryName()
		want := []string{
			"llmapi-audit/", "llmapi-audit/SKILL.md", "llmapi-audit/VERSION", "llmapi-audit/references/",
			"llmapi-audit/references/requests.md", "llmapi-audit/scripts/", binary,
		}
		sort.Strings(want)
		var names []string
		for _, file := range reader.File {
			names = append(names, file.Name)
			if !file.Modified.Equal(ArchiveTime) {
				t.Errorf("%s %s: modified %v", pkg.File, file.Name, file.Modified)
			}
			mode := file.Mode()
			switch {
			case strings.HasSuffix(file.Name, "/"):
				if !mode.IsDir() || mode.Perm() != 0o755 {
					t.Errorf("%s %s: mode %v", pkg.File, file.Name, mode)
				}
			case file.Name == binary:
				if mode.Perm() != 0o755 || !mode.IsRegular() {
					t.Errorf("%s: binary mode %v", pkg.File, mode)
				}
			default:
				if mode.Perm() != 0o644 || !mode.IsRegular() {
					t.Errorf("%s %s: mode %v", pkg.File, file.Name, mode)
				}
			}
			if file.Name == "llmapi-audit/SKILL.md" {
				content := readZipFile(t, file)
				if strings.Contains(content, "\r") {
					t.Errorf("%s: SKILL.md keeps CR line endings", pkg.File)
				}
			}
			if file.Name == binary && readZipFile(t, file) != "fake client binary for "+pkg.Platform().String()+"\n" {
				t.Errorf("%s: wrong binary", pkg.File)
			}
		}
		_ = reader.Close()
		if strings.Join(names, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s entries:\n%s\nwant:\n%s", pkg.File, strings.Join(names, "\n"), strings.Join(want, "\n"))
		}
	}
}

func readZipFile(t *testing.T, file *zip.File) string {
	t.Helper()
	reader, err := file.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPackRefusesBadInput(t *testing.T) {
	cases := map[string]func(t *testing.T, skill string, binaries map[Platform]string){
		"stray file": func(t *testing.T, skill string, _ map[Platform]string) {
			writeTestFile(t, filepath.Join(skill, "notes.txt"), "x")
		},
		"scripts directory": func(t *testing.T, skill string, _ map[Platform]string) {
			writeTestFile(t, filepath.Join(skill, "scripts", "llmaudit"), "x")
		},
		"nested reference": func(t *testing.T, skill string, _ map[Platform]string) {
			writeTestFile(t, filepath.Join(skill, "references", "deep", "x.md"), "x")
		},
		"no SKILL.md": func(t *testing.T, skill string, _ map[Platform]string) {
			if err := os.Remove(filepath.Join(skill, "SKILL.md")); err != nil {
				t.Fatal(err)
			}
		},
		"version mismatch": func(t *testing.T, skill string, _ map[Platform]string) {
			writeTestFile(t, filepath.Join(skill, "VERSION"), "9.9.9\n")
		},
		"bad version": func(t *testing.T, skill string, _ map[Platform]string) {
			writeTestFile(t, filepath.Join(skill, "VERSION"), "latest\n")
		},
		"missing binary": func(t *testing.T, _ string, binaries map[Platform]string) {
			delete(binaries, Platforms[3])
		},
		"unreadable binary": func(t *testing.T, _ string, binaries map[Platform]string) {
			binaries[Platforms[0]] = filepath.Join(t.TempDir(), "missing")
		},
		"extra platform": func(t *testing.T, _ string, binaries map[Platform]string) {
			binaries[Platform{OS: "plan9", Arch: "amd64"}] = binaries[Platforms[0]]
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			skill, binaries := fakeSkill(t), fakeBinaries(t)
			breakIt(t, skill, binaries)
			out := filepath.Join(t.TempDir(), "out")
			if _, err := Pack(PackOptions{SkillDir: skill, Binaries: binaries, OutDir: out}); err == nil {
				t.Fatal("Pack accepted the input")
			}
			if _, err := os.Stat(filepath.Join(out, ManifestFile)); err == nil {
				t.Fatal("a manifest was written despite the error")
			}
		})
	}
}

func TestPackRealSkill(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	manifest, err := Pack(PackOptions{SkillDir: realSkillDir, Binaries: fakeBinaries(t), OutDir: out})
	if err != nil {
		t.Fatalf("the repository's Skill does not pack: %v", err)
	}
	reader, err := zip.OpenReader(filepath.Join(out, manifest.Packages[0].File))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var references int
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "llmapi-audit/references/") && strings.HasSuffix(file.Name, ".md") {
			references++
		}
	}
	if references != 6 {
		t.Fatalf("packed %d reference files, want 6", references)
	}
}
