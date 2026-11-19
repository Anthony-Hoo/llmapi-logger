package agentdist

import (
	"strings"
	"testing"
)

func validManifestJSON() string {
	return `{"version":"1.2.3","min_compatible":"1.0.0","packages":[
{"os":"linux","arch":"amd64","file":"llmapi-audit-1.2.3-linux-amd64.zip","sha256":"` + strings.Repeat("a", 64) + `","size":10},
{"os":"windows","arch":"amd64","file":"llmapi-audit-1.2.3-windows-amd64.zip","sha256":"` + strings.Repeat("b", 64) + `","size":20}]}`
}

func TestParseManifestValid(t *testing.T) {
	manifest, err := ParseManifest([]byte(validManifestJSON()))
	if err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	pkg, ok := manifest.Find(Platform{OS: "windows", Arch: "amd64"})
	if !ok || pkg.Size != 20 || pkg.File != "llmapi-audit-1.2.3-windows-amd64.zip" {
		t.Fatalf("Find returned %+v, %v", pkg, ok)
	}
	if _, ok := manifest.Find(Platform{OS: "darwin", Arch: "arm64"}); ok {
		t.Fatal("Find returned an unlisted platform")
	}
	for _, name := range []string{"manifest.json", "llmapi-audit-1.2.3-linux-amd64.zip"} {
		if !manifest.Lists(name) {
			t.Errorf("Lists(%q) = false", name)
		}
	}
	for _, name := range []string{"", "llmapi-audit-1.2.3-darwin-arm64.zip", "../manifest.json", "MANIFEST.JSON"} {
		if manifest.Lists(name) {
			t.Errorf("Lists(%q) = true", name)
		}
	}
	encoded, err := manifest.Encode()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseManifest(encoded)
	if err != nil || len(again.Packages) != 2 {
		t.Fatalf("encoded manifest does not parse back: %v", err)
	}
}

func TestParseManifestRejects(t *testing.T) {
	sha := strings.Repeat("a", 64)
	entry := func(os, arch, file, digest string, size string) string {
		return `{"os":"` + os + `","arch":"` + arch + `","file":"` + file + `","sha256":"` + digest + `","size":` + size + `}`
	}
	good := entry("linux", "amd64", "llmapi-audit-1.2.3-linux-amd64.zip", sha, "10")
	wrap := func(version, minimum string, packages ...string) string {
		return `{"version":"` + version + `","min_compatible":"` + minimum + `","packages":[` + strings.Join(packages, ",") + `]}`
	}
	cases := map[string]string{
		"unknown field":         `{"version":"1.2.3","min_compatible":"1.0.0","packages":[` + good + `],"extra":1}`,
		"trailing data":         wrap("1.2.3", "1.0.0", good) + `{}`,
		"bad version":           wrap("1.2", "1.0.0", good),
		"version with slash":    wrap("1.2.3-a/b", "1.0.0", good),
		"bad min":               wrap("1.2.3", "x", good),
		"min newer":             wrap("1.2.3", "1.3.0", good),
		"no packages":           wrap("1.2.3", "1.0.0"),
		"unknown platform":      wrap("1.2.3", "1.0.0", entry("plan9", "amd64", "llmapi-audit-1.2.3-plan9-amd64.zip", sha, "10")),
		"duplicate platform":    wrap("1.2.3", "1.0.0", good, good),
		"slash in file":         wrap("1.2.3", "1.0.0", entry("linux", "amd64", "a/llmapi-audit-1.2.3-linux-amd64.zip", sha, "10")),
		"backslash in file":     wrap("1.2.3", "1.0.0", entry("linux", "amd64", `..\\llmapi-audit-1.2.3-linux-amd64.zip`, sha, "10")),
		"dot dot file":          wrap("1.2.3", "1.0.0", entry("linux", "amd64", "..", sha, "10")),
		"manifest as package":   wrap("1.2.3", "1.0.0", entry("linux", "amd64", "manifest.json", sha, "10")),
		"wrong naming":          wrap("1.2.3", "1.0.0", entry("linux", "amd64", "llmapi-audit-1.2.3-linux-arm64.zip", sha, "10")),
		"wrong version in name": wrap("1.2.3", "1.0.0", entry("linux", "amd64", "llmapi-audit-1.2.2-linux-amd64.zip", sha, "10")),
		"uppercase sha":         wrap("1.2.3", "1.0.0", entry("linux", "amd64", "llmapi-audit-1.2.3-linux-amd64.zip", strings.Repeat("A", 64), "10")),
		"short sha":             wrap("1.2.3", "1.0.0", entry("linux", "amd64", "llmapi-audit-1.2.3-linux-amd64.zip", "abc", "10")),
		"zero size":             wrap("1.2.3", "1.0.0", entry("linux", "amd64", "llmapi-audit-1.2.3-linux-amd64.zip", sha, "0")),
		"not json":              `not json`,
	}
	for name, input := range cases {
		if _, err := ParseManifest([]byte(input)); err == nil {
			t.Errorf("%s: manifest accepted", name)
		}
	}
}

func TestValidFileName(t *testing.T) {
	for _, name := range []string{"manifest.json", "llmapi-audit-0.1.0-linux-amd64.zip", "A_b-1.zip"} {
		if !ValidFileName(name) {
			t.Errorf("ValidFileName(%q) = false", name)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "/etc/passwd", `C:\x`, "a b", "a%2fb", "a\x00b", "é.zip", strings.Repeat("a", 129)} {
		if ValidFileName(name) {
			t.Errorf("ValidFileName(%q) = true", name)
		}
	}
}

func TestPackageFileNameAndPlatforms(t *testing.T) {
	if got := PackageFileName("0.1.0", Platform{OS: "darwin", Arch: "arm64"}); got != "llmapi-audit-0.1.0-darwin-arm64.zip" {
		t.Fatalf("PackageFileName = %q", got)
	}
	want := []string{"windows-amd64", "linux-amd64", "linux-arm64", "darwin-arm64", "darwin-amd64"}
	if len(Platforms) != len(want) {
		t.Fatalf("Platforms has %d entries", len(Platforms))
	}
	for index, platform := range Platforms {
		if platform.String() != want[index] {
			t.Errorf("Platforms[%d] = %s, want %s", index, platform, want[index])
		}
		if parsed, ok := ParsePlatform(want[index]); !ok || parsed != platform {
			t.Errorf("ParsePlatform(%q) failed", want[index])
		}
	}
	for _, value := range []string{"", "windows", "windows-386", "Linux-amd64", "linux_amd64"} {
		if _, ok := ParsePlatform(value); ok {
			t.Errorf("ParsePlatform(%q) accepted", value)
		}
	}
	if (Platform{OS: "windows", Arch: "amd64"}).BinaryName() != "llmaudit.exe" || (Platform{OS: "linux", Arch: "amd64"}).BinaryName() != "llmaudit" {
		t.Fatal("BinaryName is wrong")
	}
}
