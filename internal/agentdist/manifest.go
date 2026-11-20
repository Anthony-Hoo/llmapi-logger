// Package agentdist distributes the llmapi-audit Skill package
// (doc/features/25-agent-access-contract.md section 5): the package manifest,
// the signed download links, the download handler, the install prompt and the
// reproducible packer that builds the archives.
//
// It depends on the standard library and internal/agentapi only, so the web
// layer wires it in without agentdist knowing anything about the web layer.
package agentdist

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"llmapi-logger/internal/agentapi"
)

// SkillName is the Skill's name and the archive's single top-level directory.
// The install directory always ends in it.
const SkillName = "llmapi-audit"

// ManifestFile is the name of the manifest in the package directory and in a
// download link.
const ManifestFile = "manifest.json"

// Platform is one target of the command-line client.
type Platform struct {
	OS   string
	Arch string
}

// String is the "<os>-<arch>" form used in file names and in the
// install-links request.
func (platform Platform) String() string { return platform.OS + "-" + platform.Arch }

// Windows reports whether the platform's binary carries the .exe suffix and
// its install commands are PowerShell.
func (platform Platform) Windows() bool { return platform.OS == "windows" }

// BinaryName is the client's file name inside scripts/.
func (platform Platform) BinaryName() string {
	if platform.Windows() {
		return "llmaudit.exe"
	}
	return "llmaudit"
}

// Platforms are the five targets packages are built for, in manifest order.
var Platforms = []Platform{
	{OS: "windows", Arch: "amd64"},
	{OS: "linux", Arch: "amd64"},
	{OS: "linux", Arch: "arm64"},
	{OS: "darwin", Arch: "arm64"},
	{OS: "darwin", Arch: "amd64"},
}

// ParsePlatform accepts exactly one of Platforms in "<os>-<arch>" form.
func ParsePlatform(value string) (Platform, bool) {
	for _, platform := range Platforms {
		if platform.String() == value {
			return platform, true
		}
	}
	return Platform{}, false
}

// Manifest is manifest.json.
type Manifest struct {
	Version       string    `json:"version"`
	MinCompatible string    `json:"min_compatible"`
	Packages      []Package `json:"packages"`
}

// Package is one archive listed in the manifest.
type Package struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Platform is the package's target.
func (pkg Package) Platform() Platform { return Platform{OS: pkg.OS, Arch: pkg.Arch} }

var (
	fileNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidFileName reports whether name may appear in a download link: only
// [A-Za-z0-9._-], and not "." or "..". It is a syntax check; whether the file
// is served is decided by the manifest.
func ValidFileName(name string) bool {
	return name != "." && name != ".." && len(name) <= 128 && fileNamePattern.MatchString(name)
}

// PackageFileName is llmapi-audit-<version>-<os>-<arch>.zip.
func PackageFileName(version string, platform Platform) string {
	return SkillName + "-" + version + "-" + platform.OS + "-" + platform.Arch + ".zip"
}

// ParseManifest decodes and validates manifest.json strictly: unknown fields
// and trailing data are errors.
func ParseManifest(data []byte) (*Manifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("manifest: trailing data")
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return &manifest, nil
}

// Validate checks the versions, that every platform appears at most once and
// is one of Platforms, the naming scheme, the digest and the size.
func (manifest *Manifest) Validate() error {
	if _, ok := agentapi.ParseVersion(manifest.Version); !ok || !versionSafe(manifest.Version) {
		return fmt.Errorf("manifest: version %q is not MAJOR.MINOR.PATCH", manifest.Version)
	}
	if _, ok := agentapi.ParseVersion(manifest.MinCompatible); !ok || !versionSafe(manifest.MinCompatible) {
		return fmt.Errorf("manifest: min_compatible %q is not MAJOR.MINOR.PATCH", manifest.MinCompatible)
	}
	latest, _ := agentapi.ParseVersion(manifest.Version)
	minimum, _ := agentapi.ParseVersion(manifest.MinCompatible)
	if agentapi.CompareVersions(minimum, latest) > 0 {
		return errors.New("manifest: min_compatible is newer than version")
	}
	if len(manifest.Packages) == 0 {
		return errors.New("manifest: no packages")
	}
	seen := map[Platform]bool{}
	for index, pkg := range manifest.Packages {
		platform := pkg.Platform()
		if _, ok := ParsePlatform(platform.String()); !ok {
			return fmt.Errorf("manifest: package %d: unknown platform %q", index, platform.String())
		}
		if seen[platform] {
			return fmt.Errorf("manifest: platform %s listed twice", platform)
		}
		seen[platform] = true
		if !ValidFileName(pkg.File) || pkg.File == ManifestFile {
			return fmt.Errorf("manifest: package %d: invalid file name", index)
		}
		if want := PackageFileName(manifest.Version, platform); pkg.File != want {
			return fmt.Errorf("manifest: package %d: file must be %s", index, want)
		}
		if !sha256Pattern.MatchString(pkg.SHA256) {
			return fmt.Errorf("manifest: package %d: sha256 must be 64 lowercase hexadecimal characters", index)
		}
		if pkg.Size <= 0 {
			return fmt.Errorf("manifest: package %d: size must be positive", index)
		}
	}
	return nil
}

// versionSafe keeps a version usable in a file name: the build or pre-release
// suffix ParseVersion tolerates must still only use file-name characters.
func versionSafe(version string) bool {
	return fileNamePattern.MatchString(version) && !strings.Contains(version, "..")
}

// Find returns the package for platform.
func (manifest *Manifest) Find(platform Platform) (Package, bool) {
	for _, pkg := range manifest.Packages {
		if pkg.Platform() == platform {
			return pkg, true
		}
	}
	return Package{}, false
}

// Lists reports whether file is the manifest itself or one of its packages:
// the only names a download link serves.
func (manifest *Manifest) Lists(file string) bool {
	if file == ManifestFile {
		return true
	}
	for _, pkg := range manifest.Packages {
		if pkg.File == file {
			return true
		}
	}
	return false
}

// Encode is the manifest as written to manifest.json: indented, with a final
// newline, so two builds of the same packages produce the same bytes.
func (manifest *Manifest) Encode() ([]byte, error) {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
