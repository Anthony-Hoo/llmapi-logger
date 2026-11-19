package agentdist

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"llmapi-logger/internal/agentapi"
)

// ArchiveTime is the modification time of every archive entry, so archives
// do not depend on when or where they were built.
var ArchiveTime = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// Permission bits of archive entries: the client binary is executable,
// everything else is not.
const (
	dirMode    fs.FileMode = fs.ModeDir | 0o755
	fileMode   fs.FileMode = 0o644
	binaryMode fs.FileMode = 0o755
)

// skillSourcePattern lists the only files a Skill source directory may hold:
// SKILL.md, VERSION and Markdown files directly under references/. Anything
// else (a stray binary, an editor backup, a scripts/ directory) fails the
// build instead of being shipped.
var skillSourcePattern = regexp.MustCompile(`^(SKILL\.md|VERSION|references/[a-z0-9][a-z0-9-]*\.md)$`)

// PackOptions is the input of Pack.
type PackOptions struct {
	// SkillDir is the Skill source, skill/llmapi-audit.
	SkillDir string
	// Binaries maps every one of Platforms to its built llmaudit binary.
	Binaries map[Platform]string
	// OutDir receives the archives and manifest.json; it is created if
	// missing. Existing files of the same names are replaced, others are left
	// alone (and are never served: only listed files are).
	OutDir string
}

// skillFile is one text file of the Skill, by its slash path inside the
// Skill directory.
type skillFile struct {
	name string
	data []byte
}

// Pack builds one archive per platform and the manifest. The archives are
// reproducible: entries sorted by path, ArchiveTime on every entry, fixed
// permission bits, text files with LF line endings. Two runs over the same
// inputs produce byte-identical files.
func Pack(options PackOptions) (*Manifest, error) {
	files, version, err := readSkill(options.SkillDir)
	if err != nil {
		return nil, err
	}
	if version != agentapi.LatestVersion {
		return nil, fmt.Errorf("pack: VERSION is %s but the client version (agentapi.LatestVersion) is %s", version, agentapi.LatestVersion)
	}
	for _, platform := range Platforms {
		if options.Binaries[platform] == "" {
			return nil, fmt.Errorf("pack: no binary for %s", platform)
		}
	}
	if len(options.Binaries) != len(Platforms) {
		return nil, errors.New("pack: binaries given for an unknown platform")
	}
	if err := os.MkdirAll(options.OutDir, 0o755); err != nil {
		return nil, fmt.Errorf("pack: create %s: %w", options.OutDir, err)
	}
	manifest := &Manifest{Version: version, MinCompatible: agentapi.MinVersion}
	for _, platform := range Platforms {
		binary, err := os.ReadFile(options.Binaries[platform])
		if err != nil {
			return nil, fmt.Errorf("pack: read the %s binary: %w", platform, err)
		}
		archive, err := buildArchive(files, platform, binary)
		if err != nil {
			return nil, fmt.Errorf("pack: %s: %w", platform, err)
		}
		name := PackageFileName(version, platform)
		if err := writeFileAtomic(filepath.Join(options.OutDir, name), archive); err != nil {
			return nil, fmt.Errorf("pack: write %s: %w", name, err)
		}
		sum := sha256.Sum256(archive)
		manifest.Packages = append(manifest.Packages, Package{
			OS: platform.OS, Arch: platform.Arch, File: name,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(archive)),
		})
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	encoded, err := manifest.Encode()
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(options.OutDir, ManifestFile), encoded); err != nil {
		return nil, fmt.Errorf("pack: write %s: %w", ManifestFile, err)
	}
	return manifest, nil
}

// readSkill reads every file of the Skill source, refusing anything outside
// skillSourcePattern, and returns them with the version from VERSION.
func readSkill(dir string) ([]skillFile, string, error) {
	var files []skillFile
	err := filepath.WalkDir(dir, func(full string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(dir, full)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(relative)
		if name == "." {
			return nil
		}
		if entry.IsDir() {
			if name == "references" {
				return nil
			}
			return fmt.Errorf("pack: unexpected directory %s in the Skill source", name)
		}
		if !entry.Type().IsRegular() || !skillSourcePattern.MatchString(name) {
			return fmt.Errorf("pack: unexpected file %s in the Skill source", name)
		}
		data, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		files = append(files, skillFile{name: name, data: bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))})
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	var version string
	var haveSkill bool
	for _, file := range files {
		switch file.name {
		case "VERSION":
			version = strings.TrimSpace(string(file.data))
		case "SKILL.md":
			haveSkill = true
		}
	}
	if !haveSkill {
		return nil, "", errors.New("pack: the Skill source has no SKILL.md")
	}
	if _, ok := agentapi.ParseVersion(version); !ok || !versionSafe(version) {
		return nil, "", fmt.Errorf("pack: VERSION %q is not MAJOR.MINOR.PATCH", version)
	}
	return files, version, nil
}

type archiveEntry struct {
	name string
	mode fs.FileMode
	data []byte
}

func buildArchive(files []skillFile, platform Platform, binary []byte) ([]byte, error) {
	top := SkillName + "/"
	entries := []archiveEntry{
		{name: top, mode: dirMode},
		{name: top + "scripts/", mode: dirMode},
		{name: top + "scripts/" + platform.BinaryName(), mode: binaryMode, data: binary},
	}
	directories := map[string]bool{}
	for _, file := range files {
		if dir := path.Dir(file.name); dir != "." && !directories[dir] {
			directories[dir] = true
			entries = append(entries, archiveEntry{name: top + dir + "/", mode: dirMode})
		}
		entries = append(entries, archiveEntry{name: top + file.name, mode: fileMode, data: file.data})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].name < entries[right].name })

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Modified: ArchiveTime}
		header.SetMode(entry.mode)
		if entry.mode.IsDir() {
			header.Method = zip.Store
		} else {
			header.Method = zip.Deflate
		}
		content, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := content.Write(entry.data); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// writeFileAtomic writes data to a temporary file next to target and renames
// it over target.
func writeFileAtomic(target string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(target), ".agentpack-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	if _, err := io.Copy(temp, bytes.NewReader(data)); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	if err := os.Chmod(tempName, 0o644); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	if err := os.Rename(tempName, target); err != nil {
		_ = os.Remove(tempName)
		return err
	}
	return nil
}
