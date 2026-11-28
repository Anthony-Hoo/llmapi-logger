package archivecli

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/stream"
)

func modes() []bool { return []bool{true, false} }

func modeName(encrypt bool) string {
	return map[bool]string{true: "encrypted", false: "plain"}[encrypt]
}

// keyArgs are the key flags that read the scenario: the key, or for plain
// bundles alternatively --unauthenticated.
func (s *scenario) read(args ...string) []string {
	return append(args, "--dir", s.root, "--key", s.keyPath)
}

func TestListWithAndWithoutKey(t *testing.T) {
	for _, encrypt := range modes() {
		t.Run(modeName(encrypt), func(t *testing.T) {
			s := newScenario(t, encrypt)
			out := run(t, "list", "--dir", s.root).want(t, ExitOK)
			lines := out.lines()
			if len(lines) != 5 || !strings.HasPrefix(lines[0], "KIND") {
				t.Fatalf("list:\n%s", out.stdout)
			}
			for _, line := range lines[1:] {
				if !strings.Contains(line, "not_checked") || !strings.Contains(line, map[bool]string{true: "true", false: "false"}[encrypt]) {
					t.Fatalf("line %q", line)
				}
			}
			keyed := run(t, "list", "--dir", s.root, "--key", s.keyPath, "--json").want(t, ExitOK)
			var kinds []string
			for _, line := range keyed.lines() {
				var info BundleInfo
				if err := json.Unmarshal([]byte(line), &info); err != nil {
					t.Fatal(err)
				}
				if info.Auth != "ok" || info.FormatVersion != archive.FormatVersion || info.Encrypted != encrypt || strings.Contains(info.Manifest, s.root) {
					t.Fatalf("bundle %+v", info)
				}
				kinds = append(kinds, info.Kind)
			}
			if strings.Join(kinds, ",") != "gaps,bucket,bucket,conversation" && len(kinds) != 4 {
				t.Fatalf("kinds %v", kinds)
			}
			// A conversation is found through every bundle that holds it.
			if got := len(run(t, "list", "--dir", s.root, "--conversation", s.conversation, "--json").want(t, ExitOK).lines()); got != 3 {
				t.Fatalf("conversation bundles = %d, want the conversation bundle and two buckets", got)
			}
			if got := len(run(t, "list", "--dir", s.root, "--audit", "c2", "--json").want(t, ExitOK).lines()); got != 2 {
				t.Fatalf("c2 bundles = %d, want two revisions", got)
			}
			run(t, "list", "--dir", s.root, "--audit", "absent").want(t, ExitNotFound)
			// The wrong key marks every bundle, it does not hide them.
			wrong := run(t, "list", "--dir", s.root, "--key", s.otherKeyFile()).want(t, ExitOK)
			if strings.Count(wrong.stdout, "key_mismatch") != 4 {
				t.Fatalf("wrong key list:\n%s", wrong.stdout)
			}
		})
	}
}

func TestVerifyLevelsAndFailures(t *testing.T) {
	for _, encrypt := range modes() {
		t.Run(modeName(encrypt), func(t *testing.T) {
			s := newScenario(t, encrypt)
			files := run(t, "verify", "--dir", s.root).want(t, ExitOK)
			if !strings.Contains(files.stdout, "verify: 4 bundles, 4 ok, 0 failed; level files only (no key)") || strings.Count(files.stdout, "ok\tfiles\t") != 4 {
				t.Fatalf("keyless verify:\n%s", files.stdout)
			}
			full := run(t, s.read("verify")...).want(t, ExitOK)
			if !strings.Contains(full.stdout, "4 ok, 0 failed; level full") || strings.Count(full.stdout, "ok\tfull\t") != 4 {
				t.Fatalf("full verify:\n%s", full.stdout)
			}
			one := run(t, "verify", "--bundle", s.bundles["conversation"], "--key", s.keyPath, "--json").want(t, ExitOK)
			var first VerifyResult
			if err := json.Unmarshal([]byte(one.lines()[0]), &first); err != nil || first.Result != "ok" || first.Members != 2 || first.Level != "full" {
				t.Fatalf("one bundle: %+v %v", first, err)
			}
			wrong := run(t, "verify", "--dir", s.root, "--key", s.otherKeyFile()).want(t, ExitFailed)
			if strings.Count(wrong.stdout, "key_mismatch\tfull") != 4 || !strings.Contains(wrong.stdout, "0 ok, 4 failed") {
				t.Fatalf("wrong key:\n%s", wrong.stdout)
			}

			// Rejected bundles, orphaned data and temporary files are not
			// bundles; a manifest that does not parse is a failure.
			writeFile(t, filepath.Join(s.root, "sessions", "2025", "11", "old.manifest.json.rejected"), "{}")
			writeFile(t, filepath.Join(s.root, "sessions", "2025", "11", "stray.jsonl.gz.orphan"), "x")
			writeFile(t, filepath.Join(s.root, "sessions", "2025", "11", "stray.jsonl.gz"), "x")
			notes := run(t, s.read("verify")...).want(t, ExitOK)
			if !strings.Contains(notes.stderr, "data file without a manifest: sessions/2025/11/stray.jsonl.gz") || strings.Contains(notes.stdout, "rejected") {
				t.Fatalf("leftovers:\nstdout %s\nstderr %s", notes.stdout, notes.stderr)
			}
			writeFile(t, filepath.Join(s.root, "sessions", "2025", "11", "broken.manifest.json"), "{")
			broken := run(t, s.read("verify")...).want(t, ExitFailed)
			if !strings.Contains(broken.stdout, "manifest_invalid\tmanifest\t0\tsessions/2025/11/broken.manifest.json") {
				t.Fatalf("broken manifest:\n%s", broken.stdout)
			}
		})
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// tamper flips one byte in the middle of the bundle's lines file.
func tamper(t *testing.T, manifestPath string) {
	t.Helper()
	manifest, err := archive.DecodeManifest(mustRead(t, manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(manifestPath), manifest.Files[0].Name)
	data := mustRead(t, path)
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTamperedBundleFailsAndIsSkipped(t *testing.T) {
	for _, encrypt := range modes() {
		t.Run(modeName(encrypt), func(t *testing.T) {
			s := newScenario(t, encrypt)
			tamper(t, s.bundles["bucket"])
			for _, args := range [][]string{{"verify", "--dir", s.root}, s.read("verify")} {
				out := run(t, args...).want(t, ExitFailed)
				if !strings.Contains(out.stdout, "file_mismatch") || !strings.Contains(out.stdout, "3 ok, 1 failed") {
					t.Fatalf("%v:\n%s", args, out.stdout)
				}
			}
			failed := run(t, s.read("export", "--audit", "c3", "--what", "request")...).want(t, ExitFailed)
			if !strings.Contains(failed.stderr, "audit-archive: file_mismatch:") || failed.stdout != "" {
				t.Fatalf("export from a tampered bundle: %+v", failed)
			}
			// Other bundles still read; cat skips the tampered one.
			run(t, s.read("export", "--audit", "c1", "--what", "request")...).want(t, ExitOK)
			cat := run(t, s.read("cat")...).want(t, ExitFailed)
			if !strings.Contains(cat.stderr, "skipped") || strings.Contains(cat.stdout, `"audit_id":"c3"`) || !strings.Contains(cat.stdout, `"audit_id":"c1"`) {
				t.Fatalf("cat with a tampered bundle:\nstdout %.300s\nstderr %s", cat.stdout, cat.stderr)
			}
		})
	}
}

// storedLines decodes a data file of a bundle.
func storedLines(t *testing.T, s *scenario, manifestPath, role string) [][]byte {
	t.Helper()
	manifest, err := archive.DecodeManifest(mustRead(t, manifestPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest.Files {
		if file.Role != role {
			continue
		}
		var source io.Reader = bytes.NewReader(mustRead(t, filepath.Join(filepath.Dir(manifestPath), file.Name)))
		if manifest.Encrypted {
			key := s.keys.Archive.EncryptionKey()
			if source, err = stream.NewReader(source, key); err != nil {
				t.Fatal(err)
			}
		}
		decompressor, err := gzip.NewReader(source)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := io.ReadAll(decompressor)
		if err != nil {
			t.Fatal(err)
		}
		return bytes.Split(bytes.TrimSuffix(plain, []byte("\n")), []byte("\n"))
	}
	return nil
}

func TestCat(t *testing.T) {
	for _, encrypt := range modes() {
		t.Run(modeName(encrypt), func(t *testing.T) {
			s := newScenario(t, encrypt)
			all := run(t, s.read("cat")...).want(t, ExitOK)
			// Highest revisions only: c1, c3, c4, loose, c2 revision 2, and the
			// gap line; c2 revision 1 is left out.
			lines := all.lines()
			if len(lines) != 6 || strings.Count(all.stdout, `{"type":"audit","audit_id":"c2"`) != 1 || !strings.Contains(all.stdout, `"revision":"2"`) ||
				!strings.Contains(all.stdout, `"type":"gap"`) {
				t.Fatalf("cat: %d lines", len(lines))
			}
			if !strings.Contains(all.stdout, contentMarker) || !strings.Contains(all.stdout, `"value_omitted":"credential"`) {
				t.Fatal("cat shows no plaintext content or no projected credential: the credential scan would assert nothing")
			}
			// The printed lines are byte for byte the stored lines.
			stored := map[string]bool{}
			for _, path := range []string{s.bundles["conversation"], s.bundles["bucket"], s.bundles["revision"], s.bundles["gaps"]} {
				for _, line := range storedLines(t, s, path, archive.FileLines) {
					stored[string(line)] = true
				}
			}
			for _, line := range lines {
				if !stored[line] {
					t.Fatalf("cat line is not a stored line: %.200s", line)
				}
			}
			if got := len(run(t, s.read("cat", "--all-revisions")...).want(t, ExitOK).lines()); got != 7 {
				t.Fatalf("all revisions: %d lines", got)
			}
			c2 := run(t, s.read("cat", "--audit", "c2")...).want(t, ExitOK).lines()
			if len(c2) != 1 || !strings.Contains(c2[0], `"revision":"2"`) {
				t.Fatalf("c2: %v", len(c2))
			}
			if got := len(run(t, s.read("cat", "--audit", "c2", "--all-revisions")...).want(t, ExitOK).lines()); got != 2 {
				t.Fatalf("c2 all revisions: %d", got)
			}
			conversation := run(t, s.read("cat", "--conversation", s.conversation)...).want(t, ExitOK).lines()
			if len(conversation) != 3 {
				t.Fatalf("conversation lines = %d", len(conversation))
			}
			run(t, s.read("cat", "--audit", "absent")...).want(t, ExitNotFound)

			// --with-objects: the loose audit's line, then its raw chunks and
			// its split parsed_json parts, and nothing of the other audits.
			objects := run(t, s.read("cat", "--audit", "loose", "--with-objects")...).want(t, ExitOK).lines()
			types := map[string]int{}
			for _, line := range objects {
				var probe struct {
					Type    string `json:"type"`
					AuditID string `json:"audit_id"`
				}
				if err := json.Unmarshal([]byte(line), &probe); err != nil {
					t.Fatal(err)
				}
				if probe.AuditID != "loose" {
					t.Fatalf("object of %q printed for loose", probe.AuditID)
				}
				types[probe.Type]++
			}
			if types["audit"] != 1 || types[archive.EntryRawChunk] != 3 || types[archive.EntryParsedJSONPart] != 2 || types[archive.EntryContentObject] != 0 {
				t.Fatalf("with objects: %v", types)
			}
			turn := run(t, s.read("cat", "--audit", "c1", "--with-objects")...).want(t, ExitOK).lines()
			stored = map[string]bool{}
			for _, line := range storedLines(t, s, s.bundles["conversation"], archive.FileObjects) {
				stored[string(line)] = true
			}
			for _, line := range turn[1:] {
				if !stored[line] {
					t.Fatalf("object line is not stored: %.120s", line)
				}
			}
			if len(turn) < 5 {
				t.Fatalf("c1 with objects: %d lines", len(turn))
			}
		})
	}
}

func TestKeyRequirements(t *testing.T) {
	for _, encrypt := range modes() {
		t.Run(modeName(encrypt), func(t *testing.T) {
			s := newScenario(t, encrypt)
			for _, command := range [][]string{{"cat"}, {"export", "--audit", "c1"}} {
				out := run(t, append(command, "--dir", s.root)...).want(t, ExitFailed)
				if !strings.Contains(out.stderr, "audit-archive: key_required:") {
					t.Fatalf("%v without a key: %s", command, out.stderr)
				}
			}
			unauthenticated := runWith(t, "", nil, "cat", "--dir", s.root, "--unauthenticated")
			if !strings.Contains(unauthenticated.stderr, "not authenticated") {
				t.Fatalf("no warning: %s", unauthenticated.stderr)
			}
			if encrypt {
				// Encrypted bundles are never read without the key.
				unauthenticated.want(t, ExitFailed)
				if strings.Count(unauthenticated.stderr, "key_required") != 4 || unauthenticated.stdout != "" {
					t.Fatalf("encrypted without a key: %+v", unauthenticated)
				}
				run(t, "export", "--dir", s.root, "--unauthenticated", "--audit", "c1").want(t, ExitFailed)
				return
			}
			unauthenticated.want(t, ExitOK)
			if len(unauthenticated.lines()) != 6 {
				t.Fatalf("plain unauthenticated cat: %d lines", len(unauthenticated.lines()))
			}
			run(t, "export", "--dir", s.root, "--unauthenticated", "--audit", "c1", "--what", "request").want(t, ExitOK)
		})
	}
}

func TestWrongKey(t *testing.T) {
	s := newScenario(t, true)
	other := s.otherKeyFile()
	for _, args := range [][]string{
		{"export", "--dir", s.root, "--key", other, "--audit", "c1"},
		{"export", "--dir", s.root, "--key", other, "--conversation", s.conversation},
		{"cat", "--dir", s.root, "--key", other, "--audit", "c1"},
	} {
		out := run(t, args...).want(t, ExitFailed)
		if !strings.Contains(out.stderr, "audit-archive: key_mismatch:") || !strings.Contains(out.stderr, "key does not match") || out.stdout != "" {
			t.Fatalf("%v: %+v", args, out)
		}
	}
}

func TestMissingKeyFileIsNotCreated(t *testing.T) {
	s := newScenario(t, true)
	missing := filepath.Join(t.TempDir(), "absent.key")
	out := run(t, "export", "--dir", s.root, "--key", missing, "--audit", "c1").want(t, ExitFailed)
	if !strings.Contains(out.stderr, "key_file: the key file does not exist") || strings.Contains(out.stderr, missing) {
		t.Fatalf("missing key: %s", out.stderr)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("a missing key file was created")
	}
	short := filepath.Join(t.TempDir(), "short.key")
	writeFile(t, short, "too short")
	if out := run(t, "verify", "--dir", s.root, "--key", short).want(t, ExitFailed); !strings.Contains(out.stderr, "not a 32-byte key") {
		t.Fatalf("short key: %s", out.stderr)
	}
}

func TestEventMACCheck(t *testing.T) {
	s := newScenario(t, true)
	// A bundle whose copied events were signed with another master key
	// verifies only with --skip-event-mac.
	foreign := s.audit("foreign", minute(40), 2)
	other, err := NewKeys(bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s.signer = other.Events
	s.event(foreign, 2, "capture_finalized", minute(40)+5)
	manifest := s.writeSegment(true, runB, bundleSpecBucket(), s.canonical(foreign))
	out := run(t, "verify", "--bundle", manifest, "--key", s.keyPath).want(t, ExitFailed)
	if !strings.HasPrefix(out.stdout, "event_mac_mismatch\tfull") {
		t.Fatalf("foreign events: %s", out.stdout)
	}
	skipped := run(t, "verify", "--bundle", manifest, "--key", s.keyPath, "--skip-event-mac").want(t, ExitOK)
	if !strings.Contains(skipped.stdout, "except the integrity events' MACs") {
		t.Fatalf("skip: %s", skipped.stdout)
	}
	run(t, s.read("export", "--audit", "foreign", "--what", "headers")...).want(t, ExitFailed)
	exported := run(t, s.read("export", "--audit", "foreign", "--what", "headers", "--skip-event-mac")...).want(t, ExitOK)
	if !strings.Contains(exported.stderr, "--skip-event-mac") {
		t.Fatalf("no warning: %s", exported.stderr)
	}
}

func TestHelpAndExitCodes(t *testing.T) {
	none := run(t).want(t, ExitUsage)
	if !strings.Contains(none.stderr, "Usage: audit-archive <command>") {
		t.Fatalf("no arguments: %s", none.stderr)
	}
	top := run(t, "--help").want(t, ExitOK)
	for _, want := range []string{"never\nconnects to a database", "your responsibility", "Exit codes: 0 done", "list", "verify", "cat", "export", "fpr"} {
		if !strings.Contains(top.stdout, want) {
			t.Fatalf("top help lacks %q", want)
		}
	}
	for _, command := range commands() {
		help := run(t, command.name, "--help").want(t, ExitOK)
		if !strings.HasPrefix(help.stdout, "Usage: audit-archive "+command.name) || !strings.Contains(help.stdout, "Exit codes:") {
			t.Fatalf("%s help:\n%s", command.name, help.stdout)
		}
	}
	for _, name := range []string{"cat", "export"} {
		if help := run(t, name, "-h").want(t, ExitOK); !strings.Contains(help.stdout, "your responsibility") {
			t.Fatalf("%s help does not say the output is plaintext", name)
		}
	}
	if help := run(t, "export", "--help").stdout; !strings.Contains(help, strings.Join(ExportKinds, ", ")) {
		t.Fatal("export help does not list the kinds")
	}
	if help := run(t, "verify", "--help").stdout; !strings.Contains(help, "weaker") {
		t.Fatal("verify help does not label the keyless check as weaker")
	}
	for _, args := range [][]string{
		{"unknown"},
		{"list"},
		{"list", "--dir", "x", "--nope"},
		{"list", "--dir", "x", "extra"},
		{"verify"},
		{"verify", "--dir", "x", "--bundle", "y"},
		{"export", "--dir", "x", "--key", "k"},
		{"export", "--dir", "x", "--key", "k", "--audit", "a", "--what", "nope"},
		{"export", "--dir", "x", "--key", "k", "--conversation", "c", "--what", "request"},
		{"cat", "--dir", "x", "--key", "k", "--audit", "a", "--conversation", "c"},
		{"fpr"},
		{"fpr", "--key", "k", "--audit", "a"},
		{"cat", "--dir", "x", "--unauthenticated=" + "notabool"},
	} {
		out := run(t, args...).want(t, ExitUsage)
		if !strings.Contains(out.stderr, "usage") || strings.Contains(out.stderr, "notabool") {
			t.Fatalf("%v: %s", args, out.stderr)
		}
	}
	if out := run(t, "list", "--dir", filepath.Join(t.TempDir(), "absent")).want(t, ExitFailed); !strings.Contains(out.stderr, "archive_not_found") {
		t.Fatalf("absent archive: %s", out.stderr)
	}
}

// The reader must never link a store or a database driver (design K.3):
// it reads the archive directory only.
func TestDependencyGuard(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not available")
	}
	for _, target := range []string{"llmapi-logger/cmd/audit-archive", "llmapi-logger/internal/archivecli"} {
		output, err := exec.Command(goTool, "list", "-deps", target).CombinedOutput()
		if err != nil {
			t.Fatalf("go list: %v\n%s", err, output)
		}
		seen := 0
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line == "llmapi-logger/internal/archive/bundle" || line == "llmapi-logger/internal/query" {
				seen++
			}
			denied := line == "llmapi-logger/internal/app" || line == "llmapi-logger/internal/web"
			for _, prefix := range []string{"llmapi-logger/internal/storage/", "github.com/jackc/", "modernc.org/"} {
				denied = denied || strings.HasPrefix(line, prefix)
			}
			if denied {
				t.Errorf("%s depends on %s", target, line)
			}
		}
		if seen != 2 {
			t.Fatalf("%s: the dependency list does not hold the archive reader packages; the guard would assert nothing", target)
		}
	}
}
