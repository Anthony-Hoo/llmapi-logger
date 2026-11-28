package integration_test

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/archive/runner"
	"llmapi-logger/internal/archive/stream"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/protofixture"
	"llmapi-logger/internal/storage"
)

// archiveDecodeData returns the entries of a data file of a bundle: the
// frames opened with key (nil for a plain file), gunzipped, split at
// newlines.
func archiveDecodeData(t *testing.T, path string, key []byte) [][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var source io.Reader = file
	if key != nil {
		if source, err = stream.NewReader(file, key); err != nil {
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

// archiveEncodeData writes entries back as the bundle writer does: one line
// each, gzip, then the framed encryption under key.
func archiveEncodeData(t *testing.T, path string, key []byte, entries [][]byte) {
	t.Helper()
	var stored bytes.Buffer
	var sink io.Writer = &stored
	var encrypter *stream.Writer
	if key != nil {
		var err error
		if encrypter, err = stream.NewWriter(&stored, key); err != nil {
			t.Fatal(err)
		}
		sink = encrypter
	}
	compressor := gzip.NewWriter(sink)
	for _, entry := range entries {
		_, _ = compressor.Write(entry)
		_, _ = compressor.Write([]byte("\n"))
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	if encrypter != nil {
		if err := encrypter.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, stored.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// archiveResign rewrites a manifest with its files' current sizes and
// hashes, applies mutate and signs it with the archive key: what someone
// holding the key could do, so the checks below the signature are reached.
func archiveResign(t *testing.T, path string, keys *archivecli.Keys, mutate func(*archive.Manifest)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := archive.DecodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	for index, file := range manifest.Files {
		content, err := os.ReadFile(filepath.Join(filepath.Dir(path), file.Name))
		if err != nil {
			t.Fatal(err)
		}
		manifest.Files[index].Bytes, manifest.Files[index].SHA256 = int64(len(content)), sha256.Sum256(content)
	}
	if mutate != nil {
		mutate(manifest)
	}
	if err := manifest.Sign(keys.Archive); err != nil {
		t.Fatal(err)
	}
	encoded, err := archive.EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

// copyArchive copies every file under from into a new directory.
func copyArchive(t *testing.T, from string) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), "copy")
	err := filepath.WalkDir(from, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(from, path)
		target := filepath.Join(to, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return to
}

// bigExchange is a chat request whose last message carries incompressible
// text, so the bundle's objects file spans several encryption frames.
func bigExchange(t *testing.T, seed uint64, size int) protofixture.Exchange {
	t.Helper()
	built, err := protofixture.Build(protofixture.Case{Protocol: protofixture.OpenAIChat, Scenario: protofixture.ScenarioBasic}, protofixture.Options{Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	exchange := built[0]
	var request map[string]any
	if err := json.Unmarshal(exchange.RequestBody, &request); err != nil {
		t.Fatal(err)
	}
	noise := make([]byte, size)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	messages := request["messages"].([]any)
	last := messages[len(messages)-1].(map[string]any)
	last["content"] = base64.StdEncoding.EncodeToString(noise)
	if exchange.RequestBody, err = json.Marshal(request); err != nil {
		t.Fatal(err)
	}
	return exchange
}

// bundleOf finds the manifest that holds auditID and its two data files.
func bundleOf(t *testing.T, dir, auditID string) (manifestPath, lines, objects string) {
	t.Helper()
	for _, path := range manifestPaths(dir, archiveFileDigests(t, dir)) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := archive.DecodeManifest(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range manifest.Members {
			if member.AuditID != auditID {
				continue
			}
			for _, file := range manifest.Files {
				switch file.Role {
				case archive.FileLines:
					lines = filepath.Join(filepath.Dir(path), file.Name)
				case archive.FileObjects:
					objects = filepath.Join(filepath.Dir(path), file.Name)
				}
			}
			return path, lines, objects
		}
	}
	t.Fatalf("no bundle holds %s", auditID)
	return "", "", ""
}

func flipByte(t *testing.T, path string, offset int) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[offset] ^= 0x01
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Plan section 7 bullet 4 and the P3 gate's damaged bundle, on bundles a
// real run produced (encrypted): each damage is reported by audit-archive
// verify with a stable reason and exit code 1, the other bundles stay ok,
// and cat and export refuse the damaged bundle's audit with a non-zero exit
// code and nothing on standard output. Without the key verify only checks
// the files, so it reports the unsigned changes and passes the re-signed
// ones (a documented limit of the keyless level, K.1).
func TestArchiveToolReportsDamagedBundles(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, minTurns: 1})
	big := rig.send(bigExchange(t, 61, 300_000))
	conversation := protofixture.NewConversation(protofixture.AnthropicMessages, true, protofixture.Options{Seed: 62}, 0)
	for range 3 {
		rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	}
	rig.due()
	rig.requireCleanRun(rig.mustRun(), len(rig.auditIDs()))
	keys := archiveKeysOf(t, rig.keyPath)
	key := keys.Archive.EncryptionKey()

	cases := []struct {
		name    string
		damage  func(t *testing.T, manifest, lines, objects string)
		reason  string
		keyless string
	}{
		{"encrypted lines file truncated", func(t *testing.T, manifest, lines, objects string) {
			info, _ := os.Stat(lines)
			if err := os.Truncate(lines, info.Size()-10); err != nil {
				t.Fatal(err)
			}
		}, bundle.ReasonFileMismatch, bundle.ReasonFileMismatch},
		{"encrypted objects file truncated at a frame boundary, manifest re-signed", func(t *testing.T, manifest, lines, objects string) {
			if err := os.Truncate(objects, stream.HeaderSize+stream.SealedFrameSize); err != nil {
				t.Fatal(err)
			}
			archiveResign(t, manifest, keys, nil)
		}, bundle.ReasonDecryptFailed, "ok"},
		{"two frames swapped", func(t *testing.T, manifest, lines, objects string) {
			swapFirstFrames(t, objects)
		}, bundle.ReasonFileMismatch, bundle.ReasonFileMismatch},
		{"two frames swapped, manifest re-signed", func(t *testing.T, manifest, lines, objects string) {
			swapFirstFrames(t, objects)
			archiveResign(t, manifest, keys, nil)
		}, bundle.ReasonDecryptFailed, "ok"},
		{"one manifest field changed", func(t *testing.T, manifest, lines, objects string) {
			data, _ := os.ReadFile(manifest)
			decoded, err := archive.DecodeManifest(data)
			if err != nil {
				t.Fatal(err)
			}
			decoded.CreatedAtNS++
			encoded, err := archive.EncodeManifest(decoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifest, encoded, 0o600); err != nil {
				t.Fatal(err)
			}
		}, bundle.ReasonMACMismatch, "ok"},
		{"one object removed from the objects file, re-encrypted and re-signed", func(t *testing.T, manifest, lines, objects string) {
			entries := archiveDecodeData(t, objects, key)
			kept := entries[:0:0]
			removed := false
			for _, entry := range entries {
				decoded, err := archive.DecodeObjectEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				if !removed && decoded.Content != nil {
					removed = true
					continue
				}
				kept = append(kept, entry)
			}
			archiveEncodeData(t, objects, key, kept)
			archiveResign(t, manifest, keys, func(m *archive.Manifest) { m.ObjectCount-- })
		}, bundle.ReasonReferenceOpen, "ok"},
		{"one ciphertext byte of the lines file flipped", func(t *testing.T, manifest, lines, objects string) {
			flipByte(t, lines, stream.HeaderSize+5)
		}, bundle.ReasonFileMismatch, bundle.ReasonFileMismatch},
		{"one byte of a line changed, re-encrypted and re-signed", func(t *testing.T, manifest, lines, objects string) {
			entries := archiveDecodeData(t, lines, key)
			changed := bytes.Replace(entries[0], []byte(`"method":"POST"`), []byte(`"method":"POSU"`), 1)
			if bytes.Equal(changed, entries[0]) {
				t.Fatal("the line has no method field to change")
			}
			entries[0] = changed
			archiveEncodeData(t, lines, key, entries)
			archiveResign(t, manifest, keys, nil)
		}, bundle.ReasonDigestMismatch, "ok"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := copyArchive(t, rig.dir)
			manifest, lines, objects := bundleOf(t, dir, big)
			test.damage(t, manifest, lines, objects)
			relative, _ := filepath.Rel(dir, manifest)
			relative = filepath.ToSlash(relative)
			for _, keyed := range []bool{true, false} {
				args := []string{"verify", "--dir", dir, "--json"}
				want := test.reason
				if keyed {
					args = append(args, "--key", rig.keyPath)
				} else {
					want = test.keyless
				}
				code, stdout, stderr := archiveCLI(rig.ctx, args...)
				results := map[string]string{}
				for _, line := range bytes.Split(bytes.TrimSpace(stdout), []byte("\n")) {
					var result archivecli.VerifyResult
					if json.Unmarshal(line, &result) == nil && result.Manifest != "" {
						results[result.Manifest] = result.Result
					}
				}
				if results[relative] != want {
					t.Fatalf("verify (key %v) reports %q for the damaged bundle, want %q\n%s%s", keyed, results[relative], want, stdout, stderr)
				}
				for name, result := range results {
					if name != relative && result != "ok" {
						t.Fatalf("verify (key %v): undamaged bundle %s reports %s", keyed, name, result)
					}
				}
				if wantCode := map[bool]int{true: archivecli.ExitFailed, false: archivecli.ExitOK}[want == "ok"]; (want == "ok") != (code == archivecli.ExitOK) {
					t.Fatalf("verify (key %v) exit %d, want %d", keyed, code, wantCode)
				}
			}
			for _, args := range [][]string{
				{"cat", "--dir", dir, "--key", rig.keyPath, "--audit", big},
				{"cat", "--dir", dir, "--key", rig.keyPath},
				{"export", "--dir", dir, "--key", rig.keyPath, "--audit", big, "--what", "request"},
				{"export", "--dir", dir, "--key", rig.keyPath, "--audit", big, "--what", "detail"},
			} {
				if test.reason == bundle.ReasonMACMismatch && len(args) == 5 {
					// A whole-archive cat over a forged manifest: see
					// TestArchiveCatOfAnArchiveWithAForgedManifestFails.
					continue
				}
				code, stdout, stderr := archiveCLI(rig.ctx, args...)
				if code == archivecli.ExitOK {
					t.Fatalf("%s accepted the damaged bundle", strings.Join(args[:1], " "))
				}
				if args[0] == "export" && len(stdout) != 0 {
					t.Fatalf("export printed %d bytes from the damaged bundle", len(stdout))
				}
				if args[0] == "cat" && bytes.Contains(stdout, []byte(big)) {
					t.Fatalf("cat printed the damaged bundle's audit (%s)", stderr)
				}
			}
		})
	}
}

func swapFirstFrames(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const header, frame = stream.HeaderSize, stream.SealedFrameSize
	if len(data) < header+2*frame+1 {
		t.Fatalf("objects file of %d bytes has fewer than three frames", len(data))
	}
	swapped := append([]byte{}, data[:header]...)
	swapped = append(swapped, data[header+frame:header+2*frame]...)
	swapped = append(swapped, data[header:header+frame]...)
	swapped = append(swapped, data[header+2*frame:]...)
	if err := os.WriteFile(path, swapped, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The runner's own re-read (H.2 step 6, the P3 gate's damaged bundle on the
// runtime path): a bundle damaged after it was published and before it is
// sealed fails the re-read, is renamed .rejected (never deleted), its intent
// is dropped, no member is sealed, and the next run archives every audit
// once.
func TestArchiveRunnerRejectsABundleDamagedBeforeTheSeal(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, minTurns: 1})
	conversation := protofixture.NewConversation(protofixture.OpenAIResponses, true, protofixture.Options{Seed: 63}, 0)
	for range 3 {
		rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	}
	ids := rig.auditIDs()
	rig.due()
	damaged := ""
	damage := func(step string) error {
		if step != runner.StepAfterPublish || damaged != "" {
			return nil
		}
		paths := manifestPaths(rig.dir, rig.files())
		if len(paths) != 1 {
			t.Fatalf("%d manifests published", len(paths))
		}
		damaged = paths[0]
		_, lines, _ := bundleOf(t, rig.dir, ids[0])
		flipByte(t, lines, stream.HeaderSize+3)
		return nil
	}
	rig.step.Store(&damage)
	result, err := rig.run()
	rig.step.Store(nil)
	if damaged == "" || err == nil || result.Status != storage.ArchiveRunFailed || result.Counts.Segments != 0 {
		t.Fatalf("damaged run %+v: %v", result, err)
	}
	if _, err := os.Stat(damaged + bundle.RejectedSuffix); err != nil {
		t.Fatalf("the damaged manifest was not renamed aside: %v", err)
	}
	var segments, members int
	if err := rig.db.QueryRow(`SELECT (SELECT COUNT(*) FROM archive_segments), (SELECT COUNT(*) FROM archive_members)`).Scan(&segments, &members); err != nil || segments != 0 || members != 0 {
		t.Fatalf("catalog after the rejected bundle: %d segments, %d members (%v)", segments, members, err)
	}
	if !strings.Contains(string(rig.logs.Bytes()), `"error_category":"archive_failed"`) {
		t.Fatal("the failed run is not logged")
	}
	again := rig.mustRun()
	rig.requireCleanCounts(again, len(ids))
	reader := rig.reader(rig.dir)
	for _, id := range ids {
		if revisions := reader.Index().AuditRevisions(id); len(revisions) != 1 {
			t.Fatalf("%s is in %d live bundles", id, len(revisions))
		}
	}
}

// Plan section 7 bullet 5 on PostgreSQL: an audit whose capture_finalized
// event no longer matches its rows (a stage row changed after the fact), and
// one whose semantic_compacted event no longer matches (a parsed result
// changed), are not archived, stay in the hot store, are deferred
// integrity_failed and counted, the store's payload state turns failed, and
// every other audit of the pass is archived, the tampered parent's child in
// materialised form.
func TestArchiveKeepsAuditsWhoseEventsNoLongerMatch(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, minTurns: 1})
	conversation := protofixture.NewConversation(protofixture.OpenAIChat, true, protofixture.Options{Seed: 64}, 0)
	var turns []string
	for range 4 {
		turns = append(turns, rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{})))
	}
	other := protofixture.NewConversation(protofixture.Gemini, false, protofixture.Options{Seed: 65}, 1)
	leaf := ""
	for range 2 {
		leaf = rig.send(other.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	}
	ids := rig.auditIDs()
	captureTampered, semanticTampered := turns[1], leaf
	if _, err := rig.rw.Exec(`UPDATE http_stages SET host = host || '.tampered' WHERE audit_id = $1 AND stage = $2`, captureTampered, storage.StageRequestSent); err != nil {
		t.Fatal(err)
	}
	if _, err := rig.rw.Exec(`UPDATE parsed_results SET response_model = 'tampered-model' WHERE audit_id = $1`, semanticTampered); err != nil {
		t.Fatal(err)
	}
	rig.due()
	result := rig.mustRun()
	if result.Counts.IntegrityFailedAudits != 2 || result.Deferred[storage.ArchiveDeferredIntegrityFailed] != 2 ||
		result.Counts.ExportedAudits != int64(len(ids)-2) || result.Refused != 0 || result.SampleMismatched != 0 {
		t.Fatalf("result %+v for %d audits", result, len(ids))
	}
	for _, id := range []string{captureTampered, semanticTampered} {
		var reason string
		var members, hot int
		if err := rig.db.QueryRow(`SELECT COALESCE((SELECT reason FROM archive_deferred WHERE audit_id = $1), ''),
  (SELECT COUNT(*) FROM archive_members WHERE audit_id = $1), (SELECT COUNT(*) FROM audit_records WHERE audit_id = $1)`, id).Scan(&reason, &members, &hot); err != nil {
			t.Fatal(err)
		}
		if reason != storage.ArchiveDeferredIntegrityFailed || members != 0 || hot != 1 {
			t.Fatalf("%s: deferred %q, %d members, %d hot rows", id, reason, members, hot)
		}
	}
	if state := rig.store.IntegrityPayloadState(); state != "failed" {
		t.Fatalf("payload state %s", state)
	}
	if !strings.Contains(string(rig.logs.Bytes()), `"error_category":"archive_integrity_failed"`) {
		t.Fatal("the integrity failure is not logged")
	}
	reader := rig.reader(rig.dir)
	var rest []string
	for _, id := range ids {
		if id != captureTampered && id != semanticTampered {
			rest = append(rest, id)
		}
	}
	comparison := rig.compare(reader, rest)
	for _, difference := range comparison.differences {
		t.Error(difference)
	}
	child, err := reader.Audit(rig.ctx, turns[2])
	if err != nil {
		t.Fatal(err)
	}
	if child.Record.Turn.Context.Form != archive.ContextMaterialized {
		t.Fatalf("the tampered parent's child is in %s form", child.Record.Turn.Context.Form)
	}
}

// With --key, a manifest whose signature does not verify is left out of the
// index (K.2 item 2) and reported on standard error as "skipped". cat must
// then exit 1 (R.7 item 4): a caller that checks only the exit code would
// otherwise take an incomplete dump for a complete one. cat once exited 0
// here because it counted only the bundles skipped while reading.
func TestArchiveCatOfAnArchiveWithAForgedManifestFails(t *testing.T) {
	rig := newArchiveRig(t, archiveRigOptions{encrypt: true, minTurns: 1})
	conversation := protofixture.NewConversation(protofixture.OpenAIChat, false, protofixture.Options{Seed: 66}, 0)
	id := rig.send(conversation.Next(protofixture.ScenarioBasic, protofixture.Features{}))
	rig.due()
	rig.requireCleanRun(rig.mustRun(), 1)
	manifest, _, _ := bundleOf(t, rig.dir, id)
	data, _ := os.ReadFile(manifest)
	decoded, err := archive.DecodeManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	decoded.CreatedAtNS++
	encoded, err := archive.EncodeManifest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := archiveCLI(rig.ctx, "cat", "--dir", rig.dir, "--key", rig.keyPath)
	if code != archivecli.ExitFailed {
		t.Fatalf("cat exit %d with the only bundle's manifest forged (stdout %d bytes, stderr %q); R.7 item 4 wants %d",
			code, len(stdout), stderr, archivecli.ExitFailed)
	}
}
