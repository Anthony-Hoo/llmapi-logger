package bundle

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/storage"
)

// writeAndPublish runs a whole segment through the writer and returns the
// first error.
func (f *fixture) writeAndPublish(options Options, spec Spec, records []*archive.Record) error {
	writer, err := NewSegment(options, spec, f.payloads)
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := writer.Add(record); err != nil {
			return err
		}
	}
	sealed, err := writer.Seal()
	if err != nil {
		return err
	}
	return sealed.Publish()
}

func assertNothingLive(t *testing.T, root string) {
	t.Helper()
	files := listFiles(t, root)
	for _, file := range files {
		base := filepath.Base(file)
		if IsTempName(base) || strings.HasSuffix(base, ManifestSuffix) {
			t.Fatalf("left behind after a failure: %s", describe(files))
		}
	}
}

// A fault at every occurrence of every file system step leaves no published
// manifest and no temporary file, and reports the step's reason.
func TestFaultAtEveryStep(t *testing.T) {
	reasons := map[string]string{
		FaultMkdir: ReasonMkdirFailed, FaultCreate: ReasonCreateFailed, FaultWrite: ReasonDiskFull,
		FaultSync: ReasonSyncFailed, FaultClose: ReasonCloseFailed, FaultLink: ReasonLinkFailed, FaultDirSync: ReasonDirSyncFailed,
	}
	f := newFixture(t)
	records := f.conversation("conv_fault", "q", 0)
	// An incompressible body makes the writes reach the file during Add,
	// not only when the segment is sealed.
	big := f.audit("q-4", "openai", minute(3), storage.CaptureVersion2)
	f.withTurn(big, "conv_fault", turnOptions{parent: records[2], messages: []string{"big"}, response: "large", createdNS: minute(3) + 500})
	f.withRaw(big, storage.StageResponseReceived, rawData(4, 300_000), 1<<20, true)
	records = append(records, canonical(t, big))
	spec := Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_fault", Index: 1}

	counts := map[string]int{}
	options := f.options(t.TempDir(), true)
	options.Fault = func(operation, _ string) error { counts[operation]++; return nil }
	if err := f.writeAndPublish(options, spec, records); err != nil {
		t.Fatal(err)
	}
	t.Logf("file system steps of one segment: %v", counts)
	if counts[FaultWrite] <= 3 {
		t.Fatal("no write reaches a file before the segment is sealed")
	}
	for operation, reason := range reasons {
		if counts[operation] == 0 {
			t.Fatalf("operation %s never happens", operation)
		}
		for occurrence := 1; occurrence <= counts[operation]; occurrence++ {
			root := t.TempDir()
			options := f.options(root, true)
			seen := 0
			options.Fault = func(current, _ string) error {
				if current != operation {
					return nil
				}
				seen++
				if seen != occurrence {
					return nil
				}
				if operation == FaultWrite {
					return syscall.ENOSPC
				}
				return errors.New("injected")
			}
			err := f.writeAndPublish(options, spec, records)
			if ReasonOf(err) != reason {
				t.Fatalf("%s #%d: reason %q (%v), want %q", operation, occurrence, ReasonOf(err), err, reason)
			}
			assertNothingLive(t, root)
		}
	}

	// The gap writer has the same guarantees.
	root := t.TempDir()
	options = f.options(root, true)
	options.Fault = func(operation, _ string) error {
		if operation == FaultSync {
			return syscall.ENOSPC
		}
		return nil
	}
	writer, err := NewGapSegment(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Add(archive.Gap{ID: 1, Reason: "r", Detail: "{}"}); err != nil {
		t.Fatal(err)
	}
	_, err = writer.Seal()
	wantReason(t, err, ReasonSyncFailed)
	assertNothingLive(t, root)
}

// Discarding a sealed segment, for example after registering the intent
// failed, removes its temporary files.
func TestDiscardSealed(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	writer, err := NewSegment(f.options(root, true), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_disc", Index: 1}, f.payloads)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range f.conversation("conv_disc", "r", 0) {
		if err := writer.Add(record); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := writer.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if countTemps(listFiles(t, root)) != 3 {
		t.Fatalf("sealed files: %s", describe(listFiles(t, root)))
	}
	sealed.Discard()
	if files := listFiles(t, root); len(files) != 0 {
		t.Fatalf("after discard: %s", describe(files))
	}
	wantReason(t, sealed.Publish(), ReasonClosed)
}

func countTemps(files []string) int {
	count := 0
	for _, file := range files {
		if IsTempName(filepath.Base(file)) {
			count++
		}
	}
	return count
}

// scanFiles fails when any file under root contains one of the markers. With
// gunzip set, gzip files are scanned after decompression.
func scanFiles(t *testing.T, root string, gunzip bool, markers ...string) {
	t.Helper()
	for _, file := range listFiles(t, root) {
		data := readAll(t, filepath.Join(root, filepath.FromSlash(file)))
		if gunzip && bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
			reader, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if data, err = io.ReadAll(reader); err != nil {
				t.Fatal(err)
			}
		}
		for _, marker := range markers {
			if bytes.Contains(data, []byte(marker)) {
				t.Fatalf("%s contains %q", file, marker)
			}
		}
	}
}

// N.1: with encryption on no test content reaches the disk, temporary files
// included; with encryption on or off no credential does.
func TestNoPlaintextOrCredentialOnDisk(t *testing.T) {
	credential := strings.TrimPrefix(credentialMarker, "sk-")
	for _, encrypt := range []bool{true, false} {
		t.Run(map[bool]string{true: "encrypted", false: "plain"}[encrypt], func(t *testing.T) {
			f := newFixture(t)
			root := t.TempDir()
			records := f.conversation("conv_scan", "s", 0)
			loose := canonical(t, f.audit("s-9", "openai", minute(9), 2))
			options := f.options(root, encrypt)
			markers := []string{credential}
			if encrypt {
				markers = append(markers, contentMarker)
			}
			scanned := 0
			options.Fault = func(operation, _ string) error {
				if operation == FaultLink && scanned == 0 {
					scanned = countTemps(listFiles(t, root))
					scanFiles(t, root, true, markers...)
				}
				return nil
			}
			if err := f.writeAndPublish(options, Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, append(records, loose)); err != nil {
				t.Fatal(err)
			}
			if scanned != 3 {
				t.Fatalf("scanned %d temporary files before publishing, want 3", scanned)
			}
			scanFiles(t, root, true, markers...)
			if !encrypt {
				// Sanity: the scan does see content in the plain files.
				found := false
				for _, file := range listFiles(t, root) {
					if strings.HasSuffix(file, PlainSuffix) {
						reader, err := gzip.NewReader(bytes.NewReader(readAll(t, filepath.Join(root, filepath.FromSlash(file)))))
						if err != nil {
							t.Fatal(err)
						}
						data, _ := io.ReadAll(reader)
						found = found || bytes.Contains(data, []byte(contentMarker))
					}
				}
				if !found {
					t.Fatal("plain files hold no test content: the scan proves nothing")
				}
			}
			if _, err := os.Stat(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}
