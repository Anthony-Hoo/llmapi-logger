package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

func minute(n int) int64 { return baseTimeNS + int64(n)*int64(time.Minute) }

func rawData(seed byte, size int) []byte {
	data := make([]byte, size)
	state := sha256.Sum256([]byte{seed})
	for offset := 0; offset < size; offset += len(state) {
		copy(data[offset:], state[:])
		state = sha256.Sum256(state[:])
	}
	copy(data, contentMarker)
	return data
}

// conversation builds three turns of one conversation: a version 2 root with
// a complete multi-chunk response body, a version 1 child with a binary and
// a small parsed_json, and a version 2 request-only grandchild with a
// partial body and a parsed_json over the inline limit.
func (f *fixture) conversation(conversationID, prefix string, start int) []*archive.Record {
	f.t.Helper()
	r1 := f.audit(prefix+"-1", "openai", minute(start), storage.CaptureVersion2)
	f.withTurn(r1, conversationID, turnOptions{messages: []string{"hello"}, response: "hi", createdNS: minute(start) + 500})
	f.withRaw(r1, storage.StageResponseReceived, rawData(1, 5000), 2048, true)
	canonical(f.t, r1)

	r2 := f.audit(prefix+"-2", "openai", minute(start+1), storage.CaptureVersion1)
	f.withTurn(r2, conversationID, turnOptions{parent: r1, messages: []string{"second", "third"}, response: "ok", createdNS: minute(start+1) + 500, binary: true})
	f.withParsed(r2, []byte(`{"protocol":"openai","note":"`+contentMarker+`"}`))
	canonical(f.t, r2)

	r3 := f.audit(prefix+"-3", "openai", minute(start+2), storage.CaptureVersion2)
	f.withTurn(r3, conversationID, turnOptions{parent: r2, messages: []string{"fourth"}, createdNS: minute(start+2) + 500})
	f.withRaw(r3, storage.StageRequestReceived, rawData(3, 3000), 1024, false)
	large := `{"conversation":"` + strings.Repeat("x"+contentMarker, (archive.ParsedJSONInlineLimit/10)+20000) + `"}`
	f.withParsed(r3, []byte(large))
	canonical(f.t, r3)
	return []*archive.Record{r1, r2, r3}
}

func digestOf(t *testing.T, record *archive.Record) [32]byte {
	t.Helper()
	digest, err := archive.Digest(record)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

var segmentName = regexp.MustCompile(`^sessions/2025/11/20251128T\d{6}Z_20251128T\d{6}Z_(conv_[a-z]+|bucket-openai-01234567)_s\d{4}\.(jsonl\.gz(\.enc)?|objects\.jsonl\.gz(\.enc)?|manifest\.json)$`)

func TestRoundTrip(t *testing.T) {
	for _, encrypt := range []bool{true, false} {
		t.Run(map[bool]string{true: "encrypted", false: "plain"}[encrypt], func(t *testing.T) {
			f := newFixture(t)
			root := t.TempDir()
			records := f.conversation("conv_alpha", "a", 0)
			sealed := f.writeSegment(f.options(root, encrypt), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_alpha", Index: 1}, records...)

			files := listFiles(t, root)
			if len(files) != 3 {
				t.Fatalf("files = %s, want lines, objects and manifest", describe(files))
			}
			for _, file := range files {
				if !segmentName.MatchString(file) || strings.HasSuffix(file, ".enc") != encrypt && !strings.HasSuffix(file, ManifestSuffix) {
					t.Fatalf("file name %q", file)
				}
			}
			manifest := sealed.Manifest()
			if manifest.Encrypted != encrypt || manifest.LineCount != 3 || manifest.RawChunkCount != 6 || len(manifest.Conversations) != 1 ||
				manifest.FirstStartedAtNS != records[0].Audit.StartedAtNS || manifest.LastEndedAtNS != records[2].Audit.EndedAtNS {
				t.Fatalf("manifest = %+v", manifest)
			}
			if manifest.KeyFingerprint != f.keys.KeyFingerprint() {
				t.Fatal("manifest key fingerprint")
			}

			bundle, report := f.verify(sealed.ManifestPath(), encrypt)
			if report.Lines != 3 || report.RawChunks != 6 || report.BinaryObjects != 1 || report.ParsedJSONParts != 2 ||
				report.ContentObjects+report.BinaryObjects+report.ParsedJSONParts != manifest.ObjectCount {
				t.Fatalf("report = %+v", report)
			}
			for index, member := range report.Members {
				if member.Digest != digestOf(t, records[index]) || member.AuditID != records[index].Audit.AuditID || member.Revision != 1 {
					t.Fatalf("member %d = %+v", index, member)
				}
			}

			var read []*archive.Record
			err := bundle.Records(context.Background(), func(line Line) error {
				if line.Record.Turn.Context.Form != archive.ContextDelta {
					t.Errorf("line %d form %s, want delta: every parent is in the segment", line.Index, line.Record.Turn.Context.Form)
				}
				if line.Digest != digestOf(t, records[line.Index]) {
					t.Errorf("line %d digest differs from the source record", line.Index)
				}
				read = append(read, line.Record)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			objects, err := bundle.LoadObjects(context.Background(), read[2])
			if err != nil {
				t.Fatal(err)
			}
			for _, meta := range read[2].Turn.Objects {
				data, err := objects.ContentPlaintext(meta.Hash)
				if err != nil || !bytes.Equal(data, f.payloads.contents[string(meta.Hash)].Data) {
					t.Fatalf("object: %v", err)
				}
			}
			if _, err := objects.BinaryData(read[1].Turn.Binaries[0].Hash); err == nil {
				t.Fatal("binary of an unselected record was loaded")
			}
			joined, err := objects.ParsedJSON("a-3")
			if err != nil || !bytes.Equal(joined, records[2].ParsedResult.ParsedJSON) {
				t.Fatalf("parsed_json: %v", err)
			}

			// The raw chunks plug into query.VerifyRaw, which applies the
			// checks of Service.StreamRaw.
			body, ok, err := read[0].SelectBody(query.SideResponse)
			if err != nil || !ok {
				t.Fatal("no response body")
			}
			var raw bytes.Buffer
			err = query.VerifyRaw(context.Background(), read[0].RawMetadata(body), func(visit func(query.PlainChunk) error) error {
				return bundle.StreamRaw(context.Background(), read[0], body.SourceStage, visit)
			}, &raw)
			if err != nil || !bytes.Equal(raw.Bytes(), rawData(1, 5000)) {
				t.Fatalf("raw: %v", err)
			}

			if _, err := VerifyFiles(context.Background(), sealed.ManifestPath()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A conversation rolled into two segments: the first turn of the second
// segment has its parent in the first and is written materialised; the
// second segment verifies and reads on its own after the first is gone.
func TestMultiSegmentConversation(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	records := f.conversation("conv_beta", "b", 0)
	r4 := f.audit("b-4", "openai", minute(3), storage.CaptureVersion2)
	f.withTurn(r4, "conv_beta", turnOptions{parent: records[2], messages: []string{"fifth"}, response: "done", createdNS: minute(3) + 500})
	records = append(records, canonical(t, r4))

	options := f.options(root, true)
	options.SegmentMaxBytes = 1
	spec := Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_beta", Index: 1}
	var sealed []*Sealed
	writer, err := NewSegment(options, spec, f.payloads)
	if err != nil {
		t.Fatal(err)
	}
	for index, record := range records {
		if index == 2 {
			// Roll by hand after two records, as the runner does when Full
			// reports true.
			if !writer.Full() {
				t.Fatal("segment over the limit does not report full")
			}
			segment, err := writer.Seal()
			if err != nil {
				t.Fatal(err)
			}
			sealed = append(sealed, segment)
			spec.Index++
			if writer, err = NewSegment(options, spec, f.payloads); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Add(record); err != nil {
			t.Fatal(err)
		}
	}
	last, err := writer.Seal()
	if err != nil {
		t.Fatal(err)
	}
	sealed = append(sealed, last)
	for _, segment := range sealed {
		if err := segment.Publish(); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.HasSuffix(sealed[0].ManifestPath(), "_s0001"+ManifestSuffix) || !strings.HasSuffix(sealed[1].ManifestPath(), "_s0002"+ManifestSuffix) {
		t.Fatalf("segment names %s, %s", sealed[0].ManifestPath(), sealed[1].ManifestPath())
	}
	if err := Reject(sealed[0].ManifestPath()); err != nil {
		t.Fatal(err)
	}
	bundle, report := f.verify(sealed[1].ManifestPath(), true)
	if report.Lines != 2 {
		t.Fatalf("second segment has %d lines", report.Lines)
	}
	forms := []string{}
	err = bundle.Records(context.Background(), func(line Line) error {
		forms = append(forms, line.Record.Turn.Context.Form)
		if line.Digest != digestOf(t, records[2+line.Index]) {
			t.Errorf("digest of line %d", line.Index)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if forms[0] != archive.ContextMaterialized || forms[1] != archive.ContextDelta {
		t.Fatalf("forms = %v, want materialized then delta", forms)
	}
}

// A bucket with two conversations and turnless audits of both capture
// versions, after them in started_at_ns order.
func TestBucketBundle(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	first := f.conversation("conv_gamma", "c", 0)
	second := f.conversation("conv_delta", "d", 10)[:2]
	loose1 := canonical(t, f.audit("e-1", "openai", minute(1), storage.CaptureVersion1))
	loose2 := canonical(t, f.withRaw(f.audit("e-2", "openai", minute(2), storage.CaptureVersion2), storage.StageRequestReceived, rawData(9, 100), 64, true))
	records := append(append(append([]*archive.Record{}, first...), second...), loose1, loose2)
	sealed := f.writeSegment(f.options(root, true), Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, records...)
	manifest := sealed.Manifest()
	if strings.Join(manifest.Conversations, ",") != "conv_gamma,conv_delta" || manifest.Members[5].ConversationID != nil {
		t.Fatalf("conversations %v", manifest.Conversations)
	}
	if !strings.Contains(sealed.ManifestPath(), "_bucket-openai-01234567_s0001") {
		t.Fatalf("bucket name %s", sealed.ManifestPath())
	}
	_, report := f.verify(sealed.ManifestPath(), true)
	if report.Lines != 7 {
		t.Fatalf("lines = %d", report.Lines)
	}

	// Order rules: a turn after a turnless audit, a conversation that comes
	// back, and turnless audits out of started_at_ns order are refused.
	for name, order := range map[string][]*archive.Record{
		"turn after turnless":  {loose1, first[0]},
		"conversation returns": {first[0], second[0], first[1]},
		"turnless order":       {loose2, loose1},
		"turn order":           {first[1], first[0]},
	} {
		t.Run(name, func(t *testing.T) {
			writer, err := NewSegment(f.options(t.TempDir(), true), Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, f.payloads)
			if err != nil {
				t.Fatal(err)
			}
			var last error
			for _, record := range order {
				if last = writer.Add(record); last != nil {
					break
				}
			}
			wantReason(t, last, ReasonOrder)
		})
	}
}

func TestGapBundle(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	writer, err := NewGapSegment(f.options(root, true))
	if err != nil {
		t.Fatal(err)
	}
	gaps := []archive.Gap{
		{ID: 7, StartedAtNS: minute(0), EndedAtNS: minute(1), Reason: "store_unavailable", RequestCount: 3, Detail: "{}", CreatedAtNS: minute(1)},
		{ID: 9, StartedAtNS: minute(2), EndedAtNS: minute(5), Reason: "queue_full", RequestCount: 1, Detail: "{}", CreatedAtNS: minute(5)},
	}
	for _, gap := range gaps {
		if err := writer.Add(gap); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := writer.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := sealed.Publish(); err != nil {
		t.Fatal(err)
	}
	if files := listFiles(t, root); describe(files) != describe([]string{"gaps/gaps-7-9.jsonl.gz.enc", "gaps/gaps-7-9.manifest.json"}) {
		t.Fatalf("files = %s", describe(files))
	}
	bundle, report := f.verify(sealed.ManifestPath(), true)
	if report.Gaps != 2 || len(report.Members) != 0 {
		t.Fatalf("report = %+v", report)
	}
	var read []archive.Gap
	if err := bundle.Gaps(context.Background(), func(gap archive.Gap) error { read = append(read, gap); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(read) != 2 || read[1] != gaps[1] {
		t.Fatalf("gaps = %+v", read)
	}

	out, err := NewGapSegment(f.options(t.TempDir(), false))
	if err != nil {
		t.Fatal(err)
	}
	if err := out.Add(gaps[1]); err != nil {
		t.Fatal(err)
	}
	wantReason(t, out.Add(gaps[0]), ReasonOrder)
}

// Turnless audits without raw have no object entries: no objects file.
func TestSegmentWithoutObjects(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	sealed := f.writeSegment(f.options(root, true), Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1},
		canonical(t, f.audit("n-1", "openai", minute(0), storage.CaptureVersion1)),
		canonical(t, f.audit("n-2", "openai", minute(1), storage.CaptureVersion2)))
	manifest := sealed.Manifest()
	if len(manifest.Files) != 1 || manifest.ObjectCount != 0 || manifest.RawChunkCount != 0 {
		t.Fatalf("manifest files %+v", manifest.Files)
	}
	if files := listFiles(t, root); len(files) != 2 {
		t.Fatalf("files = %s", describe(files))
	}
	bundle, _ := f.verify(sealed.ManifestPath(), true)
	if _, err := bundle.LoadObjects(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The writer refuses records it cannot write correctly and then stays
// closed with its temporary files gone.
func TestWriterRejectsRecords(t *testing.T) {
	f := newFixture(t)
	records := f.conversation("conv_eps", "x", 0)
	cases := map[string]struct {
		mutate func(*archive.Record) *archive.Record
		reason string
	}{
		"protocol": {func(r *archive.Record) *archive.Record { r.Audit.Protocol = "gemini"; return r }, ReasonInvalidRecord},
		"revision": {func(r *archive.Record) *archive.Record { r.Revision = 0; return r }, ReasonInvalidRecord},
		"delta does not apply": {func(r *archive.Record) *archive.Record {
			r.Turn.Context.Ops = r.Turn.Context.Ops[:len(r.Turn.Context.Ops)-1]
			return r
		}, ReasonContextMismatch},
		"payload missing": {func(r *archive.Record) *archive.Record {
			r.RawChunks[0].Seq = 99
			_ = r.Canonicalize()
			return r
		}, ReasonPayloadFailed},
		"payload differs": {func(r *archive.Record) *archive.Record { r.RawChunks[0].SHA256[0] ^= 1; return r }, ReasonPayloadMismatch},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writer, err := NewSegment(f.options(root, true), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_eps", Index: 1}, f.payloads)
			if err != nil {
				t.Fatal(err)
			}
			copyRecord := *records[0]
			turn := *records[0].Turn
			turn.Context.Ops = append([]archive.ContextOp(nil), turn.Context.Ops...)
			copyRecord.Turn = &turn
			copyRecord.RawChunks = append([]archive.RawChunk(nil), records[0].RawChunks...)
			wantReason(t, writer.Add(test.mutate(&copyRecord)), test.reason)
			wantReason(t, writer.Add(records[0]), ReasonClosed)
			if files := listFiles(t, root); len(files) != 0 {
				t.Fatalf("files left: %s", describe(files))
			}
		})
	}
	writer, err := NewSegment(f.options(t.TempDir(), true), Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, f.payloads)
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.Seal()
	wantReason(t, err, ReasonEmptySegment)
}

// Iteration before a successful Verify is refused (G.3).
func TestIterationNeedsVerify(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	sealed := f.writeSegment(f.options(root, true), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_zeta", Index: 1},
		f.conversation("conv_zeta", "z", 0)...)
	bundle, err := Open(sealed.ManifestPath(), f.readOptions(true))
	if err != nil {
		t.Fatal(err)
	}
	wantReason(t, bundle.Records(context.Background(), func(Line) error { return nil }), ReasonNotVerified)
	_, err = bundle.LoadObjects(context.Background())
	wantReason(t, err, ReasonNotVerified)

	if _, err := Open(sealed.ManifestPath(), ReadOptions{EncryptionKey: f.keys.EncryptionKey()}); ReasonOf(err) != ReasonKeyRequired {
		t.Fatalf("open without a signer: %v", err)
	}
	if _, err := Open(sealed.ManifestPath(), ReadOptions{Signer: f.keys}); ReasonOf(err) != ReasonKeyRequired {
		t.Fatalf("open an encrypted bundle without its key: %v", err)
	}
}

// An unencrypted bundle opens without a signer only when asked to; the
// manifest is then not authenticated.
func TestUnauthenticatedPlainBundle(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	sealed := f.writeSegment(f.options(root, false), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_eta", Index: 1},
		f.conversation("conv_eta", "h", 0)...)
	bundle, err := Open(sealed.ManifestPath(), ReadOptions{Unauthenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Authenticated() {
		t.Fatal("authenticated without a signer")
	}
	if _, err := bundle.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Event MACs are checked when a verifier is given.
type rejectEvents struct{ calls int }

func (events *rejectEvents) Verify([]byte, string, string, []byte, []byte, int64) bool {
	events.calls++
	return false
}

func TestEventVerifier(t *testing.T) {
	f := newFixture(t)
	sealed := f.writeSegment(f.options(t.TempDir(), true), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_theta", Index: 1},
		f.conversation("conv_theta", "t", 0)...)
	options := f.readOptions(true)
	events := &rejectEvents{}
	options.Events = events
	bundle, err := Open(sealed.ManifestPath(), options)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bundle.Verify(context.Background())
	wantReason(t, err, ReasonEventMAC)
	if events.calls != 1 {
		t.Fatalf("calls = %d", events.calls)
	}
}

func TestRejectRenamesWithoutDeleting(t *testing.T) {
	f := newFixture(t)
	root := t.TempDir()
	sealed := f.writeSegment(f.options(root, true), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_iota", Index: 1},
		f.conversation("conv_iota", "i", 0)...)
	before := listFiles(t, root)
	if err := Reject(sealed.ManifestPath()); err != nil {
		t.Fatal(err)
	}
	after := listFiles(t, root)
	if len(after) != len(before) || countSuffix(after, RejectedSuffix) != len(before) {
		t.Fatalf("after reject: %s", describe(after))
	}
	_, err := Open(sealed.ManifestPath(), f.readOptions(true))
	wantReason(t, err, ReasonNotFound)
	index, err := BuildIndex(context.Background(), root, f.keys)
	if err != nil || len(index.Bundles()) != 0 || len(index.Leftovers().DataWithoutManifest) != 0 {
		t.Fatalf("index after reject: %v %+v", err, index)
	}
}

func readAll(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The writer never replaces a file: an existing final name fails the seal,
// and one that appears between seal and publish fails the publish; the
// existing file is unchanged and no temporary file stays.
func TestNeverOverwrites(t *testing.T) {
	f := newFixture(t)
	records := f.conversation("conv_kappa", "k", 0)
	spec := Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: "conv_kappa", Index: 1}

	reference := f.writeSegment(f.options(t.TempDir(), true), spec, records...)
	relative := func(path string) string {
		return strings.TrimPrefix(path, filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(path)))))
	}

	for _, target := range []string{"objects-at-seal", "objects-at-publish"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			objects := filepath.Join(root, relative(filepath.Join(filepath.Dir(reference.ManifestPath()), reference.Manifest().Files[1].Name)))
			writer, err := NewSegment(f.options(root, true), spec, f.payloads)
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				if err := writer.Add(record); err != nil {
					t.Fatal(err)
				}
			}
			place := func() {
				if err := os.MkdirAll(filepath.Dir(objects), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(objects, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if target == "objects-at-seal" {
				place()
				_, err := writer.Seal()
				wantReason(t, err, ReasonNameExists)
			} else {
				sealed, err := writer.Seal()
				if err != nil {
					t.Fatal(err)
				}
				place()
				wantReason(t, sealed.Publish(), ReasonNameExists)
			}
			if string(readAll(t, objects)) != "keep" {
				t.Fatal("existing file changed")
			}
			files := listFiles(t, root)
			for _, file := range files {
				if IsTempName(filepath.Base(file)) || strings.HasSuffix(file, ManifestSuffix) {
					t.Fatalf("left behind: %s", describe(files))
				}
			}
		})
	}
}

// Every part of the error stays behind Unwrap.
func TestErrorMessagesCarryOnlyTheReason(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "missing"+ManifestSuffix), ReadOptions{})
	if err == nil || err.Error() != "archive bundle: "+ReasonNotFound || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
	var target *Error
	if !errors.As(err, &target) || target.Reason() != ReasonNotFound {
		t.Fatal("not a *Error")
	}
}
