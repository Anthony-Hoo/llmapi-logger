package archivecli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/conversation"
	base "llmapi-logger/internal/parser"
	"llmapi-logger/internal/parser/openai"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// The generator of the frozen fixture bundles (compatibility promise: plan
// 4.4, design N.1, doc/features/26-cold-archive.md §2). It is not a test: it
// runs only when ARCHIVE_WRITE_FIXTURE names an output directory that does
// not exist yet, and writes there, with the format version this build
// writes, the archive directory that frozen_test.go reads:
//
//	ARCHIVE_WRITE_FIXTURE=<dir> go test ./internal/archivecli -run TestWriteFrozenFixture -count=1
//
// ARCHIVE_FIXTURE_REVISION (default 1) is the revision of every member.
//
// The inputs are fixed: the master key is the obvious test key 0x00..0x1f,
// the run id, the clock and every value are constants, the content is
// synthetic (example.com hosts, made-up prompts and credentials). The output
// bytes are still not reproducible: the bundle writer draws each segment id
// and each encrypted file's salt at random. That is why a fixture, once
// committed, is never regenerated; see frozen_test.go.

const (
	// frozenRunID is the run id of every fixture bundle.
	frozenRunID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	// frozenConversation is the conversation of the fixture's chain of
	// three turns; frozenOpenConversation holds the request-only turn.
	frozenConversation     = "conv_frozen"
	frozenOpenConversation = "conv_frozen_open"
)

// frozenMaster is the fixture's master key: the bytes 0x00 to 0x1f, a key
// nobody uses for anything else.
func frozenMaster() []byte {
	master := make([]byte, 32)
	for index := range master {
		master[index] = byte(index)
	}
	return master
}

func TestWriteFrozenFixture(t *testing.T) {
	out := os.Getenv("ARCHIVE_WRITE_FIXTURE")
	if out == "" {
		t.Skip("set ARCHIVE_WRITE_FIXTURE to the directory of a new fixture (see frozen_test.go)")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists: a committed fixture is never regenerated", out)
	}
	revision := int64(1)
	if value := os.Getenv("ARCHIVE_FIXTURE_REVISION"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 1 {
			t.Fatalf("ARCHIVE_FIXTURE_REVISION %q", value)
		}
		revision = parsed
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFrozenFixture(t, out, revision)
	t.Logf("wrote format version %s to %s", archive.FormatVersion, out)
}

// writeFrozenFixture writes, under root:
//
//   - an encrypted conversation bundle of conv_frozen: frozen-a1, a root turn
//     with an inline image (a binary object), raw request and response and a
//     response timeline, a project identity; frozen-a2, its child, kept in
//     delta form because the parent is in the same segment, with a billed
//     token link;
//   - a plain bucket: frozen-a3, capture version 1, the child of frozen-a2,
//     in materialised form (its parent is in another segment); frozen-a4, a
//     request-only turn of conv_frozen_open with a half answer in its parsed
//     result; frozen-loose, a turnless audit whose parse failed, with a
//     fallback conversation over the inline limit (a split parsed_json in
//     the objects file) and a partial raw request body;
//   - a plain gap bundle of one gap.
//
// Every audit has projected credentials (Authorization, x-api-key, Cookie,
// Set-Cookie, ?key=, and on capture version 2 a User-Agent value) and
// integrity events whose MACs are real under the master key.
func writeFrozenFixture(t *testing.T, root string, revision int64) {
	t.Helper()
	keys, err := NewKeys(frozenMaster())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, master: frozenMaster(), keys: keys, root: root,
		payloads:  &payloads{contents: map[string]archive.ContentObject{}, binaries: map[string]archive.BinaryObject{}, chunks: map[chunkID][]byte{}},
		signer:    keys.Events,
		exchanges: map[string]exchange{}, raw: map[string][]byte{}, originals: map[string]original{}}

	first, second, third := "first question", "second question", "third question"
	a1 := f.audit("frozen-a1", minute(0), storage.CaptureVersion2)
	f.withRealTurn(a1, frozenConversation, minute(0)+500, first)
	a1.ProjectIdentity = &archive.ProjectIdentity{IdentityVersion: 1, ExtractedAtNS: minute(0) + 700, Source: "codex_turn_metadata", BodyScanned: true,
		IdentityFPR: bytes.Repeat([]byte{0x11}, 32), CwdFPR: bytes.Repeat([]byte{0x14}, 32), Identity: []byte(`{"cwd":"/work/example"}`)}

	a2 := f.audit("frozen-a2", minute(1), storage.CaptureVersion2)
	f.withRealChildTurn(a2, frozenConversation, minute(1)+500, second, a1,
		[]any{userItem(first), answerItem("frozen-a1", first)}, false)
	a2.TokenLink = &archive.TokenLink{NewAPIUserID: 7, Username: "user-example", NewAPITokenID: 9, TokenName: "token-example",
		LinkedAtNS: minute(30), BillingState: "billed", Quota: integer(100), BillingAttempts: 1}

	a3 := f.audit("frozen-a3", minute(2), storage.CaptureVersion1)
	f.withRealChildTurn(a3, frozenConversation, minute(2)+500, third, a2,
		[]any{userItem(first), answerItem("frozen-a1", first), userItem(second), answerItem("frozen-a2", second)}, false)

	a4 := f.audit("frozen-a4", minute(3), storage.CaptureVersion2)
	f.withRealChildTurn(a4, frozenOpenConversation, minute(3)+500, "unanswered question", nil, nil, true)
	partial, err := json.Marshal(map[string]any{"status": "partial", base.PartialResponseMessagesKey: []conversation.Message{{
		Index: 1, Role: conversation.RoleAssistant, Phase: conversation.PhaseResponse, Direction: conversation.DirectionUpstreamToClient,
		Content: []conversation.Part{conversation.Text("half an answer " + contentMarker)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	a4.Audit.ForwardStatus, a4.Audit.CaptureStatus, a4.Audit.ParseStatus = storage.ForwardNewAPIError, storage.CapturePartial, storage.ParsePartial
	a4.ParsedResult.Status, a4.ParsedResult.ResponseModel, a4.ParsedResult.ParsedJSON = storage.ParsePartial, nil, partial

	loose := f.audit("frozen-loose", minute(4), storage.CaptureVersion2)
	loose.Audit.ParseStatus = storage.ParseError
	plain, err := a1.PlainDetail(f.payloads, nil)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := query.ReconstructPlainTurn(plain)
	if err != nil {
		t.Fatal(err)
	}
	fallback, err := auditmodel.CanonicalJSON(map[string]any{"conversation": rebuilt.Conversation, "pad": strings.Repeat("p", archive.ParsedJSONInlineLimit+1000)})
	if err != nil {
		t.Fatal(err)
	}
	loose.ParsedResult = &archive.ParsedResult{ParserName: openai.Responses, ParserVersion: "1", Status: storage.ParseError,
		ErrorCode: text("normalization_failed"), ParsedJSON: fallback, ParsedAtNS: loose.Audit.EndedAtNS + 1}
	partialRequest := []byte("partial request " + contentMarker + strings.Repeat("r", 300))
	f.withRaw(loose, storage.StageRequestReceived, "", partialRequest, 128, false)
	loose.Bodies = append(loose.Bodies, storage.BodyStream{Stage: storage.StageResponseReceived, SourceStage: storage.StageResponseReceived,
		ObservedLength: 10, State: storage.StageStateComplete, HashComplete: true, EOFSeen: true, RetentionState: storage.RetentionMetadata,
		SHA256: bytes.Repeat([]byte{1}, 32)})

	for _, record := range []*archive.Record{a1, a2, a3, a4, loose} {
		record.Revision = revision
	}
	write := func(encrypt bool, spec bundle.Spec, records ...*archive.Record) string {
		options := bundle.Options{Root: root, Signer: keys.Archive, Encrypt: encrypt, SourceSchemaVersion: "8", RunID: frozenRunID,
			Now: func() time.Time { return time.Unix(0, baseTimeNS+int64(time.Hour)) }}
		if encrypt {
			options.EncryptionKey = keys.Archive.EncryptionKey()
		}
		writer, err := bundle.NewSegment(options, spec, f.payloads)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if err := writer.Add(f.canonical(record)); err != nil {
				t.Fatalf("add %s: %v (%v)", record.Audit.AuditID, err, errors.Unwrap(err))
			}
		}
		sealed, err := writer.Seal()
		if err != nil {
			t.Fatalf("seal: %v (%v)", err, errors.Unwrap(err))
		}
		if err := sealed.Publish(); err != nil {
			t.Fatalf("publish: %v (%v)", err, errors.Unwrap(err))
		}
		return sealed.ManifestPath()
	}
	manifests := []string{
		write(true, bundle.Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: frozenConversation, Index: 1}, a1, a2),
		write(false, bundle.Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, a3, a4, loose),
	}
	gaps, err := bundle.NewGapSegment(bundle.Options{Root: root, Signer: keys.Archive, SourceSchemaVersion: "8", RunID: frozenRunID,
		Now: func() time.Time { return time.Unix(0, baseTimeNS+int64(time.Hour)) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := gaps.Add(archive.Gap{ID: 7, StartedAtNS: minute(50), EndedAtNS: minute(51), Reason: "queue_full", RequestCount: 3, Detail: "{}", CreatedAtNS: minute(52)}); err != nil {
		t.Fatal(err)
	}
	sealedGaps, err := gaps.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := sealedGaps.Publish(); err != nil {
		t.Fatal(err)
	}
	manifests = append(manifests, sealedGaps.ManifestPath())

	// What was written reads back with every check.
	for _, path := range manifests {
		opened, err := bundle.Open(path, bundle.ReadOptions{Signer: keys.Archive, EncryptionKey: keys.Archive.EncryptionKey(), Events: keys.Events})
		if err != nil {
			t.Fatalf("open %s: %v (%v)", filepath.Base(path), err, errors.Unwrap(err))
		}
		report, err := opened.Verify(context.Background())
		if err != nil {
			t.Fatalf("verify %s: %v (%v)", filepath.Base(path), err, errors.Unwrap(err))
		}
		for _, member := range report.Members {
			t.Logf("%s %s revision %d digest %x", filepath.Base(path), member.AuditID, member.Revision, member.Digest)
		}
	}
}
