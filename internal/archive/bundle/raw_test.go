package bundle

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

func (f *fixture) verifyOne(record *archive.Record) (*Bundle, error) {
	f.t.Helper()
	root := f.t.TempDir()
	sealed := f.writeSegment(f.options(root, true), Spec{Kind: archive.BundleBucket, Protocol: "openai", Index: 1}, record)
	bundle, err := Open(sealed.ManifestPath(), f.readOptions(true))
	if err != nil {
		f.t.Fatal(err)
	}
	_, err = bundle.Verify(context.Background())
	return bundle, err
}

// A forward gap in the raw chunks is accepted only for a partial body that
// recorded capture_chunk_missing, as query.StreamRaw accepts it.
func TestRawChunkGapNeedsCaptureChunkMissing(t *testing.T) {
	for _, code := range []string{storage.CaptureChunkMissing, "capture_truncated"} {
		t.Run(code, func(t *testing.T) {
			f := newFixture(t)
			record := f.withRaw(f.audit("gap-1", "openai", minute(0), storage.CaptureVersion2), storage.StageResponseReceived, rawData(5, 300), 100, false)
			record.RawChunks = []archive.RawChunk{record.RawChunks[0], record.RawChunks[2]}
			body := &record.Bodies[0]
			body.StoredLength, body.ChunkCount, body.ErrorCode = 200, 2, text(code)
			canonical(t, record)
			_, err := f.verifyOne(record)
			if code == storage.CaptureChunkMissing {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantReason(t, err, ReasonRawMismatch)
		})
	}
}

// A body deduplicated onto another stage (source_stage) is served from the
// source stage's chunks and checked against its own metadata.
func TestDeduplicatedBodyPair(t *testing.T) {
	build := func(f *fixture) *archive.Record {
		record := f.withRaw(f.audit("dup-1", "openai", minute(0), storage.CaptureVersion2), storage.StageResponseReceived, rawData(6, 2500), 1000, true)
		duplicate := record.Bodies[0]
		duplicate.Stage = storage.StageResponseSent
		record.Bodies = append(record.Bodies, duplicate)
		return canonical(f.t, record)
	}
	f := newFixture(t)
	record := build(f)
	bundle, err := f.verifyOne(record)
	if err != nil {
		t.Fatal(err)
	}
	var lines []*archive.Record
	if err := bundle.Records(context.Background(), func(line Line) error { lines = append(lines, line.Record); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, body := range lines[0].Bodies {
		var raw bytes.Buffer
		err := query.VerifyRaw(context.Background(), lines[0].RawMetadata(body), func(visit func(query.PlainChunk) error) error {
			return bundle.StreamRaw(context.Background(), lines[0], body.SourceStage, visit)
		}, &raw)
		if err != nil || !bytes.Equal(raw.Bytes(), rawData(6, 2500)) {
			t.Fatalf("%s: %v", body.Stage, err)
		}
	}

	f = newFixture(t)
	record = build(f)
	record.Bodies[1].SHA256 = bytes.Repeat([]byte{1}, 32)
	_, err = f.verifyOne(record)
	wantReason(t, err, ReasonRawMismatch)
}

func TestGapBundleTamper(t *testing.T) {
	for _, resign := range []bool{false, true} {
		f := newFixture(t)
		root := t.TempDir()
		writer, err := NewGapSegment(f.options(root, true))
		if err != nil {
			t.Fatal(err)
		}
		for id := int64(1); id <= 3; id++ {
			if err := writer.Add(archive.Gap{ID: id, StartedAtNS: minute(int(id)), EndedAtNS: minute(int(id) + 1), Reason: "r", Detail: "{}"}); err != nil {
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
		path := filepath.Join(filepath.Dir(sealed.ManifestPath()), sealed.Manifest().Files[0].Name)
		key := f.keys.EncryptionKey()
		entries := decodeFile(t, path, key)
		encodeFile(t, path, key, entries[:2])
		want := ReasonFileMismatch
		if resign {
			f.resign(sealed.ManifestPath(), nil)
			want = ReasonCountMismatch
		}
		bundle, err := Open(sealed.ManifestPath(), f.readOptions(true))
		if err != nil {
			t.Fatal(err)
		}
		_, err = bundle.Verify(context.Background())
		wantReason(t, err, want)
	}
}
