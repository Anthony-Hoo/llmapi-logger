package bundle

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/stream"
	"llmapi-logger/internal/storage"
)

// decodeFile returns the entries of a data file.
func decodeFile(t *testing.T, path string, key []byte) [][]byte {
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
	entries := bytes.Split(bytes.TrimSuffix(plain, []byte("\n")), []byte("\n"))
	return entries
}

// encodeFile rewrites a data file with entries, as the writer would.
func encodeFile(t *testing.T, path string, key []byte, entries [][]byte) {
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

// resign rewrites the manifest with the files' current sizes and hashes,
// applies mutate, and signs it with the archive key: what someone holding
// the key could do, so the deeper checks are reached.
func (f *fixture) resign(path string, mutate func(*archive.Manifest)) {
	f.t.Helper()
	manifest, err := archive.DecodeManifest(readAll(f.t, path))
	if err != nil {
		f.t.Fatal(err)
	}
	for index, file := range manifest.Files {
		data := readAll(f.t, filepath.Join(filepath.Dir(path), file.Name))
		manifest.Files[index].Bytes, manifest.Files[index].SHA256 = int64(len(data)), sha256.Sum256(data)
	}
	if mutate != nil {
		mutate(manifest)
	}
	if err := manifest.Sign(f.keys); err != nil {
		f.t.Fatal(err)
	}
	encoded, err := archive.EncodeManifest(manifest)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

type tamperTarget struct {
	manifest string
	lines    string
	objects  string
	key      []byte
}

func (f *fixture) tamperBundle(root string, encrypt bool, conversationID, prefix string) tamperTarget {
	records := f.conversation(conversationID, prefix, 0)
	big := f.audit(prefix+"-4", "openai", minute(3), storage.CaptureVersion2)
	f.withTurn(big, conversationID, turnOptions{parent: records[2], messages: []string{"big"}, response: "large", createdNS: minute(3) + 500})
	f.withRaw(big, storage.StageResponseReceived, rawData(4, 200_000), 1<<20, true)
	records = append(records, canonical(f.t, big))
	sealed := f.writeSegment(f.options(root, encrypt), Spec{Kind: archive.BundleConversation, Protocol: "openai", ConversationID: conversationID, Index: 1}, records...)
	dir := filepath.Dir(sealed.ManifestPath())
	target := tamperTarget{manifest: sealed.ManifestPath(), lines: filepath.Join(dir, sealed.Manifest().Files[0].Name), objects: filepath.Join(dir, sealed.Manifest().Files[1].Name)}
	if encrypt {
		target.key = f.keys.EncryptionKey()
	}
	return target
}

func swapFrames(t *testing.T, path string) {
	t.Helper()
	data := readAll(t, path)
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

func truncate(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.Truncate(path, size); err != nil {
		t.Fatal(err)
	}
}

func TestTamperIsDetected(t *testing.T) {
	cases := []struct {
		name    string
		encrypt bool
		tamper  func(f *fixture, target tamperTarget)
		open    func(f *fixture) ReadOptions
		reason  string
	}{
		{name: "truncated lines file", encrypt: true, reason: ReasonFileMismatch, tamper: func(f *fixture, target tamperTarget) {
			info, _ := os.Stat(target.lines)
			truncate(f.t, target.lines, info.Size()-10)
		}},
		{name: "objects cut at a frame boundary, manifest re-signed", encrypt: true, reason: ReasonDecryptFailed, tamper: func(f *fixture, target tamperTarget) {
			truncate(f.t, target.objects, stream.HeaderSize+stream.SealedFrameSize)
			f.resign(target.manifest, nil)
		}},
		{name: "frames reordered", encrypt: true, reason: ReasonFileMismatch, tamper: func(f *fixture, target tamperTarget) {
			swapFrames(f.t, target.objects)
		}},
		{name: "frames reordered, manifest re-signed", encrypt: true, reason: ReasonDecryptFailed, tamper: func(f *fixture, target tamperTarget) {
			swapFrames(f.t, target.objects)
			f.resign(target.manifest, nil)
		}},
		{name: "manifest field changed", encrypt: true, reason: ReasonMACMismatch, tamper: func(f *fixture, target tamperTarget) {
			manifest, err := archive.DecodeManifest(readAll(f.t, target.manifest))
			if err != nil {
				f.t.Fatal(err)
			}
			manifest.CreatedAtNS++
			encoded, err := archive.EncodeManifest(manifest)
			if err != nil {
				f.t.Fatal(err)
			}
			if err := os.WriteFile(target.manifest, encoded, 0o600); err != nil {
				f.t.Fatal(err)
			}
		}},
		{name: "object removed from the objects file", encrypt: true, reason: ReasonReferenceOpen, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.objects, target.key)
			encodeFile(f.t, target.objects, target.key, entries[1:])
			f.resign(target.manifest, func(m *archive.Manifest) { m.ObjectCount-- })
		}},
		{name: "stray object added", encrypt: true, reason: ReasonObjectMismatch, tamper: func(f *fixture, target tamperTarget) {
			stray := f.object("message", map[string]any{"role": "user", "content": "stray"}, false)
			entries := decodeFile(f.t, target.objects, target.key)
			entries = append(entries, archive.EncodeContentObject(f.payloads.contents[string(stray.Hash)]))
			encodeFile(f.t, target.objects, target.key, entries)
			f.resign(target.manifest, func(m *archive.Manifest) { m.ObjectCount++ })
		}},
		{name: "raw chunk changed", encrypt: true, reason: ReasonRawMismatch, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.objects, target.key)
			for index, entry := range entries {
				decoded, err := archive.DecodeObjectEntry(entry)
				if err != nil {
					f.t.Fatal(err)
				}
				if decoded.RawChunk != nil {
					decoded.RawChunk.Data[len(decoded.RawChunk.Data)-1] ^= 1
					entries[index] = archive.EncodeRawChunk(*decoded.RawChunk)
					break
				}
			}
			encodeFile(f.t, target.objects, target.key, entries)
			f.resign(target.manifest, nil)
		}},
		{name: "line changed", encrypt: true, reason: ReasonDigestMismatch, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.lines, target.key)
			entries[0] = bytes.Replace(entries[0], []byte(contentMarker+"-header"), []byte("changed-header"), 1)
			encodeFile(f.t, target.lines, target.key, entries)
			f.resign(target.manifest, nil)
		}},
		{name: "lines swapped", encrypt: true, reason: ReasonMemberMismatch, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.lines, target.key)
			entries[0], entries[1] = entries[1], entries[0]
			encodeFile(f.t, target.lines, target.key, entries)
			f.resign(target.manifest, nil)
		}},
		{name: "line removed", encrypt: true, reason: ReasonCountMismatch, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.lines, target.key)
			encodeFile(f.t, target.lines, target.key, entries[:len(entries)-1])
			f.resign(target.manifest, nil)
		}},
		{name: "parent line and member removed", encrypt: true, reason: ReasonReferenceOpen, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.lines, target.key)
			encodeFile(f.t, target.lines, target.key, entries[1:])
			f.resign(target.manifest, func(m *archive.Manifest) {
				m.Members = m.Members[1:]
				m.LineCount--
			})
		}},
		{name: "member missing from the manifest", encrypt: true, reason: ReasonCountMismatch, tamper: func(f *fixture, target tamperTarget) {
			f.resign(target.manifest, func(m *archive.Manifest) {
				m.Members = m.Members[:len(m.Members)-1]
				m.LineCount--
			})
		}},
		// The revision is not in the record digest; it is bound by the
		// manifest MAC and by the member check of every line.
		{name: "member revision changed", encrypt: true, reason: ReasonMemberMismatch, tamper: func(f *fixture, target tamperTarget) {
			f.resign(target.manifest, func(m *archive.Manifest) { m.Members[0].Revision++ })
		}},
		{name: "line revision changed", encrypt: true, reason: ReasonMemberMismatch, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.lines, target.key)
			changed := bytes.Replace(entries[0], []byte(`"revision":"1"`), []byte(`"revision":"2"`), 1)
			if bytes.Equal(changed, entries[0]) {
				f.t.Fatal("line revision not changed")
			}
			entries[0] = changed
			encodeFile(f.t, target.lines, target.key, entries)
			f.resign(target.manifest, nil)
		}},
		{name: "member digest changed", encrypt: true, reason: ReasonDigestMismatch, tamper: func(f *fixture, target tamperTarget) {
			f.resign(target.manifest, func(m *archive.Manifest) { m.Members[1].RecordDigest[0] ^= 1 })
		}},
		{name: "objects file of another bundle", encrypt: true, reason: ReasonFileMismatch, tamper: func(f *fixture, target tamperTarget) {
			other := f.tamperBundle(f.t.TempDir(), true, "conv_other", "o")
			if err := os.WriteFile(target.objects, readAll(f.t, other.objects), 0o600); err != nil {
				f.t.Fatal(err)
			}
		}},
		{name: "objects file of another bundle, manifest re-signed", encrypt: true, reason: ReasonObjectMismatch, tamper: func(f *fixture, target tamperTarget) {
			other := f.tamperBundle(f.t.TempDir(), true, "conv_other", "o")
			if err := os.WriteFile(target.objects, readAll(f.t, other.objects), 0o600); err != nil {
				f.t.Fatal(err)
			}
			f.resign(target.manifest, nil)
		}},
		{name: "wrong archive key", encrypt: true, reason: ReasonKeyMismatch, open: func(f *fixture) ReadOptions {
			other := testKeys(f.t, 0x43)
			return ReadOptions{Signer: other, EncryptionKey: other.EncryptionKey()}
		}},
		{name: "wrong encryption key", encrypt: true, reason: ReasonDecryptFailed, open: func(f *fixture) ReadOptions {
			return ReadOptions{Signer: f.keys, EncryptionKey: testKeys(f.t, 0x43).EncryptionKey()}
		}},
		{name: "plain line changed", encrypt: false, reason: ReasonFileMismatch, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.lines, nil)
			entries[0] = bytes.Replace(entries[0], []byte(contentMarker+"-header"), []byte("changed-header"), 1)
			encodeFile(f.t, target.lines, nil, entries)
		}},
		{name: "plain line changed, manifest re-signed", encrypt: false, reason: ReasonDigestMismatch, tamper: func(f *fixture, target tamperTarget) {
			entries := decodeFile(f.t, target.lines, nil)
			entries[0] = bytes.Replace(entries[0], []byte(contentMarker+"-header"), []byte("changed-header"), 1)
			encodeFile(f.t, target.lines, nil, entries)
			f.resign(target.manifest, nil)
		}},
		{name: "plain data appended after the gzip member, manifest re-signed", encrypt: false, reason: ReasonDecompressFailed, tamper: func(f *fixture, target tamperTarget) {
			data := append(readAll(f.t, target.lines), 0x1f, 0x8b)
			if err := os.WriteFile(target.lines, data, 0o600); err != nil {
				f.t.Fatal(err)
			}
			f.resign(target.manifest, nil)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			target := f.tamperBundle(t.TempDir(), test.encrypt, "conv_tamper", "p")
			if test.tamper != nil {
				test.tamper(f, target)
			}
			options := f.readOptions(test.encrypt)
			if test.open != nil {
				options = test.open(f)
			}
			bundle, err := Open(target.manifest, options)
			if err == nil {
				_, err = bundle.Verify(context.Background())
			}
			wantReason(t, err, test.reason)
		})
	}
}
