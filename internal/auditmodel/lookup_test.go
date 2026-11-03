package auditmodel

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"llmapi-logger/internal/security"
)

func lookupTurn(items int) Turn {
	values := make([]any, items)
	requestItems := make([]Item, items)
	for i := range values {
		values[i] = map[string]any{"role": "user", "content": fmt.Sprintf("item%d:%s", i, string(bytes.Repeat([]byte("synthetic "), 400))), "image": "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("synthetic binary"))}
		requestItems[i] = Item{Slot: SlotMessages, Kind: "message", Value: values[i]}
	}
	return Turn{AuditID: "lookup-test", Protocol: "openai", ParserName: "openai.chat_completions", RequestLayout: LayoutOpenAIChatRequest, ResponseLayout: LayoutNone, RequestItems: requestItems, RequestEnvelope: map[string]any{"model": "example"}, ResponseEnvelope: map[string]any{}, RequestOriginal: map[string]any{"model": "example", "messages": values}, ResponseOriginal: map[string]any{}, CreatedAtNS: 1}
}

func lookupRows(prepared PreparedTurn) ([]StoredContent, []StoredBinary) {
	objects := make([]StoredContent, 0, len(prepared.Objects))
	binaries := make([]StoredBinary, 0, len(prepared.Binaries))
	for _, o := range prepared.Objects {
		objects = append(objects, StoredContent{Hash: append([]byte(nil), o.Hash...), SemanticHash: append([]byte(nil), o.SemanticHash...), Kind: o.Kind, Compression: o.Compression, PlaintextLength: o.PlaintextLength, EncodedLength: o.EncodedLength, DataEnc: append([]byte(nil), o.DataEnc...)})
	}
	for _, o := range prepared.Binaries {
		binaries = append(binaries, StoredBinary{Hash: append([]byte(nil), o.Hash...), MediaType: o.MediaType, Compression: o.Compression, PlaintextLength: o.PlaintextLength, EncodedLength: o.EncodedLength, DataEnc: append([]byte(nil), o.DataEnc...)})
	}
	return objects, binaries
}

func TestPrepareLookupAuthenticatesAndReusesCiphertext(t *testing.T) {
	turn := lookupTurn(2)
	cipher := &countingCipher{Cipher: testCipher(t)}
	original, err := Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	content, binaries := lookupRows(original)
	cipher.encryptions = 0
	calls := 0
	prepared, err := PrepareWithLookup(turn, cipher, func(ch, bh [][]byte) ([]StoredContent, []StoredBinary, error) {
		calls++
		if len(ch) != len(content) || len(bh) != len(binaries) {
			t.Fatal("lookup did not batch unique hashes")
		}
		return content, binaries, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || cipher.encryptions != 0 {
		t.Fatalf("calls=%d encryptions=%d", calls, cipher.encryptions)
	}
	for i, object := range prepared.Objects {
		if !bytes.Equal(object.DataEnc, original.Objects[i].DataEnc) {
			t.Fatal("valid hit was resealed")
		}
	}
	if !bytes.Equal(prepared.RequestReconstructionHash, original.RequestReconstructionHash) {
		t.Fatal("reconstruction changed")
	}
	// Partial cache misses are ordinary new objects, not an error.
	cipher.encryptions = 0
	_, err = PrepareWithLookup(turn, cipher, func(_, _ [][]byte) ([]StoredContent, []StoredBinary, error) { return content[1:], nil, nil })
	if err != nil || cipher.encryptions != 2 {
		t.Fatalf("partial miss encryptions=%d err=%v", cipher.encryptions, err)
	}
}

func TestPrepareLookupRejectsCorruption(t *testing.T) {
	cipher := testCipher(t)
	turn := lookupTurn(1)
	prepared, err := Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]StoredContent, []StoredBinary) ([]StoredContent, []StoredBinary){
		"ciphertext": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			c[0].DataEnc[0] ^= 1
			return c, b
		},
		"kind": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			c[0].Kind = "wrong"
			return c, b
		},
		"semantic": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			c[0].SemanticHash[0] ^= 1
			return c, b
		},
		"plain_length": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			c[0].PlaintextLength++
			return c, b
		},
		"encoded_length": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			c[0].EncodedLength++
			return c, b
		},
		"compression_aad": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			c[0].Compression = "bad"
			return c, b
		},
		"unrequested_hash": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			c[0].Hash[0] ^= 1
			return c, b
		},
		"duplicate": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) { return append(c, c[0]), b },
		"binary_ciphertext": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			b[0].DataEnc[0] ^= 1
			return c, b
		},
		"binary_length": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			b[0].PlaintextLength++
			return c, b
		},
		"binary_media": func(c []StoredContent, b []StoredBinary) ([]StoredContent, []StoredBinary) {
			b[0].MediaType = "wrong"
			return c, b
		},
	}
	for name, modify := range tests {
		t.Run(name, func(t *testing.T) {
			c, b := lookupRows(prepared)
			c, b = modify(c, b)
			_, err := PrepareWithLookup(turn, cipher, func(_, _ [][]byte) ([]StoredContent, []StoredBinary, error) { return c, b, nil })
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("expected integrity failure, got %v", err)
			}
		})
	}
	want := errors.New("synthetic lookup failure")
	if _, err := PrepareWithLookup(turn, cipher, func(_, _ [][]byte) ([]StoredContent, []StoredBinary, error) { return nil, nil, want }); !errors.Is(err, want) {
		t.Fatal("lookup error suppressed")
	}
	turn.RequestOriginal = map[string]any{"messages": []any{}}
	calls := 0
	if _, err := PrepareWithLookup(turn, cipher, func(_, _ [][]byte) ([]StoredContent, []StoredBinary, error) { calls++; return nil, nil, nil }); !errors.Is(err, ErrReconstruction) || calls != 0 {
		t.Fatal("lookup bypassed original canonical reconstruction")
	}
}

func TestPrepareLookupAcceptsValidAlternateEncoding(t *testing.T) {
	cipher := testCipher(t)
	turn := lookupTurn(1)
	prepared, err := Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	content, binaries := lookupRows(prepared)
	for i := range content {
		if content[i].Compression != CompressionGZIP {
			continue
		}
		plain, err := openContent(cipher, content[i])
		if err != nil {
			t.Fatal(err)
		}
		aad, err := security.AAD("content_object", hashHex(content[i].Hash), content[i].Kind, CompressionNone)
		if err != nil {
			t.Fatal(err)
		}
		data, err := cipher.Encrypt(aad, plain)
		if err != nil {
			t.Fatal(err)
		}
		content[i].Compression = CompressionNone
		content[i].EncodedLength = int64(len(plain))
		content[i].DataEnc = data
		clear(plain)
	}
	result, err := PrepareWithLookup(turn, cipher, func(_, _ [][]byte) ([]StoredContent, []StoredBinary, error) { return content, binaries, nil })
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range result.Objects {
		if o.Compression != content[i].Compression || !bytes.Equal(o.DataEnc, content[i].DataEnc) {
			t.Fatal("codec drift was resealed or rejected")
		}
	}
}

func BenchmarkPrepareRepeatedHistory(b *testing.B) {
	cipher, err := security.NewAESGCM(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	turn := lookupTurn(64)
	initial, err := Prepare(turn, cipher)
	if err != nil {
		b.Fatal(err)
	}
	content, binaries := lookupRows(initial)
	for _, hit := range []bool{false, true} {
		name := "without_lookup"
		if hit {
			name = "verified_lookup"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			var lookup ObjectLookup
			if hit {
				lookup = func(_, _ [][]byte) ([]StoredContent, []StoredBinary, error) { return content, binaries, nil }
			}
			for i := 0; i < b.N; i++ {
				if _, err := PrepareWithLookup(turn, cipher, lookup); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestStoredEncodingVerificationRejectsValidButWrongPlaintext(t *testing.T) {
	cipher := testCipher(t)
	aad := []byte("synthetic-aad")
	expected := bytes.Repeat([]byte("expected"), 200)
	cases := map[string][]byte{"different": bytes.Repeat([]byte("wrong"), 200), "trailing": append(append([]byte(nil), expected...), 1), "short": expected[:len(expected)-1]}
	for name, plain := range cases {
		t.Run(name, func(t *testing.T) {
			compressed, err := gzipBytes(plain)
			if err != nil {
				t.Fatal(err)
			}
			sealed, err := cipher.Encrypt(aad, compressed)
			if err != nil {
				t.Fatal(err)
			}
			if err = verifyStoredEncoding(cipher, &contentDecoder{}, aad, sealed, CompressionGZIP, int64(len(compressed)), expected); err != ErrIntegrity {
				t.Fatalf("wrong plaintext accepted: %v", err)
			}
		})
	}
	compressed, err := gzipBytes(expected)
	if err != nil {
		t.Fatal(err)
	}
	// Authentication can be valid while a corrupt archived gzip checksum is not.
	compressed[len(compressed)-8] ^= 1
	sealed, err := cipher.Encrypt(aad, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyStoredEncoding(cipher, &contentDecoder{}, aad, sealed, CompressionGZIP, int64(len(compressed)), expected); err != ErrIntegrity {
		t.Fatal("gzip checksum failure accepted")
	}
}

func TestPrepareLookupConcurrentOperations(t *testing.T) {
	cipher := testCipher(t)
	turn := lookupTurn(4)
	first, err := Prepare(turn, cipher)
	if err != nil {
		t.Fatal(err)
	}
	content, binaries := lookupRows(first)
	for i := 0; i < 12; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			for j := 0; j < 5; j++ {
				_, err := PrepareWithLookup(turn, cipher, func(_, _ [][]byte) ([]StoredContent, []StoredBinary, error) { return content, binaries, nil })
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
