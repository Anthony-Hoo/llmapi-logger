package archive

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testManifest(t *testing.T) *Manifest {
	t.Helper()
	keys := newTestKeys()
	manifest := &Manifest{
		Format: FormatName, FormatVersion: FormatVersion, SourceSchemaVersion: "8",
		SegmentID: strings.Repeat("ab", 16), RunID: strings.Repeat("cd", 16),
		BundleKind: BundleConversation, Protocol: text("openai"), Conversations: []string{"conv_full"},
		FirstStartedAtNS: 1764300000123456789, LastEndedAtNS: 1764300001123456789, CreatedAtNS: 1764400000000000000,
		Encrypted: true, Tables: ManifestTables(),
		Files: []ManifestFile{
			{Role: FileLines, Name: "20261128T030000Z_20261128T040000Z_conv_full_s0001.jsonl.gz.enc", Bytes: 1234, SHA256: sumOf(0x10)},
			{Role: FileObjects, Name: "20261128T030000Z_20261128T040000Z_conv_full_s0001.objects.jsonl.gz.enc", Bytes: 5678, SHA256: sumOf(0x20)},
		},
		LineCount: 2, ObjectCount: 5, RawChunkCount: 1,
		Members: []ManifestMember{
			{AuditID: "audit-a", Revision: 1, ConversationID: text("conv_full"), StartedAtNS: 1764300000123456789, EndedAtNS: 1764300000923456789, RecordDigest: sumOf(0x30)},
			{AuditID: "audit-b", Revision: 2, ConversationID: text("conv_full"), StartedAtNS: 1764300000223456789, EndedAtNS: 1764300001123456789, RecordDigest: sumOf(0x40)},
		},
	}
	if err := manifest.Sign(keys); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestManifestSignVerifyAndVector(t *testing.T) {
	keys := newTestKeys()
	manifest := testManifest(t)
	if manifest.KeyFingerprint != keys.KeyFingerprint() {
		t.Fatal("Sign did not set the key fingerprint")
	}
	if err := manifest.Verify(keys); err != nil {
		t.Fatal(err)
	}
	input := ManifestMACInput(manifest)
	if !bytes.HasPrefix(input, []byte("llmapi-logger/archive-manifest/v0\x00")) || !bytes.Equal(input[len(manifestDomain):], ManifestEncoding(manifest)) {
		t.Fatal("MAC input is not the manifest domain followed by the encoding")
	}
	if string(input) == "llmapi-logger/archive-key-fingerprint/v1\x00" {
		t.Fatal("MAC input equals the key fingerprint domain")
	}
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	checkVector(t, "manifest_v0.json", encoded)
	checkVector(t, "manifest_v0.encoding.hex", []byte(hex.EncodeToString(ManifestEncoding(manifest))+"\n"))
	decoded, err := DecodeManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(keys); err != nil {
		t.Fatal(err)
	}
	again, err := EncodeManifest(decoded)
	if err != nil || !bytes.Equal(again, encoded) {
		t.Fatalf("re-encoding differs: %v", err)
	}
}

// The MAC input starts with the manifest domain for every manifest shape,
// so it can never be the key fingerprint's input.
func TestManifestMACInputAlwaysHasTheDomain(t *testing.T) {
	gaps := testManifest(t)
	gaps.BundleKind, gaps.Protocol, gaps.Conversations, gaps.Members = BundleGaps, nil, []string{}, []ManifestMember{}
	gaps.Gaps = &ManifestGaps{FirstID: 1, LastID: 9, Count: 9}
	empty := &Manifest{}
	for _, manifest := range []*Manifest{testManifest(t), gaps, empty} {
		input := ManifestMACInput(manifest)
		if !bytes.HasPrefix(input, []byte(manifestDomain)) || len(input) <= len(manifestDomain) {
			t.Fatalf("MAC input %q", input)
		}
	}
	if err := gaps.Sign(newTestKeys()); err != nil {
		t.Fatal(err)
	}
	if err := gaps.Verify(newTestKeys()); err != nil {
		t.Fatal(err)
	}
}

// Changing any field breaks the MAC.
func TestManifestTamper(t *testing.T) {
	keys := newTestKeys()
	mutations := map[string]func(*Manifest){
		"format":              func(m *Manifest) { m.Format += "x" },
		"format_version":      func(m *Manifest) { m.FormatVersion = "1" },
		"source_schema":       func(m *Manifest) { m.SourceSchemaVersion = "9" },
		"segment_id":          func(m *Manifest) { m.SegmentID = strings.Repeat("ac", 16) },
		"run_id":              func(m *Manifest) { m.RunID = strings.Repeat("ce", 16) },
		"bundle_kind":         func(m *Manifest) { m.BundleKind = BundleBucket },
		"protocol":            func(m *Manifest) { m.Protocol = text("gemini") },
		"protocol null":       func(m *Manifest) { m.Protocol = nil },
		"conversations":       func(m *Manifest) { m.Conversations = []string{"conv_other"} },
		"conversations added": func(m *Manifest) { m.Conversations = append(m.Conversations, "conv_other") },
		"first_started":       func(m *Manifest) { m.FirstStartedAtNS++ },
		"last_ended":          func(m *Manifest) { m.LastEndedAtNS++ },
		"created":             func(m *Manifest) { m.CreatedAtNS++ },
		"encrypted":           func(m *Manifest) { m.Encrypted = false },
		"tables column":       func(m *Manifest) { m.Tables["turns"] = m.Tables["turns"][1:] },
		"tables order":        func(m *Manifest) { c := m.Tables["turns"]; c[0], c[1] = c[1], c[0] },
		"tables removed":      func(m *Manifest) { delete(m.Tables, "audit_gaps") },
		"file role":           func(m *Manifest) { m.Files[0].Role, m.Files[1].Role = FileObjects, FileLines },
		"file name":           func(m *Manifest) { m.Files[0].Name += "x" },
		"file bytes":          func(m *Manifest) { m.Files[1].Bytes++ },
		"file sha256":         func(m *Manifest) { m.Files[0].SHA256[31] ^= 1 },
		"file removed":        func(m *Manifest) { m.Files = m.Files[:1] },
		"line_count":          func(m *Manifest) { m.LineCount++ },
		"object_count":        func(m *Manifest) { m.ObjectCount++ },
		"raw_chunk_count":     func(m *Manifest) { m.RawChunkCount++ },
		"member audit":        func(m *Manifest) { m.Members[0].AuditID += "x" },
		"member revision":     func(m *Manifest) { m.Members[1].Revision++ },
		"member conversation": func(m *Manifest) { m.Members[0].ConversationID = nil },
		"member started":      func(m *Manifest) { m.Members[0].StartedAtNS++ },
		"member ended":        func(m *Manifest) { m.Members[0].EndedAtNS++ },
		"member digest":       func(m *Manifest) { m.Members[1].RecordDigest[0] ^= 1 },
		"member order":        func(m *Manifest) { m.Members[0], m.Members[1] = m.Members[1], m.Members[0] },
		"gaps":                func(m *Manifest) { m.Gaps = &ManifestGaps{} },
		"mac":                 func(m *Manifest) { m.MAC[0] ^= 1 },
	}
	for name, mutate := range mutations {
		manifest := testManifest(t)
		encoded, err := EncodeManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		tampered, err := DecodeManifest(encoded)
		if err != nil {
			t.Fatal(err)
		}
		mutate(tampered)
		if err := tampered.Verify(keys); !errors.Is(err, ErrManifestMAC) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	manifest := testManifest(t)
	manifest.KeyFingerprint[0] ^= 1
	if err := manifest.Verify(keys); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("key fingerprint err=%v", err)
	}
	other := newTestKeys()
	other.signing[0] ^= 1
	if err := testManifest(t).Verify(other); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("other key err=%v", err)
	}
}

// A manifest rewritten with other whitespace and key order still verifies:
// the MAC covers the canonical encoding, not the JSON text (Q10 甲).
func TestManifestVerifiesAfterReserialisation(t *testing.T) {
	encoded, err := EncodeManifest(testManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatal(err)
	}
	sorted, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	var tabbed bytes.Buffer
	if err := json.Indent(&tabbed, sorted, "\t", "\t"); err != nil {
		t.Fatal(err)
	}
	for _, variant := range [][]byte{sorted, tabbed.Bytes(), append([]byte("\n  "), encoded...)} {
		decoded, err := DecodeManifest(variant)
		if err != nil {
			t.Fatal(err)
		}
		if err := decoded.Verify(newTestKeys()); err != nil {
			t.Fatalf("reserialised manifest: %v", err)
		}
	}
}

func TestManifestValidate(t *testing.T) {
	encoded, err := EncodeManifest(testManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(string) string{
		"format":  func(s string) string { return strings.Replace(s, `"llmapi-logger-archive"`, `"other"`, 1) },
		"version": func(s string) string { return strings.Replace(s, `"format_version": "0"`, `"format_version": "1"`, 1) },
		"schema version": func(s string) string {
			return strings.Replace(s, `"source_schema_version": "8"`, `"source_schema_version": "08"`, 1)
		},
		"segment id": func(s string) string { return strings.Replace(s, `"segment_id": "abab`, `"segment_id": "ABab`, 1) },
		"bundle kind": func(s string) string {
			return strings.Replace(s, `"bundle_kind": "conversation"`, `"bundle_kind": "session"`, 1)
		},
		"two conversations": func(s string) string {
			return strings.Replace(s, `"conversations": [`, `"conversations": ["conv_x",`, 1)
		},
		"gaps on segment": func(s string) string {
			return strings.Replace(s, `"gaps": null`, `"gaps": {"first_id":"1","last_id":"2","count":"2"}`, 1)
		},
		"unknown key":      func(s string) string { return strings.Replace(s, `"line_count"`, `"extra": 1, "line_count"`, 1) },
		"missing key":      func(s string) string { return strings.Replace(s, `"object_count": "5",`, ``, 1) },
		"duplicate table":  func(s string) string { return strings.Replace(s, `"tables": {`, `"tables": {"turns": [],`, 1) },
		"unknown table":    func(s string) string { return strings.Replace(s, `"tables": {`, `"tables": {"audit_analysis": [],`, 1) },
		"unknown role":     func(s string) string { return strings.Replace(s, `"role": "objects"`, `"role": "extra"`, 1) },
		"repeated role":    func(s string) string { return strings.Replace(s, `"role": "objects"`, `"role": "lines"`, 1) },
		"encrypted string": func(s string) string { return strings.Replace(s, `"encrypted": true`, `"encrypted": "1"`, 1) },
	}
	for name, mutate := range cases {
		mutated := mutate(string(encoded))
		if mutated == string(encoded) {
			t.Errorf("%s: mutation did not apply", name)
			continue
		}
		if _, err := DecodeManifest([]byte(mutated)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	gaps := testManifest(t)
	gaps.BundleKind = BundleGaps
	if err := gaps.Validate(); err == nil {
		t.Fatal("gap bundle with members and a protocol accepted")
	}
}
