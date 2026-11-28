package archive

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"unicode/utf8"
)

// manifestDomain starts the manifest MAC input (F.2). It carries the format
// version and is frozen with version 1, like the record digest domain. (The
// trial version 0 used ".../archive-manifest/v0".)
const manifestDomain = "llmapi-logger/archive-manifest/v1\x00"

// Bundle kinds of a manifest (decision 5.3, F.1).
const (
	BundleConversation = "conversation"
	BundleBucket       = "bucket"
	BundleGaps         = "gaps"
)

// File roles of a manifest's files list.
const (
	FileLines   = "lines"
	FileObjects = "objects"
)

var (
	// ErrKeyMismatch reports a manifest whose key_fingerprint is not the
	// fingerprint of the key in hand; nothing is decrypted or verified.
	ErrKeyMismatch = errors.New("archive: manifest was written under a different archive key")
	// ErrManifestMAC reports a manifest whose MAC does not verify.
	ErrManifestMAC = errors.New("archive: manifest signature does not verify")
	// ErrUnsupportedFormatVersion reports a manifest of this format whose
	// format_version is a well-formed version other than FormatVersion: the
	// trial version 0, or a later version this reader predates. Nothing of
	// such a bundle is read or verified. The error is also an ErrFormat.
	ErrUnsupportedFormatVersion = errors.New("archive: unsupported archive format version")
)

// UnsupportedFormatVersionError is the error of ErrUnsupportedFormatVersion
// with the manifest's version, a canonical decimal of at most 19 digits.
type UnsupportedFormatVersionError struct {
	Version string
}

func (e *UnsupportedFormatVersionError) Error() string {
	return "archive: manifest format_version " + strconv.Quote(e.Version) + " is not version " + FormatVersion + ", the only one this reader reads"
}

// Is makes the error both ErrUnsupportedFormatVersion and ErrFormat.
func (e *UnsupportedFormatVersionError) Is(target error) bool {
	return target == ErrUnsupportedFormatVersion || target == ErrFormat
}

// unsupportedVersion returns the UnsupportedFormatVersionError of a manifest
// of this format with a canonical decimal version other than FormatVersion,
// and nil otherwise (a malformed version is a plain format error).
func unsupportedVersion(format, version string) error {
	if format != FormatName || version == FormatVersion || !canonicalDecimal(version) {
		return nil
	}
	return &UnsupportedFormatVersionError{Version: version}
}

// ManifestSigner is the part of security.ArchiveKeys the manifest needs:
// SignManifest and VerifyManifest are HMAC-SHA-256 under K_sign over exactly
// the bytes given, KeyFingerprint is HMAC-SHA-256(K_sign,
// "llmapi-logger/archive-key-fingerprint/v1\x00").
type ManifestSigner interface {
	SignManifest(message []byte) [32]byte
	VerifyManifest(message []byte, mac []byte) bool
	KeyFingerprint() [32]byte
}

// Manifest is the plain JSON manifest of one segment or gap bundle (F.1).
type Manifest struct {
	Format              string
	FormatVersion       string
	SourceSchemaVersion string
	SegmentID           string
	RunID               string
	BundleKind          string
	Protocol            *string
	Conversations       []string
	FirstStartedAtNS    int64
	LastEndedAtNS       int64
	CreatedAtNS         int64
	Encrypted           bool
	KeyFingerprint      [32]byte
	Tables              map[string][]string
	Files               []ManifestFile
	LineCount           int64
	ObjectCount         int64
	RawChunkCount       int64
	Members             []ManifestMember
	Gaps                *ManifestGaps
	MAC                 [32]byte
}

// ManifestFile is one entry of files: the stored bytes and their SHA-256.
type ManifestFile struct {
	Role   string
	Name   string
	Bytes  int64
	SHA256 [32]byte
}

// ManifestMember is one audit of the segment, in line order.
type ManifestMember struct {
	AuditID        string
	Revision       int64
	ConversationID *string
	StartedAtNS    int64
	EndedAtNS      int64
	RecordDigest   [32]byte
}

// ManifestGaps is the gap range of a gap bundle.
type ManifestGaps struct {
	FirstID int64
	LastID  int64
	Count   int64
}

// Validate checks the manifest's fixed values and the rules of F.1: the
// format name and version, decimal schema version, 32-digit lowercase hex
// segment and run ids, a known bundle kind with its shape (a gap bundle has
// no protocol, no conversations, no members and a gap range; a conversation
// bundle has a protocol and exactly one conversation; a bucket has a
// protocol and no gap range), known file roles with at most one of each,
// non-negative counts, and tables naming only archived tables.
func (manifest *Manifest) Validate() error {
	if err := unsupportedVersion(manifest.Format, manifest.FormatVersion); err != nil {
		return err
	}
	switch {
	case manifest.Format != FormatName:
		return formatError("manifest format %q", manifest.Format)
	case manifest.FormatVersion != FormatVersion:
		return formatError("manifest format_version %q", manifest.FormatVersion)
	case !canonicalDecimal(manifest.SourceSchemaVersion):
		return formatError("manifest source_schema_version %q", manifest.SourceSchemaVersion)
	case !isID(manifest.SegmentID) || !isID(manifest.RunID):
		return formatError("manifest segment_id or run_id is not 32 lowercase hex digits")
	case manifest.LineCount < 0 || manifest.ObjectCount < 0 || manifest.RawChunkCount < 0:
		return formatError("manifest negative count")
	case manifest.Conversations == nil || manifest.Members == nil || manifest.Files == nil || manifest.Tables == nil:
		return formatError("manifest list is null")
	}
	switch manifest.BundleKind {
	case BundleGaps:
		if manifest.Protocol != nil || len(manifest.Conversations) != 0 || len(manifest.Members) != 0 || manifest.Gaps == nil {
			return formatError("gap bundle with protocol, conversations or members, or without a gap range")
		}
	case BundleConversation:
		if manifest.Protocol == nil || len(manifest.Conversations) != 1 || manifest.Gaps != nil {
			return formatError("conversation bundle needs a protocol and exactly one conversation")
		}
	case BundleBucket:
		if manifest.Protocol == nil || manifest.Gaps != nil {
			return formatError("bucket needs a protocol and no gap range")
		}
	default:
		return formatError("unknown bundle_kind %q", manifest.BundleKind)
	}
	roles := make(map[string]bool)
	for _, file := range manifest.Files {
		if (file.Role != FileLines && file.Role != FileObjects) || roles[file.Role] || file.Bytes < 0 || file.Name == "" {
			return formatError("manifest file role %q repeated, unknown, or without a name", file.Role)
		}
		roles[file.Role] = true
	}
	for table := range manifest.Tables {
		if !containsString(ArchivedTables, table) {
			return formatError("manifest tables name %q", table)
		}
	}
	return nil
}

func canonicalDecimal(text string) bool {
	value, err := strconv.ParseInt(text, 10, 64)
	return err == nil && value >= 0 && strconv.FormatInt(value, 10) == text
}

func isID(text string) bool {
	decoded, err := hex.DecodeString(text)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == text
}

// ManifestEncoding returns the canonical length-prefixed encoding of F.2
// (Q10 甲), without the domain string. It is independent of how the JSON is
// written.
func ManifestEncoding(manifest *Manifest) []byte {
	var buffer bytes.Buffer
	e := digestEncoder{w: &buffer}
	e.t(manifest.Format)
	e.t(manifest.FormatVersion)
	e.t(manifest.SourceSchemaVersion)
	e.t(manifest.SegmentID)
	e.t(manifest.RunID)
	e.t(manifest.BundleKind)
	e.nText(manifest.Protocol)
	e.l(len(manifest.Conversations))
	for _, conversation := range manifest.Conversations {
		e.t(conversation)
	}
	e.i(manifest.FirstStartedAtNS)
	e.i(manifest.LastEndedAtNS)
	e.i(manifest.CreatedAtNS)
	e.flag(manifest.Encrypted)
	e.b(manifest.KeyFingerprint[:])
	names := make([]string, 0, len(manifest.Tables))
	for name := range manifest.Tables {
		names = append(names, name)
	}
	sort.Strings(names)
	e.l(len(names))
	for _, name := range names {
		e.t(name)
		e.l(len(manifest.Tables[name]))
		for _, column := range manifest.Tables[name] {
			e.t(column)
		}
	}
	e.l(len(manifest.Files))
	for _, file := range manifest.Files {
		e.t(file.Role)
		e.t(file.Name)
		e.i(file.Bytes)
		e.b(file.SHA256[:])
	}
	e.i(manifest.LineCount)
	e.i(manifest.ObjectCount)
	e.i(manifest.RawChunkCount)
	e.l(len(manifest.Members))
	for _, member := range manifest.Members {
		e.t(member.AuditID)
		e.i(member.Revision)
		e.nText(member.ConversationID)
		e.i(member.StartedAtNS)
		e.i(member.EndedAtNS)
		e.b(member.RecordDigest[:])
	}
	if manifest.Gaps == nil {
		e.null()
	} else {
		e.present()
		e.i(manifest.Gaps.FirstID)
		e.i(manifest.Gaps.LastID)
		e.i(manifest.Gaps.Count)
	}
	return buffer.Bytes()
}

// ManifestMACInput is the message SignManifest and VerifyManifest see: the
// manifest domain string followed by ManifestEncoding. The domain makes the
// input differ from the key fingerprint's, which shares K_sign.
func ManifestMACInput(manifest *Manifest) []byte {
	return append([]byte(manifestDomain), ManifestEncoding(manifest)...)
}

// Sign sets KeyFingerprint from the signer, validates the manifest and sets
// MAC.
func (manifest *Manifest) Sign(signer ManifestSigner) error {
	manifest.KeyFingerprint = signer.KeyFingerprint()
	if err := manifest.Validate(); err != nil {
		return err
	}
	manifest.MAC = signer.SignManifest(ManifestMACInput(manifest))
	return nil
}

// Verify checks the key fingerprint first (ErrKeyMismatch), then the MAC
// (ErrManifestMAC).
func (manifest *Manifest) Verify(signer ManifestSigner) error {
	if fingerprint := signer.KeyFingerprint(); fingerprint != manifest.KeyFingerprint {
		return ErrKeyMismatch
	}
	if !signer.VerifyManifest(ManifestMACInput(manifest), manifest.MAC[:]) {
		return ErrManifestMAC
	}
	return nil
}

// EncodeManifest writes the manifest as indented JSON with a trailing
// newline, keys in the order of F.1.
func EncodeManifest(manifest *Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(manifest.Tables))
	for name := range manifest.Tables {
		names = append(names, name)
	}
	sort.Strings(names)
	tables := make([]member, 0, len(names))
	for _, name := range names {
		tables = append(tables, member{name, jStrings(manifest.Tables[name])})
	}
	files := make([][]byte, 0, len(manifest.Files))
	for _, file := range manifest.Files {
		files = append(files, object(
			member{"role", jText(file.Role)},
			member{"name", jText(file.Name)},
			member{"bytes", jInt(file.Bytes)},
			member{"sha256", jHex(file.SHA256[:])}))
	}
	members := make([][]byte, 0, len(manifest.Members))
	for _, m := range manifest.Members {
		members = append(members, object(
			member{"audit_id", jText(m.AuditID)},
			member{"revision", jInt(m.Revision)},
			member{"conversation_id", jNText(m.ConversationID)},
			member{"started_at_ns", jInt(m.StartedAtNS)},
			member{"ended_at_ns", jInt(m.EndedAtNS)},
			member{"record_digest", jHex(m.RecordDigest[:])}))
	}
	gaps := jsonNull
	if manifest.Gaps != nil {
		gaps = object(
			member{"first_id", jInt(manifest.Gaps.FirstID)},
			member{"last_id", jInt(manifest.Gaps.LastID)},
			member{"count", jInt(manifest.Gaps.Count)})
	}
	compact := object(
		member{"format", jText(manifest.Format)},
		member{"format_version", jText(manifest.FormatVersion)},
		member{"source_schema_version", jText(manifest.SourceSchemaVersion)},
		member{"segment_id", jText(manifest.SegmentID)},
		member{"run_id", jText(manifest.RunID)},
		member{"bundle_kind", jText(manifest.BundleKind)},
		member{"protocol", jNText(manifest.Protocol)},
		member{"conversations", jStrings(manifest.Conversations)},
		member{"first_started_at_ns", jInt(manifest.FirstStartedAtNS)},
		member{"last_ended_at_ns", jInt(manifest.LastEndedAtNS)},
		member{"created_at_ns", jInt(manifest.CreatedAtNS)},
		member{"encrypted", jBool(manifest.Encrypted)},
		member{"key_fingerprint", jHex(manifest.KeyFingerprint[:])},
		member{"tables", object(tables...)},
		member{"files", array(files)},
		member{"line_count", jInt(manifest.LineCount)},
		member{"object_count", jInt(manifest.ObjectCount)},
		member{"raw_chunk_count", jInt(manifest.RawChunkCount)},
		member{"members", array(members)},
		member{"gaps", gaps},
		member{"mac", jHex(manifest.MAC[:])},
	)
	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", "  "); err != nil {
		return nil, err
	}
	indented.WriteByte('\n')
	return indented.Bytes(), nil
}

// DecodeManifest parses a manifest. It accepts any whitespace and key order,
// rejects unknown, missing and duplicate keys and non-canonical values, and
// validates the result. It does not verify the MAC.
//
// The format and format_version are looked at first, leniently: a manifest of
// this format whose version is well formed but not FormatVersion is an
// *UnsupportedFormatVersionError, whatever the rest holds, since another
// version may have other keys and other meanings.
func DecodeManifest(data []byte) (*Manifest, error) {
	if !utf8.Valid(data) {
		return nil, formatError("manifest is not valid UTF-8")
	}
	var head map[string]json.RawMessage
	if json.Unmarshal(data, &head) == nil {
		var format, version string
		if json.Unmarshal(head["format"], &format) == nil && json.Unmarshal(head["format_version"], &version) == nil {
			if err := unsupportedVersion(format, version); err != nil {
				return nil, err
			}
		}
	}
	f, err := decodeObject(bytes.TrimSpace(data), "format", "format_version", "source_schema_version", "segment_id",
		"run_id", "bundle_kind", "protocol", "conversations", "first_started_at_ns", "last_ended_at_ns",
		"created_at_ns", "encrypted", "key_fingerprint", "tables", "files", "line_count", "object_count",
		"raw_chunk_count", "members", "gaps", "mac")
	if err != nil {
		return nil, err
	}
	e := &errs{}
	manifest := &Manifest{
		Format: e.str(f.text("format")), FormatVersion: e.str(f.text("format_version")),
		SourceSchemaVersion: e.str(f.text("source_schema_version")), SegmentID: e.str(f.text("segment_id")),
		RunID: e.str(f.text("run_id")), BundleKind: e.str(f.text("bundle_kind")), Protocol: e.nstr(f.nText("protocol")),
		FirstStartedAtNS: e.i64(f.integer("first_started_at_ns")), LastEndedAtNS: e.i64(f.integer("last_ended_at_ns")),
		CreatedAtNS: e.i64(f.integer("created_at_ns")), Encrypted: e.bl(f.boolean("encrypted")),
		KeyFingerprint: e.h(f.hash("key_fingerprint")), LineCount: e.i64(f.integer("line_count")),
		ObjectCount: e.i64(f.integer("object_count")), RawChunkCount: e.i64(f.integer("raw_chunk_count")),
		MAC: e.h(f.hash("mac")),
	}
	if e.err != nil {
		return nil, e.err
	}
	if manifest.Conversations, err = f.strings("conversations"); err != nil {
		return nil, err
	}
	tables, err := decodeTables(f["tables"])
	if err != nil {
		return nil, err
	}
	manifest.Tables = tables
	manifest.Files = []ManifestFile{}
	if err := decodeList(f, "files", func(item json.RawMessage) error {
		x, err := decodeObject(item, "role", "name", "bytes", "sha256")
		if err != nil {
			return err
		}
		manifest.Files = append(manifest.Files, ManifestFile{Role: e.str(x.text("role")), Name: e.str(x.text("name")),
			Bytes: e.i64(x.integer("bytes")), SHA256: e.h(x.hash("sha256"))})
		return e.err
	}); err != nil {
		return nil, err
	}
	manifest.Members = []ManifestMember{}
	if err := decodeList(f, "members", func(item json.RawMessage) error {
		x, err := decodeObject(item, "audit_id", "revision", "conversation_id", "started_at_ns", "ended_at_ns", "record_digest")
		if err != nil {
			return err
		}
		manifest.Members = append(manifest.Members, ManifestMember{AuditID: e.str(x.text("audit_id")),
			Revision: e.i64(x.integer("revision")), ConversationID: e.nstr(x.nText("conversation_id")),
			StartedAtNS: e.i64(x.integer("started_at_ns")), EndedAtNS: e.i64(x.integer("ended_at_ns")),
			RecordDigest: e.h(x.hash("record_digest"))})
		return e.err
	}); err != nil {
		return nil, err
	}
	if !isNull(f["gaps"]) {
		x, err := decodeObject(f["gaps"], "first_id", "last_id", "count")
		if err != nil {
			return nil, err
		}
		manifest.Gaps = &ManifestGaps{FirstID: e.i64(x.integer("first_id")), LastID: e.i64(x.integer("last_id")), Count: e.i64(x.integer("count"))}
		if e.err != nil {
			return nil, e.err
		}
	}
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return manifest, nil
}

func decodeTables(raw json.RawMessage) (map[string][]string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, formatError("tables: expected an object")
	}
	tables := make(map[string][]string)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, formatError("tables: %v", err)
		}
		name, _ := token.(string)
		if _, duplicate := tables[name]; duplicate {
			return nil, formatError("tables: duplicate %q", name)
		}
		var columns json.RawMessage
		if err := decoder.Decode(&columns); err != nil {
			return nil, formatError("tables: %v", err)
		}
		values, err := fields{"columns": columns}.strings("columns")
		if err != nil {
			return nil, err
		}
		tables[name] = values
	}
	return tables, nil
}
