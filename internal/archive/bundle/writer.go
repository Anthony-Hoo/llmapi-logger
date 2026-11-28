package bundle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/stream"
	"llmapi-logger/internal/auditmodel"
)

// DefaultSegmentMaxBytes is archive.segment_max_bytes' default (B.4, P.5).
const DefaultSegmentMaxBytes int64 = 256 << 20

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Payloads supplies the plaintext a record refers to but does not hold: the
// snapshot reader implements it over the same REPEATABLE READ snapshot that
// produced the records. Each call returns one object or one raw chunk, which
// the writer encodes, writes and drops before asking for the next (H.7).
//
// ContentObject returns the content object with the given object_hash, with
// Data the canonical JSON text; BinaryObject the binary object with the given
// binary_hash; RawChunk the plaintext of the raw chunk (stage, seq) of the
// audit. The writer checks each answer against the record's metadata.
// parsed_json needs no call: the record holds it and archive.EncodeLine
// splits it.
type Payloads interface {
	ContentObject(hash []byte) (archive.ContentObject, error)
	BinaryObject(hash []byte) (archive.BinaryObject, error)
	RawChunk(auditID, stage string, seq int64) ([]byte, error)
}

// Options configures a writer.
type Options struct {
	// Root is the archive directory. It must exist; the writer creates
	// sessions/<YYYY>/<MM> and gaps below it with 0700.
	Root string
	// Signer signs the manifest and gives its key fingerprint; it is
	// required with or without encryption.
	Signer archive.ManifestSigner
	// Encrypt selects the .enc files; EncryptionKey is K_enc
	// (stream.KeySize bytes) and is required when Encrypt is set. The writer
	// keeps a copy and clears it when the segment is sealed or aborted.
	Encrypt       bool
	EncryptionKey []byte
	// SegmentMaxBytes is the uncompressed size past which Full reports
	// true; zero means DefaultSegmentMaxBytes.
	SegmentMaxBytes int64
	// SourceSchemaVersion is the hot database's migration version.
	SourceSchemaVersion string
	// RunID is the run's 32-digit lowercase hex id.
	RunID string
	// Now is the clock of created_at_ns; nil means time.Now.
	Now func() time.Time
	// Fault, when set, is called with a Fault* operation and the path before
	// each mkdir, create, write, sync, close, link and directory sync; a
	// non-nil result is that operation's error. Tests use it to simulate a
	// full disk or an I/O error, and to look at the temporary files.
	Fault func(operation, path string) error
}

func (options Options) validate() ([]byte, error) {
	switch {
	case options.Root == "":
		return nil, fail(ReasonInvalidOptions, errors.New("empty root"))
	case options.Signer == nil:
		return nil, fail(ReasonInvalidOptions, errors.New("nil signer"))
	case !idPattern.MatchString(options.RunID):
		return nil, fail(ReasonInvalidOptions, errors.New("run id is not 32 lowercase hex digits"))
	case options.SegmentMaxBytes < 0:
		return nil, fail(ReasonInvalidOptions, errors.New("negative segment size"))
	}
	if version, err := strconv.ParseInt(options.SourceSchemaVersion, 10, 64); err != nil || version < 0 || strconv.FormatInt(version, 10) != options.SourceSchemaVersion {
		return nil, fail(ReasonInvalidOptions, errors.New("source schema version is not a decimal"))
	}
	if info, err := os.Stat(options.Root); err != nil || !info.IsDir() {
		return nil, fail(ReasonInvalidOptions, fmt.Errorf("archive root is not a directory: %w", err))
	}
	if !options.Encrypt {
		if options.EncryptionKey != nil {
			return nil, fail(ReasonInvalidOptions, errors.New("encryption key without encryption"))
		}
		return nil, nil
	}
	if len(options.EncryptionKey) != stream.KeySize {
		return nil, fail(ReasonInvalidOptions, errors.New("encryption key has the wrong length"))
	}
	return bytes.Clone(options.EncryptionKey), nil
}

func (options Options) now() int64 {
	if options.Now != nil {
		return options.Now().UnixNano()
	}
	return time.Now().UnixNano()
}

func (options Options) maxBytes() int64 {
	if options.SegmentMaxBytes == 0 {
		return DefaultSegmentMaxBytes
	}
	return options.SegmentMaxBytes
}

// Spec names the bundle a segment belongs to: Kind is
// archive.BundleConversation (with ConversationID) or archive.BundleBucket,
// Protocol the bundle's protocol, Index the segment number from 1.
type Spec struct {
	Kind           string
	Protocol       string
	ConversationID string
	Index          int
}

// SegmentWriter writes one segment of a conversation or bucket bundle.
//
// The caller adds records in segment order (B.3 item 4) and, after each Add,
// asks Full; when it reports true the caller seals this segment and opens
// the next with Index+1 (B.4: an audit never spans segments, so a segment
// can exceed the limit by one audit). Sealing leaves synced temporary files
// and a signed manifest for the caller to register (H.2 step 4) before it
// publishes.
//
// The caller does not choose the request context form. It passes every turn
// as the snapshot reads it: Context in delta form with the stored
// turn_context_ops (or already materialised) and RequestRefs set to the
// materialised refs. The writer keeps the delta form for a root turn and for
// a turn whose parent was written earlier in this segment, after checking
// that the ops applied to the parent's refs give RequestRefs; every other
// turn is written in materialised form (C.4). The digest covers RequestRefs
// only, so the form does not change it.
//
// Any error of Add or Seal is final: the writer removes the temporary files
// it created and every later call returns ReasonClosed.
type SegmentWriter struct {
	options   Options
	key       []byte
	spec      Spec
	payloads  Payloads
	faults    faults
	segmentID string
	tempDir   string
	lines     *encodedFile
	objects   *encodedFile

	members          []archive.ManifestMember
	conversations    []string
	conversationSeen map[string]bool
	first, last      int64
	contents         map[string]archive.ObjectMeta
	binaries         map[string]archive.BinaryMeta
	audits           map[string]bool
	order            orderState
	memo             map[string]turnRefs
	objectCount      int64
	rawChunkCount    int64
	done             bool
}

// NewSegment starts a segment: it creates sessions/ under the root and the
// temporary lines file there.
func NewSegment(options Options, spec Spec, payloads Payloads) (*SegmentWriter, error) {
	key, err := options.validate()
	if err != nil {
		return nil, err
	}
	switch {
	case spec.Index < 1:
		err = errors.New("segment index below 1")
	case spec.Protocol == "":
		err = errors.New("empty protocol")
	case spec.Kind == archive.BundleConversation && spec.ConversationID == "":
		err = errors.New("conversation bundle without a conversation")
	case spec.Kind == archive.BundleBucket && spec.ConversationID != "":
		err = errors.New("bucket with a conversation")
	case spec.Kind != archive.BundleConversation && spec.Kind != archive.BundleBucket:
		err = errors.New("unknown bundle kind")
	case payloads == nil:
		err = errors.New("nil payloads")
	}
	if err != nil {
		clear(key)
		return nil, fail(ReasonInvalidOptions, err)
	}
	writer := &SegmentWriter{
		options: options, key: key, spec: spec, payloads: payloads, faults: options.Fault,
		tempDir: filepath.Join(options.Root, SessionsDir), conversationSeen: map[string]bool{},
		contents: map[string]archive.ObjectMeta{}, binaries: map[string]archive.BinaryMeta{},
		audits: map[string]bool{}, memo: map[string]turnRefs{},
	}
	if writer.segmentID, err = randomHex(16); err != nil {
		clear(key)
		return nil, err
	}
	if err := makeDirs(writer.faults, options.Root, writer.tempDir); err != nil {
		clear(key)
		return nil, err
	}
	if writer.lines, err = newEncodedFile(writer.faults, writer.tempDir, writer.segmentID, roleLines, key); err != nil {
		clear(key)
		return nil, err
	}
	return writer, nil
}

// Len is the number of records added.
func (writer *SegmentWriter) Len() int { return len(writer.members) }

// UncompressedBytes is what the segment counts against SegmentMaxBytes: the
// lines and objects files before compression.
func (writer *SegmentWriter) UncompressedBytes() int64 {
	total := writer.lines.plain
	if writer.objects != nil {
		total += writer.objects.plain
	}
	return total
}

// Full reports whether the segment has passed SegmentMaxBytes, so the next
// audit goes to the next segment.
func (writer *SegmentWriter) Full() bool {
	return len(writer.members) > 0 && writer.UncompressedBytes() > writer.options.maxBytes()
}

// Add writes one record and the objects and raw chunks it refers to that
// this segment has not written yet.
func (writer *SegmentWriter) Add(record *archive.Record) error {
	if writer.done {
		return fail(ReasonClosed, nil)
	}
	if err := writer.add(record); err != nil {
		writer.Abort()
		return err
	}
	return nil
}

func (writer *SegmentWriter) add(record *archive.Record) error {
	if record == nil {
		return fail(ReasonInvalidRecord, errors.New("nil record"))
	}
	if err := record.CheckCanonical(); err != nil {
		return fail(ReasonInvalidRecord, err)
	}
	audit := record.Audit
	switch {
	case record.Revision < 1:
		return fail(ReasonInvalidRecord, errors.New("revision below 1"))
	case audit.AuditID == "":
		return fail(ReasonInvalidRecord, errors.New("empty audit id"))
	case audit.Protocol != writer.spec.Protocol:
		return fail(ReasonInvalidRecord, errors.New("protocol differs from the bundle's"))
	case writer.audits[audit.AuditID]:
		return fail(ReasonInvalidRecord, errors.New("audit already in the segment"))
	case writer.spec.Kind == archive.BundleConversation && (record.Turn == nil || record.Turn.Row.ConversationID != writer.spec.ConversationID):
		return fail(ReasonInvalidRecord, errors.New("record outside the bundle's conversation"))
	case record.ParsedResult != nil && record.ParsedResult.ParsedJSONRef != nil:
		return fail(ReasonInvalidRecord, errors.New("parsed_json given only as a reference"))
	}
	changed, err := writer.order.next(record)
	if err != nil {
		return fail(ReasonOrder, err)
	}
	if changed {
		writer.memo = map[string]turnRefs{}
	}
	lineRecord := *record
	var refs turnRefs
	if record.Turn != nil {
		turn := *record.Turn
		if _, duplicate := writer.memo[turn.Row.TurnID]; duplicate {
			return fail(ReasonInvalidRecord, errors.New("turn already in the segment"))
		}
		if turn.Context, err = writer.placeContext(record.Turn); err != nil {
			return err
		}
		lineRecord.Turn = &turn
		refs = turnRefs{request: cloneRefs(turn.RequestRefs), response: turn.ResponseRefs()}
	}
	line, digest, parts, err := archive.EncodeLine(&lineRecord)
	if err != nil {
		return fail(ReasonInvalidRecord, err)
	}
	if err := writer.lines.writeEntry(line); err != nil {
		return err
	}
	if err := writer.writeObjects(record, parts); err != nil {
		return err
	}
	writer.audits[audit.AuditID] = true
	if record.Turn != nil {
		writer.memo[record.Turn.Row.TurnID] = refs
	}
	conversation := record.ConversationID()
	if conversation != nil && !writer.conversationSeen[*conversation] {
		writer.conversationSeen[*conversation] = true
		writer.conversations = append(writer.conversations, *conversation)
	}
	if len(writer.members) == 0 || audit.StartedAtNS < writer.first {
		writer.first = audit.StartedAtNS
	}
	if len(writer.members) == 0 || audit.EndedAtNS > writer.last {
		writer.last = audit.EndedAtNS
	}
	writer.members = append(writer.members, archive.ManifestMember{
		AuditID: audit.AuditID, Revision: record.Revision, ConversationID: conversation,
		StartedAtNS: audit.StartedAtNS, EndedAtNS: audit.EndedAtNS, RecordDigest: digest,
	})
	return nil
}

// placeContext returns the request context the line carries (C.4).
func (writer *SegmentWriter) placeContext(turn *archive.Turn) (archive.RequestContext, error) {
	row := turn.Row
	if turn.RequestRefs == nil && row.RequestItemCount > 0 {
		return archive.RequestContext{}, fail(ReasonInvalidRecord, archive.ErrNotMaterialized)
	}
	want := turn.RequestRefs
	if want == nil {
		want = []auditmodel.ObjectRef{}
	}
	check := func(context archive.RequestContext, parent *turnRefs) (archive.RequestContext, error) {
		refs, err := materialize(row, context, parent)
		if err != nil || !refsEqual(refs, want) {
			return archive.RequestContext{}, fail(ReasonContextMismatch, err)
		}
		return context, nil
	}
	switch turn.Context.Form {
	case archive.ContextMaterialized:
		return check(turn.Context, nil)
	case archive.ContextDelta:
		if row.ParentTurnID == nil {
			return check(turn.Context, nil)
		}
		if parent, ok := writer.memo[*row.ParentTurnID]; ok {
			return check(turn.Context, &parent)
		}
		return check(archive.RequestContext{Form: archive.ContextMaterialized, Refs: cloneRefs(want)}, nil)
	}
	return archive.RequestContext{}, fail(ReasonInvalidRecord, errors.New("unknown request context form"))
}

func (writer *SegmentWriter) objectsFile() (*encodedFile, error) {
	if writer.objects == nil {
		objects, err := newEncodedFile(writer.faults, writer.tempDir, writer.segmentID, roleObjects, writer.key)
		if err != nil {
			return nil, err
		}
		writer.objects = objects
	}
	return writer.objects, nil
}

func (writer *SegmentWriter) writeObject(entry []byte) error {
	objects, err := writer.objectsFile()
	if err != nil {
		return err
	}
	return objects.writeEntry(entry)
}

// writeObjects writes, in this order, the turn's content objects and binary
// objects not yet in the segment, the record's raw chunks in (stage, seq)
// order, and the parts of a split parsed_json in part order. The reader
// relies on the chunks of one stage and the parts of one audit appearing in
// order.
func (writer *SegmentWriter) writeObjects(record *archive.Record, parts []archive.ParsedJSONPart) error {
	if turn := record.Turn; turn != nil {
		for _, meta := range turn.Objects {
			if written, ok := writer.contents[string(meta.Hash)]; ok {
				if !sameObjectMeta(written, meta) {
					return fail(ReasonPayloadMismatch, errors.New("content object metadata differs between lines"))
				}
				continue
			}
			object, err := writer.payloads.ContentObject(bytes.Clone(meta.Hash))
			if err != nil {
				return fail(ReasonPayloadFailed, err)
			}
			if !bytes.Equal(object.Hash, meta.Hash) || !bytes.Equal(object.SemanticHash, meta.SemanticHash) || object.Kind != meta.Kind ||
				object.PlaintextLength != meta.PlaintextLength || int64(len(object.Data)) != meta.PlaintextLength ||
				!auditmodel.EqualHash(auditmodel.ContentHash(object.Data), meta.Hash) {
				return fail(ReasonPayloadMismatch, errors.New("content object differs from the line"))
			}
			if err := writer.writeObject(archive.EncodeContentObject(object)); err != nil {
				return err
			}
			writer.contents[string(meta.Hash)] = cloneObjectMeta(meta)
			writer.objectCount++
		}
		for _, meta := range turn.Binaries {
			if written, ok := writer.binaries[string(meta.Hash)]; ok {
				if written.MediaType != meta.MediaType || written.PlaintextLength != meta.PlaintextLength {
					return fail(ReasonPayloadMismatch, errors.New("binary object metadata differs between lines"))
				}
				continue
			}
			binary, err := writer.payloads.BinaryObject(bytes.Clone(meta.Hash))
			if err != nil {
				return fail(ReasonPayloadFailed, err)
			}
			if !bytes.Equal(binary.Hash, meta.Hash) || binary.MediaType != meta.MediaType || binary.PlaintextLength != meta.PlaintextLength ||
				int64(len(binary.Data)) != meta.PlaintextLength || !auditmodel.EqualHash(auditmodel.BinaryHash(binary.Data), meta.Hash) {
				return fail(ReasonPayloadMismatch, errors.New("binary object differs from the line"))
			}
			if err := writer.writeObject(archive.EncodeBinaryObject(binary)); err != nil {
				return err
			}
			writer.binaries[string(meta.Hash)] = archive.BinaryMeta{Hash: bytes.Clone(meta.Hash), MediaType: meta.MediaType, PlaintextLength: meta.PlaintextLength}
			writer.objectCount++
		}
	}
	for _, chunk := range record.RawChunks {
		data, err := writer.payloads.RawChunk(record.Audit.AuditID, chunk.Stage, chunk.Seq)
		if err != nil {
			return fail(ReasonPayloadFailed, err)
		}
		if int64(len(data)) != chunk.PlaintextLength || sha256.Sum256(data) != chunk.SHA256 {
			return fail(ReasonPayloadMismatch, errors.New("raw chunk differs from the line"))
		}
		if err := writer.writeObject(archive.EncodeRawChunk(archive.RawChunkData{AuditID: record.Audit.AuditID, Stage: chunk.Stage, Seq: chunk.Seq, Data: data})); err != nil {
			return err
		}
		writer.rawChunkCount++
	}
	for _, part := range parts {
		if err := writer.writeObject(archive.EncodeParsedJSONPart(part)); err != nil {
			return err
		}
		writer.objectCount++
	}
	return nil
}

func sameObjectMeta(left, right archive.ObjectMeta) bool {
	return bytes.Equal(left.Hash, right.Hash) && bytes.Equal(left.SemanticHash, right.SemanticHash) &&
		left.Kind == right.Kind && left.PlaintextLength == right.PlaintextLength
}

func cloneObjectMeta(meta archive.ObjectMeta) archive.ObjectMeta {
	return archive.ObjectMeta{Hash: bytes.Clone(meta.Hash), SemanticHash: bytes.Clone(meta.SemanticHash), Kind: meta.Kind, PlaintextLength: meta.PlaintextLength}
}

// Abort removes the temporary files of an unsealed segment. It is safe to
// call more than once and after Seal, when it does nothing.
func (writer *SegmentWriter) Abort() {
	if writer.done {
		return
	}
	writer.done = true
	writer.lines.discard()
	writer.objects.discard()
	clear(writer.key)
}

// Seal finishes the data files (gzip trailer, last frame, fsync), chooses the
// final names, writes and syncs the signed manifest as a temporary file and
// creates the destination directory. Nothing is published yet.
func (writer *SegmentWriter) Seal() (*Sealed, error) {
	if writer.done {
		return nil, fail(ReasonClosed, nil)
	}
	sealed, err := writer.seal()
	if err != nil {
		writer.Abort()
		return nil, err
	}
	writer.done = true
	clear(writer.key)
	return sealed, nil
}

func (writer *SegmentWriter) seal() (*Sealed, error) {
	if len(writer.members) == 0 {
		return nil, fail(ReasonEmptySegment, nil)
	}
	if err := writer.lines.close(); err != nil {
		return nil, err
	}
	if writer.objects != nil {
		if err := writer.objects.close(); err != nil {
			return nil, err
		}
	}
	base, err := segmentBase(writer.spec.Kind, writer.spec.Protocol, writer.spec.ConversationID, writer.options.RunID, writer.first, writer.last, writer.spec.Index)
	if err != nil {
		return nil, err
	}
	dir := monthDir(writer.options.Root, writer.first)
	encrypted := writer.options.Encrypt
	data := []*outFile{writer.lines.out}
	files := []archive.ManifestFile{{Role: archive.FileLines, Name: linesName(base, encrypted), Bytes: writer.lines.out.size, SHA256: writer.lines.out.sum()}}
	if writer.objects != nil {
		data = append(data, writer.objects.out)
		files = append(files, archive.ManifestFile{Role: archive.FileObjects, Name: objectsName(base, encrypted), Bytes: writer.objects.out.size, SHA256: writer.objects.out.sum()})
	}
	protocol := writer.spec.Protocol
	conversations := writer.conversations
	if conversations == nil {
		conversations = []string{}
	}
	manifest := &archive.Manifest{
		Format: archive.FormatName, FormatVersion: archive.FormatVersion, SourceSchemaVersion: writer.options.SourceSchemaVersion,
		SegmentID: writer.segmentID, RunID: writer.options.RunID, BundleKind: writer.spec.Kind, Protocol: &protocol,
		Conversations: conversations, FirstStartedAtNS: writer.first, LastEndedAtNS: writer.last, CreatedAtNS: writer.options.now(),
		Encrypted: encrypted, Tables: archive.ManifestTables(), Files: files, LineCount: int64(len(writer.members)),
		ObjectCount: writer.objectCount, RawChunkCount: writer.rawChunkCount, Members: writer.members,
	}
	return sealSegment(writer.faults, writer.options, manifest, writer.tempDir, dir, base, data)
}

// sealSegment signs and writes the manifest temporary file and prepares the
// destination directory. On error the caller removes data; sealSegment
// removes what it created itself.
func sealSegment(f faults, options Options, manifest *archive.Manifest, tempDir, dir, base string, data []*outFile) (*Sealed, error) {
	finals := make([]string, 0, len(data)+1)
	for _, file := range manifest.Files {
		finals = append(finals, filepath.Join(dir, file.Name))
	}
	finals = append(finals, filepath.Join(dir, manifestName(base)))
	for _, final := range finals {
		if _, err := os.Lstat(final); err == nil {
			return nil, fail(ReasonNameExists, errors.New("final name exists"))
		}
	}
	if err := manifest.Sign(options.Signer); err != nil {
		return nil, fail(ReasonManifestFailed, err)
	}
	encoded, err := archive.EncodeManifest(manifest)
	if err != nil {
		return nil, fail(ReasonManifestFailed, err)
	}
	manifestTemp, err := writeWhole(f, tempDir, manifest.SegmentID, roleManifest, encoded)
	if err != nil {
		return nil, err
	}
	if err := makeDirs(f, options.Root, dir); err != nil {
		manifestTemp.discard()
		return nil, err
	}
	return &Sealed{faults: f, manifest: manifest, tempDir: tempDir, dir: dir, temps: append(append([]*outFile(nil), data...), manifestTemp), finals: finals}, nil
}

// Sealed is a segment whose files are complete, synced and still under
// temporary names.
type Sealed struct {
	faults   faults
	manifest *archive.Manifest
	tempDir  string
	dir      string
	temps    []*outFile // data files, then the manifest
	finals   []string   // their final paths, in the same order
	state    sealedState
}

type sealedState int

const (
	stateSealed sealedState = iota
	statePublished
	stateGone
)

// Manifest is the signed manifest: segment_id, members with their record
// digests and revisions, files and counts, for registering the intent
// (H.2 step 4). The caller must not modify it.
func (sealed *Sealed) Manifest() *archive.Manifest { return sealed.manifest }

// ManifestPath is the manifest's final path.
func (sealed *Sealed) ManifestPath() string { return sealed.finals[len(sealed.finals)-1] }

// Publish links the data files to their final names, syncs the directory,
// links the manifest last, syncs the directory again and removes the
// temporary names (H.2 step 5). It never replaces a file: an existing final
// name fails with ReasonNameExists. On any failure the files it already
// linked are renamed with RejectedSuffix (manifest first) and the
// temporary files are removed, so no manifest stays published. Calling it
// again after success returns nil.
func (sealed *Sealed) Publish() error {
	switch sealed.state {
	case statePublished:
		return nil
	case stateGone:
		return fail(ReasonClosed, nil)
	}
	var linked []string
	last := len(sealed.temps) - 1
	for index := 0; index < last; index++ {
		if err := linkNew(sealed.faults, sealed.temps[index].path, sealed.finals[index]); err != nil {
			return sealed.unwind(linked, err)
		}
		linked = append(linked, sealed.finals[index])
	}
	if err := syncDir(sealed.faults, sealed.dir); err != nil {
		return sealed.unwind(linked, err)
	}
	if err := linkNew(sealed.faults, sealed.temps[last].path, sealed.finals[last]); err != nil {
		return sealed.unwind(linked, err)
	}
	linked = append(linked, sealed.finals[last])
	if err := syncDir(sealed.faults, sealed.dir); err != nil {
		return sealed.unwind(linked, err)
	}
	for _, temp := range sealed.temps {
		temp.discard()
	}
	_ = syncDirectory(sealed.tempDir)
	sealed.state = statePublished
	return nil
}

func (sealed *Sealed) unwind(linked []string, err error) error {
	for index := len(linked) - 1; index >= 0; index-- {
		_, _ = renameAside(linked[index], RejectedSuffix)
	}
	for _, temp := range sealed.temps {
		temp.discard()
	}
	_ = syncDirectory(sealed.dir)
	sealed.state = stateGone
	return err
}

// Discard removes the temporary files of a segment that will not be
// published (for example because registering the intent failed). It does
// nothing after Publish.
func (sealed *Sealed) Discard() {
	if sealed.state != stateSealed {
		return
	}
	for _, temp := range sealed.temps {
		temp.discard()
	}
	sealed.state = stateGone
}
