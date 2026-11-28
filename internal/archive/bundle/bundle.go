package bundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"os"
	"path/filepath"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/stream"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// maxManifestBytes bounds a manifest file. A manifest lists the members of
// one segment; even a segment of a million audits stays far below this.
const maxManifestBytes = 256 << 20

// EventVerifier checks the MAC of one copied integrity event (J.2 item 7);
// *security.IntegritySigner implements it.
type EventVerifier interface {
	Verify(previousMAC []byte, auditID, eventType string, payloadDigest, eventMAC []byte, createdAtNS int64) bool
}

// ReadOptions configures Open.
type ReadOptions struct {
	// Signer verifies the manifest's key fingerprint and MAC. Without it,
	// Open refuses the bundle unless Unauthenticated is set.
	Signer archive.ManifestSigner
	// EncryptionKey is K_enc; it is required for an encrypted bundle.
	EncryptionKey []byte
	// Unauthenticated allows opening a bundle without Signer: the manifest's
	// MAC is not checked (K.1 --unauthenticated). An encrypted bundle still
	// needs EncryptionKey.
	Unauthenticated bool
	// Events, when set, checks the MAC of every copied integrity event. It
	// needs the integrity key of the source installation; without it that
	// one check of J.2 is skipped.
	Events EventVerifier
}

// Bundle is an opened segment or gap bundle.
type Bundle struct {
	path          string
	dir           string
	manifest      *archive.Manifest
	options       ReadOptions
	key           []byte
	files         map[string]archive.ManifestFile
	authenticated bool
	verified      bool
}

// readManifest reads and decodes a manifest file and checks its file list:
// bare names, a lines file, and an objects file exactly when a segment has
// object entries (none for a gap bundle).
func readManifest(path string) (*archive.Manifest, map[string]archive.ManifestFile, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fail(ReasonNotFound, err)
	}
	if err != nil {
		return nil, nil, fail(ReasonReadFailed, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxManifestBytes {
		return nil, nil, fail(ReasonManifestInvalid, errors.New("manifest is not a regular file of bounded size"))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fail(ReasonReadFailed, err)
	}
	manifest, err := archive.DecodeManifest(data)
	if err != nil {
		return nil, nil, fail(ReasonManifestInvalid, err)
	}
	files := make(map[string]archive.ManifestFile, len(manifest.Files))
	for _, file := range manifest.Files {
		if !plainFileName(file.Name) {
			return nil, nil, fail(ReasonManifestInvalid, errors.New("file name is not a bare name"))
		}
		files[file.Role] = file
	}
	_, hasLines := files[archive.FileLines]
	_, hasObjects := files[archive.FileObjects]
	wantObjects := manifest.BundleKind != archive.BundleGaps && manifest.ObjectCount+manifest.RawChunkCount > 0
	if !hasLines || hasObjects != wantObjects {
		return nil, nil, fail(ReasonManifestInvalid, errors.New("files do not match the bundle kind and counts"))
	}
	if manifest.BundleKind == archive.BundleGaps && (manifest.ObjectCount != 0 || manifest.RawChunkCount != 0) {
		return nil, nil, fail(ReasonManifestInvalid, errors.New("gap bundle with objects"))
	}
	return manifest, files, nil
}

// Open reads the manifest at manifestPath and, with a signer, verifies its
// key fingerprint (ReasonKeyMismatch: nothing is decrypted) and MAC. It reads
// no data file; Verify does.
func Open(manifestPath string, options ReadOptions) (*Bundle, error) {
	manifest, files, err := readManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	bundle := &Bundle{path: manifestPath, dir: filepath.Dir(manifestPath), manifest: manifest, options: options, files: files}
	switch {
	case options.Signer != nil:
		if err := manifest.Verify(options.Signer); err != nil {
			if errors.Is(err, archive.ErrKeyMismatch) {
				return nil, fail(ReasonKeyMismatch, err)
			}
			return nil, fail(ReasonMACMismatch, err)
		}
		bundle.authenticated = true
	case !options.Unauthenticated:
		return nil, fail(ReasonKeyRequired, errors.New("no signer"))
	}
	if manifest.Encrypted {
		if len(options.EncryptionKey) != stream.KeySize {
			return nil, fail(ReasonKeyRequired, errors.New("encrypted bundle without an encryption key"))
		}
		bundle.key = bytes.Clone(options.EncryptionKey)
	}
	return bundle, nil
}

// VerifyFiles is the keyless layer of K.1 verify: the manifest parses and
// every file's stored size and SHA-256 equal the manifest's.
func VerifyFiles(ctx context.Context, manifestPath string) (*archive.Manifest, error) {
	manifest, files, err := readManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(manifestPath)
	for _, file := range manifest.Files {
		if err := hashFile(ctx, filepath.Join(dir, files[file.Role].Name), file); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

// Manifest is the decoded manifest. The caller must not modify it.
func (bundle *Bundle) Manifest() *archive.Manifest { return bundle.manifest }

// Path is the manifest's path.
func (bundle *Bundle) Path() string { return bundle.path }

// Authenticated reports whether the manifest's MAC was verified.
func (bundle *Bundle) Authenticated() bool { return bundle.authenticated }

func (bundle *Bundle) filePath(role string) string {
	return filepath.Join(bundle.dir, bundle.files[role].Name)
}

func (bundle *Bundle) eachLine(ctx context.Context, visit func([]byte) error) error {
	return eachEntry(ctx, bundle.filePath(archive.FileLines), bundle.files[archive.FileLines], bundle.key, visit)
}

func (bundle *Bundle) eachObject(ctx context.Context, visit func(archive.ObjectEntry) error) error {
	file, ok := bundle.files[archive.FileObjects]
	if !ok {
		return nil
	}
	return eachEntry(ctx, bundle.filePath(archive.FileObjects), file, bundle.key, func(entry []byte) error {
		decoded, err := archive.DecodeObjectEntry(entry)
		if err != nil {
			return fail(ReasonObjectMismatch, err)
		}
		return visit(decoded)
	})
}

// Line is one line of a segment, its record materialised.
type Line struct {
	// Index is the line's position, which is also its member's position.
	Index  int
	Record *archive.Record
	Digest [32]byte
}

// Report is what Verify found: the counts and each member's recomputed
// record digest, for the runner to compare with what it computed from the
// hot database (H.2 step 6, J.2 item 3).
type Report struct {
	Manifest        *archive.Manifest
	Lines           int64
	ContentObjects  int64
	BinaryObjects   int64
	ParsedJSONParts int64
	RawChunks       int64
	Gaps            int64
	Members         []MemberDigest
}

// MemberDigest is the record digest recomputed from one line.
type MemberDigest struct {
	AuditID  string
	Revision int64
	Digest   [32]byte
}

// Verify runs every check of J.2 that needs no database, in its order:
// file sizes and SHA-256 (the manifest was checked by Open), then a pass
// over the lines and a pass over the objects file. Any failure voids the
// bundle; the error's reason says which check failed. Records, LoadObjects,
// StreamRaw and Gaps are available only after a Verify that succeeded
// (G.3: nothing is output from a bundle before all of it verified).
func (bundle *Bundle) Verify(ctx context.Context) (*Report, error) {
	bundle.verified = false
	for _, file := range bundle.manifest.Files {
		if err := hashFile(ctx, bundle.filePath(file.Role), file); err != nil {
			return nil, err
		}
	}
	report := &Report{Manifest: bundle.manifest}
	var err error
	if bundle.manifest.BundleKind == archive.BundleGaps {
		err = bundle.verifyGaps(ctx, report)
	} else {
		err = bundle.verifySegment(ctx, report)
	}
	if err != nil {
		return nil, err
	}
	bundle.verified = true
	return report, nil
}

func (bundle *Bundle) requireVerified() error {
	if !bundle.verified {
		return fail(ReasonNotVerified, nil)
	}
	return nil
}

func (bundle *Bundle) verifyGaps(ctx context.Context, report *Report) error {
	manifest := bundle.manifest
	var first, last, lastID int64
	err := bundle.eachLine(ctx, func(entry []byte) error {
		gap, err := archive.DecodeGap(entry)
		if err != nil {
			return fail(ReasonLineInvalid, err)
		}
		if report.Gaps > 0 && gap.ID <= lastID {
			return fail(ReasonOrder, errors.New("gap ids not strictly increasing"))
		}
		if report.Gaps == 0 {
			if gap.ID != manifest.Gaps.FirstID {
				return fail(ReasonMemberMismatch, errors.New("first gap id differs from the manifest"))
			}
			first, last = gap.StartedAtNS, gap.EndedAtNS
		}
		first, last, lastID = min(first, gap.StartedAtNS), max(last, gap.EndedAtNS), gap.ID
		report.Gaps++
		report.Lines++
		return nil
	})
	if err != nil {
		return err
	}
	switch {
	case report.Lines != manifest.LineCount || report.Gaps != manifest.Gaps.Count:
		return fail(ReasonCountMismatch, errors.New("gap count differs from the manifest"))
	case lastID != manifest.Gaps.LastID || first != manifest.FirstStartedAtNS || last != manifest.LastEndedAtNS:
		return fail(ReasonMemberMismatch, errors.New("gap range differs from the manifest"))
	}
	return nil
}

// lineChecker runs the per-line checks of J.2 items 3 and 6 that the line
// alone (and the earlier lines of the segment) can answer. It keeps the
// refs of the turns of the current conversation group only.
type lineChecker struct {
	bundle        *Bundle
	order         orderState
	memo          map[string]turnRefs
	audits        map[string]bool
	conversations []string
	seen          map[string]bool
	first, last   int64
	count         int
}

func newLineChecker(bundle *Bundle) *lineChecker {
	return &lineChecker{bundle: bundle, memo: map[string]turnRefs{}, audits: map[string]bool{}, seen: map[string]bool{}}
}

func (checker *lineChecker) check(entry []byte) (Line, error) {
	manifest := checker.bundle.manifest
	index := checker.count
	if index >= len(manifest.Members) {
		return Line{}, fail(ReasonCountMismatch, errors.New("more lines than members"))
	}
	record, lineDigest, err := archive.DecodeLine(entry)
	if err != nil {
		return Line{}, fail(ReasonLineInvalid, err)
	}
	audit := record.Audit
	member := manifest.Members[index]
	conversation := record.ConversationID()
	if member.AuditID != audit.AuditID || member.Revision != record.Revision || member.StartedAtNS != audit.StartedAtNS ||
		member.EndedAtNS != audit.EndedAtNS || !equalOptional(member.ConversationID, conversation) {
		return Line{}, fail(ReasonMemberMismatch, errors.New("line differs from its member"))
	}
	if checker.audits[audit.AuditID] || record.Revision < 1 || manifest.Protocol == nil || audit.Protocol != *manifest.Protocol ||
		manifest.BundleKind == archive.BundleConversation && (conversation == nil || *conversation != manifest.Conversations[0]) {
		return Line{}, fail(ReasonMemberMismatch, errors.New("line does not belong to this bundle"))
	}
	changed, err := checker.order.next(record)
	if err != nil {
		return Line{}, fail(ReasonOrder, err)
	}
	if changed {
		checker.memo = map[string]turnRefs{}
	}
	if turn := record.Turn; turn != nil {
		if _, duplicate := checker.memo[turn.Row.TurnID]; duplicate {
			return Line{}, fail(ReasonMemberMismatch, errors.New("turn repeated in the segment"))
		}
		var parent *turnRefs
		if turn.Context.Form == archive.ContextDelta && turn.Row.ParentTurnID != nil {
			found, ok := checker.memo[*turn.Row.ParentTurnID]
			if !ok {
				return Line{}, fail(ReasonReferenceOpen, errors.New("delta turn whose parent is not earlier in the segment"))
			}
			parent = &found
		}
		var request, response []auditmodel.ObjectRef
		if parent != nil {
			request, response = parent.request, parent.response
		}
		if err := turn.Materialize(request, response); err != nil {
			return Line{}, fail(ReasonContextMismatch, err)
		}
		if turn.RequestRefs == nil {
			turn.RequestRefs = []auditmodel.ObjectRef{}
		}
	}
	digest, err := archive.Digest(record)
	if err != nil {
		return Line{}, fail(ReasonLineInvalid, err)
	}
	if digest != lineDigest || digest != member.RecordDigest {
		return Line{}, fail(ReasonDigestMismatch, errors.New("record digest differs"))
	}
	if err := checkTurnClosure(record); err != nil {
		return Line{}, err
	}
	if err := checkRawMetadata(record); err != nil {
		return Line{}, err
	}
	if verifier := checker.bundle.options.Events; verifier != nil {
		for _, event := range record.IntegrityEvents {
			if !verifier.Verify(event.PreviousMAC, audit.AuditID, event.EventType, event.PayloadDigest, event.EventMAC, event.CreatedAtNS) {
				return Line{}, fail(ReasonEventMAC, errors.New("integrity event MAC does not verify"))
			}
		}
	}
	if turn := record.Turn; turn != nil {
		checker.memo[turn.Row.TurnID] = turnRefs{request: turn.RequestRefs, response: turn.ResponseRefs()}
	}
	checker.audits[audit.AuditID] = true
	if conversation != nil && !checker.seen[*conversation] {
		checker.seen[*conversation] = true
		checker.conversations = append(checker.conversations, *conversation)
	}
	if index == 0 || audit.StartedAtNS < checker.first {
		checker.first = audit.StartedAtNS
	}
	if index == 0 || audit.EndedAtNS > checker.last {
		checker.last = audit.EndedAtNS
	}
	checker.count++
	return Line{Index: index, Record: record, Digest: digest}, nil
}

// done checks what the manifest says about all lines together.
func (checker *lineChecker) done() error {
	manifest := checker.bundle.manifest
	if int64(checker.count) != manifest.LineCount || checker.count != len(manifest.Members) {
		return fail(ReasonCountMismatch, errors.New("line count differs from the manifest"))
	}
	if checker.first != manifest.FirstStartedAtNS || checker.last != manifest.LastEndedAtNS {
		return fail(ReasonMemberMismatch, errors.New("time range differs from the manifest"))
	}
	if len(checker.conversations) != len(manifest.Conversations) {
		return fail(ReasonMemberMismatch, errors.New("conversations differ from the manifest"))
	}
	for index, conversation := range checker.conversations {
		if manifest.Conversations[index] != conversation {
			return fail(ReasonMemberMismatch, errors.New("conversations differ from the manifest"))
		}
	}
	return nil
}

func equalOptional(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// checkTurnClosure checks the line's own references (J.2 items 4 and 6): the
// listed objects are exactly the envelopes and the request and response refs,
// with the semantic hashes the refs carry; the listed binaries are exactly
// those the binary refs name; every binary and external ref belongs to a
// listed object; external value hashes recompute.
func checkTurnClosure(record *archive.Record) error {
	turn := record.Turn
	if turn == nil {
		return nil
	}
	objects := make(map[string]archive.ObjectMeta, len(turn.Objects))
	for _, object := range turn.Objects {
		objects[string(object.Hash)] = object
	}
	referenced := make(map[string]bool, len(turn.Objects))
	reference := func(hash, semantic []byte) error {
		object, ok := objects[string(hash)]
		if !ok {
			return fail(ReasonReferenceOpen, errors.New("ref to an object the line does not list"))
		}
		if semantic != nil && !bytes.Equal(object.SemanticHash, semantic) {
			return fail(ReasonObjectMismatch, errors.New("ref semantic hash differs from the object's"))
		}
		referenced[string(hash)] = true
		return nil
	}
	for _, envelope := range [][]byte{turn.Row.RequestEnvelopeHash, turn.Row.ResponseEnvelopeHash} {
		if len(envelope) > 0 {
			if err := reference(envelope, nil); err != nil {
				return err
			}
		}
	}
	for _, ref := range turn.RequestRefs {
		if err := reference(ref.ObjectHash, ref.SemanticHash); err != nil {
			return err
		}
	}
	for _, item := range turn.ResponseItems {
		if err := reference(item.ObjectHash, item.SemanticHash); err != nil {
			return err
		}
	}
	if len(referenced) != len(objects) {
		return fail(ReasonObjectMismatch, errors.New("line lists an object no ref uses"))
	}
	binaries := make(map[string]bool, len(turn.Binaries))
	for _, binary := range turn.Binaries {
		binaries[string(binary.Hash)] = false
	}
	for _, ref := range turn.BinaryRefs {
		if _, ok := objects[string(ref.ObjectHash)]; !ok {
			return fail(ReasonReferenceOpen, errors.New("binary ref of an unlisted object"))
		}
		if _, ok := binaries[string(ref.BinaryHash)]; !ok {
			return fail(ReasonReferenceOpen, errors.New("binary ref to an unlisted binary"))
		}
		binaries[string(ref.BinaryHash)] = true
	}
	for _, used := range binaries {
		if !used {
			return fail(ReasonObjectMismatch, errors.New("line lists a binary no ref uses"))
		}
	}
	for _, ref := range turn.ExternalRefs {
		if _, ok := objects[string(ref.ObjectHash)]; !ok {
			return fail(ReasonReferenceOpen, errors.New("external ref of an unlisted object"))
		}
		if !auditmodel.EqualHash(auditmodel.ExternalValueHash(ref.RefKind, ref.Value), ref.ValueHash) {
			return fail(ReasonObjectMismatch, errors.New("external value hash does not recompute"))
		}
	}
	return nil
}

// checkRawMetadata checks the raw chunk metadata of the line against the
// body rows as query.StreamRaw would serve them (J.2 item 5): every chunk
// belongs to the source stage of a body with full retention; for each such
// body the chunks of its source stage run on in seq and offset (a forward
// gap only for a partial body with capture_chunk_missing, within the
// observed length), their count is chunk_count and their bytes
// stored_length. The SHA-256 of a complete body needs the bytes and is
// checked in the objects pass.
func checkRawMetadata(record *archive.Record) error {
	sources := make(map[string]bool)
	for _, body := range record.Bodies {
		if body.RetentionState != storage.RetentionFull || body.State == storage.StageStateStreaming {
			continue
		}
		sources[body.SourceStage] = true
		chunks := record.OwningChunks(body)
		missing := body.State == storage.StageStatePartial && body.ErrorCode != nil && *body.ErrorCode == storage.CaptureChunkMissing
		var sequence, offset, total int64
		for _, chunk := range chunks {
			if chunk.Seq != sequence || chunk.Offset != offset {
				if !missing || chunk.Seq <= sequence || chunk.Offset < offset {
					return fail(ReasonRawMismatch, errors.New("raw chunks do not run on"))
				}
			}
			if chunk.PlaintextLength < 0 || missing && (chunk.Offset > body.ObservedLength || chunk.PlaintextLength > body.ObservedLength-chunk.Offset) {
				return fail(ReasonRawMismatch, errors.New("raw chunk outside the observed body"))
			}
			total += chunk.PlaintextLength
			sequence, offset = chunk.Seq+1, chunk.Offset+chunk.PlaintextLength
		}
		if total != body.StoredLength || int64(len(chunks)) != body.ChunkCount {
			return fail(ReasonRawMismatch, errors.New("raw chunks differ from chunk_count or stored_length"))
		}
		if bodyComplete(body) && len(body.SHA256) != sha256.Size {
			return fail(ReasonRawMismatch, errors.New("complete body without a SHA-256"))
		}
	}
	for _, chunk := range record.RawChunks {
		if !sources[chunk.Stage] {
			return fail(ReasonRawMismatch, errors.New("raw chunk of a stage no full body is served from"))
		}
	}
	return nil
}

// bodyComplete is query's definition of a complete body: its SHA-256 covers
// all stored bytes.
func bodyComplete(body storage.BodyStream) bool {
	return body.State == storage.StageStateComplete && body.HashComplete && body.EOFSeen && body.StoredLength == body.ObservedLength
}

// scanLines decodes and checks every line and calls visit with it.
func (bundle *Bundle) scanLines(ctx context.Context, visit func(Line) error) error {
	checker := newLineChecker(bundle)
	err := bundle.eachLine(ctx, func(entry []byte) error {
		line, err := checker.check(entry)
		if err != nil {
			return err
		}
		return visit(line)
	})
	if err != nil {
		return err
	}
	return checker.done()
}

// Records calls visit with every line in order, its turn materialised. The
// record is the caller's. It needs a successful Verify first, and still
// checks every line and the file's hash as it goes.
func (bundle *Bundle) Records(ctx context.Context, visit func(Line) error) error {
	if err := bundle.requireVerified(); err != nil {
		return err
	}
	if bundle.manifest.BundleKind == archive.BundleGaps {
		return fail(ReasonInvalidOptions, errors.New("gap bundle has no records"))
	}
	return bundle.scanLines(ctx, visit)
}

// Gaps calls visit with every gap of a gap bundle, after a successful Verify.
func (bundle *Bundle) Gaps(ctx context.Context, visit func(archive.Gap) error) error {
	if err := bundle.requireVerified(); err != nil {
		return err
	}
	if bundle.manifest.BundleKind != archive.BundleGaps {
		return fail(ReasonInvalidOptions, errors.New("not a gap bundle"))
	}
	return bundle.eachLine(ctx, func(entry []byte) error {
		gap, err := archive.DecodeGap(entry)
		if err != nil {
			return fail(ReasonLineInvalid, err)
		}
		return visit(gap)
	})
}

// expectations is what the lines say the objects file must hold, built in
// the lines pass and ticked off in the objects pass. It holds metadata only:
// hashes, lengths and a running SHA-256 per raw stream and split parsed_json.
type expectations struct {
	contents map[string]*expectedContent
	binaries map[string]*expectedBinary
	chunks   map[chunkKey]*expectedChunk
	streams  map[streamKey]*expectedStream
	parts    map[string]*expectedParts
}

type chunkKey struct {
	auditID, stage string
	seq            int64
}

type streamKey struct{ auditID, stage string }

type expectedContent struct {
	meta archive.ObjectMeta
	seen bool
}

type expectedBinary struct {
	meta archive.BinaryMeta
	seen bool
}

type expectedChunk struct {
	length int64
	sha256 [32]byte
	seen   bool
}

type expectedStream struct {
	seqs    []int64
	next    int
	digest  hash.Hash
	digests [][]byte // SHA-256 of every complete body served from the stream
}

type expectedParts struct {
	ref    archive.ParsedJSONRef
	next   int64
	length int64
	digest hash.Hash
}

func newExpectations() *expectations {
	return &expectations{
		contents: map[string]*expectedContent{}, binaries: map[string]*expectedBinary{},
		chunks: map[chunkKey]*expectedChunk{}, streams: map[streamKey]*expectedStream{}, parts: map[string]*expectedParts{},
	}
}

func (expected *expectations) add(record *archive.Record) error {
	if turn := record.Turn; turn != nil {
		for _, object := range turn.Objects {
			if existing, ok := expected.contents[string(object.Hash)]; ok {
				if !sameObjectMeta(existing.meta, object) {
					return fail(ReasonObjectMismatch, errors.New("lines disagree on a content object"))
				}
				continue
			}
			expected.contents[string(object.Hash)] = &expectedContent{meta: object}
		}
		for _, binary := range turn.Binaries {
			if existing, ok := expected.binaries[string(binary.Hash)]; ok {
				if existing.meta.MediaType != binary.MediaType || existing.meta.PlaintextLength != binary.PlaintextLength {
					return fail(ReasonObjectMismatch, errors.New("lines disagree on a binary object"))
				}
				continue
			}
			expected.binaries[string(binary.Hash)] = &expectedBinary{meta: binary}
		}
	}
	auditID := record.Audit.AuditID
	for _, chunk := range record.RawChunks {
		expected.chunks[chunkKey{auditID, chunk.Stage, chunk.Seq}] = &expectedChunk{length: chunk.PlaintextLength, sha256: chunk.SHA256}
		key := streamKey{auditID, chunk.Stage}
		stream := expected.streams[key]
		if stream == nil {
			stream = &expectedStream{digest: sha256.New()}
			expected.streams[key] = stream
		}
		stream.seqs = append(stream.seqs, chunk.Seq)
	}
	for _, body := range record.Bodies {
		if body.RetentionState != storage.RetentionFull || !bodyComplete(body) {
			continue
		}
		key := streamKey{auditID, body.SourceStage}
		stream := expected.streams[key]
		if stream == nil {
			stream = &expectedStream{digest: sha256.New()}
			expected.streams[key] = stream
		}
		stream.digests = append(stream.digests, body.SHA256)
	}
	if parsed := record.ParsedResult; parsed != nil && parsed.ParsedJSONRef != nil {
		expected.parts[auditID] = &expectedParts{ref: *parsed.ParsedJSONRef, digest: sha256.New()}
	}
	return nil
}

// accept checks one objects file entry (J.2 items 4 and 5).
func (expected *expectations) accept(entry archive.ObjectEntry, report *Report) error {
	switch {
	case entry.Content != nil:
		object := entry.Content
		want, ok := expected.contents[string(object.Hash)]
		if !ok || want.seen {
			return fail(ReasonObjectMismatch, errors.New("content object no line lists, or listed twice"))
		}
		if err := checkContentObject(want.meta, object); err != nil {
			return err
		}
		want.seen = true
		report.ContentObjects++
	case entry.Binary != nil:
		binary := entry.Binary
		want, ok := expected.binaries[string(binary.Hash)]
		if !ok || want.seen {
			return fail(ReasonObjectMismatch, errors.New("binary object no line lists, or listed twice"))
		}
		if binary.MediaType != want.meta.MediaType || binary.PlaintextLength != want.meta.PlaintextLength ||
			int64(len(binary.Data)) != binary.PlaintextLength || !auditmodel.EqualHash(auditmodel.BinaryHash(binary.Data), binary.Hash) {
			return fail(ReasonObjectMismatch, errors.New("binary object does not match its hash or the line"))
		}
		want.seen = true
		report.BinaryObjects++
	case entry.RawChunk != nil:
		chunk := entry.RawChunk
		want, ok := expected.chunks[chunkKey{chunk.AuditID, chunk.Stage, chunk.Seq}]
		if !ok || want.seen {
			return fail(ReasonRawMismatch, errors.New("raw chunk no line lists, or listed twice"))
		}
		if int64(len(chunk.Data)) != want.length || sha256.Sum256(chunk.Data) != want.sha256 {
			return fail(ReasonRawMismatch, errors.New("raw chunk does not match the line"))
		}
		stream := expected.streams[streamKey{chunk.AuditID, chunk.Stage}]
		if stream.next >= len(stream.seqs) || stream.seqs[stream.next] != chunk.Seq {
			return fail(ReasonOrder, errors.New("raw chunks out of seq order"))
		}
		stream.next++
		_, _ = stream.digest.Write(chunk.Data)
		want.seen = true
		report.RawChunks++
	case entry.ParsedJSONPart != nil:
		part := entry.ParsedJSONPart
		want, ok := expected.parts[part.AuditID]
		if !ok || part.Part != want.next || want.next >= want.ref.Parts || len(part.Data) == 0 || len(part.Data) > archive.ParsedJSONInlineLimit {
			return fail(ReasonObjectMismatch, errors.New("parsed_json part no line refers to, or out of order"))
		}
		want.next++
		want.length += int64(len(part.Data))
		_, _ = want.digest.Write(part.Data)
		report.ParsedJSONParts++
	default:
		return fail(ReasonObjectMismatch, errors.New("empty objects entry"))
	}
	return nil
}

// checkContentObject checks a content object against its own content
// address and the line's metadata: length, ContentHash, schema version,
// kind, and the semantic hash, which for an envelope is its object hash
// (auditmodel.Prepare) and for an item SemanticHash(kind, value).
func checkContentObject(meta archive.ObjectMeta, object *archive.ContentObject) error {
	if !bytes.Equal(object.SemanticHash, meta.SemanticHash) || object.Kind != meta.Kind || object.PlaintextLength != meta.PlaintextLength ||
		int64(len(object.Data)) != object.PlaintextLength || !auditmodel.EqualHash(auditmodel.ContentHash(object.Data), object.Hash) {
		return fail(ReasonObjectMismatch, errors.New("content object does not match its address or the line"))
	}
	var decoded auditmodel.DecodedObject
	if err := auditmodel.DecodeJSON(object.Data, &decoded); err != nil || decoded.SchemaVersion != auditmodel.SchemaVersion || decoded.Kind != object.Kind {
		return fail(ReasonObjectMismatch, errors.New("content object does not decode"))
	}
	var semantic []byte
	if decoded.Kind == "request_envelope" || decoded.Kind == "response_envelope" {
		semantic = object.Hash
	} else {
		var err error
		if semantic, err = auditmodel.SemanticHash(decoded.Kind, decoded.Value); err != nil {
			return fail(ReasonObjectMismatch, err)
		}
	}
	if !auditmodel.EqualHash(semantic, object.SemanticHash) {
		return fail(ReasonObjectMismatch, errors.New("semantic hash does not recompute"))
	}
	return nil
}

// finish checks that everything the lines refer to was in the objects file
// and the whole-body SHA-256 of every complete body.
func (expected *expectations) finish() error {
	for _, want := range expected.contents {
		if !want.seen {
			return fail(ReasonReferenceOpen, errors.New("content object missing from the objects file"))
		}
	}
	for _, want := range expected.binaries {
		if !want.seen {
			return fail(ReasonReferenceOpen, errors.New("binary object missing from the objects file"))
		}
	}
	for _, want := range expected.chunks {
		if !want.seen {
			return fail(ReasonReferenceOpen, errors.New("raw chunk missing from the objects file"))
		}
	}
	for _, stream := range expected.streams {
		sum := stream.digest.Sum(nil)
		for _, digest := range stream.digests {
			if !bytes.Equal(sum, digest) {
				return fail(ReasonRawMismatch, errors.New("complete body SHA-256 differs"))
			}
		}
	}
	for _, want := range expected.parts {
		if want.next != want.ref.Parts {
			return fail(ReasonReferenceOpen, errors.New("parsed_json part missing from the objects file"))
		}
		if want.length != want.ref.Length || [32]byte(want.digest.Sum(nil)) != want.ref.SHA256 {
			return fail(ReasonObjectMismatch, errors.New("parsed_json parts differ from the reference"))
		}
	}
	return nil
}

func (bundle *Bundle) verifySegment(ctx context.Context, report *Report) error {
	expected := newExpectations()
	err := bundle.scanLines(ctx, func(line Line) error {
		report.Lines++
		report.Members = append(report.Members, MemberDigest{AuditID: line.Record.Audit.AuditID, Revision: line.Record.Revision, Digest: line.Digest})
		return expected.add(line.Record)
	})
	if err != nil {
		return err
	}
	if err := bundle.eachObject(ctx, func(entry archive.ObjectEntry) error { return expected.accept(entry, report) }); err != nil {
		return err
	}
	if err := expected.finish(); err != nil {
		return err
	}
	manifest := bundle.manifest
	if report.ContentObjects+report.BinaryObjects+report.ParsedJSONParts != manifest.ObjectCount || report.RawChunks != manifest.RawChunkCount {
		return fail(ReasonCountMismatch, errors.New("object counts differ from the manifest"))
	}
	return nil
}

// ObjectSet holds the content objects, binary objects and parsed_json parts
// of selected records, loaded by one pass over the objects file. It is an
// archive.ObjectSource.
type ObjectSet struct {
	contents map[string][]byte
	binaries map[string][]byte
	parts    map[string][]archive.ParsedJSONPart
	refs     map[string]archive.ParsedJSONRef
}

// ContentPlaintext returns a loaded content object's canonical JSON.
func (set *ObjectSet) ContentPlaintext(hash []byte) ([]byte, error) {
	if data, ok := set.contents[string(hash)]; ok {
		return data, nil
	}
	return nil, fail(ReasonNotFound, errors.New("content object not loaded"))
}

// BinaryData returns a loaded binary object's bytes.
func (set *ObjectSet) BinaryData(hash []byte) ([]byte, error) {
	if data, ok := set.binaries[string(hash)]; ok {
		return data, nil
	}
	return nil, fail(ReasonNotFound, errors.New("binary object not loaded"))
}

// ParsedJSON returns the joined parsed_json of a loaded record whose line
// split it into the objects file, checked against the line's reference.
func (set *ObjectSet) ParsedJSON(auditID string) ([]byte, error) {
	ref, ok := set.refs[auditID]
	if !ok {
		return nil, fail(ReasonNotFound, errors.New("no split parsed_json loaded for the audit"))
	}
	joined, err := archive.JoinParsedJSON(ref, set.parts[auditID])
	if err != nil {
		return nil, fail(ReasonObjectMismatch, err)
	}
	return joined, nil
}

// LoadObjects reads the objects file once and keeps only what the given
// records refer to: their turns' content and binary objects and their split
// parsed_json parts. Raw chunks are not loaded; StreamRaw streams them. The
// memory used is that of the selected records' objects, not of the file
// (H.7): gzip and the frame stream allow no random access, so a lookup is a
// sequential pass that picks the entries it needs. It needs a successful
// Verify first.
func (bundle *Bundle) LoadObjects(ctx context.Context, records ...*archive.Record) (*ObjectSet, error) {
	if err := bundle.requireVerified(); err != nil {
		return nil, err
	}
	set := &ObjectSet{contents: map[string][]byte{}, binaries: map[string][]byte{}, parts: map[string][]archive.ParsedJSONPart{}, refs: map[string]archive.ParsedJSONRef{}}
	wantContents, wantBinaries := map[string]bool{}, map[string]bool{}
	for _, record := range records {
		if record.Turn != nil {
			for _, object := range record.Turn.Objects {
				wantContents[string(object.Hash)] = true
			}
			for _, binary := range record.Turn.Binaries {
				wantBinaries[string(binary.Hash)] = true
			}
		}
		if parsed := record.ParsedResult; parsed != nil && parsed.ParsedJSONRef != nil {
			set.refs[record.Audit.AuditID] = *parsed.ParsedJSONRef
		}
	}
	err := bundle.eachObject(ctx, func(entry archive.ObjectEntry) error {
		switch {
		case entry.Content != nil && wantContents[string(entry.Content.Hash)]:
			if !auditmodel.EqualHash(auditmodel.ContentHash(entry.Content.Data), entry.Content.Hash) {
				return fail(ReasonObjectMismatch, errors.New("content object does not match its address"))
			}
			set.contents[string(entry.Content.Hash)] = entry.Content.Data
		case entry.Binary != nil && wantBinaries[string(entry.Binary.Hash)]:
			if !auditmodel.EqualHash(auditmodel.BinaryHash(entry.Binary.Data), entry.Binary.Hash) {
				return fail(ReasonObjectMismatch, errors.New("binary object does not match its hash"))
			}
			set.binaries[string(entry.Binary.Hash)] = entry.Binary.Data
		case entry.ParsedJSONPart != nil:
			if _, ok := set.refs[entry.ParsedJSONPart.AuditID]; ok {
				set.parts[entry.ParsedJSONPart.AuditID] = append(set.parts[entry.ParsedJSONPart.AuditID], *entry.ParsedJSONPart)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(set.contents) != len(wantContents) || len(set.binaries) != len(wantBinaries) {
		return nil, fail(ReasonReferenceOpen, errors.New("objects missing from the objects file"))
	}
	return set, nil
}

// StreamRaw calls visit with the raw chunks of one stage of the record, in
// seq order, one chunk in memory at a time, by one pass over the objects
// file. Pass the body's SourceStage (archive.Record.OwningChunks). The
// visitor has the shape query.VerifyRaw takes. It needs a successful Verify
// first.
func (bundle *Bundle) StreamRaw(ctx context.Context, record *archive.Record, stage string, visit func(query.PlainChunk) error) error {
	if err := bundle.requireVerified(); err != nil {
		return err
	}
	metadata := map[int64]archive.RawChunk{}
	for _, chunk := range record.RawChunks {
		if chunk.Stage == stage {
			metadata[chunk.Seq] = chunk
		}
	}
	visited := 0
	err := bundle.eachObject(ctx, func(entry archive.ObjectEntry) error {
		chunk := entry.RawChunk
		if chunk == nil || chunk.AuditID != record.Audit.AuditID || chunk.Stage != stage {
			return nil
		}
		meta, ok := metadata[chunk.Seq]
		if !ok || int64(len(chunk.Data)) != meta.PlaintextLength || sha256.Sum256(chunk.Data) != meta.SHA256 {
			return fail(ReasonRawMismatch, errors.New("raw chunk does not match the line"))
		}
		visited++
		return visit(query.PlainChunk{Seq: chunk.Seq, Offset: meta.Offset, PlaintextLength: int(meta.PlaintextLength), Data: chunk.Data})
	})
	if err != nil {
		return err
	}
	if visited != len(metadata) {
		return fail(ReasonReferenceOpen, errors.New("raw chunks missing from the objects file"))
	}
	return nil
}
