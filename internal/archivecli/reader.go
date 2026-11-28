package archivecli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// ReaderOptions configures OpenReader.
type ReaderOptions struct {
	// Keys verifies every manifest (key fingerprint and MAC) before it is
	// indexed and decrypts encrypted bundles. Without it Unauthenticated
	// must be set, and only bundles written without encryption can be read.
	Keys *Keys
	// Unauthenticated reads bundles without checking manifest signatures
	// (K.1 --unauthenticated). It is ignored when Keys is set.
	Unauthenticated bool
	// SkipEventMAC leaves out the check of the copied integrity events'
	// MACs (J.2 item 7), which otherwise runs whenever Keys is set.
	SkipEventMAC bool
}

// Reader reads an archive directory through the manifest index (K.2): it
// never connects to a database and never looks a record up by file name.
// Every bundle is fully verified (bundle.Verify, every check of J.2 that
// needs no database) before anything is read from it, once per Reader.
type Reader struct {
	root    string
	index   *bundle.Index
	options bundle.ReadOptions
	opened  map[string]*opened
}

type opened struct {
	bundle *bundle.Bundle
	err    error
}

// OpenReader builds the index of root. With keys, a manifest whose key
// fingerprint or MAC does not verify is left out of every lookup (it is in
// Problems), so a forged manifest cannot shadow an authentic revision.
func OpenReader(ctx context.Context, root string, options ReaderOptions) (*Reader, error) {
	if options.Keys == nil && !options.Unauthenticated {
		return nil, &cliError{code: codeKeyRequired, message: messages[codeKeyRequired]}
	}
	var signer archive.ManifestSigner
	readOptions := bundle.ReadOptions{Unauthenticated: options.Keys == nil}
	if keys := options.Keys; keys != nil {
		signer = keys.Archive
		readOptions.Signer = keys.Archive
		readOptions.EncryptionKey = keys.Archive.EncryptionKey()
		if !options.SkipEventMAC {
			readOptions.Events = keys.Events
		}
	}
	index, err := buildIndex(ctx, root, signer)
	if err != nil {
		return nil, err
	}
	return &Reader{root: root, index: index, options: readOptions, opened: map[string]*opened{}}, nil
}

func buildIndex(ctx context.Context, root string, signer archive.ManifestSigner) (*bundle.Index, error) {
	index, err := bundle.BuildIndex(ctx, root, signer)
	if bundle.ReasonOf(err) == bundle.ReasonNotFound {
		return nil, &cliError{code: codeArchiveAbsent, message: messages[codeArchiveAbsent]}
	}
	return index, err
}

// Close clears the encryption key copy the reader holds.
func (reader *Reader) Close() { clear(reader.options.EncryptionKey) }

// Index is the manifest index.
func (reader *Reader) Index() *bundle.Index { return reader.index }

// Authenticated reports whether the reader checks manifest signatures.
func (reader *Reader) Authenticated() bool { return reader.options.Signer != nil }

// Bundle opens and verifies the bundle of entry, once per reader.
func (reader *Reader) Bundle(ctx context.Context, entry bundle.Entry) (*bundle.Bundle, error) {
	if cached, ok := reader.opened[entry.ManifestPath]; ok {
		return cached.bundle, cached.err
	}
	result := &opened{}
	result.bundle, result.err = bundle.Open(entry.ManifestPath, reader.options)
	if result.err == nil {
		if _, err := result.bundle.Verify(ctx); err != nil {
			result.bundle, result.err = nil, err
		}
	}
	if bundle.ReasonOf(result.err) == bundle.ReasonCanceled {
		return nil, result.err
	}
	reader.opened[entry.ManifestPath] = result
	return result.bundle, result.err
}

// missing is the error of a lookup that found nothing: key_mismatch when
// manifests were left out because the key does not match them (the wrong
// key leaves the index empty), incomplete when other manifests were left
// out (one of them may hold what was asked for), not_found otherwise.
func (reader *Reader) missing() error {
	for _, problem := range reader.index.Problems() {
		if problem.Reason == bundle.ReasonKeyMismatch {
			return &cliError{code: codeKeyMismatch, message: "not found under this key; the key does not match some bundles of the archive"}
		}
	}
	if err := reader.Incomplete(); err != nil {
		return err
	}
	return &cliError{code: codeNotFound, message: messages[codeNotFound]}
}

// Incomplete is the error of a read whose result may be incomplete because
// the index left manifests out (a signature or key fingerprint that does
// not verify, or a manifest that does not parse): nil when it left none
// out. A left-out manifest cannot be trusted to say which audits or
// conversations it holds, so any of them makes every result possibly
// incomplete, filtered or not.
func (reader *Reader) Incomplete() error {
	if problems := reader.index.Problems(); len(problems) > 0 {
		return &cliError{code: codeIncomplete, message: fmt.Sprintf("%d manifest(s) of the archive could not be used (listed above), so the result may be incomplete", len(problems))}
	}
	return nil
}

// errStop ends a pass over the lines early.
var errStop = errors.New("stop")

// recordAt returns the record of one line, scanning the lines up to it
// (delta turns are materialised from earlier lines, so no line is skipped).
func recordAt(ctx context.Context, opened *bundle.Bundle, line int) (*archive.Record, error) {
	var found *archive.Record
	err := opened.Records(ctx, func(current bundle.Line) error {
		if current.Index == line {
			found = current.Record
			return errStop
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	if found == nil {
		return nil, &cliError{code: codeNotFound, message: messages[codeNotFound]}
	}
	return found, nil
}

// Audit returns the highest revision of one audit (K.2 item 3). Only the
// bundle that holds it is read, one line at a time; its objects are loaded
// when an export needs them, and raw bodies are streamed.
func (reader *Reader) Audit(ctx context.Context, auditID string) (*AuditRecord, error) {
	location, ok := reader.index.Audit(auditID)
	if !ok {
		return nil, reader.missing()
	}
	opened, err := reader.Bundle(ctx, location.Entry)
	if err != nil {
		return nil, err
	}
	record, err := recordAt(ctx, opened, location.Line)
	if err != nil {
		return nil, err
	}
	return &AuditRecord{Record: record, Bundle: opened, ManifestPath: location.Entry.ManifestPath}, nil
}

// AuditRecord is one archived audit and the verified bundle that holds it.
type AuditRecord struct {
	Record       *archive.Record
	Bundle       *bundle.Bundle
	ManifestPath string

	objects    *bundle.ObjectSet
	parsedJSON []byte
	loaded     bool
}

// setObjects supplies objects already loaded for several records.
func (audit *AuditRecord) setObjects(objects *bundle.ObjectSet) error {
	audit.objects, audit.loaded = objects, true
	return audit.loadParsed()
}

func (audit *AuditRecord) loadParsed() error {
	if parsed := audit.Record.ParsedResult; parsed != nil && parsed.ParsedJSONRef != nil {
		joined, err := audit.objects.ParsedJSON(audit.Record.Audit.AuditID)
		if err != nil {
			return err
		}
		audit.parsedJSON = joined
	}
	return nil
}

// load reads the record's content and binary objects and a split
// parsed_json, by one pass over the objects file.
func (audit *AuditRecord) load(ctx context.Context) error {
	if audit.loaded {
		return nil
	}
	objects, err := audit.Bundle.LoadObjects(ctx, audit.Record)
	if err != nil {
		return err
	}
	return audit.setObjects(objects)
}

// PlainDetail is the query layer's plaintext input for the audit (R.1).
func (audit *AuditRecord) PlainDetail(ctx context.Context) (query.PlainDetail, error) {
	if err := audit.load(ctx); err != nil {
		return query.PlainDetail{}, err
	}
	return audit.Record.PlainDetail(audit.objects, audit.parsedJSON)
}

// Detail is query.Service.Get for the audit after the credential projection:
// comparable with archive.ProjectDetail of the hot side's Detail.
func (audit *AuditRecord) Detail(ctx context.Context) (archive.ProjectedDetail, error) {
	if err := audit.load(ctx); err != nil {
		return archive.ProjectedDetail{}, err
	}
	return audit.Record.Detail(audit.objects, audit.parsedJSON)
}

// Summary is the audit's query.Service.List row after the projection, with
// ConversationTurns nil: comparable with archive.ProjectSummary.
func (audit *AuditRecord) Summary() archive.ProjectedSummary { return audit.Record.Summary() }

// Turn is query.Service.ReconstructTurn for the audit.
func (audit *AuditRecord) Turn(ctx context.Context) (query.ReconstructedTurn, error) {
	plain, err := audit.PlainDetail(ctx)
	if err != nil {
		return query.ReconstructedTurn{}, err
	}
	return query.ReconstructPlainTurn(plain)
}

// SessionConversation is query.Service.SessionConversation for the audit.
func (audit *AuditRecord) SessionConversation(ctx context.Context) (*conversation.Conversation, error) {
	plain, err := audit.PlainDetail(ctx)
	if err != nil {
		return nil, err
	}
	return query.PlainSessionConversation(plain)
}

// body is the body row that serves side, chosen as the query layer chooses
// it (query.RawStages), or query.ErrNotFound.
func (audit *AuditRecord) body(side query.Side) (storage.BodyStream, error) {
	body, ok, err := audit.Record.SelectBody(side)
	if err != nil {
		return storage.BodyStream{}, err
	}
	if !ok {
		return storage.BodyStream{}, query.ErrNotFound
	}
	return body, nil
}

// Timeline is query.Service.Timeline for the audit: the timeline of the
// selected body's source stage, with the selected body's observed length.
func (audit *AuditRecord) Timeline(side query.Side) (query.StreamTimeline, error) {
	body, err := audit.body(side)
	if err != nil {
		return query.StreamTimeline{}, err
	}
	stored, plaintext, ok := audit.Record.StoredTimeline(body)
	if !ok {
		return query.StreamTimeline{}, query.ErrNotFound
	}
	// Service.Timeline refuses an empty stored timeline before decrypting.
	if stored.EventCount <= 0 || stored.PlaintextLength <= 0 || len(plaintext) == 0 {
		return query.StreamTimeline{}, query.ErrIntegrity
	}
	return query.TimelineFromPlain(stored, plaintext)
}

// RawMeta is query.Service.RawMeta for the audit.
func (audit *AuditRecord) RawMeta(side query.Side) (query.RawMetadata, error) {
	body, err := audit.body(side)
	if err != nil {
		return query.RawMetadata{}, err
	}
	return query.RawMetadataFromPlain(audit.Record.RawMetadata(body))
}

// StreamRaw is query.Service.StreamRaw for the audit: the chunks of the
// selected body's source stage, one in memory at a time, with the query
// layer's continuity and SHA-256 checks.
func (audit *AuditRecord) StreamRaw(ctx context.Context, side query.Side, destination io.Writer) error {
	body, err := audit.body(side)
	if err != nil {
		return err
	}
	return query.VerifyRaw(ctx, audit.Record.RawMetadata(body), func(visit func(query.PlainChunk) error) error {
		return audit.Bundle.StreamRaw(ctx, audit.Record, body.SourceStage, visit)
	}, destination)
}

// ConversationTurns calls visit with the highest revision of every audit of
// the conversation, in turn order (turns.created_at_ns, then audit_id),
// across all the bundles that hold the conversation (K.2). A first pass over
// each bundle collects the order; a second reads the records in batches of
// at most conversationBatch per pass, with their objects.
func (reader *Reader) ConversationTurns(ctx context.Context, conversationID string, visit func(*AuditRecord) error) error {
	entries := reader.index.Conversation(conversationID)
	if len(entries) == 0 {
		return reader.missing()
	}
	type position struct {
		createdAtNS int64
		auditID     string
		entry       bundle.Entry
		line        int
	}
	var positions []position
	for _, entry := range entries {
		opened, err := reader.Bundle(ctx, entry)
		if err != nil {
			return err
		}
		err = opened.Records(ctx, func(line bundle.Line) error {
			record := line.Record
			if record.Turn == nil || record.Turn.Row.ConversationID != conversationID || !reader.isHighest(entry, line.Index, record.Audit.AuditID) {
				return nil
			}
			positions = append(positions, position{record.Turn.Row.CreatedAtNS, record.Audit.AuditID, entry, line.Index})
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(positions) == 0 {
		return reader.missing()
	}
	sort.Slice(positions, func(left, right int) bool {
		a, b := positions[left], positions[right]
		if a.createdAtNS != b.createdAtNS {
			return a.createdAtNS < b.createdAtNS
		}
		return a.auditID < b.auditID
	})
	for start := 0; start < len(positions); {
		end := start + 1
		for end < len(positions) && end-start < conversationBatch && positions[end].entry.ManifestPath == positions[start].entry.ManifestPath {
			end++
		}
		run := positions[start:end]
		opened, err := reader.Bundle(ctx, run[0].entry)
		if err != nil {
			return err
		}
		wanted := make(map[int]*archive.Record, len(run))
		for _, item := range run {
			wanted[item.line] = nil
		}
		last := run[0].line
		for _, item := range run {
			last = max(last, item.line)
		}
		err = opened.Records(ctx, func(line bundle.Line) error {
			if _, ok := wanted[line.Index]; ok {
				wanted[line.Index] = line.Record
			}
			if line.Index >= last {
				return errStop
			}
			return nil
		})
		if err != nil && !errors.Is(err, errStop) {
			return err
		}
		records := make([]*archive.Record, 0, len(run))
		for _, item := range run {
			if wanted[item.line] == nil {
				return &cliError{code: codeNotFound, message: messages[codeNotFound]}
			}
			records = append(records, wanted[item.line])
		}
		objects, err := opened.LoadObjects(ctx, records...)
		if err != nil {
			return err
		}
		for index, item := range run {
			audit := &AuditRecord{Record: records[index], Bundle: opened, ManifestPath: item.entry.ManifestPath}
			if err := audit.setObjects(objects); err != nil {
				return err
			}
			if err := visit(audit); err != nil {
				return err
			}
		}
		start = end
	}
	return nil
}

// conversationBatch bounds the records (and their objects) held at once by
// ConversationTurns.
const conversationBatch = 64

// isHighest reports whether the line of entry is the audit's highest
// indexed revision.
func (reader *Reader) isHighest(entry bundle.Entry, line int, auditID string) bool {
	location, ok := reader.index.Audit(auditID)
	return ok && location.Entry.ManifestPath == entry.ManifestPath && location.Line == line
}
