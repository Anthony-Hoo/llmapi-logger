package archivecli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/query"
)

// ---- list -----------------------------------------------------------------

// BundleInfo is one bundle as list prints it.
type BundleInfo struct {
	Manifest         string   `json:"manifest"`
	Kind             string   `json:"kind"`
	Protocol         *string  `json:"protocol"`
	FormatVersion    string   `json:"format_version"`
	Encrypted        bool     `json:"encrypted"`
	FirstStartedAt   string   `json:"first_started_at"`
	LastEndedAt      string   `json:"last_ended_at"`
	FirstStartedAtNS int64    `json:"first_started_at_ns,string"`
	LastEndedAtNS    int64    `json:"last_ended_at_ns,string"`
	Members          int      `json:"members"`
	Conversations    []string `json:"conversations"`
	Gaps             *GapInfo `json:"gaps"`
	// Auth is not_checked without a key, else ok, key_mismatch or
	// mac_mismatch.
	Auth string `json:"auth"`
}

// GapInfo is the gap range of a gap bundle.
type GapInfo struct {
	FirstID int64 `json:"first_id,string"`
	LastID  int64 `json:"last_id,string"`
	Count   int64 `json:"count,string"`
}

func formatNS(ns int64) string { return time.Unix(0, ns).UTC().Format(time.RFC3339) }

// Authenticity checks a manifest's key fingerprint and MAC: ok,
// key_mismatch or mac_mismatch.
func Authenticity(manifest *archive.Manifest, keys *Keys) string {
	if keys == nil {
		return "not_checked"
	}
	switch err := manifest.Verify(keys.Archive); {
	case err == nil:
		return "ok"
	case errors.Is(err, archive.ErrKeyMismatch):
		return bundle.ReasonKeyMismatch
	default:
		return bundle.ReasonMACMismatch
	}
}

func runList(ctx context.Context, env *Env, args []string) error {
	var c common
	var conversationID, auditID string
	var asJSON bool
	flags := flagSet("list")
	c.archiveFlags(flags)
	flags.StringVar(&conversationID, "conversation", "", "")
	flags.StringVar(&auditID, "audit", "", "")
	flags.BoolVar(&asJSON, "json", false, "")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if err := c.requireDir(); err != nil {
		return err
	}
	if conversationID != "" && auditID != "" {
		return usageError("give --conversation or --audit, not both")
	}
	keys, err := c.keys()
	if err != nil {
		return err
	}
	// The index is built without the signer, so that bundles whose
	// signature fails are listed and marked rather than left out.
	index, err := buildIndex(ctx, c.dir, nil)
	if err != nil {
		return err
	}
	for _, problem := range index.Problems() {
		fmt.Fprintf(env.Stderr, "audit-archive: unreadable manifest %s: %s\n", c.relative(problem.Path), problem.Reason)
	}
	entries := index.Bundles()
	switch {
	case conversationID != "":
		entries = index.Conversation(conversationID)
	case auditID != "":
		entries = nil
		seen := map[string]bool{}
		for _, location := range index.AuditRevisions(auditID) {
			if !seen[location.Entry.ManifestPath] {
				seen[location.Entry.ManifestPath] = true
				entries = append(entries, location.Entry)
			}
		}
	}
	sort.SliceStable(entries, func(left, right int) bool { return entries[left].ManifestPath < entries[right].ManifestPath })
	out := newOutput(env.Stdout)
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if !asJSON {
		fmt.Fprintln(table, "KIND\tPROTOCOL\tFIRST_STARTED\tLAST_ENDED\tMEMBERS\tCONVERSATIONS\tENCRYPTED\tFORMAT\tAUTH\tMANIFEST")
	}
	for _, entry := range entries {
		manifest := entry.Manifest
		info := BundleInfo{
			Manifest: c.relative(entry.ManifestPath), Kind: manifest.BundleKind, Protocol: manifest.Protocol,
			FormatVersion: manifest.FormatVersion, Encrypted: manifest.Encrypted,
			FirstStartedAt: formatNS(manifest.FirstStartedAtNS), LastEndedAt: formatNS(manifest.LastEndedAtNS),
			FirstStartedAtNS: manifest.FirstStartedAtNS, LastEndedAtNS: manifest.LastEndedAtNS,
			Members: len(manifest.Members), Conversations: append([]string{}, manifest.Conversations...),
			Auth: Authenticity(manifest, keys),
		}
		if gaps := manifest.Gaps; gaps != nil {
			info.Gaps = &GapInfo{FirstID: gaps.FirstID, LastID: gaps.LastID, Count: gaps.Count}
		}
		if asJSON {
			encoded, err := json.Marshal(info)
			if err != nil {
				return err
			}
			if err := out.line(encoded); err != nil {
				return err
			}
			continue
		}
		protocol := "-"
		if info.Protocol != nil {
			protocol = printable(*info.Protocol)
		}
		conversations := strconv.Itoa(len(info.Conversations))
		if len(info.Conversations) == 1 {
			conversations = printable(info.Conversations[0])
		}
		if info.Gaps != nil {
			conversations = fmt.Sprintf("gaps %d-%d", info.Gaps.FirstID, info.Gaps.LastID)
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%d\t%s\t%t\t%s\t%s\t%s\n", info.Kind, protocol, info.FirstStartedAt, info.LastEndedAt,
			info.Members, conversations, info.Encrypted, info.FormatVersion, info.Auth, printable(info.Manifest))
	}
	if !asJSON {
		_ = table.Flush()
	}
	if err := out.flush(); err != nil {
		return err
	}
	if (conversationID != "" || auditID != "") && len(entries) == 0 {
		return &cliError{code: codeNotFound, message: "no bundle holds it"}
	}
	return nil
}

// ---- verify ---------------------------------------------------------------

// VerifyResult is one bundle's verify outcome.
type VerifyResult struct {
	Manifest string `json:"manifest"`
	// Level is "files" for the keyless layer, "full" with the key, and
	// "manifest" for a manifest that does not parse.
	Level   string `json:"level"`
	Result  string `json:"result"`
	Members int    `json:"members"`
}

// VerifyBundle runs the checks of one bundle: the keyless file layer
// without keys, every check of J.2 that needs no database with them (event
// MACs unless skipEventMAC). It returns "ok" or the failure's reason code.
func VerifyBundle(ctx context.Context, manifestPath string, keys *Keys, skipEventMAC bool) VerifyResult {
	result := VerifyResult{Manifest: manifestPath, Level: "files"}
	if keys == nil {
		manifest, err := bundle.VerifyFiles(ctx, manifestPath)
		if manifest != nil {
			result.Members = len(manifest.Members)
		}
		result.Result = resultCode(err)
		return result
	}
	result.Level = "full"
	options := bundle.ReadOptions{Signer: keys.Archive, EncryptionKey: keys.Archive.EncryptionKey()}
	defer clear(options.EncryptionKey)
	if !skipEventMAC {
		options.Events = keys.Events
	}
	opened, err := bundle.Open(manifestPath, options)
	if err != nil {
		result.Result = resultCode(err)
		return result
	}
	result.Members = len(opened.Manifest().Members)
	_, err = opened.Verify(ctx)
	result.Result = resultCode(err)
	return result
}

func resultCode(err error) string {
	if err == nil {
		return "ok"
	}
	if reason := bundle.ReasonOf(err); reason != "" {
		return reason
	}
	return bundle.ReasonReadFailed
}

func runVerify(ctx context.Context, env *Env, args []string) error {
	var c common
	var single string
	var asJSON bool
	flags := flagSet("verify")
	c.archiveFlags(flags)
	flags.StringVar(&single, "bundle", "", "")
	flags.BoolVar(&c.skipEventMAC, "skip-event-mac", false, "")
	flags.BoolVar(&asJSON, "json", false, "")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if (c.dir == "") == (single == "") {
		return usageError("give --dir <archive> or --bundle <manifest>")
	}
	keys, err := c.keys()
	if err != nil {
		return err
	}
	var results []VerifyResult
	if single != "" {
		results = append(results, VerifyBundle(ctx, single, keys, c.skipEventMAC))
	} else {
		index, err := buildIndex(ctx, c.dir, nil)
		if err != nil {
			return err
		}
		for _, problem := range index.Problems() {
			results = append(results, VerifyResult{Manifest: problem.Path, Level: "manifest", Result: problem.Reason})
		}
		for _, entry := range index.Bundles() {
			if err := ctx.Err(); err != nil {
				return err
			}
			results = append(results, VerifyBundle(ctx, entry.ManifestPath, keys, c.skipEventMAC))
		}
		leftovers := index.Leftovers()
		for _, path := range leftovers.DataWithoutManifest {
			fmt.Fprintf(env.Stderr, "audit-archive: note: data file without a manifest: %s\n", printable(c.relative(path)))
		}
		for _, path := range leftovers.Temporary {
			fmt.Fprintf(env.Stderr, "audit-archive: note: temporary file of an interrupted run: %s\n", printable(c.relative(path)))
		}
	}
	sort.SliceStable(results, func(left, right int) bool { return results[left].Manifest < results[right].Manifest })
	out := newOutput(env.Stdout)
	failed := 0
	for _, result := range results {
		if result.Result != "ok" {
			failed++
		}
		if single == "" {
			result.Manifest = c.relative(result.Manifest)
		}
		if asJSON {
			encoded, err := json.Marshal(result)
			if err != nil {
				return err
			}
			_ = out.line(encoded)
			continue
		}
		out.printf("%s\t%s\t%d\t%s\n", result.Result, result.Level, result.Members, printable(result.Manifest))
	}
	level := "full: every check that needs no database"
	switch {
	case keys == nil:
		level = "files only (no key): manifests parse and file sizes and SHA-256 match; signatures and content were NOT checked"
	case c.skipEventMAC:
		level += ", except the integrity events' MACs"
	}
	summary := fmt.Sprintf("verify: %d bundles, %d ok, %d failed; level %s", len(results), len(results)-failed, failed, level)
	if asJSON {
		encoded, _ := json.Marshal(map[string]any{"summary": true, "bundles": len(results), "ok": len(results) - failed, "failed": failed,
			"level": map[bool]string{true: "files", false: "full"}[keys == nil], "event_mac_checked": keys != nil && !c.skipEventMAC})
		_ = out.line(encoded)
	} else {
		out.printf("%s\n", summary)
	}
	if err := out.flush(); err != nil {
		return err
	}
	if failed > 0 {
		return &exitStatus{code: ExitFailed}
	}
	return nil
}

// ---- cat ------------------------------------------------------------------

// CatOptions selects what Cat prints.
type CatOptions struct {
	ConversationID string
	AuditID        string
	AllRevisions   bool
	WithObjects    bool
}

// Cat writes the decrypted lines of the selected audits as JSON Lines in the
// archive's line format (archive.EncodeLine of each verified record), and
// with WithObjects the objects file entries they refer to. A bundle that
// does not verify is reported to skipped and not printed. It returns
// not_found when the filter matches nothing.
func Cat(ctx context.Context, reader *Reader, options CatOptions, destination io.Writer, skipped func(string, error)) (int, error) {
	index := reader.Index()
	filtered := options.ConversationID != "" || options.AuditID != ""
	var entries []bundle.Entry
	switch {
	case options.AuditID != "":
		seen := map[string]bool{}
		for _, location := range index.AuditRevisions(options.AuditID) {
			if !seen[location.Entry.ManifestPath] {
				seen[location.Entry.ManifestPath] = true
				entries = append(entries, location.Entry)
			}
		}
	case options.ConversationID != "":
		entries = index.Conversation(options.ConversationID)
	default:
		entries = index.Bundles()
	}
	if filtered && len(entries) == 0 {
		return 0, reader.missing()
	}
	sort.SliceStable(entries, func(left, right int) bool { return entries[left].ManifestPath < entries[right].ManifestPath })
	printed, skippedAny := 0, false
	for _, entry := range entries {
		opened, err := reader.Bundle(ctx, entry)
		if err != nil {
			if bundle.ReasonOf(err) == bundle.ReasonCanceled {
				return printed, err
			}
			skippedAny = true
			skipped(entry.ManifestPath, err)
			continue
		}
		if entry.Manifest.BundleKind == archive.BundleGaps {
			if filtered {
				continue
			}
			err := opened.Gaps(ctx, func(gap archive.Gap) error {
				printed++
				return writeLine(destination, archive.EncodeGap(gap))
			})
			if err != nil {
				return printed, err
			}
			continue
		}
		// Everything in the objects file belongs to a printed line only when
		// every line is printed.
		selection := newSelection(!filtered && options.AllRevisions)
		err = opened.Records(ctx, func(line bundle.Line) error {
			record := line.Record
			switch {
			case options.AuditID != "" && record.Audit.AuditID != options.AuditID:
				return nil
			case options.ConversationID != "" && (record.Turn == nil || record.Turn.Row.ConversationID != options.ConversationID):
				return nil
			case !options.AllRevisions && !reader.isHighest(entry, line.Index, record.Audit.AuditID):
				return nil
			}
			encoded, _, _, err := archive.EncodeLine(record)
			if err != nil {
				return err
			}
			printed++
			if options.WithObjects {
				selection.add(record)
			}
			return writeLine(destination, encoded)
		})
		if err != nil {
			return printed, err
		}
		if options.WithObjects && (selection.all || len(selection.audits) > 0) {
			err := opened.Objects(ctx, func(object archive.ObjectEntry) error {
				if encoded := selection.encode(object); encoded != nil {
					return writeLine(destination, encoded)
				}
				return nil
			})
			if err != nil {
				return printed, err
			}
		}
	}
	if filtered && printed == 0 && !skippedAny {
		return 0, reader.missing()
	}
	return printed, nil
}

// selection is the set of objects file entries the printed lines refer to,
// kept as hashes and audit ids only.
type selection struct {
	all      bool
	contents map[string]bool
	binaries map[string]bool
	audits   map[string]bool
}

func newSelection(all bool) *selection {
	return &selection{all: all, contents: map[string]bool{}, binaries: map[string]bool{}, audits: map[string]bool{}}
}

func (s *selection) add(record *archive.Record) {
	s.audits[record.Audit.AuditID] = true
	if turn := record.Turn; turn != nil {
		for _, object := range turn.Objects {
			s.contents[string(object.Hash)] = true
		}
		for _, binary := range turn.Binaries {
			s.binaries[string(binary.Hash)] = true
		}
	}
}

// encode returns the entry's line when it is selected, else nil. A content
// or binary object shared by several printed lines is printed once, as the
// objects file holds it once.
func (s *selection) encode(entry archive.ObjectEntry) []byte {
	switch {
	case entry.Content != nil && (s.all || s.contents[string(entry.Content.Hash)]):
		return archive.EncodeContentObject(*entry.Content)
	case entry.Binary != nil && (s.all || s.binaries[string(entry.Binary.Hash)]):
		return archive.EncodeBinaryObject(*entry.Binary)
	case entry.RawChunk != nil && (s.all || s.audits[entry.RawChunk.AuditID]):
		return archive.EncodeRawChunk(*entry.RawChunk)
	case entry.ParsedJSONPart != nil && (s.all || s.audits[entry.ParsedJSONPart.AuditID]):
		return archive.EncodeParsedJSONPart(*entry.ParsedJSONPart)
	}
	return nil
}

func runCat(ctx context.Context, env *Env, args []string) error {
	var c common
	var options CatOptions
	flags := flagSet("cat")
	c.readFlags(flags)
	flags.StringVar(&options.ConversationID, "conversation", "", "")
	flags.StringVar(&options.AuditID, "audit", "", "")
	flags.BoolVar(&options.AllRevisions, "all-revisions", false, "")
	flags.BoolVar(&options.WithObjects, "with-objects", false, "")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	if options.ConversationID != "" && options.AuditID != "" {
		return usageError("give --conversation or --audit, not both")
	}
	reader, err := c.openReader(ctx, env)
	if err != nil {
		return err
	}
	defer reader.Close()
	out := newOutput(env.Stdout)
	skippedAny := false
	_, err = Cat(ctx, reader, options, out, func(path string, err error) {
		skippedAny = true
		code, _ := describe(err)
		fmt.Fprintf(env.Stderr, "audit-archive: skipped %s: %s\n", printable(c.relative(path)), code)
	})
	if flushErr := out.flush(); err == nil {
		err = flushErr
	}
	if err != nil {
		return err
	}
	// A manifest the index left out may hold lines of the selected scope:
	// what was printed is good, but it may not be everything.
	if err := reader.Incomplete(); err != nil {
		return err
	}
	if skippedAny {
		return &exitStatus{code: ExitFailed}
	}
	return nil
}

// ---- export ---------------------------------------------------------------

func runExport(ctx context.Context, env *Env, args []string) error {
	var c common
	var auditID, conversationID, what string
	flags := flagSet("export")
	c.readFlags(flags)
	flags.StringVar(&auditID, "audit", "", "")
	flags.StringVar(&conversationID, "conversation", "", "")
	flags.StringVar(&what, "what", KindConversation, "")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	switch {
	case (auditID == "") == (conversationID == ""):
		return usageError("give --audit <id> or --conversation <id>")
	case !knownKind(what):
		return usageError("--what must be one of %s", strings.Join(ExportKinds, ", "))
	case conversationID != "" && what != KindConversation:
		return usageError("--conversation exports the conversation form only")
	}
	reader, err := c.openReader(ctx, env)
	if err != nil {
		return err
	}
	defer reader.Close()
	out := newOutput(env.Stdout)
	if conversationID != "" {
		err = ExportConversationTurns(ctx, reader, conversationID, out)
	} else {
		var audit *AuditRecord
		audit, err = reader.Audit(ctx, auditID)
		if err == nil && strings.HasPrefix(what, "raw-") {
			side := query.Side(strings.TrimPrefix(what, "raw-"))
			if metadata, metaErr := audit.RawMeta(side); metaErr == nil {
				fmt.Fprintf(env.Stderr, "audit-archive: raw %s: observed_length=%d stored_length=%d complete=%t missing_chunks=%t sha256=%s\n",
					side, metadata.ObservedLength, metadata.StoredLength, metadata.Complete, metadata.MissingChunks, orDash(metadata.SHA256))
			}
		}
		if err == nil {
			err = ExportAudit(ctx, audit, what, out)
		}
	}
	if flushErr := out.flush(); err == nil {
		err = flushErr
	}
	if err == nil {
		// A left-out manifest may hold a higher revision of the audit or
		// more turns of the conversation.
		err = reader.Incomplete()
	}
	return err
}

func orDash(text string) string {
	if text == "" {
		return "-"
	}
	return text
}

// writeLine writes data and a newline.
func writeLine(destination io.Writer, data []byte) error {
	if _, err := destination.Write(append(data, '\n')); err != nil {
		var coded *cliError
		if errors.As(err, &coded) {
			return err
		}
		return &cliError{code: codeWriteFailed, message: messages[codeWriteFailed]}
	}
	return nil
}
