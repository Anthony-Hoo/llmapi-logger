package archivecli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/termio"
)

// KnownKey holds the three candidate fingerprints of a known API key (D.4).
type KnownKey struct {
	Raw    [32]byte
	Bearer [32]byte
	// APIKeyFPR is the normalised key's audit_records.api_key_fpr, nil when
	// the key normalises to nothing.
	APIKeyFPR []byte
}

// Fingerprints computes the candidates of a known key. The key is not kept.
func Fingerprints(keys *Keys, key []byte) KnownKey {
	raw, bearer := archive.KnownKeyFingerprints(keys.Archive, key)
	return KnownKey{Raw: raw, Bearer: bearer, APIKeyFPR: keys.Credential.Fingerprint(string(key))}
}

// Match is one place an archived record holds a known key.
type Match struct {
	AuditID  string
	Revision int64
	// Where is "header <stage> <kind> <name>", "user_agent",
	// "request_uri <name>" or "api_key_fpr".
	Where string
	// Form is the candidate that matched: raw, bearer or api_key_fpr.
	Form string
}

// MatchRecord lists the places of record that hold the known key: projected
// header and User-Agent values and credential query segments whose value_fpr
// is one of the two value candidates, and api_key_fpr.
func MatchRecord(record *archive.Record, known KnownKey) []Match {
	var matches []Match
	form := func(fingerprint [32]byte) string {
		switch {
		case hmac.Equal(fingerprint[:], known.Raw[:]):
			return "raw"
		case hmac.Equal(fingerprint[:], known.Bearer[:]):
			return "bearer"
		}
		return ""
	}
	add := func(where, form string) {
		matches = append(matches, Match{AuditID: record.Audit.AuditID, Revision: record.Revision, Where: where, Form: form})
	}
	for _, header := range record.Headers.Values {
		if header.Value.Omitted {
			if name := form(header.Value.Fingerprint); name != "" {
				add(fmt.Sprintf("header %s %s %s", header.Stage, header.Kind, printable(header.Name)), name)
			}
		}
	}
	for _, value := range record.Audit.UserAgent {
		if value.Omitted {
			if name := form(value.Fingerprint); name != "" {
				add("user_agent", name)
			}
		}
	}
	for _, segment := range record.Audit.RequestURI.Segments {
		if segment.Credential {
			if name := form(segment.Fingerprint); name != "" {
				add("request_uri "+printable(segment.RawName), name)
			}
		}
	}
	if known.APIKeyFPR != nil && hmac.Equal(record.Audit.APIKeyFPR, known.APIKeyFPR) {
		add("api_key_fpr", "api_key_fpr")
	}
	return matches
}

// readKnownKey reads the known key: the first line of path, or of standard
// input, typed without echo when it is a terminal.
func readKnownKey(env *Env, path string) ([]byte, error) {
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return nil, &cliError{code: codeKeyFile, message: "the known key file cannot be read"}
		}
		defer file.Close()
		return firstLine(file)
	}
	if env.Terminal != nil && env.Terminal.IsInteractive() {
		fmt.Fprint(env.Stderr, "Known API key (input hidden): ")
		line, err := env.Terminal.ReadLineNoEcho()
		fmt.Fprintln(env.Stderr)
		if errors.Is(err, termio.ErrInterrupted) {
			return nil, &cliError{code: codeCanceled, message: messages[codeCanceled]}
		}
		if err != nil {
			return nil, &cliError{code: codeUsage, message: "could not read the key from the terminal"}
		}
		return line, nil
	}
	if env.Stdin == nil {
		return nil, usageError("no known key: give --known-key-file or pass it on standard input")
	}
	return firstLine(env.Stdin)
}

// firstLine reads up to the first newline (bounded), without the line
// ending.
func firstLine(source io.Reader) ([]byte, error) {
	reader := bufio.NewReaderSize(io.LimitReader(source, termio.MaxLine+2), termio.MaxLine+2)
	line, err := reader.ReadSlice('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		termio.Wipe(line)
		return nil, usageError("the known key is not one line of at most %d bytes", termio.MaxLine)
	}
	key := bytes.Clone(bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r")))
	termio.Wipe(line)
	if len(key) > termio.MaxLine {
		termio.Wipe(key)
		return nil, usageError("the known key is not one line of at most %d bytes", termio.MaxLine)
	}
	return key, nil
}

func runFpr(ctx context.Context, env *Env, args []string) error {
	var c common
	var knownPath, conversationID, auditID string
	flags := flagSet("fpr")
	c.archiveFlags(flags)
	flags.BoolVar(&c.skipEventMAC, "skip-event-mac", false, "")
	flags.StringVar(&knownPath, "known-key-file", "", "")
	flags.StringVar(&conversationID, "conversation", "", "")
	flags.StringVar(&auditID, "audit", "", "")
	if err := parseFlags(flags, args); err != nil {
		return err
	}
	switch {
	case c.keyPath == "":
		return usageError("--key <master key file> is required: the fingerprints are keyed")
	case (conversationID != "" || auditID != "") && c.dir == "":
		return usageError("--conversation and --audit narrow the search of --dir")
	case conversationID != "" && auditID != "":
		return usageError("give --conversation or --audit, not both")
	}
	keys, err := c.keys()
	if err != nil {
		return err
	}
	key, err := readKnownKey(env, knownPath)
	if err != nil {
		return err
	}
	if len(key) == 0 {
		return usageError("the known key is empty")
	}
	known := Fingerprints(keys, key)
	termio.Wipe(key)
	out := newOutput(env.Stdout)
	out.printf("raw          %s\n", hex.EncodeToString(known.Raw[:]))
	out.printf("bearer       %s\n", hex.EncodeToString(known.Bearer[:]))
	if known.APIKeyFPR != nil {
		out.printf("api_key_fpr  %s\n", hex.EncodeToString(known.APIKeyFPR))
	} else {
		out.printf("api_key_fpr  -\n")
	}
	if c.dir == "" {
		return out.flush()
	}
	reader, err := OpenReader(ctx, c.dir, ReaderOptions{Keys: keys, SkipEventMAC: c.skipEventMAC})
	if err != nil {
		_ = out.flush()
		return err
	}
	defer reader.Close()
	for _, problem := range reader.Index().Problems() {
		fmt.Fprintf(env.Stderr, "audit-archive: skipped %s: %s\n", printable(c.relative(problem.Path)), problem.Reason)
	}
	entries := reader.Index().Bundles()
	switch {
	case conversationID != "":
		entries = reader.Index().Conversation(conversationID)
	case auditID != "":
		entries = nil
		seen := map[string]bool{}
		for _, location := range reader.Index().AuditRevisions(auditID) {
			if !seen[location.Entry.ManifestPath] {
				seen[location.Entry.ManifestPath] = true
				entries = append(entries, location.Entry)
			}
		}
	}
	if len(entries) == 0 {
		_ = out.flush()
		return reader.missing()
	}
	found, audits, skipped := 0, map[string]bool{}, false
	for _, entry := range entries {
		if entry.Manifest.BundleKind == archive.BundleGaps {
			continue
		}
		opened, err := reader.Bundle(ctx, entry)
		if err != nil {
			if bundle.ReasonOf(err) == bundle.ReasonCanceled {
				return err
			}
			skipped = true
			code, _ := describe(err)
			fmt.Fprintf(env.Stderr, "audit-archive: skipped %s: %s\n", printable(c.relative(entry.ManifestPath)), code)
			continue
		}
		err = opened.Records(ctx, func(line bundle.Line) error {
			record := line.Record
			if auditID != "" && record.Audit.AuditID != auditID ||
				conversationID != "" && (record.Turn == nil || record.Turn.Row.ConversationID != conversationID) {
				return nil
			}
			for _, match := range MatchRecord(record, known) {
				found++
				audits[match.AuditID] = true
				out.printf("match %s revision %d %s %s\n", printable(match.AuditID), match.Revision, match.Where, match.Form)
			}
			return nil
		})
		if err != nil {
			_ = out.flush()
			return err
		}
	}
	out.printf("fpr: %d matches in %d audits\n", found, len(audits))
	if err := out.flush(); err != nil {
		return err
	}
	if err := reader.Incomplete(); err != nil {
		return err
	}
	switch {
	case skipped:
		return &exitStatus{code: ExitFailed}
	case found == 0:
		return &exitStatus{code: ExitNotFound}
	}
	return nil
}
