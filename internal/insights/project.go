package insights

import (
	"context"
	"errors"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// ProjectIdentityVersion is bumped whenever the extracted identity would
// change for the same evidence. It is independent of AnalysisVersion, so a
// change here never re-runs the slow analysis backfill.
const ProjectIdentityVersion = 1

// Project identity fingerprint domains.
const (
	DomainProjectIdentity = "orgreport/identity"
	DomainProjectRemote   = "orgreport/remote"
	DomainProjectRoot     = "orgreport/root"
	DomainProjectCwd      = "orgreport/cwd"
)

const (
	// projectScanMessages is how many leading and trailing messages are
	// scanned for environment blocks (doc section 5.1).
	projectScanMessages = 8
	// maxProjectTextBytes bounds one scanned text block.
	maxProjectTextBytes = 1 << 20
	maxDeclaredBytes    = 256
)

type compiledProjectPattern struct {
	kind    string
	pattern *regexp.Regexp
}

type compiledProjectSignals struct {
	headers  []ProjectHeader
	paths    []ProjectBodyPath
	patterns []compiledProjectPattern
}

// ProjectExtractor reads the project identity a request reveals. It is data
// driven by the vocabulary and never looks at other audits; inheritance
// across a session happens at report time.
type ProjectExtractor struct {
	vocab   *Vocabulary
	shared  compiledProjectSignals
	clients map[string]compiledProjectSignals
}

// NewProjectExtractor compiles the vocabulary's project signals. A nil vocab
// means the built-in one.
func NewProjectExtractor(vocab *Vocabulary) (*ProjectExtractor, error) {
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	compile := func(headers []ProjectHeader, paths []ProjectBodyPath, patterns []ProjectTextPattern) (compiledProjectSignals, error) {
		signals := compiledProjectSignals{headers: headers, paths: paths}
		for _, pattern := range patterns {
			compiled, err := compileProjectPattern(pattern.Pattern)
			if err != nil {
				return compiledProjectSignals{}, err
			}
			signals.patterns = append(signals.patterns, compiledProjectPattern{kind: pattern.Kind, pattern: compiled})
		}
		return signals, nil
	}
	shared, err := compile(vocab.Project.Headers, vocab.Project.BodyPaths, vocab.Project.TextPatterns)
	if err != nil {
		return nil, err
	}
	extractor := &ProjectExtractor{vocab: vocab, shared: shared, clients: map[string]compiledProjectSignals{}}
	for name, rule := range vocab.Clients {
		signals, err := compile(rule.ProjectHeaders, rule.ProjectBodyPaths, rule.ProjectTextPatterns)
		if err != nil {
			return nil, err
		}
		extractor.clients[name] = signals
	}
	return extractor, nil
}

// Extract returns the identity of one request. The client's own signals are
// tried before the shared ones; body paths before headers (Codex sends the
// canonical copy in the body and a projection in the header); text last,
// filling only what is still missing.
func (extractor *ProjectExtractor) Extract(input Input) orgreport.Identity {
	identity := orgreport.Identity{}
	client := detectClient(input.Headers, extractor.vocab)
	signals := []compiledProjectSignals{extractor.clients[client], extractor.shared}

	var root map[string]any
	if len(input.Request) != 0 {
		if value, err := decodeJSON(input.Request); err == nil {
			root = asMap(value)
		}
	}
	turnMetadata := false
	for _, set := range signals {
		for _, spec := range set.paths {
			if spec.Kind == ProjectKindCodexTurnMetadata && turnMetadata {
				continue
			}
			value := bodyValue(root, spec.Path)
			if value == nil {
				continue
			}
			if applyProjectValue(&identity, spec.Kind, value) && spec.Kind == ProjectKindCodexTurnMetadata {
				turnMetadata = true
			}
		}
	}
	for _, set := range signals {
		for _, spec := range set.headers {
			if spec.Kind == ProjectKindCodexTurnMetadata && turnMetadata {
				continue
			}
			for _, value := range input.Headers.Values(spec.Header) {
				if applyProjectValue(&identity, spec.Kind, value) && spec.Kind == ProjectKindCodexTurnMetadata {
					turnMetadata = true
				}
			}
		}
	}

	var patterns []compiledProjectPattern
	for _, set := range signals {
		patterns = append(patterns, set.patterns...)
	}
	if len(patterns) != 0 && root != nil {
		texts := extractor.scanTexts(input)
		textIdentity := orgreport.Identity{}
		for _, text := range texts {
			for _, pattern := range patterns {
				matches := pattern.pattern.FindAllStringSubmatch(text, -1)
				if len(matches) == 0 {
					continue
				}
				// The last occurrence wins: an environment update follows the
				// original environment block.
				if value := firstGroup(matches[len(matches)-1]); value != "" {
					applyTextValue(&textIdentity, pattern.kind, value)
				}
			}
		}
		if identity.Declared == "" {
			identity.Declared = textIdentity.Declared
		}
		for _, remote := range textIdentity.Remotes {
			identity.AddRemote(remote)
		}
		for _, root := range textIdentity.Roots {
			identity.AddRoot(root)
		}
		if identity.Cwd == "" {
			identity.Cwd = textIdentity.Cwd
		}
	}
	identity.Finish()
	return identity
}

// scanTexts returns the system, developer and user texts of the first and
// last projectScanMessages messages, in prompt order. Tool results, tool
// calls and assistant text are never scanned: a file listing in a tool output
// must not become the session's working directory.
func (extractor *ProjectExtractor) scanTexts(input Input) []string {
	request, err := parseRequest(input, extractor.vocab)
	if err != nil {
		return nil
	}
	lastMessage := 0
	for _, item := range request.items {
		lastMessage = max(lastMessage, item.msg)
	}
	texts := make([]string, 0, 8)
	for _, item := range request.items {
		if item.text == "" {
			continue
		}
		switch item.Category {
		case CategorySystem, CategoryUser, CategoryInjected:
		default:
			continue
		}
		if item.msg > projectScanMessages && item.msg <= lastMessage-projectScanMessages {
			continue
		}
		text := item.text
		if len(text) > maxProjectTextBytes {
			text = text[:maxProjectTextBytes]
		}
		texts = append(texts, text)
	}
	return texts
}

func firstGroup(match []string) string {
	for _, group := range match[1:] {
		if trimmed := strings.TrimSpace(group); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func applyTextValue(identity *orgreport.Identity, kind, value string) {
	switch kind {
	case ProjectKindDeclared:
		if len(value) <= maxDeclaredBytes {
			identity.Declared = value
		}
	case ProjectKindRemote:
		identity.AddRemote(value)
	case ProjectKindRoot:
		identity.Roots = nil
		identity.AddRoot(value)
	case ProjectKindRootFile:
		identity.Roots = nil
		identity.AddRoot(fileDirectory(value))
	case ProjectKindCwd:
		identity.Cwd = orgreport.NormalizePath(value)
	}
}

// applyProjectValue applies a header or body value. It reports whether the
// value carried something usable.
func applyProjectValue(identity *orgreport.Identity, kind string, value any) bool {
	switch kind {
	case ProjectKindCodexTurnMetadata:
		return applyTurnMetadata(identity, value)
	}
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	switch kind {
	case ProjectKindDeclared:
		if len(text) > maxDeclaredBytes || identity.Declared != "" {
			return false
		}
		identity.Declared = text
	case ProjectKindOpenCodeProject:
		lower := strings.ToLower(text)
		if !isHex(lower) || len(lower) != 40 || identity.ProjectHash != "" {
			return false
		}
		identity.ProjectHash = lower
	case ProjectKindRemote:
		before := len(identity.Remotes)
		identity.AddRemote(text)
		return len(identity.Remotes) > before
	case ProjectKindRoot, ProjectKindRootFile:
		if kind == ProjectKindRootFile {
			text = fileDirectory(text)
		}
		before := len(identity.Roots)
		identity.AddRoot(text)
		return len(identity.Roots) > before
	case ProjectKindCwd:
		if identity.Cwd != "" {
			return false
		}
		identity.Cwd = orgreport.NormalizePath(text)
		return identity.Cwd != ""
	default:
		return false
	}
	return true
}

// applyTurnMetadata reads Codex x-codex-turn-metadata: a JSON object, or the
// JSON string that client_metadata and the header carry, whose workspaces map
// repository roots to their fetch remotes.
func applyTurnMetadata(identity *orgreport.Identity, value any) bool {
	if text, ok := value.(string); ok {
		decoded, err := decodeJSON([]byte(text))
		if err != nil {
			return false
		}
		value = decoded
	}
	workspaces := asMap(asMap(value)["workspaces"])
	if len(workspaces) == 0 {
		return false
	}
	roots := make([]string, 0, len(workspaces))
	for root := range workspaces {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	found := false
	for _, root := range roots {
		before := len(identity.Roots)
		identity.AddRoot(root)
		found = found || len(identity.Roots) > before
		remotes := asMap(asMap(workspaces[root])["associated_remote_urls"])
		names := make([]string, 0, len(remotes))
		for name := range remotes {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool {
			if (names[i] == "origin") != (names[j] == "origin") {
				return names[i] == "origin"
			}
			return names[i] < names[j]
		})
		for _, name := range names {
			if remote := asString(remotes[name]); remote != "" {
				identity.AddRemote(remote)
				found = true
			}
		}
	}
	return found
}

func fileDirectory(file string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(file), "\\", "/")
	directory := path.Dir(normalized)
	if directory == "." {
		return ""
	}
	return directory
}

func bodyValue(root map[string]any, dotted string) any {
	if root == nil || dotted == "" {
		return nil
	}
	current := any(root)
	for _, key := range strings.Split(dotted, ".") {
		object := asMap(current)
		if object == nil {
			return nil
		}
		current = object[key]
	}
	return current
}

func isHex(text string) bool {
	for _, char := range text {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return text != ""
}

// ProjectStore persists identity rows.
type ProjectStore interface {
	SaveProjectIdentity(ctx context.Context, row storage.ProjectIdentityRow) error
}

// ProjectRunner extracts, fingerprints, encrypts and stores the project
// identity of one parsed audit. It implements the parser worker's analyzer
// hook, separately from Runner, so enabling reports never changes
// audit_analysis.
type ProjectRunner struct {
	store     ProjectStore
	cipher    security.Cipher
	fp        Fingerprinter
	extractor *ProjectExtractor
	now       func() time.Time
}

// NewProjectRunner validates its collaborators.
func NewProjectRunner(store ProjectStore, cipher security.Cipher, vocab *Vocabulary, fp Fingerprinter) (*ProjectRunner, error) {
	if store == nil || cipher == nil || fp == nil {
		return nil, errors.New("insights: project runner needs a store, cipher and fingerprinter")
	}
	if len(fp.Fingerprint(DomainProjectIdentity, nil)) != storage.ProjectFingerprintSize {
		return nil, errors.New("insights: fingerprinter must produce 32-byte tags")
	}
	extractor, err := NewProjectExtractor(vocab)
	if err != nil {
		return nil, err
	}
	return &ProjectRunner{store: store, cipher: cipher, fp: fp, extractor: extractor, now: time.Now}, nil
}

// AnalyzeAudit stores the identity of one audit. bodyScanned is true for the
// live path, where the request body is always present.
func (runner *ProjectRunner) AnalyzeAudit(ctx context.Context, input Input) error {
	return runner.Save(ctx, input, len(input.Request) != 0)
}

// Strong reports whether the headers alone carry a remote, a project hash or
// a declared project, so a backfill need not read the body.
func (runner *ProjectRunner) Strong(input Input) bool {
	headerOnly := input
	headerOnly.Request = nil
	switch runner.extractor.Extract(headerOnly).Source {
	case orgreport.SourceDeclared, orgreport.SourceCodexTurnMetadata, orgreport.SourceAgentHeader:
		return true
	}
	return false
}

// Save extracts and stores one row; bodyScanned tells whether input carries
// the request body.
func (runner *ProjectRunner) Save(ctx context.Context, input Input, bodyScanned bool) error {
	row, err := runner.Row(input, bodyScanned)
	if err != nil {
		return &RunError{Code: ErrorCodeProjectFailed, Err: err}
	}
	if err := runner.store.SaveProjectIdentity(ctx, row); err != nil {
		return &RunError{Code: ErrorCodeProjectSaveFailed, Err: err}
	}
	return nil
}

// Stable error codes of the project runner.
const (
	ErrorCodeProjectFailed     = "project_identity_failed"
	ErrorCodeProjectSaveFailed = "project_identity_save_failed"
)

// Row builds the stored row without saving it.
func (runner *ProjectRunner) Row(input Input, bodyScanned bool) (storage.ProjectIdentityRow, error) {
	if input.AuditID == "" {
		return storage.ProjectIdentityRow{}, errors.New("insights: project identity without audit id")
	}
	identity := runner.extractor.Extract(input)
	row := storage.ProjectIdentityRow{
		AuditID: input.AuditID, Version: ProjectIdentityVersion, ExtractedAtNS: runner.now().UnixNano(),
		Source: identity.Source, BodyScanned: bodyScanned,
	}
	if identity.Empty() {
		return row, nil
	}
	canonical := identity.Canonical()
	defer clear(canonical)
	row.IdentityFPR = runner.fp.Fingerprint(DomainProjectIdentity, canonical)
	if len(identity.Remotes) != 0 {
		row.RemoteFPR = runner.fp.Fingerprint(DomainProjectRemote, []byte(identity.Remotes[0]))
	}
	if len(identity.Roots) != 0 {
		row.RootFPR = runner.fp.Fingerprint(DomainProjectRoot, []byte(identity.Roots[0]))
	}
	if identity.Cwd != "" {
		row.CwdFPR = runner.fp.Fingerprint(DomainProjectCwd, []byte(identity.Cwd))
	}
	aad, err := ProjectIdentityAAD(input.AuditID, row.Version)
	if err != nil {
		return storage.ProjectIdentityRow{}, err
	}
	sealed, err := runner.cipher.Encrypt(aad, canonical)
	if err != nil {
		return storage.ProjectIdentityRow{}, err
	}
	row.IdentityEnc = sealed
	return row, nil
}

// ProjectIdentityAAD binds identity_enc to its audit and row version.
func ProjectIdentityAAD(auditID string, version int) ([]byte, error) {
	return orgreport.IdentityAAD(auditID, version)
}
