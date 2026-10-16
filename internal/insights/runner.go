package insights

import (
	"context"
	"errors"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// Stable error codes for analysis failures. They are logged by the parser
// worker; analysis never changes the parse status, and the backfill job picks
// up audits whose analysis row is missing.
const (
	ErrorCodeAnalysisFailed     = "analysis_failed"
	ErrorCodeAnalysisSaveFailed = "analysis_save_failed"
)

// RunError carries a stable error code next to the underlying error. Only the
// code and a storage error class may be logged.
type RunError struct {
	Code string
	Err  error
}

func (err *RunError) Error() string {
	if err.Err == nil {
		return "insights: " + err.Code
	}
	return "insights: " + err.Code + ": " + err.Err.Error()
}

func (err *RunError) Unwrap() error { return err.Err }

// ErrorCode returns the stable code of an AnalyzeAudit error.
func ErrorCode(err error) string {
	var runErr *RunError
	if errors.As(err, &runErr) && runErr.Code != "" {
		return runErr.Code
	}
	return ErrorCodeAnalysisFailed
}

// RunnerStore is the persistence surface of Runner, implemented by
// *sqlite.Store.
type RunnerStore interface {
	LinkStore
	LoadAnalysisAuditMeta(ctx context.Context, auditID string) (sqlite.AnalysisAuditMeta, error)
	SaveAnalysis(ctx context.Context, row sqlite.AnalysisRow) error
}

// Runner analyses, links and stores one parsed audit. It is called by the
// parser worker after the parse result is saved and owns everything from the
// decoded bodies to the audit_analysis row.
type Runner struct {
	store  RunnerStore
	vocab  *Vocabulary
	fp     Fingerprinter
	linker *Linker
	now    func() time.Time
}

// NewRunner validates its collaborators. A nil vocab means the built-in one.
func NewRunner(store RunnerStore, cipher security.Cipher, vocab *Vocabulary, fp Fingerprinter) (*Runner, error) {
	if store == nil || cipher == nil || fp == nil {
		return nil, errors.New("insights: runner needs a store, cipher and fingerprinter")
	}
	// A typed nil fingerprinter inside the interface returns nil tags, which
	// would silently store rows without any fingerprint.
	if len(fp.Fingerprint(DomainItem, nil)) != sqlite.AnalysisFingerprintSize {
		return nil, errors.New("insights: fingerprinter must produce 32-byte tags")
	}
	if vocab == nil {
		vocab = defaultVocabulary()
	}
	linker, err := NewLinker(store, fp, CipherDetailCodec{Cipher: cipher}, vocab)
	if err != nil {
		return nil, err
	}
	return &Runner{store: store, vocab: vocab, fp: fp, linker: linker, now: time.Now}, nil
}

// AnalyzeAudit fills the audit timing of input from storage, derives the
// analysis, links it and saves the row. Errors are *RunError values.
func (runner *Runner) AnalyzeAudit(ctx context.Context, input Input) error {
	if runner == nil {
		return &RunError{Code: ErrorCodeAnalysisFailed, Err: errors.New("nil runner")}
	}
	meta, err := runner.store.LoadAnalysisAuditMeta(ctx, input.AuditID)
	if err != nil {
		return &RunError{Code: ErrorCodeAnalysisFailed, Err: err}
	}
	input.StartedAtNS = meta.StartedAtNS
	if meta.EndedAtNS != nil {
		input.EndedAtNS = *meta.EndedAtNS
	}
	input.FirstEventNS = relativeNS(meta.FirstEventAtNS, meta.StartedAtNS)
	input.LastEventNS = relativeNS(meta.LastEventAtNS, meta.StartedAtNS)

	analysis, err := Analyze(input, runner.vocab, runner.fp)
	if err != nil {
		return &RunError{Code: ErrorCodeAnalysisFailed, Err: err}
	}
	identity := IdentifyAgent(input, runner.vocab)
	analysis.Agent = identity
	row, err := runner.linker.Link(ctx, LinkInput{
		Meta:         meta,
		Protocol:     input.Protocol,
		Analysis:     analysis,
		Identity:     identity,
		SpawnPrompts: SpawnPrompts(input, runner.vocab),
		OpeningHints: OpeningUserHints(input, runner.vocab),
		AnalyzedAtNS: runner.now().UnixNano(),
	})
	if err != nil {
		return &RunError{Code: ErrorCodeAnalysisFailed, Err: err}
	}
	if err := runner.store.SaveAnalysis(ctx, row); err != nil {
		return &RunError{Code: ErrorCodeAnalysisSaveFailed, Err: err}
	}
	return nil
}

func relativeNS(absolute *int64, startedAtNS int64) *int64 {
	if absolute == nil || *absolute < startedAtNS {
		return nil
	}
	relative := *absolute - startedAtNS
	return &relative
}
