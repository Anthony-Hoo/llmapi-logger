// Package handover holds what the capture session hands to the parser worker
// when an audit has been committed on the unified write path (issue #59
// stage 3, design G): the committed audit's identity and outcome, and the
// plaintext evidence the session still held, so the parse does not read the
// raw back from the database. It has only data types, so internal/audit can
// build a job without depending on the parser.
package handover

import (
	"sync"

	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/storage"
)

// Job is one committed audit for the parser worker. A job without Evidence is
// an id-only job: the worker reads the audit from the database, as it does
// for an audit it was notified of.
type Job struct {
	// Audit is the committed audit's identity (AuditID, Protocol, ParserName,
	// Path) and outcome. An id-only job needs only AuditID.
	Audit storage.ParserAudit
	// Evidence is the plaintext of the committed evidence, nil for an
	// id-only job.
	Evidence *Evidence
	// Release gives the evidence's plaintext share of the capture memory
	// budget back and clears the plaintext. The worker calls it exactly once,
	// whatever happens to the job: refused, parsed, or dropped when the worker
	// stops. Nil means nothing to release.
	Release func()
}

// Evidence is what the parser's Input is built from, as the database would
// give it for the same committed audit.
type Evidence struct {
	// CaptureVersion selects where the content and allowlisted Headers come
	// from: the sealed rows of version 1, the Header fields of version 2.
	CaptureVersion int
	// Request is request_received, Response is response_received.
	Request  Stage
	Response Stage
}

// Stage is one parser-relevant stage of a committed audit.
type Stage struct {
	// Present means the stage has a row.
	Present bool
	// StatusCode is the stage row's status code.
	StatusCode *int
	// HeaderRows are the stage's sealed Header rows (kind header), version 1.
	HeaderRows []storage.HTTPHeader
	// Headers are the stage's Header fields in snapshot order, version 2.
	// The job owns them; Release clears them.
	Headers []headerblock.Field
	// Body is the committed body row, nil when the stage has no body.
	Body *storage.BodyStream
	// Chunks are the plaintext of the body's stored chunks in seq order. The
	// job owns them; Release clears them.
	Chunks []Chunk
}

// Chunk is the plaintext of one stored chunk.
type Chunk struct {
	Seq    int64
	Offset int64
	Data   []byte
}

// Bytes returns the body plaintext the evidence holds.
func (evidence *Evidence) Bytes() int64 {
	if evidence == nil {
		return 0
	}
	var total int64
	for _, stage := range [2]*Stage{&evidence.Request, &evidence.Response} {
		for _, chunk := range stage.Chunks {
			total += int64(len(chunk.Data))
		}
	}
	return total
}

// Clear zeroes the plaintext the evidence holds.
func (evidence *Evidence) Clear() {
	if evidence == nil {
		return
	}
	for _, stage := range [2]*Stage{&evidence.Request, &evidence.Response} {
		for _, chunk := range stage.Chunks {
			clear(chunk.Data)
		}
		for _, field := range stage.Headers {
			for _, value := range field.Values {
				clear(value)
			}
		}
	}
}

// Once wraps release so that calling the result more than once releases
// once.
func Once(release func()) func() {
	if release == nil {
		return nil
	}
	var once sync.Once
	return func() { once.Do(release) }
}
