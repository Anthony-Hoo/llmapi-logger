package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/conversation"
	"llmapi-logger/internal/query"
)

// Sampler compares one archived member with what the hot store serves for
// the same audit (J.3). Equal false is a difference; an error means the
// comparison could not be made.
type Sampler interface {
	Compare(ctx context.Context, audit *archivecli.AuditRecord) (bool, error)
}

// HotReader is the part of query.Service the sample reads the hot side
// through.
type HotReader interface {
	Get(ctx context.Context, auditID string, scope *query.Scope) (query.Detail, error)
	ReconstructTurn(ctx context.Context, auditID string) (query.ReconstructedTurn, error)
	SessionConversation(ctx context.Context, auditID string) (*conversation.Conversation, error)
	Timeline(ctx context.Context, auditID string, side query.Side) (query.StreamTimeline, error)
	RawMeta(ctx context.Context, auditID string, side query.Side) (query.RawMetadata, error)
	StreamRaw(ctx context.Context, auditID string, side query.Side, destination io.Writer) error
}

// QuerySampler is the sample of J.3 over the query service: the hot side's
// detail goes through the credential projection (archive.ProjectDetail),
// and both sides are rendered with the reader tool's export renderers
// (internal/archivecli) and compared byte for byte: detail (which holds the
// headers, request URI and conversation), the reconstructed turn with the
// provider request and response, the session conversation, both timelines,
// both raw bodies (SHA-256 of the streamed bytes) and their metadata. Where
// a side has no such export, the error classes are compared instead.
type QuerySampler struct {
	Hot           HotReader
	Fingerprinter archive.CredentialFingerprinter
}

var errorClasses = []error{query.ErrNotFound, query.ErrNotRetained, query.ErrNotReady, query.ErrNoTurnGraph, query.ErrIntegrity}

// errorClass is the class J.3 compares, "" for no error and "other" for an
// error of no class.
func errorClass(err error) string {
	if err == nil {
		return ""
	}
	for _, class := range errorClasses {
		if errors.Is(err, class) {
			return class.Error()
		}
	}
	return "other"
}

// errHotUnavailable is a hot-side read that failed for no class reason,
// such as a database error: no comparison was possible.
var errHotUnavailable = errors.New("archive runner: the hot side could not be read")

// pair compares the classes of the two errors: equal reports whether the
// pair agrees, render whether both succeeded and their values are to be
// compared.
func pair(hot, archived error) (equal, render bool, err error) {
	if hot != nil && errorClass(hot) == "other" {
		return false, false, errHotUnavailable
	}
	if errorClass(hot) != errorClass(archived) {
		return false, false, nil
	}
	return true, hot == nil, nil
}

func rendered(write func(*bytes.Buffer) error) ([]byte, error) {
	var buffer bytes.Buffer
	err := write(&buffer)
	return buffer.Bytes(), err
}

func sameRendering(hot, archived func(*bytes.Buffer) error) (bool, error) {
	left, err := rendered(hot)
	if err != nil {
		return false, err
	}
	right, err := rendered(archived)
	if err != nil {
		return false, nil
	}
	return bytes.Equal(left, right), nil
}

// Compare implements Sampler.
func (sampler QuerySampler) Compare(ctx context.Context, audit *archivecli.AuditRecord) (bool, error) {
	id := audit.Record.Audit.AuditID
	hotDetail, hotErr := sampler.Hot.Get(ctx, id, nil)
	archivedDetail, archivedErr := audit.Detail(ctx)
	if equal, render, err := pair(hotErr, archivedErr); err != nil || !equal {
		return false, err
	} else if render {
		projected := archive.ProjectDetail(sampler.Fingerprinter, hotDetail)
		if same, err := sameRendering(
			func(buffer *bytes.Buffer) error { return archivecli.WriteDetail(buffer, projected) },
			func(buffer *bytes.Buffer) error { return archivecli.WriteDetail(buffer, archivedDetail) },
		); err != nil || !same {
			return false, err
		}
		if same, err := sameRendering(
			func(buffer *bytes.Buffer) error { return archivecli.WriteHeaders(buffer, id, projected.Headers) },
			func(buffer *bytes.Buffer) error { return archivecli.WriteHeaders(buffer, id, archivedDetail.Headers) },
		); err != nil || !same {
			return false, err
		}
	}

	hotTurn, hotErr := sampler.Hot.ReconstructTurn(ctx, id)
	archivedTurn, archivedErr := audit.Turn(ctx)
	if equal, render, err := pair(hotErr, archivedErr); err != nil || !equal {
		return false, err
	} else if render {
		for _, values := range [][2]any{
			{hotTurn.Turn, archivedTurn.Turn},
			{hotTurn.Request, archivedTurn.Request},
			{hotTurn.Response, archivedTurn.Response},
			{hotTurn.Conversation, archivedTurn.Conversation},
		} {
			if same, err := sameRendering(
				func(buffer *bytes.Buffer) error { return archivecli.WriteProviderBody(buffer, values[0]) },
				func(buffer *bytes.Buffer) error { return archivecli.WriteProviderBody(buffer, values[1]) },
			); err != nil || !same {
				return false, err
			}
		}
	}

	hotConversation, hotErr := sampler.Hot.SessionConversation(ctx, id)
	archivedConversation, archivedErr := audit.SessionConversation(ctx)
	if equal, render, err := pair(hotErr, archivedErr); err != nil || !equal {
		return false, err
	} else if render {
		if same, err := sameRendering(
			func(buffer *bytes.Buffer) error { return archivecli.WriteConversation(buffer, hotConversation) },
			func(buffer *bytes.Buffer) error { return archivecli.WriteConversation(buffer, archivedConversation) },
		); err != nil || !same {
			return false, err
		}
	}

	for _, side := range []query.Side{query.SideRequest, query.SideResponse} {
		hotTimeline, hotErr := sampler.Hot.Timeline(ctx, id, side)
		archivedTimeline, archivedErr := audit.Timeline(side)
		if equal, render, err := pair(hotErr, archivedErr); err != nil || !equal {
			return false, err
		} else if render {
			if same, err := sameRendering(
				func(buffer *bytes.Buffer) error { return archivecli.WriteTimeline(buffer, hotTimeline) },
				func(buffer *bytes.Buffer) error { return archivecli.WriteTimeline(buffer, archivedTimeline) },
			); err != nil || !same {
				return false, err
			}
		}

		hotMeta, hotErr := sampler.Hot.RawMeta(ctx, id, side)
		archivedMeta, archivedErr := audit.RawMeta(side)
		if equal, render, err := pair(hotErr, archivedErr); err != nil || !equal {
			return false, err
		} else if render && hotMeta != archivedMeta {
			return false, nil
		}
		hotHash, archivedHash := sha256.New(), sha256.New()
		hotErr = sampler.Hot.StreamRaw(ctx, id, side, hotHash)
		archivedErr = audit.StreamRaw(ctx, side, archivedHash)
		if equal, render, err := pair(hotErr, archivedErr); err != nil || !equal {
			return false, err
		} else if render && !bytes.Equal(hotHash.Sum(nil), archivedHash.Sum(nil)) {
			return false, nil
		}
	}
	return true, ctx.Err()
}

// sample compares sampleSize members of a verified bundle, never one the
// intent registered stale (it changed after the snapshot already). A member
// that differs is checked against the hot store's current change stamp:
// changed since the snapshot, it counts as stale and does not void the
// bundle; unchanged, the bundle is void (J.3).
func (current *run) sample(opened *bundle.Bundle, members map[string]memberInfo, stale map[string]bool) error {
	options := current.options()
	manifest := opened.Manifest()
	var eligible []int
	for index, member := range manifest.Members {
		if !stale[member.AuditID] {
			eligible = append(eligible, index)
		}
	}
	count := sampleSize(options.VerifySample, len(eligible))
	if count == 0 {
		return nil
	}
	// A partial Fisher-Yates draw of count lines.
	for index := 0; index < count; index++ {
		pick := index + int(options.Random()*float64(len(eligible)-index))
		pick = min(pick, len(eligible)-1)
		eligible[index], eligible[pick] = eligible[pick], eligible[index]
	}
	wanted := map[int]bool{}
	last := 0
	for _, line := range eligible[:count] {
		wanted[line] = true
		last = max(last, line)
	}
	var records []*archive.Record
	stop := errors.New("stop")
	err := opened.Records(current.ctx, func(line bundle.Line) error {
		if wanted[line.Index] {
			records = append(records, line.Record)
		}
		if line.Index >= last {
			return stop
		}
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		return fail("", err)
	}
	for _, record := range records {
		audit := &archivecli.AuditRecord{Record: record, Bundle: opened, ManifestPath: opened.Path()}
		equal, err := options.Sampler.Compare(current.ctx, audit)
		if current.ctx.Err() != nil {
			return current.ctx.Err()
		}
		if err != nil {
			return fail("sample_failed", err)
		}
		if equal {
			continue
		}
		stamp, exists, err := options.Store.ChangeStamp(current.ctx, record.Audit.AuditID)
		if err != nil {
			return fail("sample_failed", err)
		}
		if !exists || stamp != members[record.Audit.AuditID].stamp {
			current.result.Counts.StaleAudits++
			continue
		}
		return fail("sample_mismatch", errors.New("a sampled member differs from the hot store"))
	}
	return nil
}
