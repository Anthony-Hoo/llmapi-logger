package integration_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archivecli"
	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/query"
)

// The read-equivalence comparison of design J.3, written for these tests
// rather than taken from the runner's sample (runner.QuerySampler): it also
// compares the list summary, compares the raw bodies byte for byte rather
// than by hash, renders every export kind of the reader tool against the
// same kind built from the hot side, and counts what it compared.

// hotErrorCode is the error class of a hot-side read in the reader tool's
// codes; "other" is an error of no class, which the comparison refuses.
func hotErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, query.ErrNotFound):
		return "not_found"
	case errors.Is(err, query.ErrNotRetained):
		return "not_retained"
	case errors.Is(err, query.ErrNotReady):
		return "not_ready"
	case errors.Is(err, query.ErrNoTurnGraph):
		return "no_turn_graph"
	case errors.Is(err, query.ErrIntegrity):
		return "integrity"
	}
	return "other"
}

// archiveComparison counts, per kind, the pairs compared by value and the
// pairs whose two error classes were compared, and lists the differences.
type archiveComparison struct {
	values      map[string]int
	classes     map[string]map[string]int
	differences []string
}

func newArchiveComparison() *archiveComparison {
	return &archiveComparison{values: map[string]int{}, classes: map[string]map[string]int{}}
}

func (c *archiveComparison) differ(auditID, kind, format string, arguments ...any) {
	c.differences = append(c.differences, fmt.Sprintf("%s %s: ", auditID, kind)+fmt.Sprintf(format, arguments...))
}

// pair compares the outcome of one kind: equal error classes, or both
// rendered and byte for byte equal.
func (c *archiveComparison) pair(auditID, kind string, hotErr, archivedErr error, hot, archived func() ([]byte, error)) {
	hotCode, archivedCode := hotErrorCode(hotErr), archivecli.ErrorCode(archivedErr)
	if hotCode == "other" {
		c.differ(auditID, kind, "the hot side failed with an error of no class: %v", hotErr)
		return
	}
	if hotCode != archivedCode {
		c.differ(auditID, kind, "hot %q, archive %q (%v)", hotCode, archivedCode, archivedErr)
		return
	}
	if hotCode != "" {
		if c.classes[kind] == nil {
			c.classes[kind] = map[string]int{}
		}
		c.classes[kind][hotCode]++
		return
	}
	left, err := hot()
	if err != nil {
		c.differ(auditID, kind, "hot rendering: %v", err)
		return
	}
	right, err := archived()
	if err != nil {
		c.differ(auditID, kind, "archive rendering: %v", err)
		return
	}
	if !bytes.Equal(left, right) {
		c.differ(auditID, kind, "differs\n hot     %s\n archive %s", clip(left), clip(right))
		return
	}
	c.values[kind]++
}

func clip(data []byte) string {
	if len(data) > 600 {
		return string(data[:600]) + "..."
	}
	return string(data)
}

func render(write func(*bytes.Buffer) error) func() ([]byte, error) {
	return func() ([]byte, error) {
		var buffer bytes.Buffer
		err := write(&buffer)
		return buffer.Bytes(), err
	}
}

func jsonOf(value any) func() ([]byte, error) {
	return func() ([]byte, error) { return json.Marshal(value) }
}

// summaries lists every audit of the hot store through query.Service.List.
func (rig *archiveRig) summaries() map[string]query.AuditSummary {
	rig.t.Helper()
	out := map[string]query.AuditSummary{}
	cursor := query.Cursor{}
	for {
		page, err := rig.hot.List(rig.ctx, query.Filter{}, cursor, query.MaxLimit)
		if err != nil {
			rig.t.Fatal(err)
		}
		for _, item := range page.Items {
			out[item.AuditID] = item
		}
		if page.NextCursor == nil {
			return out
		}
		cursor = *page.NextCursor
	}
}

// compare runs J.3 for every id: what the reader tool reads from the
// bundles in reader against what the query service serves from the hot
// store, after the credential projection.
func (rig *archiveRig) compare(reader *archivecli.Reader, ids []string) *archiveComparison {
	t := rig.t
	t.Helper()
	ctx := rig.ctx
	c := newArchiveComparison()
	summaries := rig.summaries()
	for _, id := range ids {
		audit, err := reader.Audit(ctx, id)
		if err != nil {
			c.differ(id, "lookup", "%v", err)
			continue
		}

		hotSummary, ok := summaries[id]
		if !ok {
			c.differ(id, "summary", "not in the hot list")
		} else {
			c.pair(id, "summary", nil, nil, jsonOf(archive.ProjectSummary(rig.keys, hotSummary)), jsonOf(audit.Summary()))
		}

		hotDetail, hotErr := rig.hot.Get(ctx, id, nil)
		archivedDetail, archivedErr := audit.Detail(ctx)
		projected := archive.ProjectDetail(rig.keys, hotDetail)
		c.pair(id, "detail", hotErr, archivedErr,
			render(func(b *bytes.Buffer) error { return archivecli.WriteDetail(b, projected) }),
			render(func(b *bytes.Buffer) error { return archivecli.WriteDetail(b, archivedDetail) }))

		hotTurn, hotErr := rig.hot.ReconstructTurn(ctx, id)
		archivedTurn, archivedErr := audit.Turn(ctx)
		c.pair(id, "turn", hotErr, archivedErr, jsonOf(hotTurn.Turn), jsonOf(archivedTurn.Turn))
		c.pair(id, "turn.request", hotErr, archivedErr,
			func() ([]byte, error) { return auditmodel.CanonicalJSON(hotTurn.Request) },
			func() ([]byte, error) { return auditmodel.CanonicalJSON(archivedTurn.Request) })
		c.pair(id, "turn.response", hotErr, archivedErr,
			func() ([]byte, error) { return auditmodel.CanonicalJSON(hotTurn.Response) },
			func() ([]byte, error) { return auditmodel.CanonicalJSON(archivedTurn.Response) })
		c.pair(id, "turn.conversation", hotErr, archivedErr, jsonOf(hotTurn.Conversation), jsonOf(archivedTurn.Conversation))

		hotSession, hotErr := rig.hot.SessionConversation(ctx, id)
		archivedSession, archivedErr := audit.SessionConversation(ctx)
		c.pair(id, "session", hotErr, archivedErr, jsonOf(hotSession), jsonOf(archivedSession))

		for _, side := range []query.Side{query.SideRequest, query.SideResponse} {
			hotTimeline, hotErr := rig.hot.Timeline(ctx, id, side)
			archivedTimeline, archivedErr := audit.Timeline(side)
			c.pair(id, "timeline."+string(side), hotErr, archivedErr, jsonOf(hotTimeline), jsonOf(archivedTimeline))

			hotMeta, hotErr := rig.hot.RawMeta(ctx, id, side)
			archivedMeta, archivedErr := audit.RawMeta(side)
			c.pair(id, "rawmeta."+string(side), hotErr, archivedErr, jsonOf(hotMeta), jsonOf(archivedMeta))

			var hotRaw, archivedRaw bytes.Buffer
			hotErr = rig.hot.StreamRaw(ctx, id, side, &hotRaw)
			archivedErr = audit.StreamRaw(ctx, side, &archivedRaw)
			c.pair(id, "raw."+string(side), hotErr, archivedErr,
				func() ([]byte, error) { return hotRaw.Bytes(), nil }, func() ([]byte, error) { return archivedRaw.Bytes(), nil })
		}

		// Every export kind of audit-archive, against the same export built
		// from the hot side.
		for _, kind := range archivecli.ExportKinds {
			var archivedOut bytes.Buffer
			archivedErr := archivecli.ExportAudit(ctx, audit, kind, &archivedOut)
			hotOut, hotErr := rig.hotExport(id, kind)
			hotCode, archivedCode := hotErr, archivecli.ErrorCode(archivedErr)
			if hotCode != archivedCode {
				c.differ(id, "export "+kind, "hot %q, archive %q", hotCode, archivedCode)
				continue
			}
			if hotCode != "" {
				if c.classes["export "+kind] == nil {
					c.classes["export "+kind] = map[string]int{}
				}
				c.classes["export "+kind][hotCode]++
				continue
			}
			if !bytes.Equal(hotOut, archivedOut.Bytes()) {
				c.differ(id, "export "+kind, "differs\n hot     %s\n archive %s", clip(hotOut), clip(archivedOut.Bytes()))
				continue
			}
			c.values["export "+kind]++
		}
	}
	return c
}

// hotExport is one audit-archive export kind built from the hot side the
// way the facade builds it, with the credential projection; the error is
// the reader tool's code of the failure, "" on success.
func (rig *archiveRig) hotExport(id, kind string) ([]byte, string) {
	ctx := rig.ctx
	var out bytes.Buffer
	code := func(err error) string {
		if code := hotErrorCode(err); code != "other" {
			return code
		}
		return "hot:" + err.Error()
	}
	switch kind {
	case archivecli.KindConversation, archivecli.KindHeaders, archivecli.KindDetail:
		detail, err := rig.hot.Get(ctx, id, nil)
		if err != nil {
			return nil, code(err)
		}
		projected := archive.ProjectDetail(rig.keys, detail)
		switch kind {
		case archivecli.KindConversation:
			if detail.Conversation == nil {
				return nil, "not_available"
			}
			err = archivecli.WriteConversation(&out, detail.Conversation)
		case archivecli.KindHeaders:
			err = archivecli.WriteHeaders(&out, id, projected.Headers)
		default:
			err = archivecli.WriteDetail(&out, projected)
		}
		if err != nil {
			return nil, code(err)
		}
	case archivecli.KindRequest, archivecli.KindResponse:
		turn, err := rig.hot.ReconstructTurn(ctx, id)
		if err != nil {
			return nil, code(err)
		}
		body := turn.Request
		if kind == archivecli.KindResponse {
			if turn.Turn.ResponseLayout == auditmodel.LayoutNone {
				return nil, "not_available"
			}
			body = turn.Response
		}
		if err := archivecli.WriteProviderBody(&out, body); err != nil {
			return nil, code(err)
		}
	case archivecli.KindTimelineRequest, archivecli.KindTimelineResponse:
		timeline, err := rig.hot.Timeline(ctx, id, query.Side(strings.TrimPrefix(kind, "timeline-")))
		if err != nil {
			return nil, code(err)
		}
		if err := archivecli.WriteTimeline(&out, timeline); err != nil {
			return nil, code(err)
		}
	case archivecli.KindRawRequest, archivecli.KindRawResponse:
		if err := rig.hot.StreamRaw(ctx, id, query.Side(strings.TrimPrefix(kind, "raw-")), &out); err != nil {
			return nil, code(err)
		}
	default:
		return nil, "unknown kind"
	}
	return out.Bytes(), ""
}

// report is a sorted, readable summary of the counts.
func (c *archiveComparison) report() string {
	var kinds []string
	seen := map[string]bool{}
	for kind := range c.values {
		seen[kind] = true
	}
	for kind := range c.classes {
		seen[kind] = true
	}
	for kind := range seen {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	var lines []string
	for _, kind := range kinds {
		lines = append(lines, fmt.Sprintf("%-26s values %4d  classes %v", kind, c.values[kind], c.classes[kind]))
	}
	return strings.Join(lines, "\n")
}
