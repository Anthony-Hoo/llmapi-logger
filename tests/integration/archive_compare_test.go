package integration_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
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
	values map[string]int
	// audits are the records compared, for checks after the comparison.
	audits      map[string]*archivecli.AuditRecord
	classes     map[string]map[string]int
	differences []string
}

func newArchiveComparison() *archiveComparison {
	return &archiveComparison{values: map[string]int{}, classes: map[string]map[string]int{}, audits: map[string]*archivecli.AuditRecord{}}
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
// bundles in reader's directory against what the query service serves from
// the hot store, after the credential projection. The audits are grouped by
// the bundle that holds them and the groups compared by up to
// archiveSendWorkers goroutines, each with a reader of its own (a reader
// is not shared between goroutines), so each bundle is read by one of them.
func (rig *archiveRig) compare(reader *archivecli.Reader, ids []string) *archiveComparison {
	t := rig.t
	t.Helper()
	summaries := rig.summaries()
	keys := archiveKeysOf(t, rig.keyPath)
	root, ok := rig.readerRoots[reader]
	if !ok {
		t.Fatal("compare needs a reader opened by rig.reader")
	}
	c := newArchiveComparison()
	groups := map[string][]string{}
	var order []string
	for _, id := range ids {
		location, ok := reader.Index().Audit(id)
		if !ok {
			c.differ(id, "lookup", "not in the index")
			continue
		}
		path := location.Entry.ManifestPath
		if groups[path] == nil {
			order = append(order, path)
		}
		groups[path] = append(groups[path], id)
	}
	work := make(chan []string)
	parts := make(chan *archiveComparison)
	var workers sync.WaitGroup
	for range archiveSendWorkers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			own, err := archivecli.OpenReader(rig.ctx, root, archivecli.ReaderOptions{Keys: keys})
			if err != nil {
				part := newArchiveComparison()
				part.differ("-", "open reader", "%v", err)
				parts <- part
				for range work {
				}
				return
			}
			defer own.Close()
			for group := range work {
				part := newArchiveComparison()
				rig.compareInto(part, own, group, summaries)
				parts <- part
			}
		}()
	}
	go func() {
		for _, path := range order {
			work <- groups[path]
		}
		close(work)
		workers.Wait()
		close(parts)
	}()
	for part := range parts {
		c.merge(part)
	}
	sort.Strings(c.differences)
	return c
}

func (c *archiveComparison) merge(other *archiveComparison) {
	for kind, count := range other.values {
		c.values[kind] += count
	}
	for kind, classes := range other.classes {
		if c.classes[kind] == nil {
			c.classes[kind] = map[string]int{}
		}
		for class, count := range classes {
			c.classes[kind][class] += count
		}
	}
	c.differences = append(c.differences, other.differences...)
	for id, audit := range other.audits {
		c.audits[id] = audit
	}
}

// hotValues are the hot side's reads of one audit, read once and used both
// for the J.3 pairs and for the export kinds.
type hotValues struct {
	detail                query.Detail
	detailErr             error
	turn                  query.ReconstructedTurn
	turnErr               error
	timelines             map[query.Side]query.StreamTimeline
	timelineErrs, rawErrs map[query.Side]error
	raws                  map[query.Side][]byte
}

// compareInto compares the given audits into c; it runs on any goroutine
// and reports through c only.
func (rig *archiveRig) compareInto(c *archiveComparison, reader *archivecli.Reader, ids []string, summaries map[string]query.AuditSummary) {
	ctx := rig.ctx
	// One pass over the bundle's lines (bundle.Records, as the reader tool's
	// own ConversationTurns reads them) instead of reader.Audit per audit,
	// which scans the lines up to each one: the same records, without a
	// pass per audit. Every audit of ids is in this one bundle.
	records := map[string]*archivecli.AuditRecord{}
	if len(ids) > 0 {
		location, _ := reader.Index().Audit(ids[0])
		opened, err := reader.Bundle(ctx, location.Entry)
		if err != nil {
			c.differ(ids[0], "bundle", "%v", err)
			return
		}
		wanted := map[int]bool{}
		for _, id := range ids {
			if location, ok := reader.Index().Audit(id); ok && location.Entry.ManifestPath == opened.Path() {
				wanted[location.Line] = true
			}
		}
		if err := opened.Records(ctx, func(line bundle.Line) error {
			if wanted[line.Index] {
				records[line.Record.Audit.AuditID] = &archivecli.AuditRecord{Record: line.Record, Bundle: opened, ManifestPath: opened.Path()}
			}
			return nil
		}); err != nil {
			c.differ(ids[0], "bundle", "%v", err)
			return
		}
	}
	for _, id := range ids {
		audit := records[id]
		if audit == nil {
			c.differ(id, "lookup", "not in its bundle's lines")
			continue
		}
		c.audits[id] = audit

		hotSummary, ok := summaries[id]
		if !ok {
			c.differ(id, "summary", "not in the hot list")
		} else {
			c.pair(id, "summary", nil, nil, jsonOf(archive.ProjectSummary(rig.keys, hotSummary)), jsonOf(audit.Summary()))
		}

		hot := hotValues{timelines: map[query.Side]query.StreamTimeline{}, timelineErrs: map[query.Side]error{}, rawErrs: map[query.Side]error{}, raws: map[query.Side][]byte{}}
		hot.detail, hot.detailErr = rig.hot.Get(ctx, id, nil)
		archivedDetail, archivedErr := audit.Detail(ctx)
		projected := archive.ProjectDetail(rig.keys, hot.detail)
		c.pair(id, "detail", hot.detailErr, archivedErr,
			render(func(b *bytes.Buffer) error { return archivecli.WriteDetail(b, projected) }),
			render(func(b *bytes.Buffer) error { return archivecli.WriteDetail(b, archivedDetail) }))

		hot.turn, hot.turnErr = rig.hot.ReconstructTurn(ctx, id)
		hotTurn, hotErr := hot.turn, hot.turnErr
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
			hot.timelines[side], hot.timelineErrs[side] = hotTimeline, hotErr
			archivedTimeline, archivedErr := audit.Timeline(side)
			c.pair(id, "timeline."+string(side), hotErr, archivedErr, jsonOf(hotTimeline), jsonOf(archivedTimeline))

			hotMeta, hotErr := rig.hot.RawMeta(ctx, id, side)
			archivedMeta, archivedErr := audit.RawMeta(side)
			c.pair(id, "rawmeta."+string(side), hotErr, archivedErr, jsonOf(hotMeta), jsonOf(archivedMeta))

			var hotRaw, archivedRaw bytes.Buffer
			hotErr = rig.hot.StreamRaw(ctx, id, side, &hotRaw)
			hot.raws[side], hot.rawErrs[side] = hotRaw.Bytes(), hotErr
			archivedErr = audit.StreamRaw(ctx, side, &archivedRaw)
			c.pair(id, "raw."+string(side), hotErr, archivedErr,
				func() ([]byte, error) { return hotRaw.Bytes(), nil }, func() ([]byte, error) { return archivedRaw.Bytes(), nil })
		}

		// Every export kind of audit-archive, against the same export built
		// from the hot side's reads above.
		for _, kind := range archivecli.ExportKinds {
			var archivedOut bytes.Buffer
			archivedErr := archivecli.ExportAudit(ctx, audit, kind, &archivedOut)
			hotOut, hotCode := rig.hotExport(id, kind, hot)
			archivedCode := archivecli.ErrorCode(archivedErr)
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
}

// way the facade builds it, with the credential projection; the error is
// the reader tool's code of the failure, "" on success.
// hotExport is one audit-archive export kind built from the hot side's
// reads the way the facade builds it, with the credential projection; the
// code is the reader tool's code of the failure, "" on success.
func (rig *archiveRig) hotExport(id, kind string, hot hotValues) ([]byte, string) {
	var out bytes.Buffer
	code := func(err error) string {
		if code := hotErrorCode(err); code != "other" {
			return code
		}
		return "hot:" + err.Error()
	}
	switch kind {
	case archivecli.KindConversation, archivecli.KindHeaders, archivecli.KindDetail:
		if hot.detailErr != nil {
			return nil, code(hot.detailErr)
		}
		projected := archive.ProjectDetail(rig.keys, hot.detail)
		var err error
		switch kind {
		case archivecli.KindConversation:
			if hot.detail.Conversation == nil {
				return nil, "not_available"
			}
			err = archivecli.WriteConversation(&out, hot.detail.Conversation)
		case archivecli.KindHeaders:
			err = archivecli.WriteHeaders(&out, id, projected.Headers)
		default:
			err = archivecli.WriteDetail(&out, projected)
		}
		if err != nil {
			return nil, code(err)
		}
	case archivecli.KindRequest, archivecli.KindResponse:
		if hot.turnErr != nil {
			return nil, code(hot.turnErr)
		}
		body := hot.turn.Request
		if kind == archivecli.KindResponse {
			if hot.turn.Turn.ResponseLayout == auditmodel.LayoutNone {
				return nil, "not_available"
			}
			body = hot.turn.Response
		}
		if err := archivecli.WriteProviderBody(&out, body); err != nil {
			return nil, code(err)
		}
	case archivecli.KindTimelineRequest, archivecli.KindTimelineResponse:
		side := query.Side(strings.TrimPrefix(kind, "timeline-"))
		if err := hot.timelineErrs[side]; err != nil {
			return nil, code(err)
		}
		if err := archivecli.WriteTimeline(&out, hot.timelines[side]); err != nil {
			return nil, code(err)
		}
	case archivecli.KindRawRequest, archivecli.KindRawResponse:
		side := query.Side(strings.TrimPrefix(kind, "raw-"))
		if err := hot.rawErrs[side]; err != nil {
			return nil, code(err)
		}
		out.Write(hot.raws[side])
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
