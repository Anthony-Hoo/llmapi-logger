package audit

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"llmapi-logger/internal/storage/sqlite"
)

const gapFlushInterval = 30 * time.Second

type gapWriter interface {
	InsertAuditGaps(context.Context, []sqlite.AuditGap) error
}

type gapAggregate struct {
	startedAtNS int64
	endedAtNS   int64
	count       int
}

// gapBuffer keeps at most one aggregate per stable reason. It deliberately
// stores no request data or dependency error text.
type gapBuffer struct {
	writer gapWriter
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	pending map[string]gapAggregate
	started bool
	closed  bool
	cancel  context.CancelFunc
	wake    chan struct{}
	wait    sync.WaitGroup
	flushMu sync.Mutex
}

func newGapBuffer(writer gapWriter, logger *slog.Logger, now func() time.Time) *gapBuffer {
	if logger == nil {
		logger = slog.Default()
	}
	if now == nil {
		now = time.Now
	}
	return &gapBuffer{
		writer:  writer,
		logger:  logger,
		now:     now,
		pending: make(map[string]gapAggregate, 4),
		wake:    make(chan struct{}, 1),
	}
}

func (buffer *gapBuffer) record(reason string) {
	if buffer == nil {
		return
	}
	if _, ok := gapDetail(reason); !ok {
		return
	}
	nowNS := buffer.now().UnixNano()
	buffer.mu.Lock()
	if buffer.closed {
		buffer.mu.Unlock()
		return
	}
	aggregate := buffer.pending[reason]
	if aggregate.count == 0 {
		aggregate.startedAtNS = nowNS
	}
	aggregate.endedAtNS = nowNS
	aggregate.count++
	buffer.pending[reason] = aggregate
	buffer.mu.Unlock()
	buffer.trigger()
}

func (buffer *gapBuffer) trigger() {
	if buffer == nil || buffer.writer == nil {
		return
	}
	select {
	case buffer.wake <- struct{}{}:
	default:
	}
}

func (buffer *gapBuffer) start(parent context.Context) {
	if buffer == nil || buffer.writer == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	buffer.mu.Lock()
	if buffer.started || buffer.closed {
		buffer.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	buffer.started = true
	buffer.cancel = cancel
	buffer.wait.Add(1)
	buffer.mu.Unlock()
	go buffer.run(ctx)
}

func (buffer *gapBuffer) run(ctx context.Context) {
	defer buffer.wait.Done()
	ticker := time.NewTicker(gapFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-buffer.wake:
			buffer.flushAndLog(ctx)
		case <-ticker.C:
			buffer.flushAndLog(ctx)
		}
	}
}

func (buffer *gapBuffer) close(ctx context.Context) {
	if buffer == nil {
		return
	}
	buffer.mu.Lock()
	if buffer.closed {
		buffer.mu.Unlock()
		return
	}
	buffer.closed = true
	cancel := buffer.cancel
	buffer.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	buffer.wait.Wait()

	if buffer.writer == nil {
		if count := buffer.pendingCount(); count > 0 {
			buffer.logger.Warn("audit gaps were not persisted",
				"request_count", count,
				"error_category", "gap_storage_unavailable",
			)
		}
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	buffer.flushAndLog(ctx)
}

func (buffer *gapBuffer) flushAndLog(ctx context.Context) {
	if err := buffer.flush(ctx); err != nil && !errors.Is(err, context.Canceled) {
		buffer.logger.Warn("audit gap flush failed", "error_category", "gap_flush_failed")
	}
}

func (buffer *gapBuffer) flush(ctx context.Context) error {
	if buffer == nil || buffer.writer == nil {
		return nil
	}
	buffer.flushMu.Lock()
	defer buffer.flushMu.Unlock()

	gaps := buffer.take()
	if len(gaps) == 0 {
		return nil
	}
	if err := buffer.writer.InsertAuditGaps(ctx, gaps); err != nil {
		buffer.merge(gaps)
		return err
	}
	return nil
}

func (buffer *gapBuffer) take() []sqlite.AuditGap {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	if len(buffer.pending) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(buffer.pending))
	for reason := range buffer.pending {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	createdAtNS := buffer.now().UnixNano()
	gaps := make([]sqlite.AuditGap, 0, len(reasons))
	for _, reason := range reasons {
		aggregate := buffer.pending[reason]
		detail, _ := gapDetail(reason)
		gaps = append(gaps, sqlite.AuditGap{
			StartedAtNS:  aggregate.startedAtNS,
			EndedAtNS:    aggregate.endedAtNS,
			Reason:       reason,
			RequestCount: aggregate.count,
			Detail:       detail,
			CreatedAtNS:  createdAtNS,
		})
	}
	clear(buffer.pending)
	return gaps
}

func (buffer *gapBuffer) merge(gaps []sqlite.AuditGap) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	for _, gap := range gaps {
		aggregate := buffer.pending[gap.Reason]
		if aggregate.count == 0 || gap.StartedAtNS < aggregate.startedAtNS {
			aggregate.startedAtNS = gap.StartedAtNS
		}
		if gap.EndedAtNS > aggregate.endedAtNS {
			aggregate.endedAtNS = gap.EndedAtNS
		}
		aggregate.count += gap.RequestCount
		buffer.pending[gap.Reason] = aggregate
	}
}

func (buffer *gapBuffer) pendingCount() int {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	total := 0
	for _, aggregate := range buffer.pending {
		total += aggregate.count
	}
	return total
}

func gapDetail(reason string) (string, bool) {
	switch reason {
	case sqlite.GapReasonDBUnavailable:
		return sqlite.GapDetailDBUnavailable, true
	case sqlite.GapReasonQueueFull:
		return sqlite.GapDetailQueueFull, true
	case sqlite.GapReasonEncryption:
		return sqlite.GapDetailEncryption, true
	case sqlite.GapReasonWrite:
		return sqlite.GapDetailWrite, true
	default:
		return "", false
	}
}
