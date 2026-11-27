package auditbench

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// memorySampler records the peak Go memory per phase. The whole process is
// sampled: application, fake upstream and load driver together.
type memorySampler struct {
	phase   atomic.Int32
	mu      sync.Mutex
	total   []uint64
	heap    []uint64
	samples []metrics.Sample
}

func newMemorySampler(phases int) *memorySampler {
	return &memorySampler{
		total: make([]uint64, phases), heap: make([]uint64, phases),
		samples: []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/objects:bytes"}},
	}
}

func (sampler *memorySampler) sample() {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	metrics.Read(sampler.samples)
	phase := int(sampler.phase.Load())
	if phase < 0 || phase >= len(sampler.total) {
		return
	}
	if value := sampler.samples[0].Value; value.Kind() == metrics.KindUint64 {
		sampler.total[phase] = max(sampler.total[phase], value.Uint64())
	}
	if value := sampler.samples[1].Value; value.Kind() == metrics.KindUint64 {
		sampler.heap[phase] = max(sampler.heap[phase], value.Uint64())
	}
}

func (sampler *memorySampler) loop(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sampler.sample()
		}
	}
}

func (sampler *memorySampler) peaks(phase int) (uint64, uint64) {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	return sampler.total[phase], sampler.heap[phase]
}

// peakRSS reads VmHWM on Linux; elsewhere it returns 0.
func peakRSS() uint64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "VmHWM:"))
		if len(fields) >= 1 {
			if value, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
				return value * 1024
			}
		}
	}
	return 0
}

// countingHandler discards application logs and keeps only how often each
// warning or error message occurred. Messages in this code base are fixed
// strings; attributes, which may carry ids, are never kept.
type countingHandler struct {
	mu     *sync.Mutex
	counts map[string]int64
}

func newCountingHandler() *countingHandler {
	return &countingHandler{mu: &sync.Mutex{}, counts: make(map[string]int64)}
}

func (handler *countingHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn
}

func (handler *countingHandler) Handle(_ context.Context, record slog.Record) error {
	key := record.Level.String() + ": " + record.Message
	record.Attrs(func(attribute slog.Attr) bool {
		if attribute.Key == "error_code" || attribute.Key == "error_category" {
			key += " [" + attribute.Value.String() + "]"
			return false
		}
		return true
	})
	handler.mu.Lock()
	handler.counts[key]++
	handler.mu.Unlock()
	return nil
}

func (handler *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return handler }
func (handler *countingHandler) WithGroup(string) slog.Handler      { return handler }

func (handler *countingHandler) snapshot() map[string]int64 {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	result := make(map[string]int64, len(handler.counts))
	for key, value := range handler.counts {
		result[key] = value
	}
	return result
}
