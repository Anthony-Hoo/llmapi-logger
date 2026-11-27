package audit

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/audit/staging"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage/sqlite"
)

// TestMeasureStaging reports, for a 16 MiB and a 64 MiB streamed response
// with the default memory budget, the bytes written to staging, the file
// syncs, the peak heap of the process while the request runs and the time
// spent in Finish, next to the legacy path. It only runs with
// LLMAPI_MEASURE_STAGING=1.
func TestMeasureStaging(t *testing.T) {
	if os.Getenv("LLMAPI_MEASURE_STAGING") != "1" {
		t.Skip("set LLMAPI_MEASURE_STAGING=1 to measure")
	}
	cipher, err := security.NewAESGCM(bytes.Repeat([]byte{3}, security.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, size := range []int{16 << 20, 64 << 20} {
		response := sseBody(size, uint64(size))
		request := []byte(`{"model":"model-example","stream":true}`)
		for _, writePath := range []string{WritePathLegacy, WritePathUnified} {
			var finishes []time.Duration
			var peak uint64
			var stats staging.Stats
			for round := range 3 {
				store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), fmt.Sprintf("m%d.db", round)))
				if err != nil {
					t.Fatal(err)
				}
				options := Options{WritePath: writePath}
				var stager *staging.Stager
				if writePath == WritePathUnified {
					if stager, err = staging.Open(filepath.Join(t.TempDir(), "staging"), cipher, staging.Options{Logger: quiet}); err != nil {
						t.Fatal(err)
					}
					options.Stager = stager
				}
				manager, err := NewManagerWithOptions(store, cipher, nil, ModeAvailable, quiet, options)
				if err != nil {
					t.Fatal(err)
				}
				runtime.GC()
				var base runtime.MemStats
				runtime.ReadMemStats(&base)
				var high atomic.Uint64
				done := make(chan struct{})
				sampled := make(chan struct{})
				go func() {
					defer close(sampled)
					var stats runtime.MemStats
					for {
						runtime.ReadMemStats(&stats)
						if stats.HeapInuse > high.Load() {
							high.Store(stats.HeapInuse)
						}
						select {
						case <-done:
							return
						case <-time.After(2 * time.Millisecond):
						}
					}
				}()
				session := driveStream(t, manager, request, response)
				started := time.Now()
				if err := session.Finish(); err != nil {
					t.Fatal(err)
				}
				finishes = append(finishes, time.Since(started))
				close(done)
				<-sampled
				if delta := high.Load() - min(high.Load(), base.HeapInuse); delta > peak {
					peak = delta
				}
				if stager != nil {
					stager.Flush()
					stats = stager.Stats()
					_ = stager.Close()
				}
				if terminal, _ := session.Terminal(); terminal.CaptureStatus != "complete" {
					t.Fatalf("%s: capture %s", writePath, terminal.CaptureStatus)
				}
				_ = store.Close()
			}
			t.Logf("%s %d MiB stream: Finish median %v; peak heap above baseline %.1f MiB; staging wrote %.1f MiB in %d records, %d file syncs, %d directory syncs",
				writePath, size>>20, median(finishes), float64(peak)/(1<<20), float64(stats.BytesWritten)/(1<<20), stats.Records, stats.Fsyncs, stats.DirSyncs)
		}
	}
}
