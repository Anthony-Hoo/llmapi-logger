package web

import (
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
)

// What one request body may cost (contract section 0.1 items 163 and 170).
// Before the value limit, an array of empty objects under args.labels at the
// plan's 512 KiB limit allocated about 880 times the body, some 440 MiB per
// request, and 30 such requests at once held about 1 GiB of heap.

// repeatedElements is prefix, then element repeated with commas in between
// as often as fits in limit bytes, then suffix.
func repeatedElements(prefix, element, suffix string, limit int) string {
	count := (limit - len(prefix) - len(suffix) + 1) / (len(element) + 1)
	return prefix + strings.TrimSuffix(strings.Repeat(element+",", count), ",") + suffix
}

// costlyBodyShapes are the elements that cost the most per byte to decode:
// an empty object or array, a number, an object of one key, nested arrays
// around an object, a string holding brackets.
var costlyBodyShapes = map[string]string{
	"empty objects":          `{}`,
	"empty arrays":           `[]`,
	"zeros":                  `0`,
	"objects of one key":     `{"a":0}`,
	"nested arrays":          `[[[[[[{}]]]]]]`,
	"strings with brackets":  `"[{[{"`,
	"objects of three keys":  `{"a":0,"b":"","c":[]}`,
	"empty strings and null": `"",null`,
}

// costlyBodyEndpoint is a list inside a request body that an endpoint
// decodes element by element.
type costlyBodyEndpoint struct {
	name, method, path, prefix, suffix string
	limit                              int
	// maxMiB is the most one request may allocate.
	maxMiB int
}

func costlyBodyEndpoints() []costlyBodyEndpoint {
	return []costlyBodyEndpoint{
		{"plan args.labels", http.MethodPost, "/plans", `{"op":"analysis.calibrate","args":{"labels":[`, `]}}`, int(maxAgentPlanBodyBytes), 32},
		{"plan set.rules", http.MethodPost, "/plans", `{"op":"config.set","kind":"project","set":{"name":"d","group_id":null,"enabled":true,"rules":[`, `]}}`, int(maxAgentPlanBodyBytes), 32},
		{"plan add.keywords", http.MethodPost, "/plans", `{"op":"config.set","kind":"content-rule","id":"1","add":{"keywords":[`, `]}}`, int(maxAgentPlanBodyBytes), 32},
		{"plan set.ranked_clients", http.MethodPost, "/plans", `{"op":"config.set","kind":"weekly-settings","set":{"ranked_clients":[`, `]}}`, int(maxAgentPlanBodyBytes), 32},
		{"preview rules", http.MethodPost, "/config/project-preview", `{"week":"2026-01-05","group_id":null,"project_id":1,"rules":[`, `]}`, int(maxAgentPreviewBodyBytes), 4},
		{"test-model set", http.MethodPost, "/analysis/test-model", `{"set":{"llm.model":[`, `]}}`, int(maxAgentKeyBodyBytes), 4},
	}
}

func (endpoint costlyBodyEndpoint) token(fixture *writeFixture) string {
	if endpoint.path == "/config/project-preview" {
		return fixture.adminRead
	}
	return fixture.adminWrite
}

// TestAgentBodyCostIsBoundedAtTheByteLimits sends, to every endpoint that
// decodes a list element by element, each costly shape filled up to the
// endpoint's size limit: each request is refused with INVALID_ARGUMENT and
// allocates at most the endpoint's bound (32 MiB for a plan, 4 MiB for the
// smaller bodies).
func TestAgentBodyCostIsBoundedAtTheByteLimits(t *testing.T) {
	fixture := newWriteFixture(t)
	for _, endpoint := range costlyBodyEndpoints() {
		for shape, element := range costlyBodyShapes {
			body := repeatedElements(endpoint.prefix, element, endpoint.suffix, endpoint.limit)
			var refused agentapi.ErrorBody
			allocated := allocatedBy(func() {
				refused = failure(t, fixture.facade(endpoint.method, endpoint.path, body, endpoint.token(fixture)))
			})
			t.Logf("%-24s %-22s %7d bytes: %s %v, %6d KiB allocated (%.1fx)", endpoint.name, shape, len(body), refused.Code, refused.Details["reason"],
				allocated>>10, float64(allocated)/float64(len(body)))
			if refused.Code != agentapi.CodeInvalidArgument {
				t.Errorf("%s, %s: %s", endpoint.name, shape, refused.Code)
			}
			if allocated > uint64(endpoint.maxMiB)<<20 {
				t.Errorf("%s, %s: %d MiB allocated for one %d-byte body, more than %d MiB", endpoint.name, shape, allocated>>20, len(body), endpoint.maxMiB)
			}
		}
	}
}

// concurrentPeak sends body to POST /plans from 30 requests at once and
// returns how far the heap in use rose above where it was before, and the
// error codes of the answers.
func concurrentPeak(t *testing.T, fixture *writeFixture, body string) (int64, map[agentapi.Code]int) {
	t.Helper()
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		var stats runtime.MemStats
		for {
			select {
			case <-stop:
				return
			default:
			}
			runtime.ReadMemStats(&stats)
			if stats.HeapInuse > peak.Load() {
				peak.Store(stats.HeapInuse)
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	var mu sync.Mutex
	codes := map[agentapi.Code]int{}
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < 30; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response := fixture.facade(http.MethodPost, "/plans", body, fixture.adminWrite)
			code := agentapi.Code("OK")
			if response.Code != http.StatusOK {
				code = failure(t, response).Code
			}
			mu.Lock()
			codes[code]++
			mu.Unlock()
		}()
	}
	close(start)
	wait.Wait()
	close(stop)
	<-sampled
	return int64(peak.Load()) - int64(base.HeapInuse), codes
}

// peakAnswersDidTheWork reports whether the 30 answers of concurrentPeak are
// the ones a measurement of the peak needs, for bodies that pass the value
// limit and so take a decoding slot: every request either had its body
// decoded and was refused for it (INVALID_ARGUMENT), or waited agentBodyWait
// for a slot and was refused with TIMEOUT. How many wait that long depends on
// the machine: none on a fast one, some under the race detector. None is
// turned away for a rate, which would do no work, and at least as many as
// there are slots were decoded.
func peakAnswersDidTheWork(codes map[agentapi.Code]int) bool {
	decoded, waited := codes[agentapi.CodeInvalidArgument], codes[agentapi.CodeTimeout]
	return decoded+waited == 30 && decoded >= maxAgentBodyDecoders
}

// TestAgentBodyConcurrentPeakIsBoundedAtTheByteLimit: 30 plan requests at
// once, each the costliest body at the plan's size limit, raise the heap in
// use by less than 150 MiB, and every one of them is refused for its body
// (none is turned away for a rate or a wait, which would do no work). A body
// of this size is over the value limit, so it is refused by the scan and
// never waits for a decoding slot: no machine is slow enough for a TIMEOUT.
func TestAgentBodyConcurrentPeakIsBoundedAtTheByteLimit(t *testing.T) {
	const maxPeakMiB = 150
	fixture := newWriteFixture(t)
	body := repeatedElements(`{"op":"analysis.calibrate","args":{"labels":[`, `{}`, `]}}`, int(maxAgentPlanBodyBytes))
	above, codes := concurrentPeak(t, fixture, body)
	t.Logf("30 x %d bytes of empty labels at once: the heap in use rose %d MiB; answers %v", len(body), above>>20, codes)
	if codes[agentapi.CodeInvalidArgument] != 30 {
		t.Errorf("answers %v, want 30 INVALID_ARGUMENT", codes)
	}
	if above > maxPeakMiB<<20 {
		t.Errorf("the heap in use rose %d MiB, more than %d MiB", above>>20, maxPeakMiB)
	}
}
