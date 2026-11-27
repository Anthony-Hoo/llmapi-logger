package auditbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"llmapi-logger/internal/protofixture"
)

// Workload is the traffic one run sends. Two runs are comparable only when
// their workloads are equal.
type Workload struct {
	Profile         string             `json:"profile"`
	Seed            uint64             `json:"seed"`
	Conversations   int                `json:"conversations"`
	Turns           int                `json:"turns_per_conversation"`
	Concurrency     int                `json:"concurrency"`
	Mix             map[string]float64 `json:"protocol_mix"`
	StreamShare     float64            `json:"stream_share"`
	AbnormalShare   float64            `json:"abnormal_share"`
	BranchShare     float64            `json:"branch_share"`
	HistoryItems    int                `json:"history_items"`
	ItemBytes       int                `json:"item_bytes"`
	DeltaBytes      int                `json:"delta_bytes"`
	ToolDefinitions int                `json:"tool_definitions"`
	SystemBytes     int                `json:"system_bytes"`
	FirstByteMS     int                `json:"upstream_first_byte_ms"`
	ChunkDelayMS    int                `json:"upstream_chunk_delay_ms"`
	IdleSeconds     int                `json:"idle_seconds"`
	ReadSamples     int                `json:"read_samples"`
	LatencySample   float64            `json:"latency_sample"`
	CallerLookups   bool               `json:"newapi_caller_lookups"`
	Insights        bool               `json:"insights"`
	OrgReports      bool               `json:"org_reports"`
}

// profiles are the defaults behind --profile. heavy resembles the deployment
// of appendix A.1: about 1 MB request bodies and 220 context items per turn.
var profiles = map[string]Workload{
	"small": {
		Conversations: 24, Turns: 6, Concurrency: 4, HistoryItems: 0, ItemBytes: 400, DeltaBytes: 24,
		ToolDefinitions: 4, SystemBytes: 1200,
	},
	"heavy": {
		Conversations: 8, Turns: 6, Concurrency: 2, HistoryItems: 214, ItemBytes: 4600, DeltaBytes: 16,
		ToolDefinitions: 12, SystemBytes: 12000,
	},
}

const defaultMix = "openai.responses=5,openai.chat_completions=1,anthropic.messages=2,gemini=2"

func parseMix(value string) (map[string]float64, error) {
	mix := make(map[string]float64)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, weight, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("protocol mix entry %q is not name=weight", entry)
		}
		if _, ok := protofixture.ParseProtocol(name); !ok {
			return nil, fmt.Errorf("unknown protocol %q in mix", name)
		}
		parsed, err := strconv.ParseFloat(weight, 64)
		if err != nil || parsed < 0 {
			return nil, fmt.Errorf("invalid weight in protocol mix entry %q", entry)
		}
		mix[name] += parsed
	}
	total := 0.0
	for _, weight := range mix {
		total += weight
	}
	if total <= 0 {
		return nil, errors.New("protocol mix has no positive weight")
	}
	return mix, nil
}

func (workload Workload) options() protofixture.Options {
	return protofixture.Options{
		Seed: workload.Seed, HistoryItems: workload.HistoryItems, ItemBytes: workload.ItemBytes,
		DeltaBytes: workload.DeltaBytes, ToolDefinitions: workload.ToolDefinitions, SystemBytes: workload.SystemBytes,
	}
}

type assignment struct {
	protocol protofixture.Protocol
	stream   bool
}

// assign gives every conversation a protocol and a mode. The counts follow
// the mix and the stream share exactly (largest remainder), so every protocol
// with a weight appears once there are enough conversations, and two runs of
// the same workload send the same traffic; only the order is shuffled.
func (workload Workload) assign(rng *rand.Rand) []assignment {
	names := make([]string, 0, len(workload.Mix))
	total := 0.0
	for name, weight := range workload.Mix {
		if weight > 0 {
			names = append(names, name)
			total += weight
		}
	}
	sort.Strings(names)
	counts := make(map[string]int, len(names))
	exact := make(map[string]float64, len(names))
	assigned := 0
	for _, name := range names {
		exact[name] = float64(workload.Conversations) * workload.Mix[name] / total
		counts[name] = int(exact[name])
		// A protocol with a weight is never left out while there are
		// enough conversations for all of them.
		if counts[name] == 0 && workload.Conversations >= len(names) {
			counts[name] = 1
		}
		assigned += counts[name]
	}
	// Then move single conversations to or from the protocol whose count is
	// furthest from its exact share.
	for assigned != workload.Conversations {
		best, bestGap := "", 0.0
		for _, name := range names {
			gap := exact[name] - float64(counts[name])
			if assigned > workload.Conversations {
				gap = -gap
				if counts[name] <= 1 {
					continue
				}
			}
			if best == "" || gap > bestGap {
				best, bestGap = name, gap
			}
		}
		if assigned > workload.Conversations {
			counts[best]--
			assigned--
		} else {
			counts[best]++
			assigned++
		}
	}
	type remainder struct {
		name  string
		value float64
	}
	remainders := make([]remainder, 0, len(names))
	// The streamed conversations are split the same way: exactly
	// round(conversations x share) in total, spread over the protocols.
	streams := make(map[string]int, len(names))
	streamedTotal := 0
	for _, name := range names {
		share := float64(counts[name]) * workload.StreamShare
		streams[name] = int(share)
		streamedTotal += streams[name]
		remainders = append(remainders, remainder{name, share - float64(streams[name])})
	}
	sort.SliceStable(remainders, func(left, right int) bool { return remainders[left].value > remainders[right].value })
	wanted := int(float64(workload.Conversations)*workload.StreamShare + 0.5)
	for index := 0; streamedTotal < wanted && index < len(remainders); index++ {
		if streams[remainders[index].name] < counts[remainders[index].name] {
			streams[remainders[index].name]++
			streamedTotal++
		}
	}
	result := make([]assignment, 0, workload.Conversations)
	for _, name := range names {
		protocol, _ := protofixture.ParseProtocol(name)
		streamed := streams[name]
		for index := range counts[name] {
			result = append(result, assignment{protocol: protocol, stream: index < streamed})
		}
	}
	rng.Shuffle(len(result), func(left, right int) { result[left], result[right] = result[right], result[left] })
	return result
}

// requestRecord is what the client measured for one request.
type requestRecord struct {
	caseName  string
	group     string
	requestID string
	expect    string
	status    int
	ttfb      time.Duration
	end       time.Duration
	endAt     time.Time
	err       string
	sentBytes int
	tracked   bool
	forwarded bool
}

// driver sends the workload through the proxy's listener.
type driver struct {
	workload Workload
	proxyURL string
	upstream *protofixture.Upstream
	client   *http.Client
	newAPI   *fakeNewAPI
	tracker  *queryTracker

	mu      sync.Mutex
	records []requestRecord
}

func newDriver(workload Workload, proxyURL string, upstream *protofixture.Upstream, newAPI *fakeNewAPI, tracker *queryTracker) *driver {
	transport := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        workload.Concurrency * 2,
		MaxIdleConnsPerHost: workload.Concurrency * 2,
		DisableCompression:  true,
		IdleConnTimeout:     90 * time.Second,
	}
	return &driver{
		workload: workload, proxyURL: proxyURL, upstream: upstream, newAPI: newAPI, tracker: tracker,
		client: &http.Client{Transport: transport, Timeout: 10 * time.Minute},
	}
}

// run sends every conversation and returns when all requests have finished.
func (driver *driver) run(ctx context.Context) {
	plan := rand.New(rand.NewPCG(driver.workload.Seed, 0xbe7c))
	type job struct {
		index    int
		protocol protofixture.Protocol
		stream   bool
		branchAt int
		rng      *rand.Rand
	}
	jobs := make([]job, 0, driver.workload.Conversations)
	for index, assigned := range driver.workload.assign(plan) {
		value := job{index: index, protocol: assigned.protocol, stream: assigned.stream,
			rng: rand.New(rand.NewPCG(driver.workload.Seed, uint64(index)+0x10000))}
		if driver.workload.Turns >= 2 && plan.Float64() < driver.workload.BranchShare {
			value.branchAt = 2 + plan.IntN(driver.workload.Turns-1)
		}
		jobs = append(jobs, value)
	}
	queue := make(chan job)
	var wait sync.WaitGroup
	for range max(1, driver.workload.Concurrency) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for current := range queue {
				driver.conversation(ctx, current.index, current.protocol, current.stream, current.branchAt, current.rng)
			}
		}()
	}
	for _, value := range jobs {
		select {
		case queue <- value:
		case <-ctx.Done():
		}
	}
	close(queue)
	wait.Wait()
}

func (driver *driver) conversation(ctx context.Context, index int, protocol protofixture.Protocol, stream bool, branchAt int, rng *rand.Rand) {
	conversation := protofixture.NewConversation(protocol, stream, driver.workload.options(), index)
	abnormal := make([]protofixture.Scenario, 0)
	for _, scenario := range protofixture.AbnormalScenarios() {
		if !scenario.StreamOnly() || stream {
			abnormal = append(abnormal, scenario)
		}
	}
	for turn := 1; turn <= driver.workload.Turns && ctx.Err() == nil; turn++ {
		if rng.Float64() < driver.workload.AbnormalShare {
			if exchange, err := conversation.Abnormal(abnormal[rng.IntN(len(abnormal))]); err == nil {
				driver.send(ctx, &exchange, rng)
			}
		}
		if turn == branchAt && conversation.CanBranch() {
			fork := conversation.Fork()
			exchange := fork.Next(protofixture.ScenarioBranch, fork.MixedFeatures())
			driver.send(ctx, &exchange, rng)
		}
		exchange := conversation.Next(protofixture.ScenarioMixed, conversation.MixedFeatures())
		driver.send(ctx, &exchange, rng)
	}
}

func (driver *driver) send(ctx context.Context, exchange *protofixture.Exchange, rng *rand.Rand) {
	mode := "json"
	if exchange.Stream {
		mode = "sse"
	}
	record := requestRecord{
		caseName:  fmt.Sprintf("%s/%s/%s", exchange.Protocol, exchange.Scenario, mode),
		group:     fmt.Sprintf("%s/%s", exchange.Protocol, mode),
		expect:    exchange.Expect.Status,
		sentBytes: len(exchange.RequestBody),
		tracked:   rng.Float64() < driver.workload.LatencySample,
	}
	id := driver.upstream.Register(exchange)
	record.requestID = id
	driver.newAPI.remember(id, exchange)

	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	started := time.Now()
	var firstByte time.Time
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte = time.Now() }}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(requestCtx, trace), exchange.Method,
		driver.proxyURL+exchange.Path, bytes.NewReader(exchange.RequestBody))
	if err != nil {
		driver.upstream.Forget(id)
		record.err = "request_build"
		driver.add(record)
		return
	}
	request.Header = exchange.RequestHeader.Clone()
	request.Header.Set(protofixture.ExchangeHeader, id)
	response, err := driver.client.Do(request)
	if err != nil {
		record.err = "transport"
		record.end = time.Since(started)
		record.endAt = time.Now()
		driver.add(record)
		return
	}
	record.status = response.StatusCode
	if !firstByte.IsZero() {
		record.ttfb = firstByte.Sub(started)
	}
	if exchange.Response.ClientCancel && exchange.Response.CutAt > 0 {
		prefix := make([]byte, exchange.Response.CutAt)
		if _, err := io.ReadFull(response.Body, prefix); err != nil {
			record.err = "cancel_read"
		}
		cancel()
	} else if _, err := io.Copy(io.Discard, response.Body); err != nil {
		if exchange.Response.Abort {
			record.err = "upstream_abort_expected"
		} else {
			record.err = "body_read"
		}
	}
	record.end = time.Since(started)
	record.endAt = time.Now()
	_ = response.Body.Close()
	// The fake upstream answers with the exchange id as the NewAPI request
	// id; without it the proxy answered on its own (an interceptor
	// rejection) and the audit row carries no id to find it by.
	record.forwarded = response.Header.Get(protofixture.NewAPIRequestIDHeader) == id
	if !record.forwarded {
		driver.upstream.Forget(id)
	}
	if record.tracked && record.forwarded {
		driver.tracker.watch(id, record.endAt)
	}
	driver.add(record)
}

func (driver *driver) add(record requestRecord) {
	driver.mu.Lock()
	driver.records = append(driver.records, record)
	driver.mu.Unlock()
}

func (driver *driver) snapshotRecords() []requestRecord {
	driver.mu.Lock()
	defer driver.mu.Unlock()
	return append([]requestRecord(nil), driver.records...)
}
