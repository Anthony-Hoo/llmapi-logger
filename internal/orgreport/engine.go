package orgreport

import (
	"sort"
)

// Span is one request interval [StartNS, EndNS] in Unix nanoseconds, weighted
// towards a project. A span whose end precedes its start is a point.
type Span struct {
	StartNS int64
	EndNS   int64
	Project ProjectKey
}

func (span Span) end() int64 {
	if span.EndNS < span.StartNS {
		return span.StartNS
	}
	return span.EndNS
}

// Block is a maximal run of spans of one root whose gaps are at most the idle
// gap. Its active time is EndNS-StartNS, idle gaps inside it included, the
// same way tokscale sessionizes messages (doc section 2.3).
type Block struct {
	StartNS int64
	EndNS   int64
	// Weights is the summed span duration per project inside the block. When
	// every span is a point the weights are span counts instead.
	Weights map[ProjectKey]int64
	Spans   int
}

// Duration returns the active time of the block.
func (block Block) Duration() int64 { return block.EndNS - block.StartNS }

// BuildBlocks merges the spans of one root. A span joins the current block
// when it starts no later than the block end plus gapNS (so a gap of exactly
// gapNS merges). Spans need not be sorted; the input is not modified.
func BuildBlocks(spans []Span, gapNS int64) []Block {
	if len(spans) == 0 {
		return nil
	}
	ordered := append([]Span(nil), spans...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].StartNS != ordered[j].StartNS {
			return ordered[i].StartNS < ordered[j].StartNS
		}
		return ordered[i].end() < ordered[j].end()
	})
	blocks := make([]Block, 0, 4)
	durations := map[ProjectKey]int64{}
	counts := map[ProjectKey]int64{}
	current := Block{StartNS: ordered[0].StartNS, EndNS: ordered[0].end()}
	flush := func() {
		current.Weights = durations
		positive := false
		for _, value := range durations {
			if value > 0 {
				positive = true
				break
			}
		}
		if !positive {
			current.Weights = counts
		}
		blocks = append(blocks, current)
		durations, counts = map[ProjectKey]int64{}, map[ProjectKey]int64{}
	}
	for index, span := range ordered {
		if index > 0 && span.StartNS > current.EndNS+gapNS {
			flush()
			current = Block{StartNS: span.StartNS, EndNS: span.end()}
		}
		if end := span.end(); end > current.EndNS {
			current.EndNS = end
		}
		current.Spans++
		durations[span.Project] += span.end() - span.StartNS
		counts[span.Project]++
	}
	flush()
	return blocks
}

// Allocate splits an amount of active time over the block's projects in
// proportion to their weights. The parts always sum to amount exactly: the
// rounding remainder goes to the heaviest project (lowest key on ties).
func Allocate(amount int64, weights map[ProjectKey]int64) map[ProjectKey]int64 {
	result := make(map[ProjectKey]int64, len(weights))
	if amount <= 0 || len(weights) == 0 {
		return result
	}
	keys := make([]ProjectKey, 0, len(weights))
	var total int64
	for key, weight := range weights {
		if weight <= 0 {
			continue
		}
		keys = append(keys, key)
		total += weight
	}
	if total == 0 {
		return result
	}
	sort.Slice(keys, func(i, j int) bool {
		if weights[keys[i]] != weights[keys[j]] {
			return weights[keys[i]] > weights[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var assigned int64
	for _, key := range keys {
		part := mulDiv(amount, weights[key], total)
		result[key] = part
		assigned += part
	}
	result[keys[0]] += amount - assigned
	return result
}

// mulDiv returns a*b/c without overflowing for the nanosecond magnitudes used
// here (a week is ~6e14 ns; weights are bounded by the same order).
func mulDiv(a, b, c int64) int64 {
	if c == 0 {
		return 0
	}
	return int64(float64(a) * (float64(b) / float64(c)))
}

// Overlap returns the part of [startNS, endNS) that falls inside the window
// [fromNS, toNS). A zero-length block belongs to the window containing its
// start and contributes nothing.
func Overlap(startNS, endNS, fromNS, toNS int64) int64 {
	if endNS <= startNS {
		return 0
	}
	low, high := max(startNS, fromNS), min(endNS, toNS)
	if high <= low {
		return 0
	}
	return high - low
}

// StartsIn reports whether a point at ns falls in [fromNS, toNS).
func StartsIn(ns, fromNS, toNS int64) bool { return ns >= fromNS && ns < toNS }

// Concurrency is the sweep-line result over root blocks.
type Concurrency struct {
	// Peak is the largest number of root blocks active at one instant.
	Peak int
	// BusyNS is the length of the union of all blocks.
	BusyNS int64
	// SumNS is the summed length of all blocks (parallel time counted once
	// per root). Average concurrency while busy is SumNS / BusyNS.
	SumNS int64
}

// Average returns the mean number of concurrent roots while at least one was
// active, or 0.
func (concurrency Concurrency) Average() float64 {
	if concurrency.BusyNS <= 0 {
		return 0
	}
	return float64(concurrency.SumNS) / float64(concurrency.BusyNS)
}

// Interval is a half-open [StartNS, EndNS) range used by the sweep.
type Interval struct{ StartNS, EndNS int64 }

// Sweep counts concurrent intervals. Touching intervals (one ends exactly
// where the next starts) are not concurrent. Zero-length intervals count
// towards Peak only, never towards time.
func Sweep(intervals []Interval) Concurrency {
	type event struct {
		at    int64
		delta int
	}
	events := make([]event, 0, 2*len(intervals))
	result := Concurrency{}
	for _, interval := range intervals {
		if interval.EndNS < interval.StartNS {
			continue
		}
		if interval.EndNS == interval.StartNS {
			if result.Peak == 0 {
				result.Peak = 1
			}
			continue
		}
		result.SumNS += interval.EndNS - interval.StartNS
		events = append(events, event{interval.StartNS, 1}, event{interval.EndNS, -1})
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at != events[j].at {
			return events[i].at < events[j].at
		}
		return events[i].delta < events[j].delta // ends before starts
	})
	active := 0
	var busyStart int64
	for _, current := range events {
		if current.delta > 0 && active == 0 {
			busyStart = current.at
		}
		active += current.delta
		if active > result.Peak {
			result.Peak = active
		}
		if current.delta < 0 && active == 0 {
			result.BusyNS += current.at - busyStart
		}
	}
	return result
}
