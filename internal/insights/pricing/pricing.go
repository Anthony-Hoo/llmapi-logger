// Package pricing estimates request cost from an embedded price snapshot and an
// optional local override file. It never performs network requests: prices are
// list-price estimates that must be refreshed by editing prices.json or by
// supplying insights.pricing_file.
package pricing

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"llmapi-logger/internal/insights"
)

//go:embed prices.json
var embeddedPrices []byte

// ScheduleGranularityMinutes is the resolution of schedule boundaries. Usage is
// aggregated into slots of this length and each slot is priced at its start, so
// a boundary that falls inside a slot would misprice the requests around it.
const ScheduleGranularityMinutes = 30

// maxPriceFileBytes bounds the override file so a wrong path cannot exhaust memory.
const maxPriceFileBytes = 4 << 20

// Entry is the price of one model in USD per one million tokens.
type Entry struct {
	Input         float64  `json:"input"`
	Output        float64  `json:"output"`
	CacheRead     *float64 `json:"cache_read,omitempty"`  // nil: falls back to Input
	CacheWrite    *float64 `json:"cache_write,omitempty"` // nil: falls back to Input
	ContextWindow int64    `json:"context,omitempty"`     // 0: unknown
}

// Schedule multiplies the cost of matching requests, for example off-peak
// discounts. Times are UTC. A window whose End is not after its Start wraps
// past midnight and its Weekdays refer to the day the window started. The first
// matching schedule wins. Start and End must fall on a 30-minute boundary
// (ScheduleGranularityMinutes).
type Schedule struct {
	Model      string  `json:"model"`    // glob, case-insensitive, matched against the id and the bare name
	Weekdays   []int   `json:"weekdays"` // 0 = Sunday; empty means every day
	Start      string  `json:"start"`    // HH:MM
	End        string  `json:"end"`      // HH:MM
	Multiplier float64 `json:"multiplier"`

	startMinute, endMinute int
}

type file struct {
	Snapshot  string           `json:"snapshot,omitempty"`
	Note      string           `json:"note,omitempty"`
	Models    map[string]Entry `json:"models"`
	Schedules []Schedule       `json:"schedules,omitempty"`
}

// Table resolves model names to prices. It is immutable and safe for
// concurrent use.
type Table struct {
	entries   map[string]Entry
	byBare    map[string][]string // bare model name -> full ids
	bares     []string            // distinct bare names, longest first
	schedules []Schedule
	snapshot  string
}

// Load returns the embedded snapshot merged with the optional override file.
// Override entries replace embedded entries with the same id; override
// schedules are appended. An unreadable or invalid override is an error.
func Load(overridePath string) (*Table, error) {
	base, err := decode(embeddedPrices)
	if err != nil {
		return nil, fmt.Errorf("pricing: embedded snapshot: %w", err)
	}
	table := &Table{entries: map[string]Entry{}, snapshot: base.Snapshot}
	table.merge(base)
	if overridePath != "" {
		handle, err := os.Open(overridePath)
		if err != nil {
			return nil, fmt.Errorf("pricing: open override file: %w", err)
		}
		defer handle.Close()
		buffer := new(bytes.Buffer)
		if _, err := buffer.ReadFrom(io.LimitReader(handle, maxPriceFileBytes+1)); err != nil {
			return nil, fmt.Errorf("pricing: read override file: %w", err)
		}
		if buffer.Len() > maxPriceFileBytes {
			return nil, errors.New("pricing: override file is too large")
		}
		override, err := decode(buffer.Bytes())
		if err != nil {
			return nil, fmt.Errorf("pricing: override file: %w", err)
		}
		table.merge(override)
	}
	table.index()
	return table, nil
}

func decode(data []byte) (file, error) {
	var parsed file
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil {
		return file{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return file{}, errors.New("unexpected trailing data")
	}
	normalized := make(map[string]Entry, len(parsed.Models))
	for id, entry := range parsed.Models {
		key := strings.ToLower(strings.TrimSpace(id))
		if key == "" || strings.ContainsAny(key, " \t\r\n\x00") {
			return file{}, fmt.Errorf("invalid model id %q", id)
		}
		if _, duplicate := normalized[key]; duplicate {
			return file{}, fmt.Errorf("duplicate model id %q", id)
		}
		if err := entry.validate(); err != nil {
			return file{}, fmt.Errorf("model %q: %w", id, err)
		}
		normalized[key] = entry
	}
	parsed.Models = normalized
	for index := range parsed.Schedules {
		if err := parsed.Schedules[index].prepare(); err != nil {
			return file{}, fmt.Errorf("schedule %d: %w", index, err)
		}
	}
	return parsed, nil
}

func (entry Entry) validate() error {
	for _, value := range []float64{entry.Input, entry.Output} {
		if !validRate(value) {
			return errors.New("rates must be finite and not negative")
		}
	}
	for _, value := range []*float64{entry.CacheRead, entry.CacheWrite} {
		if value != nil && !validRate(*value) {
			return errors.New("rates must be finite and not negative")
		}
	}
	if entry.ContextWindow < 0 {
		return errors.New("context must not be negative")
	}
	return nil
}

func validRate(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func (schedule *Schedule) prepare() error {
	schedule.Model = strings.ToLower(strings.TrimSpace(schedule.Model))
	if schedule.Model == "" {
		return errors.New("model glob is required")
	}
	if _, err := path.Match(schedule.Model, ""); err != nil {
		return errors.New("invalid model glob")
	}
	var err error
	if schedule.startMinute, err = parseClock(schedule.Start); err != nil {
		return err
	}
	if schedule.endMinute, err = parseClock(schedule.End); err != nil {
		return err
	}
	for _, minute := range []int{schedule.startMinute, schedule.endMinute} {
		if minute%ScheduleGranularityMinutes != 0 {
			return fmt.Errorf("start and end must fall on a %d-minute boundary (minutes 00 or 30)", ScheduleGranularityMinutes)
		}
	}
	if schedule.startMinute == schedule.endMinute {
		return errors.New("start and end must differ")
	}
	if !(schedule.Multiplier > 0) || math.IsInf(schedule.Multiplier, 0) || schedule.Multiplier > 100 {
		return errors.New("multiplier must be in (0, 100]")
	}
	for _, day := range schedule.Weekdays {
		if day < 0 || day > 6 {
			return errors.New("weekdays must be 0 (Sunday) to 6")
		}
	}
	return nil
}

func parseClock(value string) (int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil || parsed.Format("15:04") != value {
		return 0, fmt.Errorf("invalid time %q, want HH:MM", value)
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func (table *Table) merge(source file) {
	for id, entry := range source.Models {
		table.entries[id] = entry
	}
	table.schedules = append(table.schedules, source.Schedules...)
}

func (table *Table) index() {
	table.byBare = make(map[string][]string, len(table.entries))
	for id := range table.entries {
		bare := bareName(id)
		table.byBare[bare] = append(table.byBare[bare], id)
	}
	for _, ids := range table.byBare {
		sort.Strings(ids)
	}
	table.bares = table.bares[:0]
	for bare := range table.byBare {
		table.bares = append(table.bares, bare)
	}
	sort.Slice(table.bares, func(i, j int) bool {
		if len(table.bares[i]) != len(table.bares[j]) {
			return len(table.bares[i]) > len(table.bares[j])
		}
		return table.bares[i] < table.bares[j]
	})
}

func bareName(id string) string {
	if index := strings.LastIndex(id, "/"); index >= 0 {
		return id[index+1:]
	}
	return id
}

// Snapshot reports the date recorded in the embedded price snapshot.
func (table *Table) Snapshot() string {
	if table == nil {
		return ""
	}
	return table.snapshot
}

// HasSchedules reports whether any time-of-day multiplier is configured, in
// which case callers must price by request time rather than in bulk.
func (table *Table) HasSchedules() bool {
	return table != nil && len(table.schedules) != 0
}

// Lookup resolves a model name: exact id (case-insensitive), then the id with
// its provider prefix stripped, then the longest known family that the name
// extends with a "-", "@" or ":" suffix (a dated release). Anything ambiguous
// is unknown.
func (table *Table) Lookup(model string) (Entry, bool) {
	entry, _, ok := table.lookup(model)
	return entry, ok
}

func (table *Table) lookup(model string) (Entry, string, bool) {
	if table == nil {
		return Entry{}, "", false
	}
	name := strings.ToLower(strings.TrimSpace(model))
	if name == "" {
		return Entry{}, "", false
	}
	if entry, ok := table.entries[name]; ok {
		return entry, name, true
	}
	bare := bareName(name)
	if bare == "" {
		return Entry{}, "", false
	}
	if ids, ok := table.byBare[bare]; ok {
		if len(ids) == 1 {
			return table.entries[ids[0]], ids[0], true
		}
		return Entry{}, "", false
	}
	for _, candidate := range table.bares {
		if len(candidate) >= len(bare) || !strings.HasPrefix(bare, candidate) {
			continue
		}
		if separator := bare[len(candidate)]; separator != '-' && separator != '@' && separator != ':' {
			continue
		}
		// bares is longest first, so the first hit is the longest family and
		// the only question is whether it is shared between providers.
		if ids := table.byBare[candidate]; len(ids) == 1 {
			return table.entries[ids[0]], ids[0], true
		}
		return Entry{}, "", false
	}
	return Entry{}, "", false
}

// ContextWindow returns the model's context window, or nil when unknown.
func (table *Table) ContextWindow(model string) *int64 {
	entry, ok := table.Lookup(model)
	if !ok || entry.ContextWindow <= 0 {
		return nil
	}
	window := entry.ContextWindow
	return &window
}

// Cost estimates the USD cost of one request, or nil when the model has no
// known price. Missing cache rates fall back to the input rate.
func (table *Table) Cost(usage insights.Usage, model string, startedAt time.Time) *float64 {
	return table.CostTokens(model, startedAt,
		deref(usage.UncachedInput), deref(usage.CacheRead), deref(usage.CacheWrite), deref(usage.Output))
}

// CostTokens is Cost for already summed buckets.
func (table *Table) CostTokens(model string, startedAt time.Time, uncached, cacheRead, cacheWrite, output int64) *float64 {
	entry, id, ok := table.lookup(model)
	if !ok {
		return nil
	}
	readRate, writeRate := entry.Input, entry.Input
	if entry.CacheRead != nil {
		readRate = *entry.CacheRead
	}
	if entry.CacheWrite != nil {
		writeRate = *entry.CacheWrite
	}
	cost := (float64(uncached)*entry.Input + float64(cacheRead)*readRate +
		float64(cacheWrite)*writeRate + float64(output)*entry.Output) / 1e6
	cost *= table.multiplier(id, startedAt)
	return &cost
}

func (table *Table) multiplier(id string, at time.Time) float64 {
	if len(table.schedules) == 0 || at.IsZero() {
		return 1
	}
	at = at.UTC()
	minute := at.Hour()*60 + at.Minute()
	bare := bareName(id)
	for _, schedule := range table.schedules {
		if !globMatches(schedule.Model, id) && !globMatches(schedule.Model, bare) {
			continue
		}
		var weekday time.Weekday
		switch {
		case schedule.startMinute < schedule.endMinute:
			if minute < schedule.startMinute || minute >= schedule.endMinute {
				continue
			}
			weekday = at.Weekday()
		case minute >= schedule.startMinute:
			weekday = at.Weekday()
		case minute < schedule.endMinute:
			weekday = (at.Weekday() + 6) % 7
		default:
			continue
		}
		if len(schedule.Weekdays) != 0 && !containsInt(schedule.Weekdays, int(weekday)) {
			continue
		}
		return schedule.Multiplier
	}
	return 1
}

func globMatches(pattern, value string) bool {
	matched, err := path.Match(pattern, value)
	return err == nil && matched
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func deref(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
