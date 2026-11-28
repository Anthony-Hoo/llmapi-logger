package runner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/archive"
	"llmapi-logger/internal/archive/bundle"
	"llmapi-logger/internal/storage"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(step time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(step)
}

type harness struct {
	t       *testing.T
	fixture *fixture
	store   *fakeStore
	dir     string
	sampler *fakeSampler
	clock   *clock
	options Options
	logs    *syncBuffer
}

type syncBuffer struct {
	mu   sync.Mutex
	data strings.Builder
}

func (buffer *syncBuffer) Write(p []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.Write(p)
}

func (buffer *syncBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.data.String()
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "archive")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := testKeys(t)
	fixture := &fixture{t: t, keys: keys, payloads: newPayloads()}
	store := newFakeStore(fixture.payloads)
	c := &clock{now: time.Unix(0, baseTimeNS).Add(10 * 24 * time.Hour)}
	sampler := &fakeSampler{}
	logs := &syncBuffer{}
	h := &harness{t: t, fixture: fixture, store: store, dir: dir, sampler: sampler, clock: c, logs: logs}
	h.options = Options{
		Mode: storage.ArchiveModeExportOnly, Dir: dir, Encrypt: true, RunAt: "03:00", Location: time.UTC, RetentionDays: 1,
		SegmentMaxBytes: bundle.DefaultSegmentMaxBytes, ConversationMinTurns: 3, ConversationMinBytes: 16 << 20, PassAudits: 100,
		RunDeadline: time.Hour, VerifySample: 1, Store: store, Keys: keys, Sampler: sampler, SourceSchemaVersion: "8",
		Logger: slog.New(slog.NewJSONHandler(logs, nil)), Now: c.Now,
	}
	return h
}

func (h *harness) runner() *Runner {
	h.t.Helper()
	runner, err := New(h.options)
	if err != nil {
		h.t.Fatal(err)
	}
	return runner
}

func (h *harness) run() (Result, error) {
	h.t.Helper()
	return h.runner().RunOnce(context.Background())
}

func (h *harness) mustRun() Result {
	h.t.Helper()
	result, err := h.run()
	if err != nil || result.Status != storage.ArchiveRunCompleted {
		h.t.Fatalf("run: %+v, %v (%v)", result, err, causeOf(err))
	}
	return result
}

func causeOf(err error) error {
	for err != nil {
		next := unwrapOnce(err)
		if next == nil {
			return err
		}
		err = next
	}
	return nil
}

func unwrapOnce(err error) error {
	if wrapper, ok := err.(interface{ Unwrap() error }); ok {
		return wrapper.Unwrap()
	}
	return nil
}

func stampOf(id string, version int) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("%s/%d", id, version)))
}

// addTurnless adds a due audit without a turn.
func (h *harness) addTurnless(id, protocol string, startedNS int64) *fakeAudit {
	record := h.fixture.audit(id, protocol, startedNS)
	record = h.fixture.withRaw(record, storage.StageRequestReceived, []byte("request body of "+id), 7)
	audit := &fakeAudit{id: id, startedNS: startedNS, protocol: protocol, stamp: stampOf(id, 0), build: func() *archive.Record { return record }}
	h.store.audits[id] = audit
	return audit
}

// addConversation adds a chain of turns, one audit each, started a second
// apart from startedNS.
func (h *harness) addConversation(conversationID, protocol string, turns int, startedNS int64) []*fakeAudit {
	var parent *archive.Record
	var audits []*fakeAudit
	for index := 0; index < turns; index++ {
		id := fmt.Sprintf("%s-t%02d", conversationID, index)
		started := startedNS + int64(index)*int64(time.Second)
		record := h.fixture.audit(id, protocol, started)
		record = h.fixture.withTurn(record, conversationID, parent, started+10, "message "+id)
		parent = record
		conversation, created := conversationID, started+10
		built := record
		audit := &fakeAudit{id: id, startedNS: started, protocol: protocol, conversation: &conversation, turnCreatedNS: &created,
			stamp: stampOf(id, 0), build: func() *archive.Record { return built }}
		h.store.audits[id] = audit
		audits = append(audits, audit)
	}
	return audits
}

// bundles indexes the archive directory.
func (h *harness) bundles() []bundle.Entry {
	h.t.Helper()
	index, err := bundle.BuildIndex(context.Background(), h.dir, h.options.Keys)
	if err != nil {
		h.t.Fatal(err)
	}
	if problems := index.Problems(); len(problems) > 0 {
		h.t.Fatalf("index problems %+v", problems)
	}
	entries := index.Bundles()
	sort.Slice(entries, func(left, right int) bool { return entries[left].ManifestPath < entries[right].ManifestPath })
	return entries
}

// verifyAll re-reads every bundle.
func (h *harness) verifyAll() {
	h.t.Helper()
	for _, entry := range h.bundles() {
		read := bundle.ReadOptions{Signer: h.options.Keys, EncryptionKey: h.options.Keys.EncryptionKey()}
		opened, err := bundle.Open(entry.ManifestPath, read)
		if err != nil {
			h.t.Fatal(err)
		}
		if _, err := opened.Verify(context.Background()); err != nil {
			h.t.Fatalf("verify %s: %v", filepath.Base(entry.ManifestPath), err)
		}
	}
}

// files lists every regular file under the archive directory, relative.
func (h *harness) files() []string {
	h.t.Helper()
	var out []string
	err := filepath.Walk(h.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			relative, _ := filepath.Rel(h.dir, path)
			out = append(out, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		h.t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func countMatching(files []string, match func(string) bool) int {
	count := 0
	for _, file := range files {
		if match(file) {
			count++
		}
	}
	return count
}

func isTemp(file string) bool { return bundle.IsTempName(filepath.Base(file)) }

// requireEachOnce checks that every listed audit has exactly one sealed
// member that is not stale, and that the members match the bundles.
func (h *harness) requireEachOnce(ids ...string) {
	h.t.Helper()
	sealed := h.store.sealedMembers()
	for _, id := range ids {
		current := 0
		for _, member := range sealed[id] {
			if member.State == storage.ArchiveMemberSealed {
				current++
			}
		}
		if current != 1 {
			h.t.Fatalf("audit %s has %d current sealed members: %+v", id, current, sealed[id])
		}
	}
	inBundles := map[string]int{}
	for _, entry := range h.bundles() {
		for _, member := range entry.Manifest.Members {
			inBundles[member.AuditID]++
		}
	}
	for _, id := range ids {
		if inBundles[id] < 1 {
			h.t.Fatalf("audit %s is in no bundle", id)
		}
	}
	_ = io.Discard
}

func ids(audits []*fakeAudit) []string {
	out := make([]string, 0, len(audits))
	for _, audit := range audits {
		out = append(out, audit.id)
	}
	return out
}
