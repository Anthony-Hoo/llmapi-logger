package integration_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/app"
)

// Paging journey: the cursors of the three paged facade reads (requests
// list, usage sessions, analysis sessions) followed page by page through the
// real llmaudit code against the real application on PostgreSQL, compared
// with one unpaged listing of the same query, and the cursor binding of
// contract section 0.1 items 117 and 149 checked on the real stack.

// pagingChat sends one chat completion through the audited proxy. messages
// alternate user and assistant, starting with the user; the fake gateway
// always answers "hi", so a later turn that repeats the earlier messages
// with that answer continues the same conversation.
func pagingChat(client *http.Client, baseURL, apiKey, model string, messages ...string) error {
	type message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	list := make([]message, 0, len(messages))
	for index, content := range messages {
		role := "user"
		if index%2 == 1 {
			role = "assistant"
		}
		list = append(list, message{Role: role, Content: content})
	}
	body, err := json.Marshal(map[string]any{"model": model, "stream": false, "messages": list})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+apiKey)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var discard bytes.Buffer
	_, _ = discard.ReadFrom(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("proxied response status = %d", response.StatusCode)
	}
	return nil
}

// waitForPagingPipeline waits until records audit records exist and every one
// of them is finished, parsed, normalized into a turn and analysed for
// insights, so that the listings below no longer change.
func waitForPagingPipeline(t *testing.T, dsn string, records int) {
	t.Helper()
	deadline := time.Now().Add(integrationTimeout)
	var audits, open, turns, analysed int
	for {
		db := openAuditDatabase(t, dsn)
		err := db.QueryRow(`SELECT
			(SELECT count(*) FROM audit_records),
			(SELECT count(*) FROM audit_records WHERE ended_at_ns IS NULL OR parse_status IN ('pending', 'processing')),
			(SELECT count(*) FROM turns),
			(SELECT count(*) FROM audit_analysis)`).Scan(&audits, &open, &turns, &analysed)
		_ = db.Close()
		if err != nil {
			t.Fatalf("pipeline state: %v", err)
		}
		if audits == records && open == 0 && turns == records && analysed == records {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pipeline not settled: %d audits (want %d), %d open, %d turns, %d analysed", audits, records, open, turns, analysed)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pagingPage is one page of a paged read.
type pagingPage struct {
	ids  []string
	next string
	data map[string]any
}

// readPage runs one paged read, which must succeed with complete meta, and
// returns the key field of every item and the next cursor.
func (cli *journeyCLI) readPage(key string, args ...string) pagingPage {
	cli.t.Helper()
	exit, envelope := cli.run(args...)
	if exit != 0 || !envelope.OK {
		cli.t.Fatalf("llmaudit %s = exit %d: %s", strings.Join(args, " "), exit, cli.stderr.snapshot())
	}
	if envelope.Meta == nil || !envelope.Meta.Complete || envelope.Meta.State != "ok" {
		cli.t.Fatalf("llmaudit %s meta = %+v", strings.Join(args, " "), envelope.Meta)
	}
	var data map[string]any
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		cli.t.Fatalf("llmaudit %s data = %s", strings.Join(args, " "), envelope.Data)
	}
	items, ok := data["items"].([]any)
	if !ok {
		cli.t.Fatalf("llmaudit %s has no items array: %s", strings.Join(args, " "), envelope.Data)
	}
	next, ok := data["next_cursor"].(string)
	if !ok {
		cli.t.Fatalf("llmaudit %s has no next_cursor string: %s", strings.Join(args, " "), envelope.Data)
	}
	page := pagingPage{next: next, data: data}
	for _, item := range items {
		id, _ := item.(map[string]any)[key].(string)
		if id == "" {
			cli.t.Fatalf("llmaudit %s item without %s: %v", strings.Join(args, " "), key, item)
		}
		page.ids = append(page.ids, id)
	}
	return page
}

// unpaged reads the whole list in one page of limit and requires that there
// is no next page.
func (cli *journeyCLI) unpaged(key string, limit int, args ...string) pagingPage {
	cli.t.Helper()
	page := cli.readPage(key, append(append([]string{}, args...), "--limit", strconv.Itoa(limit))...)
	if page.next != "" || len(page.ids) >= limit {
		cli.t.Fatalf("llmaudit %s --limit %d is not one complete page: %d items, next_cursor %q", strings.Join(args, " "), limit, len(page.ids), page.next)
	}
	return page
}

// followPages pages through a read from the first page until next_cursor is
// empty; limits gives the page size of each call (the last one repeats).
func (cli *journeyCLI) followPages(key string, limits []int, args ...string) ([]pagingPage, []int) {
	cli.t.Helper()
	var pages []pagingPage
	var used []int
	cursor := ""
	for call := 0; ; call++ {
		if call > 50 {
			cli.t.Fatalf("llmaudit %s: more than 50 pages", strings.Join(args, " "))
		}
		limit := limits[min(call, len(limits)-1)]
		command := append(append([]string{}, args...), "--limit", strconv.Itoa(limit))
		if cursor != "" {
			command = append(command, "--cursor", cursor)
		}
		page := cli.readPage(key, command...)
		pages = append(pages, page)
		used = append(used, limit)
		if page.next == "" {
			return pages, used
		}
		if page.next == cursor {
			cli.t.Fatalf("llmaudit %s returned the cursor it was given", strings.Join(command, " "))
		}
		cursor = page.next
	}
}

// assertPagesMatch: the pages, joined, are exactly want (no record twice,
// none missing, the same order); every page but the last is full; the last
// page is not empty unless the whole list is; its cursor is empty.
func assertPagesMatch(t *testing.T, label string, pages []pagingPage, limits []int, want []string) {
	t.Helper()
	var joined []string
	seen := map[string]int{}
	for index, page := range pages {
		for _, id := range page.ids {
			if previous, ok := seen[id]; ok {
				t.Errorf("%s: %s on page %d and again on page %d", label, id, previous+1, index+1)
			}
			seen[id] = index
		}
		joined = append(joined, page.ids...)
		last := index == len(pages)-1
		switch {
		case !last && len(page.ids) != limits[index]:
			t.Errorf("%s: page %d of %d has %d items, want %d", label, index+1, len(pages), len(page.ids), limits[index])
		case last && len(page.ids) > limits[index]:
			t.Errorf("%s: last page has %d items, more than its limit %d", label, len(page.ids), limits[index])
		case last && len(page.ids) == 0 && len(want) != 0:
			t.Errorf("%s: the last page (%d of %d) is empty: a full page before it returned a next_cursor", label, index+1, len(pages))
		case last && page.next != "":
			t.Errorf("%s: last page has cursor %q", label, page.next)
		}
	}
	if !reflect.DeepEqual(joined, want) && !(len(joined) == 0 && len(want) == 0) {
		t.Errorf("%s: pages give\n  %v\nunpaged listing gives\n  %v", label, joined, want)
	}
}

// refusedCursor runs a read that must fail with INVALID_ARGUMENT for its
// cursor with reason.
func (cli *journeyCLI) refusedCursor(reason string, args ...string) {
	cli.t.Helper()
	exit, envelope := cli.run(args...)
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != agentapi.CodeInvalidArgument || exit != agentapi.ExitCode(agentapi.CodeInvalidArgument) {
		cli.t.Fatalf("llmaudit %s = exit %d %s, want INVALID_ARGUMENT %s", strings.Join(args, " "), exit, cli.stderr.snapshot(), reason)
	}
	field, _ := envelope.Error.Details["field"].(string)
	if envelope.Error.Details["reason"] != reason || !strings.Contains(field, "cursor") {
		cli.t.Fatalf("llmaudit %s details = %v, want field cursor and reason %s", strings.Join(args, " "), envelope.Error.Details, reason)
	}
}

// tamperCursor changes one character of segment (0 version, 1 list, 2 key
// id, 3 binding, 4 tag, 5 inner position) of a c3 cursor and encodes it again.
func tamperCursor(t *testing.T, cursor string, segment int) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatalf("cursor is not base64url: %v", err)
	}
	parts := strings.SplitN(string(decoded), "|", 6)
	if len(parts) != 6 || parts[0] != "c3" {
		t.Fatalf("cursor is not a c3 cursor of six parts")
	}
	part := []byte(parts[segment])
	last := len(part) - 1
	if part[last] == 'A' {
		part[last] = 'B'
	} else {
		part[last] = 'A'
	}
	parts[segment] = string(part)
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "|")))
}

func filterIDs(page pagingPage, keep func(item map[string]any) bool) []string {
	var ids []string
	for _, item := range page.data["items"].([]any) {
		entry := item.(map[string]any)
		if keep(entry) {
			ids = append(ids, entry["audit_id"].(string))
		}
	}
	return ids
}

func TestAgentJourneyPaging(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-local","model":"model-result","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	upstream := newAPIWithTokenLogin(t, responseBody)
	cfg := journeyConfig(t, upstream.URL)
	cfg.DeveloperLogin.Enabled = true
	packageDir, _ := packJourneyPackages(t)
	running := startApp(t, cfg, app.WithAgentPackageDir(packageDir))
	client := &http.Client{Timeout: integrationTimeout}

	// The developer's records carry models starting with alpha-, the other
	// key's beta-: the model is the oracle of whose record a row is.
	// A burst sent at once, so that several records start in the same
	// second: two of the developer key, seven of the other.
	type send struct{ key, model, text string }
	burst := []send{
		{developerKeyAlpha, "alpha-single", "alpha single one"},
		{developerKeyAlpha, "alpha-single", "alpha single two"},
	}
	for index := range 7 {
		model := "beta-filter"
		if index%2 == 1 {
			model = "beta-other"
		}
		burst = append(burst, send{developerKeyBeta, model, fmt.Sprintf("beta single %d", index)})
	}
	var wait sync.WaitGroup
	errs := make(chan error, len(burst))
	for _, request := range burst {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errs <- pagingChat(client, running.baseURL, request.key, request.model, request.text)
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("burst request: %v", err)
		}
	}
	records := len(burst)
	waitForPagingPipeline(t, cfg.DatabaseURL, records)

	// A three-turn conversation of the developer key, one turn at a time.
	turn := []string{"alpha conversation opener"}
	for _, next := range []string{"alpha conversation second", "alpha conversation third"} {
		if err := pagingChat(client, running.baseURL, developerKeyAlpha, "alpha-conversation", turn...); err != nil {
			t.Fatalf("conversation turn: %v", err)
		}
		records++
		waitForPagingPipeline(t, cfg.DatabaseURL, records)
		turn = append(turn, "hi", next)
	}
	if err := pagingChat(client, running.baseURL, developerKeyAlpha, "alpha-conversation", turn...); err != nil {
		t.Fatalf("conversation turn: %v", err)
	}
	records++
	waitForPagingPipeline(t, cfg.DatabaseURL, records)

	// An administrator and a developer, each with a read token.
	var codes []string
	adminCookie := adminWebSession(t, client, running.adminURL)
	admin := newJourneyCLI(t)
	if login := admin.login(running.adminURL, pageApproval(t, client, running.adminURL, adminCookie, "read", &codes)); login["role"] != "admin" {
		t.Fatalf("administrator login %v", login)
	}
	developerCookie, status := developerLogin(t, client, running.adminURL, developerKeyAlpha)
	if developerCookie == nil {
		t.Fatalf("developer sign-in = %d", status)
	}
	developer := newJourneyCLI(t)
	if login := developer.login(running.adminURL, pageApproval(t, client, running.adminURL, developerCookie, "read", &codes)); login["role"] != "developer" {
		t.Fatalf("developer login %v", login)
	}

	// requests list. The reference: one unpaged listing of every turn.
	noCollapse := []string{"requests", "list", "--no-collapse"}
	reference := admin.unpaged("audit_id", 200, noCollapse...)
	if len(reference.ids) != records || reference.data["collapse_applied"] != false {
		t.Fatalf("unpaged listing: %d records (want %d), collapse_applied %v", len(reference.ids), records, reference.data["collapse_applied"])
	}
	// The data the paging runs on: records sharing a start second, and one
	// conversation of three turns.
	seconds := map[int64]int{}
	conversations := map[string]int{}
	for _, item := range reference.data["items"].([]any) {
		entry := item.(map[string]any)
		started, err := time.Parse(time.RFC3339Nano, fmt.Sprint(entry["started_at"]))
		if err != nil {
			t.Fatalf("started_at of %v", entry)
		}
		seconds[started.Unix()]++
		if entry["request_model_untrusted"] == "alpha-conversation" {
			conversations[fmt.Sprint(entry["conversation_id"])]++
		}
	}
	shared := 0
	for _, count := range seconds {
		shared = max(shared, count)
	}
	if shared < 2 {
		t.Fatalf("no two records share a start second: %v", seconds)
	}
	if len(conversations) != 1 || conversations[fmt.Sprint(nil)] != 0 {
		t.Fatalf("the conversation turns are not one conversation: %v", conversations)
	}
	t.Logf("%d records, at most %d in one second, %d seconds", records, shared, len(seconds))

	// Every turn, two per page.
	pages, limits := admin.followPages("audit_id", []int{2}, noCollapse...)
	assertPagesMatch(t, "admin requests list --no-collapse", pages, limits, reference.ids)

	// The page size may change between pages.
	pages, limits = admin.followPages("audit_id", []int{2, 3, 1, 4}, noCollapse...)
	assertPagesMatch(t, "admin requests list --no-collapse, changing --limit", pages, limits, reference.ids)

	// One filter: three records, so the second page is not full.
	modelFilter := []string{"requests", "list", "--model", "beta-other"}
	filtered := admin.unpaged("audit_id", 200, modelFilter...)
	if want := filterIDs(reference, func(item map[string]any) bool { return item["request_model_untrusted"] == "beta-other" }); len(want) != 3 || !reflect.DeepEqual(filtered.ids, want) {
		t.Fatalf("--model beta-other lists %v, want %v", filtered.ids, want)
	}
	pages, limits = admin.followPages("audit_id", []int{2}, modelFilter...)
	assertPagesMatch(t, "admin requests list --model beta-other", pages, limits, filtered.ids)

	// Another filter, matching every record: twelve, a multiple of the page
	// size, so the last page is full.
	statusFilter := []string{"requests", "list", "--status", "200"}
	byStatus := admin.unpaged("audit_id", 200, statusFilter...)
	if !reflect.DeepEqual(byStatus.ids, reference.ids) || len(byStatus.ids) != 12 {
		t.Fatalf("--status 200 lists %v, want every record %v (twelve)", byStatus.ids, reference.ids)
	}
	pages, limits = admin.followPages("audit_id", []int{2}, statusFilter...)
	assertPagesMatch(t, "admin requests list --status 200", pages, limits, byStatus.ids)

	// The default collapsing: one row per conversation.
	collapsedList := []string{"requests", "list"}
	collapsed := admin.unpaged("audit_id", 200, collapsedList...)
	if collapsed.data["collapse_applied"] != true || len(collapsed.ids) != records-2 {
		t.Fatalf("collapsed listing: %d rows (want %d), collapse_applied %v", len(collapsed.ids), records-2, collapsed.data["collapse_applied"])
	}
	pages, limits = admin.followPages("audit_id", []int{2}, collapsedList...)
	assertPagesMatch(t, "admin requests list", pages, limits, collapsed.ids)

	// The developer: the union of the pages is exactly the developer key's
	// records, nothing of the other key.
	ownTurns := filterIDs(reference, func(item map[string]any) bool {
		return strings.HasPrefix(fmt.Sprint(item["request_model_untrusted"]), "alpha-")
	})
	if len(ownTurns) != 5 {
		t.Fatalf("the developer key has %d records, want 5", len(ownTurns))
	}
	ownReference := developer.unpaged("audit_id", 200, noCollapse...)
	if !reflect.DeepEqual(ownReference.ids, ownTurns) {
		t.Fatalf("developer unpaged listing %v, want %v", ownReference.ids, ownTurns)
	}
	pages, limits = developer.followPages("audit_id", []int{2}, noCollapse...)
	assertPagesMatch(t, "developer requests list --no-collapse", pages, limits, ownTurns)
	ownCollapsed := developer.unpaged("audit_id", 200, collapsedList...)
	wantCollapsed := filterIDs(collapsed, func(item map[string]any) bool {
		return strings.HasPrefix(fmt.Sprint(item["request_model_untrusted"]), "alpha-")
	})
	if ownCollapsed.data["collapse_applied"] != true || len(wantCollapsed) != 3 || !reflect.DeepEqual(ownCollapsed.ids, wantCollapsed) {
		t.Fatalf("developer collapsed listing %v (collapse_applied %v), want %v", ownCollapsed.ids, ownCollapsed.data["collapse_applied"], wantCollapsed)
	}
	pages, limits = developer.followPages("audit_id", []int{2}, collapsedList...)
	assertPagesMatch(t, "developer requests list", pages, limits, wantCollapsed)

	// Cursor binding on the real stack.
	adminCursor := admin.readPage("audit_id", append(append([]string{}, noCollapse...), "--limit", "2")...).next
	developerCursor := developer.readPage("audit_id", append(append([]string{}, noCollapse...), "--limit", "2")...).next
	filterCursor := admin.readPage("audit_id", append(append([]string{}, modelFilter...), "--limit", "2")...).next
	if adminCursor == "" || developerCursor == "" || filterCursor == "" {
		t.Fatal("a first page of two has no next_cursor")
	}
	// Another identity, with the same arguments, both ways.
	developer.refusedCursor("cursor_query_mismatch", append(append([]string{}, noCollapse...), "--limit", "2", "--cursor", adminCursor)...)
	admin.refusedCursor("cursor_query_mismatch", append(append([]string{}, noCollapse...), "--limit", "2", "--cursor", developerCursor)...)
	// Another filter set: another value, an added filter, a dropped one.
	admin.refusedCursor("cursor_query_mismatch", "requests", "list", "--model", "beta-filter", "--limit", "2", "--cursor", filterCursor)
	admin.refusedCursor("cursor_query_mismatch", "requests", "list", "--no-collapse", "--status", "200", "--limit", "2", "--cursor", adminCursor)
	admin.refusedCursor("cursor_query_mismatch", "requests", "list", "--limit", "2", "--cursor", filterCursor)
	// One character changed: in the version, in the tag, in the position.
	versionChanged := []byte(adminCursor)
	versionChanged[0]++
	admin.refusedCursor("invalid_cursor", append(append([]string{}, noCollapse...), "--limit", "2", "--cursor", string(versionChanged))...)
	admin.refusedCursor("invalid_cursor", append(append([]string{}, noCollapse...), "--limit", "2", "--cursor", tamperCursor(t, adminCursor, 4))...)
	admin.refusedCursor("invalid_cursor", append(append([]string{}, noCollapse...), "--limit", "2", "--cursor", tamperCursor(t, adminCursor, 5))...)
	// Only --limit changed: accepted, and it continues where the first page ended.
	if page := admin.readPage("audit_id", append(append([]string{}, noCollapse...), "--limit", "5", "--cursor", adminCursor)...); !reflect.DeepEqual(page.ids, reference.ids[2:7]) {
		t.Fatalf("next page with --limit 5 = %v, want %v", page.ids, reference.ids[2:7])
	}

	// usage sessions: one card per conversation, here one per standalone
	// request plus the three-turn conversation.
	usageArgs := []string{"usage", "sessions", "--since", "1h"}
	usage := admin.unpaged("session_id", 100, usageArgs...)
	if len(usage.ids) != records-2 {
		t.Fatalf("usage sessions lists %d cards, want %d", len(usage.ids), records-2)
	}
	pages, limits = admin.followPages("session_id", []int{1}, usageArgs...)
	assertPagesMatch(t, "admin usage sessions", pages, limits, usage.ids)
	// Sorted by tokens: every standalone request used the same tokens, so
	// the sort key ties across pages.
	byTokens := append(append([]string{}, usageArgs...), "--sort", "tokens")
	usageByTokens := admin.unpaged("session_id", 100, byTokens...)
	pages, limits = admin.followPages("session_id", []int{1}, byTokens...)
	assertPagesMatch(t, "admin usage sessions --sort tokens", pages, limits, usageByTokens.ids)
	ownUsage := developer.unpaged("session_id", 100, usageArgs...)
	if len(ownUsage.ids) != 3 {
		t.Fatalf("developer usage sessions lists %v, want 3 cards", ownUsage.ids)
	}
	for _, id := range ownUsage.ids {
		if !strings.Contains(strings.Join(usage.ids, " "), id) {
			t.Fatalf("developer card %s is not in the administrator's list", id)
		}
	}
	pages, limits = developer.followPages("session_id", []int{1}, usageArgs...)
	assertPagesMatch(t, "developer usage sessions", pages, limits, ownUsage.ids)
	usageCursor := admin.readPage("session_id", append(append([]string{}, usageArgs...), "--limit", "1")...).next
	developer.refusedCursor("cursor_query_mismatch", append(append([]string{}, usageArgs...), "--limit", "1", "--cursor", usageCursor)...)
	admin.refusedCursor("cursor_query_mismatch", append(append([]string{}, byTokens...), "--limit", "1", "--cursor", usageCursor)...)
	admin.refusedCursor("invalid_cursor", append(append([]string{}, usageArgs...), "--limit", "1", "--cursor", tamperCursor(t, usageCursor, 5))...)

	// analysis sessions: a session is analysed only after it has been idle
	// for session_analysis.session_idle_minutes, at least 5 minutes, so this
	// test cannot populate it. The read is paged anyway: whatever rows exist
	// (none here) must come out the same.
	analysisArgs := []string{"analysis", "sessions", "--since", "1h"}
	for _, cli := range []*journeyCLI{admin, developer} {
		analysis := cli.unpaged("session_id", 200, analysisArgs...)
		pages, limits = cli.followPages("session_id", []int{1}, analysisArgs...)
		assertPagesMatch(t, "analysis sessions", pages, limits, analysis.ids)
		t.Logf("analysis sessions: %d rows in %d pages", len(analysis.ids), len(pages))
	}
}
