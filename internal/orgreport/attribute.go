package orgreport

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// loadMargin extends every week load on both sides so that blocks crossing a
// week boundary are split by overlap instead of being cut at the boundary.
// A block longer than the margin that crosses the boundary would be cut; that
// needs more than 24 hours of activity without a gap above the idle gap.
const loadMargin = 24 * time.Hour

// Attributed is a loaded and attributed time range.
type Attributed struct {
	Requests   []Request
	Identities map[string]Identity
	Compiled   *Compiled
}

// openIdentities decrypts each distinct identity once. A row that fails to
// decrypt is dropped (its requests count as identified but unattributed).
func (service *Service) openIdentities(sealed []SealedIdentity) map[string]Identity {
	identities := make(map[string]Identity, len(sealed))
	if service.cipher == nil {
		return identities
	}
	failures := 0
	for _, row := range sealed {
		aad, err := IdentityAAD(row.AuditID, row.Version)
		if err != nil {
			failures++
			continue
		}
		plaintext, err := service.cipher.Decrypt(aad, row.Enc)
		if err != nil {
			failures++
			continue
		}
		var identity Identity
		err = json.Unmarshal(plaintext, &identity)
		clear(plaintext)
		if err != nil {
			failures++
			continue
		}
		identities[row.Key] = identity
	}
	if failures > 0 {
		service.logger.Warn("org identity decryption failed", "error_code", "org_identity_decrypt_failed", "count", failures)
	}
	return identities
}

// load reads and attributes [fromNS, toNS) with the active catalog.
func (service *Service) load(ctx context.Context, fromNS, toNS int64) (Attributed, error) {
	if service.data == nil {
		return Attributed{}, ErrUnavailable
	}
	requests, err := service.data.LoadOrgRequests(ctx, fromNS, toNS)
	if err != nil {
		return Attributed{}, err
	}
	sealed, err := service.data.LoadOrgIdentities(ctx, fromNS, toNS)
	if err != nil {
		return Attributed{}, err
	}
	compiled := service.current.Load()
	identities := service.openIdentities(sealed)
	Attribute(requests, identities, compiled)
	return Attributed{Requests: requests, Identities: identities, Compiled: compiled}, nil
}

// Attribute runs doc section 5.2 in place: session inheritance of identity
// keys, then rule resolution per user group. Users' known repository roots
// map their working directories to repositories.
func Attribute(requests []Request, identities map[string]Identity, compiled *Compiled) {
	InheritIdentities(requests)
	roots := map[int64]map[string]struct{}{}
	for _, request := range requests {
		identity, ok := identities[request.IdentityKey]
		if !ok {
			continue
		}
		for _, root := range identity.Roots {
			if roots[request.UserID] == nil {
				roots[request.UserID] = map[string]struct{}{}
			}
			roots[request.UserID][root] = struct{}{}
		}
	}
	known := map[int64][]string{}
	for user, set := range roots {
		list := make([]string, 0, len(set))
		for root := range set {
			list = append(list, root)
		}
		sort.Strings(list)
		known[user] = list
	}
	type memo struct {
		user int64
		key  string
	}
	cache := map[memo]ProjectKey{}
	for index := range requests {
		request := &requests[index]
		if request.IdentityKey == "" {
			request.Project = ProjectNoContext
			continue
		}
		key := memo{user: request.UserID, key: request.IdentityKey}
		if project, ok := cache[key]; ok {
			request.Project = project
			continue
		}
		identity, ok := identities[request.IdentityKey]
		project := ProjectUnattributed
		if ok {
			project = compiled.Resolve(identity, compiled.GroupOf(request.UserID), known[request.UserID])
		}
		cache[key] = project
		request.Project = project
	}
}

// Label returns the display value of an unattributed identity: its first
// remote, else root, else working directory.
func (identity Identity) Label() (kind, value string) {
	switch {
	case len(identity.Remotes) != 0:
		return RuleRepoURL, identity.Remotes[0]
	case len(identity.Roots) != 0:
		return RulePathGlob, identity.Roots[0]
	case identity.Cwd != "":
		return RulePathGlob, identity.Cwd
	case identity.Declared != "":
		return RuleAgentProject, identity.Declared
	case identity.ProjectHash != "":
		return "opencode_project", identity.ProjectHash
	}
	return "", ""
}

// UnattributedEntry is one repository or directory that matched no rule.
// Values are decrypted plaintext and only ever reach administrators.
type UnattributedEntry struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Requests  int    `json:"requests"`
	Users     int    `json:"users"`
	DraftRule Rule   `json:"draft_rule"`
}

// Unattributed returns the top limit unattributed identities of a week, by
// request count.
func (service *Service) Unattributed(ctx context.Context, weekLabel string, limit int) ([]UnattributedEntry, error) {
	week, err := service.resolveWeek(weekLabel)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		return nil, ErrInvalid
	}
	attributed, err := service.load(ctx, week.Start.UnixNano(), week.End.UnixNano())
	if err != nil {
		return nil, err
	}
	type bucket struct {
		entry UnattributedEntry
		users map[int64]struct{}
	}
	buckets := map[string]*bucket{}
	for _, request := range attributed.Requests {
		if request.Project != ProjectUnattributed {
			continue
		}
		identity, ok := attributed.Identities[request.IdentityKey]
		if !ok {
			continue
		}
		kind, value := identity.Label()
		if value == "" {
			continue
		}
		slot := buckets[kind+"\x00"+value]
		if slot == nil {
			slot = &bucket{entry: UnattributedEntry{Kind: kind, Value: value, DraftRule: draftRule(kind, value)}, users: map[int64]struct{}{}}
			buckets[kind+"\x00"+value] = slot
		}
		slot.entry.Requests++
		slot.users[request.UserID] = struct{}{}
	}
	entries := make([]UnattributedEntry, 0, len(buckets))
	for _, slot := range buckets {
		slot.entry.Users = len(slot.users)
		entries = append(entries, slot.entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Requests != entries[j].Requests {
			return entries[i].Requests > entries[j].Requests
		}
		return entries[i].Value < entries[j].Value
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func draftRule(kind, value string) Rule {
	switch kind {
	case RuleRepoURL:
		return Rule{Kind: RuleRepoURL, Pattern: value}
	case RuleAgentProject:
		return Rule{Kind: RuleAgentProject, Pattern: value}
	case RulePathGlob:
		if name := RepoName(value); name != "" {
			return Rule{Kind: RuleRepoName, Pattern: name}
		}
	}
	return Rule{Kind: RulePathGlob, Pattern: value + "/**"}
}

// PreviewInput is a draft rule set to test against a week.
type PreviewInput struct {
	Week    string `json:"week"`
	GroupID *int64 `json:"group_id"`
	Rules   []Rule `json:"rules"`
	// ProjectID excludes the project being edited from "currently other".
	ProjectID int64 `json:"project_id"`
}

// PreviewResult counts what the draft rules would match.
type PreviewResult struct {
	Requests     int `json:"requests"`
	Identities   int `json:"identities"`
	Users        int `json:"users"`
	Unattributed int `json:"from_unattributed"`
	OtherProject int `json:"from_other_projects"`
}

// Preview tests draft rules against a week's identities without changing the
// catalog. A group-scoped draft only sees that group's members.
func (service *Service) Preview(ctx context.Context, input PreviewInput) (PreviewResult, error) {
	week, err := service.resolveWeek(input.Week)
	if err != nil {
		return PreviewResult{}, err
	}
	rules, err := CompileRules(normalizeRules(input.Rules))
	if err != nil {
		return PreviewResult{}, err
	}
	if len(rules) == 0 {
		return PreviewResult{}, errors.Join(ErrInvalid, errors.New("orgreport: preview needs at least one rule"))
	}
	attributed, err := service.load(ctx, week.Start.UnixNano(), week.End.UnixNano())
	if err != nil {
		return PreviewResult{}, err
	}
	result := PreviewResult{}
	identities := map[string]bool{}
	users := map[int64]struct{}{}
	matched := map[string]bool{}
	for _, request := range attributed.Requests {
		if input.GroupID != nil && attributed.Compiled.GroupOf(request.UserID) != *input.GroupID {
			continue
		}
		identity, ok := attributed.Identities[request.IdentityKey]
		if !ok {
			continue
		}
		hit, seen := matched[request.IdentityKey]
		if !seen {
			hit = MatchRules(rules, identity, identity.Roots)
			matched[request.IdentityKey] = hit
		}
		if !hit {
			continue
		}
		result.Requests++
		identities[request.IdentityKey] = true
		users[request.UserID] = struct{}{}
		switch {
		case request.Project == ProjectUnattributed:
			result.Unattributed++
		case request.Project > 0 && int64(request.Project) != input.ProjectID:
			result.OtherProject++
		}
	}
	result.Identities, result.Users = len(identities), len(users)
	return result, nil
}

// resolveWeek parses a week label; empty means the current week.
func (service *Service) resolveWeek(label string) (Week, error) {
	if label == "" {
		return service.settings.WeekOf(service.now()), nil
	}
	week, err := service.settings.ParseWeek(label)
	if err != nil {
		return Week{}, errors.Join(ErrInvalid, err)
	}
	return week, nil
}
