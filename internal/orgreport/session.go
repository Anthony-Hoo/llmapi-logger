package orgreport

import (
	"context"
	"sort"
)

// SessionInput is what attributing one analysis session reads: the requests
// of one agent-tree root sent with one API key, in start order, and the
// sealed identities they carry.
type SessionInput struct {
	Requests []Request
	// Extracted counts the requests that have a project identity row, with or
	// without a signal. The others have not been through the extractor yet.
	Extracted  int
	Identities []SealedIdentity
}

// SessionDataStore reads one analysis session's attribution input.
type SessionDataStore interface {
	LoadOrgSession(ctx context.Context, agentRootFPR, apiKeyFPR []byte) (SessionInput, error)
}

// SessionProject is where one analysis session is booked (doc 24 section 6.1).
type SessionProject struct {
	// Known is false while no verdict is possible: no request carried a
	// project signal and some have not been through the extractor yet.
	Known bool
	// Project is a positive project id or one of the two unmatched buckets.
	Project ProjectKey
	// Name and Level describe a matched project: its name and the strongest
	// signal level a rule matched at.
	Name  string
	Level string
	// Service marks a caller classified as a service principal.
	Service bool
}

// ResolveSession attributes one analysis session with the active catalog. It
// reads only that session's own requests, so the requests another API key
// sent under the same client session id never influence the result.
func (service *Service) ResolveSession(ctx context.Context, agentRootFPR, apiKeyFPR []byte) (SessionProject, error) {
	store, ok := service.data.(SessionDataStore)
	if !ok {
		return SessionProject{}, ErrUnavailable
	}
	input, err := store.LoadOrgSession(ctx, agentRootFPR, apiKeyFPR)
	if err != nil {
		return SessionProject{}, err
	}
	return ResolveSession(input.Requests, input.Extracted, service.openIdentities(input.Identities), service.current.Load()), nil
}

// ProjectName returns the current name of a project, or "" when it is gone.
func (service *Service) ProjectName(id int64) string {
	return service.current.Load().ProjectName(id)
}

// ResolveSession reduces the per-request attribution of one session's
// requests (in start order) to a single booking:
//
//   - a matched project wins over the unmatched buckets; among several
//     projects the one with the most requests, then the one seen first;
//   - otherwise "unattributed" when any request carried a repository or
//     path, else "no project context";
//   - working directories map to the repository roots seen in this session.
//
// requests is modified in place (identity inheritance and Project).
func ResolveSession(requests []Request, extracted int, identities map[string]Identity, compiled *Compiled) SessionProject {
	result := SessionProject{Project: ProjectNoContext}
	if len(requests) == 0 {
		return result
	}
	userID, tokenID := int64(0), int64(0)
	for _, request := range requests {
		if userID == 0 {
			userID = request.UserID
		}
		if tokenID == 0 {
			tokenID = request.TokenID
		}
	}
	result.Service = compiled.IsService(userID, tokenID)

	InheritIdentities(requests)
	rootSet := map[string]struct{}{}
	for _, request := range requests {
		for _, root := range identities[request.IdentityKey].Roots {
			rootSet[root] = struct{}{}
		}
	}
	roots := make([]string, 0, len(rootSet))
	for root := range rootSet {
		roots = append(roots, root)
	}
	sort.Strings(roots)

	type verdict struct {
		project ProjectKey
		level   string
	}
	type tally struct {
		count int
		first int
		level string
	}
	group := compiled.GroupOf(userID)
	cache := map[string]verdict{}
	projects := map[ProjectKey]*tally{}
	withPath := false
	for position := range requests {
		request := &requests[position]
		if request.IdentityKey == "" {
			request.Project = ProjectNoContext
			continue
		}
		resolved, seen := cache[request.IdentityKey]
		if !seen {
			resolved = verdict{project: ProjectUnattributed}
			if identity, ok := identities[request.IdentityKey]; ok {
				resolved.project, resolved.level = compiled.ResolveLevel(identity, group, roots)
			}
			cache[request.IdentityKey] = resolved
		}
		request.Project = resolved.project
		switch {
		case resolved.project > 0:
			entry := projects[resolved.project]
			if entry == nil {
				entry = &tally{first: position, level: resolved.level}
				projects[resolved.project] = entry
			}
			entry.count++
			if LevelRank(resolved.level) < LevelRank(entry.level) {
				entry.level = resolved.level
			}
		case resolved.project == ProjectUnattributed:
			withPath = true
		}
	}
	if len(projects) != 0 {
		var best *tally
		for project, entry := range projects {
			if best == nil || entry.count > best.count || (entry.count == best.count && entry.first < best.first) {
				best, result.Project = entry, project
			}
		}
		result.Known, result.Level = true, best.level
		result.Name = compiled.ProjectName(int64(result.Project))
		return result
	}
	if withPath {
		result.Known, result.Project = true, ProjectUnattributed
		return result
	}
	result.Known = extracted >= len(requests)
	return result
}
