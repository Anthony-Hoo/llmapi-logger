package orgreport

import (
	"sort"
)

// Principals carries the administrator's classification and grouping.
type Principals struct {
	// UserClass and TokenClass map ids to ClassHuman or ClassService. A token
	// entry wins over its user's entry.
	UserClass  map[int64]string
	TokenClass map[int64]string
	// Groups maps a NewAPI user to its single project group.
	Groups map[int64]int64
}

// Service reports whether a request made by user with token is booked to
// the service section, and whether the decision came from the token.
func (principals Principals) Service(userID, tokenID int64) (service, byToken bool) {
	if class, ok := principals.TokenClass[tokenID]; ok && tokenID > 0 {
		return class == ClassService, class == ClassService
	}
	return principals.UserClass[userID] == ClassService, false
}

// Flag codes attached to a ranking row; flags never exclude a row.
const (
	FlagConcurrency        = "concurrency"
	FlagSingleRequestRoots = "single_request_roots"
	FlagInferred           = "inferred_sessions"
)

// Flag explains one anomaly or caveat of a row.
type Flag struct {
	Code      string `json:"code"`
	Value     int64  `json:"value"`
	Threshold int64  `json:"threshold,omitempty"`
}

// ProjectCell is one user's usage of one project in one week.
type ProjectCell struct {
	Project  ProjectKey `json:"project"`
	ActiveNS int64      `json:"active_ns"`
	Roots    int        `json:"roots"`
	Requests int        `json:"requests"`
	Tokens   Tokens     `json:"tokens"`
	CostUSD  float64    `json:"cost_usd"`
}

// UserRow is one human user's week. ActiveNS counts ranked clients only;
// OtherActiveNS holds the clients outside ranked_clients.
type UserRow struct {
	UserID             int64         `json:"user_id"`
	GroupID            int64         `json:"group_id"`
	ActiveNS           int64         `json:"active_ns"`
	OtherActiveNS      int64         `json:"other_active_ns"`
	InferredNS         int64         `json:"inferred_ns"`
	Roots              int           `json:"roots"`
	SingleRequestRoots int           `json:"single_request_roots"`
	Requests           int           `json:"requests"`
	IdentifiedRequests int           `json:"identified_requests"`
	BilledRequests     int           `json:"billed_requests"`
	Tokens             Tokens        `json:"tokens"`
	CostUSD            float64       `json:"cost_usd"`
	PeakConcurrency    int           `json:"peak_concurrency"`
	AvgConcurrency     float64       `json:"avg_concurrency"`
	Daily              []int64       `json:"daily_active_ns"`
	Projects           []ProjectCell `json:"projects"`
	Flags              []Flag        `json:"flags"`
}

// Coverage returns identified / all requests, or 0 without requests.
func (row UserRow) Coverage() float64 {
	if row.Requests == 0 {
		return 0
	}
	return float64(row.IdentifiedRequests) / float64(row.Requests)
}

// ServiceRow is a service principal's week: a whole user (TokenID 0) or one
// service token of an otherwise human user.
type ServiceRow struct {
	UserID   int64   `json:"user_id"`
	TokenID  int64   `json:"token_id"`
	ActiveNS int64   `json:"active_ns"`
	Roots    int     `json:"roots"`
	Requests int     `json:"requests"`
	Tokens   Tokens  `json:"tokens"`
	CostUSD  float64 `json:"cost_usd"`
}

// WeekResult is the computed week. Users are sorted by ActiveNS descending
// (then user id); UserID 0 collects requests whose caller is unresolved.
type WeekResult struct {
	Users   []UserRow    `json:"users"`
	Service []ServiceRow `json:"service"`
}

// WeekInput is everything ComputeWeek reads. Requests must already carry
// their Project; they may extend beyond the week (a margin on both sides) so
// that blocks crossing a boundary are split proportionally.
type WeekInput struct {
	Week       Week
	Settings   Settings
	Requests   []Request
	Principals Principals
}

type owner struct {
	userID  int64
	tokenID int64
	service bool
}

type rootKey struct {
	owner owner
	root  string
}

type rootState struct {
	requests []*Request
}

type ownerAcc struct {
	row      UserRow
	service  ServiceRow
	projects map[ProjectKey]*ProjectCell
	roots    map[ProjectKey]map[string]struct{}
	blocks   []Interval
}

// ComputeWeek implements doc section 6.1: per root, merge request spans into
// blocks; sum roots per user (parallel roots add up); split blocks over the
// week and its days by overlap; allocate each block to projects by span
// weight; sweep concurrency over root blocks.
func ComputeWeek(input WeekInput) WeekResult {
	fromNS, toNS := input.Week.Start.UnixNano(), input.Week.End.UnixNano()
	days := input.Week.Days()
	gapNS := int64(input.Settings.IdleGap)

	owners := map[owner]*ownerAcc{}
	accFor := func(key owner) *ownerAcc {
		acc := owners[key]
		if acc == nil {
			acc = &ownerAcc{
				row:      UserRow{UserID: key.userID, GroupID: input.Principals.Groups[key.userID], Daily: make([]int64, 7)},
				service:  ServiceRow{UserID: key.userID, TokenID: key.tokenID},
				projects: map[ProjectKey]*ProjectCell{},
				roots:    map[ProjectKey]map[string]struct{}{},
			}
			owners[key] = acc
		}
		return acc
	}
	cellFor := func(acc *ownerAcc, project ProjectKey) *ProjectCell {
		cell := acc.projects[project]
		if cell == nil {
			cell = &ProjectCell{Project: project}
			acc.projects[project] = cell
		}
		return cell
	}

	roots := map[rootKey]*rootState{}
	for index := range input.Requests {
		request := &input.Requests[index]
		service, byToken := input.Principals.Service(request.UserID, request.TokenID)
		key := owner{userID: request.UserID, service: service}
		if byToken {
			key.tokenID = request.TokenID
		}
		acc := accFor(key)
		inWeek := StartsIn(request.StartNS, fromNS, toNS)
		if inWeek {
			acc.row.Requests++
			acc.row.Tokens.add(request.Tokens)
			acc.row.CostUSD += request.CostUSD
			if request.Billed {
				acc.row.BilledRequests++
			}
			if request.IdentityKey != "" {
				acc.row.IdentifiedRequests++
			}
			cell := cellFor(acc, request.Project)
			cell.Requests++
			cell.Tokens.add(request.Tokens)
			cell.CostUSD += request.CostUSD
		}
		root := request.RootKey
		if root == "" {
			if sideRole(request.Role) || request.CacheWarm {
				// An auxiliary request without any session: usage only.
				continue
			}
			// A main request without any session identity is its own root.
			root = "audit:" + request.AuditID
		}
		state := roots[rootKey{owner: key, root: root}]
		if state == nil {
			state = &rootState{}
			roots[rootKey{owner: key, root: root}] = state
		}
		state.requests = append(state.requests, request)
	}

	for key, state := range roots {
		acc := owners[key.owner]
		spans := make([]Span, 0, len(state.requests))
		clients := map[string]int{}
		inferred := false
		inWeekRequests := 0
		projectsInWeek := map[ProjectKey]struct{}{}
		for _, request := range state.requests {
			clients[request.Client]++
			inferred = inferred || request.Inferred
			if StartsIn(request.StartNS, fromNS, toNS) {
				inWeekRequests++
				projectsInWeek[request.Project] = struct{}{}
			}
			if request.CacheWarm {
				continue
			}
			spans = append(spans, Span{StartNS: request.StartNS, EndNS: request.EndNS, Project: request.Project})
		}
		// Only ranked clients feed the ranking row's project split, daily
		// curve, concurrency and single-request count; other clients' time is
		// reported as one OtherActiveNS figure.
		ranked := key.owner.service || input.Settings.RankedClients[majorityClient(clients)]
		var active int64
		for _, block := range BuildBlocks(spans, gapNS) {
			overlap := Overlap(block.StartNS, block.EndNS, fromNS, toNS)
			if overlap <= 0 {
				continue
			}
			active += overlap
			if !ranked {
				continue
			}
			acc.blocks = append(acc.blocks, Interval{StartNS: max(block.StartNS, fromNS), EndNS: min(block.EndNS, toNS)})
			for project, part := range Allocate(overlap, block.Weights) {
				cellFor(acc, project).ActiveNS += part
				projectsInWeek[project] = struct{}{}
			}
			for day := 0; day < 7; day++ {
				acc.row.Daily[day] += Overlap(block.StartNS, block.EndNS, days[day].UnixNano(), days[day+1].UnixNano())
			}
		}
		if inWeekRequests == 0 && active == 0 {
			continue
		}
		acc.row.Roots++
		acc.service.Roots++
		if ranked && len(state.requests) == 1 {
			acc.row.SingleRequestRoots++
		}
		for project := range projectsInWeek {
			if acc.roots[project] == nil {
				acc.roots[project] = map[string]struct{}{}
			}
			acc.roots[project][key.root] = struct{}{}
		}
		if ranked {
			acc.row.ActiveNS += active
		} else {
			acc.row.OtherActiveNS += active
		}
		if inferred {
			acc.row.InferredNS += active
		}
	}

	result := WeekResult{Users: []UserRow{}, Service: []ServiceRow{}}
	for key, acc := range owners {
		if acc.row.Requests == 0 && acc.row.Roots == 0 {
			continue
		}
		if key.service {
			acc.service.ActiveNS = acc.row.ActiveNS + acc.row.OtherActiveNS
			acc.service.Requests = acc.row.Requests
			acc.service.Tokens = acc.row.Tokens
			acc.service.CostUSD = acc.row.CostUSD
			result.Service = append(result.Service, acc.service)
			continue
		}
		row := acc.row
		concurrency := Sweep(acc.blocks)
		row.PeakConcurrency = concurrency.Peak
		row.AvgConcurrency = concurrency.Average()
		row.Projects = make([]ProjectCell, 0, len(acc.projects))
		for project, cell := range acc.projects {
			cell.Roots = len(acc.roots[project])
			if cell.Requests == 0 && cell.ActiveNS == 0 {
				continue
			}
			row.Projects = append(row.Projects, *cell)
		}
		sort.Slice(row.Projects, func(i, j int) bool {
			if row.Projects[i].ActiveNS != row.Projects[j].ActiveNS {
				return row.Projects[i].ActiveNS > row.Projects[j].ActiveNS
			}
			return row.Projects[i].Project < row.Projects[j].Project
		})
		row.Flags = []Flag{}
		if limit := input.Settings.MaxConcurrentRoots; limit > 0 && row.PeakConcurrency > limit {
			row.Flags = append(row.Flags, Flag{Code: FlagConcurrency, Value: int64(row.PeakConcurrency), Threshold: int64(limit)})
		}
		if limit := input.Settings.MaxSingleRequestRoots; limit > 0 && row.SingleRequestRoots > limit {
			row.Flags = append(row.Flags, Flag{Code: FlagSingleRequestRoots, Value: int64(row.SingleRequestRoots), Threshold: int64(limit)})
		}
		if row.InferredNS > 0 {
			row.Flags = append(row.Flags, Flag{Code: FlagInferred, Value: row.InferredNS})
		}
		result.Users = append(result.Users, row)
	}
	sort.Slice(result.Users, func(i, j int) bool {
		if result.Users[i].ActiveNS != result.Users[j].ActiveNS {
			return result.Users[i].ActiveNS > result.Users[j].ActiveNS
		}
		return result.Users[i].UserID < result.Users[j].UserID
	})
	sort.Slice(result.Service, func(i, j int) bool {
		if result.Service[i].UserID != result.Service[j].UserID {
			return result.Service[i].UserID < result.Service[j].UserID
		}
		return result.Service[i].TokenID < result.Service[j].TokenID
	})
	return result
}

func majorityClient(counts map[string]int) string {
	best, bestCount := "", -1
	for client, count := range counts {
		if count > bestCount || (count == bestCount && client < best) {
			best, bestCount = client, count
		}
	}
	return best
}
