package orgreport

import "sort"

// InheritIdentities fills IdentityKey of requests that carried none
// (doc section 5.2), in place:
//
//  1. Within one agent node, a request inherits the latest earlier identified
//     request; requests before the node's first identification take that
//     first identity (Codex sends git data only after its background scan).
//  2. A node without any identified request, and a request without a node,
//     take the majority identity of its root (ties: the identity seen first).
//  3. A request without a root keeps no identity.
//
// Nodes and roots are scoped by caller (CallerKey): a request never inherits
// the identity of another caller that reused the same client session id.
//
// It returns the number of requests that received an inherited identity.
func InheritIdentities(requests []Request) int {
	scoped := func(caller, key string) string {
		if key == "" {
			return ""
		}
		return caller + "\x00" + key
	}
	rootOf := func(request Request) string { return scoped(request.CallerKey, request.RootKey) }
	nodeOf := func(request Request) string { return scoped(request.CallerKey, request.NodeKey) }
	order := make([]int, len(requests))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(i, j int) bool {
		left, right := requests[order[i]], requests[order[j]]
		if left.StartNS != right.StartNS {
			return left.StartNS < right.StartNS
		}
		return left.AuditID < right.AuditID
	})

	type tally struct {
		counts map[string]int
		first  map[string]int
	}
	roots := map[string]*tally{}
	nodes := map[string][]int{}
	for position, index := range order {
		request := requests[index]
		if root := rootOf(request); root != "" && request.IdentityKey != "" {
			counter := roots[root]
			if counter == nil {
				counter = &tally{counts: map[string]int{}, first: map[string]int{}}
				roots[root] = counter
			}
			if _, seen := counter.first[request.IdentityKey]; !seen {
				counter.first[request.IdentityKey] = position
			}
			counter.counts[request.IdentityKey]++
		}
		if node := nodeOf(request); node != "" {
			nodes[node] = append(nodes[node], index)
		}
	}
	majority := func(root string) string {
		counter := roots[root]
		if counter == nil {
			return ""
		}
		best, bestCount, bestFirst := "", 0, 0
		for key, count := range counter.counts {
			first := counter.first[key]
			if count > bestCount || (count == bestCount && first < bestFirst) {
				best, bestCount, bestFirst = key, count, first
			}
		}
		return best
	}

	inherited := 0
	assigned := make([]bool, len(requests))
	for _, members := range nodes {
		firstKnown := ""
		for _, index := range members {
			if requests[index].IdentityKey != "" {
				firstKnown = requests[index].IdentityKey
				break
			}
		}
		last := firstKnown
		for _, index := range members {
			assigned[index] = true
			if requests[index].IdentityKey != "" {
				last = requests[index].IdentityKey
				continue
			}
			value := last
			if value == "" {
				value = majority(rootOf(requests[index]))
			}
			if value != "" {
				requests[index].IdentityKey = value
				inherited++
			}
		}
	}
	for index := range requests {
		if assigned[index] || requests[index].IdentityKey != "" || requests[index].RootKey == "" {
			continue
		}
		if value := majority(rootOf(requests[index])); value != "" {
			requests[index].IdentityKey = value
			inherited++
		}
	}
	return inherited
}
