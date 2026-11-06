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
// It returns the number of requests that received an inherited identity.
func InheritIdentities(requests []Request) int {
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
		if request.RootKey != "" && request.IdentityKey != "" {
			counter := roots[request.RootKey]
			if counter == nil {
				counter = &tally{counts: map[string]int{}, first: map[string]int{}}
				roots[request.RootKey] = counter
			}
			if _, seen := counter.first[request.IdentityKey]; !seen {
				counter.first[request.IdentityKey] = position
			}
			counter.counts[request.IdentityKey]++
		}
		if request.NodeKey != "" {
			nodes[request.NodeKey] = append(nodes[request.NodeKey], index)
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
				value = majority(requests[index].RootKey)
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
		if value := majority(requests[index].RootKey); value != "" {
			requests[index].IdentityKey = value
			inherited++
		}
	}
	return inherited
}
