package backend

// This file holds the small pure helpers used to compute incremental updates
// between a previously applied State and a new one. They are pure (no I/O) so
// the diffing logic can be unit-tested directly.

// cloneIPSet returns a deep copy of an IPSet.
func cloneIPSet(s IPSet) IPSet {
	return IPSet{
		V4: append([]string(nil), s.V4...),
		V6: append([]string(nil), s.V6...),
	}
}

// cloneState returns a deep copy of a State, suitable for retaining as the
// "last applied" snapshot.
func cloneState(s State) State {
	out := State{
		Global:  cloneIPSet(s.Global),
		PerUser: make(map[int]IPSet, len(s.PerUser)),
	}
	for uid, set := range s.PerUser {
		out.PerUser[uid] = cloneIPSet(set)
	}
	return out
}

// sameUIDs reports whether two per-user maps cover exactly the same set of uids.
// When they differ, the rule/chain structure must change and a full rebuild is
// required; otherwise only set elements may have changed and an incremental
// update suffices.
func sameUIDs(a, b map[int]IPSet) bool {
	if len(a) != len(b) {
		return false
	}
	for uid := range a {
		if _, ok := b[uid]; !ok {
			return false
		}
	}
	return true
}

// diffStrings returns the elements added (present in next, not in prev) and
// removed (present in prev, not in next).
func diffStrings(prev, next []string) (added, removed []string) {
	prevSet := make(map[string]bool, len(prev))
	for _, v := range prev {
		prevSet[v] = true
	}
	nextSet := make(map[string]bool, len(next))
	for _, v := range next {
		nextSet[v] = true
	}
	for _, v := range next {
		if !prevSet[v] {
			added = append(added, v)
		}
	}
	for _, v := range prev {
		if !nextSet[v] {
			removed = append(removed, v)
		}
	}
	return added, removed
}
