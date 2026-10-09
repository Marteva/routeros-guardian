package detect

// Behaviour drift (model.AlertBehaviorDrift) is not implemented in the MVP.
//
// TODO(drift): weekly job (from Tick, once per ISO week) comparing the set of
// destination countries/ASNs weighted by bytes of the last 7 days with the
// previous 3 weeks (weighted Jaccard distance). Alert only for strict kinds
// when distance ≥ 0.6 AND the previous weeks were mutually similar
// (distance ≤ 0.2), i.e. a stable device whose profile suddenly changed.
// This needs per-week destination aggregates, which model.Store does not
// expose yet (DestStats only has FirstSeen/LastSeen/Bytes totals), so it is
// deferred until the store can provide e.g. DestStatsBetween(mac, from, to).

// jaccard returns the Jaccard distance (1 - |A∩B|/|A∪B|) of two sets; it is
// the building block the drift detector will use.
func jaccard[K comparable](a, b map[K]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	return 1 - float64(inter)/float64(union)
}
