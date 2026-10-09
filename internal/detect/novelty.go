package detect

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// destRetry is how long to wait after a failed DestStats load. Without the
// known-destination set every destination would look new, so novelty is
// simply skipped for the device until the load succeeds.
const destRetry = 5 * time.Minute

// ensureDest lazily loads the device's known countries/ASNs from the store.
func (e *Engine) ensureDest(ctx context.Context, st *devState, t time.Time) {
	if st.destLoaded || (!st.destRetryAt.IsZero() && t.Before(st.destRetryAt)) {
		return
	}
	ds, err := e.store.DestStats(ctx, st.dev.MAC)
	if err != nil {
		e.log.Warn("load dest stats", "mac", st.dev.MAC, "err", err)
		st.destRetryAt = t.Add(destRetry)
		return
	}
	hs, err := e.store.HourStats(ctx, st.dev.MAC, t.Add(-e.cfg.BaselineWindow), t.UTC().Truncate(time.Hour))
	if err != nil {
		e.log.Warn("load hour stats", "mac", st.dev.MAC, "err", err)
		st.destRetryAt = t.Add(destRetry)
		return
	}
	st.activeHours = len(hs)
	st.countries = make(map[string]struct{})
	prof := e.profile(st)
	if prof.NewASN {
		st.asns = make(map[uint32]struct{})
	}
	for _, d := range ds {
		if d.Country != "" {
			st.countries[d.Country] = struct{}{}
			e.household[d.Country] = struct{}{}
		}
		if st.asns != nil && d.ASN != 0 {
			st.asns[d.ASN] = struct{}{}
		}
	}
	if prof.ASNMaxKnown > 0 && len(st.asns) > prof.ASNMaxKnown {
		st.asns = nil // unstable destination set: ASN novelty is meaningless
	}
	st.destLoaded = true
}

func (p *pending) add(f *model.FlowSample) {
	p.tx += f.TxBytes
	p.rx += f.RxBytes
	if f.NewConn {
		p.conns++
	}
	if p.asOrg == "" {
		p.asOrg = f.ASOrg
	}
	if p.asn == 0 {
		p.asn = f.ASN
	}
	if p.country == "" {
		p.country = f.Country
	}
	if len(p.samples) < maxSamples {
		for _, s := range p.samples {
			if s == f.Dst {
				return
			}
		}
		p.samples = append(p.samples, f.Dst)
	}
}

// meets reports whether any enabled criterion (0 = disabled) is met.
func meets(p *pending, minTx, minTotal uint64, minConns int) bool {
	return (minTx > 0 && p.tx >= minTx) ||
		(minTotal > 0 && p.tx+p.rx >= minTotal) ||
		(minConns > 0 && p.conns >= minConns)
}

// infraFlow reports background infrastructure traffic that hits random
// servers world-wide by design (NTP pool, public DNS, ICMP) and therefore
// says nothing about novel behaviour.
func infraFlow(f *model.FlowSample) bool {
	switch strings.ToLower(f.Proto) {
	case "icmp", "icmpv6":
		return true
	case "udp", "tcp":
		p := f.Dst.Port()
		return p == 123 || p == 53
	}
	return false
}

// trackDest accumulates traffic to unknown destinations. It returns an
// immediate Critical alert when a strict device uploads a lot to a new country.
func (e *Engine) trackDest(st *devState, f *model.FlowSample, t time.Time) (model.Alert, bool) {
	if infraFlow(f) {
		return model.Alert{}, false
	}
	if f.ASN != 0 && st.asns != nil {
		if _, ok := st.asns[f.ASN]; !ok {
			if st.pendASN == nil {
				st.pendASN = make(map[uint32]*pending)
			}
			p := st.pendASN[f.ASN]
			if p == nil {
				p = &pending{}
				st.pendASN[f.ASN] = p
			}
			p.add(f)
		}
	}
	if f.Country == "" {
		return model.Alert{}, false
	}
	if _, ok := st.countries[f.Country]; ok {
		return model.Alert{}, false
	}
	if st.pendCountry == nil {
		st.pendCountry = make(map[string]*pending)
	}
	p := st.pendCountry[f.Country]
	if p == nil {
		p = &pending{}
		st.pendCountry[f.Country] = p
	}
	p.add(f)
	prof := e.profile(st)
	if p.alerted || prof.CountryCriticalTx == 0 || p.tx < prof.CountryCriticalTx || !e.enabled(model.AlertNewCountry) {
		return model.Alert{}, false
	}
	if !e.countryEligible(st, prof, f.Country, t) {
		return model.Alert{}, false
	}
	p.alerted = true
	return e.countryAlert(st, prof, []*pending{p}, t, true), true
}

// countryEligible holds the device-level conditions for a new-country alert.
func (e *Engine) countryEligible(st *devState, prof Profile, cc string, at time.Time) bool {
	if !prof.NewCountry || !e.behaviourAllowed(st, at) || st.activeHours < e.cfg.MinHistoryHours {
		return false
	}
	if prof.CountryMaxKnown > 0 && len(st.countries) >= prof.CountryMaxKnown {
		return false // globetrotter device
	}
	if prof.CountryHouseholdNew {
		if _, ok := e.household[cc]; ok {
			return false
		}
	}
	return true
}

// finishHour closes the device's hourly bucket: emits at most one
// new-country and one new-ASN alert, then marks every pending destination
// as known (sub-threshold one-off hits are learnt silently, exactly as the
// store will have them after a restart).
func (e *Engine) finishHour(st *devState) []model.Alert {
	if st.curHour.IsZero() {
		return nil
	}
	defer func() {
		st.pendCountry = nil
		st.pendASN = nil
		st.activeHours++
	}()
	at := st.curHour.Add(time.Hour)
	prof := e.profile(st)
	var out []model.Alert

	ccs := make([]string, 0, len(st.pendCountry))
	for cc := range st.pendCountry {
		ccs = append(ccs, cc)
	}
	sort.Strings(ccs)
	var newC []*pending
	for _, cc := range ccs {
		p := st.pendCountry[cc]
		if !p.alerted && meets(p, prof.CountryMinTx, prof.CountryMinTotal, prof.CountryMinConns) &&
			e.countryEligible(st, prof, cc, at) {
			newC = append(newC, p)
		}
	}
	if len(newC) > 0 && e.enabled(model.AlertNewCountry) {
		out = append(out, e.countryAlert(st, prof, newC, at, false))
	}
	for _, cc := range ccs {
		st.countries[cc] = struct{}{}
		e.household[cc] = struct{}{}
	}

	if st.asns != nil {
		asns := make([]uint32, 0, len(st.pendASN))
		for a := range st.pendASN {
			asns = append(asns, a)
		}
		sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
		allowed := prof.NewASN && e.enabled(model.AlertNewASN) && e.behaviourAllowed(st, at) &&
			st.activeHours >= e.cfg.MinHistoryHours
		var newA []*pending
		for _, a := range asns {
			p := st.pendASN[a]
			if _, newCountry := st.pendCountry[p.country]; newCountry {
				continue // covered by (or learnt together with) the new-country decision
			}
			if allowed && meets(p, prof.ASNMinTx, prof.ASNMinTotal, prof.ASNMinConns) {
				newA = append(newA, p)
			}
		}
		if len(newA) > 0 {
			out = append(out, e.asnAlert(st, prof, newA, at))
		}
		for _, a := range asns {
			st.asns[a] = struct{}{}
		}
		if prof.ASNMaxKnown > 0 && len(st.asns) > prof.ASNMaxKnown {
			st.asns = nil
		}
	}
	return out
}

func destEvidence(ps []*pending) []map[string]any {
	var out []map[string]any
	for _, p := range ps {
		ex := make([]string, len(p.samples))
		for i, s := range p.samples {
			ex[i] = s.String()
		}
		out = append(out, map[string]any{
			"country":   p.country,
			"asn":       p.asn,
			"as_org":    p.asOrg,
			"tx_bytes":  p.tx,
			"rx_bytes":  p.rx,
			"new_conns": p.conns,
			"examples":  ex,
		})
	}
	return out
}

func sortedKeys[K comparable](m map[K]struct{}, less func(a, b K) bool, limit int) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func asLabel(asn uint32, org string) string {
	if asn == 0 {
		return ""
	}
	if org == "" {
		return fmt.Sprintf("AS%d", asn)
	}
	return fmt.Sprintf("AS%d %s", asn, org)
}

func examples(l loc, s []netip.AddrPort) string {
	if len(s) == 0 {
		return ""
	}
	parts := make([]string, len(s))
	for i, a := range s {
		parts[i] = a.String()
	}
	return l.t("alert.dest.examples", strings.Join(parts, ", "))
}

func destLine(l loc, p *pending, what string) string {
	if al := asLabel(p.asn, p.asOrg); al != "" && !strings.HasPrefix(what, al) {
		what += " (" + al + ")"
	}
	return l.t("alert.dest.line", what, l.bytes(float64(p.tx)), l.bytes(float64(p.rx)), p.conns,
		l.word("new_conn", p.conns), examples(l, p.samples))
}

func (e *Engine) countryAlert(st *devState, prof Profile, ps []*pending, at time.Time, critical bool) model.Alert {
	l := e.lang
	ccs := make([]string, len(ps))
	for i, p := range ps {
		ccs[i] = p.country
	}
	name := l.deviceName(st.dev)
	var title string
	if len(ccs) == 1 {
		title = l.t("alert.country.title.one", name, ccs[0])
	} else {
		title = l.t("alert.country.title.many", name, strings.Join(ccs, ", "))
	}
	known := sortedKeys(st.countries, func(a, b string) bool { return a < b }, 20)
	var det []string
	for _, p := range ps {
		det = append(det, l.t("alert.country.first", destLine(l, p, p.country)))
	}
	if len(known) > 0 {
		n := len(st.countries)
		det = append(det, l.t("alert.country.known", n, l.word("country", n), strings.Join(known, ", ")))
	}
	sev := model.SevWarning
	if critical {
		sev = model.SevCritical
		det = append(det, l.t("alert.country.advice_crit", l.kind(st.dev.EffectiveKind()),
			l.bytes(float64(prof.CountryCriticalTx))))
	} else {
		det = append(det, l.t("alert.country.advice_warn"))
	}
	return model.Alert{
		Time:      at,
		DeviceMAC: st.dev.MAC,
		Kind:      model.AlertNewCountry,
		Severity:  sev,
		Title:     title,
		Detail:    strings.Join(det, " "),
		Evidence: map[string]any{
			"hour":            st.curHour,
			"device_kind":     st.dev.EffectiveKind(),
			"new":             destEvidence(ps),
			"known_countries": len(st.countries),
			"known_list":      known,
			"active_hours":    st.activeHours,
			"min_tx":          prof.CountryMinTx,
			"min_total":       prof.CountryMinTotal,
			"min_conns":       prof.CountryMinConns,
			"critical_tx":     prof.CountryCriticalTx,
			"immediate":       critical,
		},
		DedupKey: "new_country:" + st.dev.MAC + ":" + strings.Join(ccs, ","),
	}
}

func (e *Engine) asnAlert(st *devState, prof Profile, ps []*pending, at time.Time) model.Alert {
	l := e.lang
	labels := make([]string, len(ps))
	keys := make([]string, len(ps))
	for i, p := range ps {
		labels[i] = asLabel(p.asn, p.asOrg)
		keys[i] = fmt.Sprint(p.asn)
	}
	name := l.deviceName(st.dev)
	var title string
	if len(ps) == 1 {
		title = l.t("alert.asn.title.one", name, labels[0])
	} else {
		title = l.t("alert.asn.title.many", name, len(ps))
	}
	var det []string
	for i, p := range ps {
		what := labels[i]
		if p.country != "" {
			what += " [" + p.country + "]"
		}
		det = append(det, l.t("alert.asn.first", destLine(l, p, what)))
	}
	n := len(st.asns)
	det = append(det, l.t("alert.asn.known", l.kind(st.dev.EffectiveKind()), n, l.word("network", n)))
	return model.Alert{
		Time:      at,
		DeviceMAC: st.dev.MAC,
		Kind:      model.AlertNewASN,
		Severity:  model.SevWarning,
		Title:     title,
		Detail:    strings.Join(det, " "),
		Evidence: map[string]any{
			"hour":         st.curHour,
			"device_kind":  st.dev.EffectiveKind(),
			"new":          destEvidence(ps),
			"known_asns":   len(st.asns),
			"active_hours": st.activeHours,
			"min_tx":       prof.ASNMinTx,
			"min_total":    prof.ASNMinTotal,
			"min_conns":    prof.ASNMinConns,
			"max_known":    prof.ASNMaxKnown,
		},
		DedupKey: "new_asn:" + st.dev.MAC + ":" + strings.Join(keys, ","),
	}
}
