package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/config"
	"github.com/Marteva/routeros-guardian/internal/detect"
	"github.com/Marteva/routeros-guardian/internal/fingerprint"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
	"github.com/Marteva/routeros-guardian/internal/store"
)

const (
	historyDays = 7
	// markerKey is a settings row that marks a database as seeded by this
	// tool (Guardian ignores unknown keys). -reset refuses databases without it.
	markerKey = "demo.seeded_at"
)

// seedStats summarises what seed wrote.
type seedStats struct {
	Devices  int // device rows (MAC addresses)
	Rows     int // rows in the UI device list (grouped)
	Alerts   int
	HourRows int
	Flows    int // synthetic flow samples folded into the aggregates
}

// seed writes the fictional household into st: settings (learning finished),
// devices, 7 days of hourly traffic and destinations, and the alerts the
// real detection engine raises for the story told by that traffic. All
// random values come from fixed seeds, so the result only depends on now.
func seed(ctx context.Context, st *store.SQLite, hh *household, now time.Time) (seedStats, error) {
	tl := newTimeline(now)
	stats := seedStats{Devices: len(hh.devices), Rows: hh.displayRows()}

	set, err := seedSettings(ctx, st, tl)
	if err != nil {
		return stats, err
	}
	for _, d := range hh.devices {
		if _, err := st.UpsertDevice(ctx, d.stored(tl)); err != nil {
			return stats, fmt.Errorf("demo: device %s: %w", d.id, err)
		}
	}

	// Traffic. The garden camera's traffic to China is held back: the
	// detector must see the first contact before the store knows the country.
	gen := &trafficGen{r: rand.New(rand.NewPCG(7, 2026))}
	cam := hh.get(idGardenCam)
	var toChina, camFirstHour []model.FlowSample
	var camNext model.FlowSample
	for _, d := range hh.devices {
		flows := gen.deviceFlows(d, tl)
		stats.Flows += len(flows)
		keep := flows
		if d == cam {
			keep = nil
			for _, f := range flows {
				hour := f.Time.Truncate(time.Hour)
				if f.Country == chinanetCN.country {
					toChina = append(toChina, f)
				} else {
					keep = append(keep, f)
				}
				switch {
				case hour.Equal(tl.cnHour):
					camFirstHour = append(camFirstHour, f)
				case hour.Equal(tl.spikeHour) && f.Country != chinanetCN.country &&
					(camNext.Time.IsZero() || f.Time.Before(camNext.Time)):
					camNext = f
				}
			}
		}
		if err := st.RecordFlows(ctx, keep); err != nil {
			return stats, fmt.Errorf("demo: traffic of %s: %w", d.id, err)
		}
	}

	var alerts []model.Alert
	add := func(as []model.Alert, err error) error {
		alerts = append(alerts, as...)
		return err
	}

	// 1. The camera talks to China for the first time (new country, hourly path).
	sort.Slice(camFirstHour, func(i, j int) bool { return camFirstHour[i].Time.Before(camFirstHour[j].Time) })
	e, sink := newDetector(st, set, tl.learnStart)
	e.Flows(ctx, camFirstHour)
	e.Flows(ctx, []model.FlowSample{camNext}) // the next hour closes the first one
	if err := add(sink.expect("new country", want{model.AlertNewCountry, cam.mac})); err != nil {
		return stats, err
	}
	if err := st.RecordFlows(ctx, toChina); err != nil {
		return stats, fmt.Errorf("demo: traffic to CN: %w", err)
	}

	// 2. ... and uploads 2.8 GB in the last completed hour (hourly evaluation).
	e, sink = newDetector(st, set, tl.learnStart)
	e.Tick(ctx, tl.now)
	if err := add(sink.expect("upload spike", want{model.AlertUploadSpike, cam.mac})); err != nil {
		return stats, err
	}

	// 3. Yesterday night the robot vacuum scanned the internet.
	e, sink = newDetector(st, set, tl.learnStart)
	e.Tick(ctx, tl.fanoutHour.Add(time.Hour+4*time.Minute))
	if err := add(sink.expect("fan-out", want{model.AlertDestFanout, hh.get(idVacuum).mac})); err != nil {
		return stats, err
	}

	// 4. Initial inventory summary, one day after installation.
	e, sink = newDetector(st, set, tl.learnStart)
	e.Tick(ctx, tl.inventoryEnd().Add(23*time.Minute))
	inv, err := sink.expect("inventory", want{model.AlertNewDevice, ""})
	if err != nil {
		return stats, err
	}
	for i := range inv {
		inv[i].Acked = true // read long ago
	}
	alerts = append(alerts, inv...)

	// 5. Devices that joined after the inventory. Alex's iPhone got a new
	// private MAC with the same hostname: no alert, it is the same phone.
	e, sink = newDetector(st, set, tl.learnStart)
	for _, id := range []string{idIPhone, idGuestTab, idESP} {
		e.DeviceSeen(ctx, hh.get(id).firstSight(tl), true)
	}
	if err := add(sink.expect("new devices",
		want{model.AlertNewDevice, hh.get(idGuestTab).mac},
		want{model.AlertNewDevice, hh.get(idESP).mac})); err != nil {
		return stats, err
	}

	sort.SliceStable(alerts, func(i, j int) bool { return alerts[i].Time.Before(alerts[j].Time) })
	for i := range alerts {
		if err := st.InsertAlert(ctx, &alerts[i]); err != nil {
			return stats, err
		}
	}
	stats.Alerts = len(alerts)

	hs, err := st.HourStats(ctx, "", tl.hour.Add(-(historyDays+1)*24*time.Hour), tl.now.Add(time.Hour))
	if err != nil {
		return stats, err
	}
	stats.HourRows = len(hs)
	// Mark the database as demo data last: a failed seed is never reused.
	return stats, st.PutSettings(ctx, map[string]string{markerKey: tl.now.Format(time.RFC3339)})
}

func seedSettings(ctx context.Context, st *store.SQLite, tl timeline) (settings.Settings, error) {
	mgr, err := settings.NewManager(ctx, st, settings.Defaults(config.Config{
		Language:    "en",
		LearnPeriod: 7 * 24 * time.Hour,
		DedupWindow: 6 * time.Hour,
		Retention:   60 * 24 * time.Hour,
	}))
	if err != nil {
		return settings.Settings{}, err
	}
	s, err := mgr.Update(ctx, func(s *settings.Settings) error {
		s.LearningStart = tl.learnStart
		return nil
	})
	if err != nil {
		return s, fmt.Errorf("demo: settings: %w", err)
	}
	return s, nil
}

// stored is the device as the database holds it today (with the user's edits).
func (d *device) stored(tl timeline) model.Device {
	m := d.firstSight(tl)
	m.Note, m.KindOverride, m.GroupID = d.note, d.kindOverride, d.groupID
	m.LastSeen = d.lastSeen(tl)
	return m
}

// firstSight is the device as the collector reported it when it first
// appeared (no user edits yet), enriched like Guardian's ingest does.
func (d *device) firstSight(tl timeline) model.Device {
	m := model.Device{
		MAC: d.mac, IP: d.ip, Hostname: d.hostname, ClassID: d.classID, Comment: d.comment,
		FirstSeen: d.joined(tl), LastSeen: d.joined(tl),
	}
	fingerprint.Enrich(&m)
	return m
}

// ---------------------------------------------------------------------------
// detector

// captureSink collects the alerts of a detection engine.
type captureSink struct{ alerts []model.Alert }

func (c *captureSink) Emit(_ context.Context, a model.Alert) { c.alerts = append(c.alerts, a) }

type want struct{ kind, mac string }

// expect returns the captured alerts if they are exactly the wanted ones.
func (c *captureSink) expect(step string, ws ...want) ([]model.Alert, error) {
	ok := len(c.alerts) == len(ws)
	for i := 0; ok && i < len(ws); i++ {
		ok = c.alerts[i].Kind == ws[i].kind && c.alerts[i].DeviceMAC == ws[i].mac
	}
	if ok {
		return c.alerts, nil
	}
	got := make([]string, len(c.alerts))
	for i, a := range c.alerts {
		got[i] = fmt.Sprintf("%s %s %q", a.Kind, a.DeviceMAC, a.Title)
	}
	return nil, fmt.Errorf("demo: %s: the detector raised [%s], want %v (did the detection thresholds change?)",
		step, strings.Join(got, "; "), ws)
}

// newDetector returns a fresh engine with the seeded settings whose alerts
// are captured instead of stored.
func newDetector(st model.Store, s settings.Settings, start time.Time) (*detect.Engine, *captureSink) {
	cfg := detect.DefaultConfig()
	cfg.Logger = slog.New(slog.DiscardHandler)
	sink := &captureSink{}
	e := detect.New(st, sink, cfg, start)
	e.SetSettings(s)
	return e, sink
}

// ---------------------------------------------------------------------------
// traffic

type trafficGen struct{ r *rand.Rand }

// endpoint is one destination address of a flow.
type endpoint struct {
	dst   netip.AddrPort
	proto string
	d     *destination
}

func (g *trafficGen) endpoint(d *destination, ports []uint16) endpoint {
	if ports == nil {
		ports = d.ports
	}
	proto := "tcp"
	if g.r.Float64() < d.udp {
		proto = "udp"
	}
	return endpoint{netip.AddrPortFrom(d.randomAddr(g.r), ports[g.r.IntN(len(ports))]), proto, d}
}

// pool picks n distinct destination addresses (weighted by operator).
func (g *trafficGen) pool(ws []weighted, n int, ports []uint16) []endpoint {
	seen := map[netip.Addr]bool{}
	out := make([]endpoint, 0, n)
	for tries := 0; len(out) < n && tries < 50*n; tries++ {
		e := g.endpoint(pick(g.r, ws), ports)
		if !seen[e.dst.Addr()] {
			seen[e.dst.Addr()] = true
			out = append(out, e)
		}
	}
	return out
}

// deviceFlows generates the device's traffic for the last historyDays days
// up to now (the current hour only so far), as flow samples.
func (g *trafficGen) deviceFlows(d *device, tl timeline) []model.FlowSample {
	first, last := d.joined(tl), d.lastSeen(tl)
	var out []model.FlowSample
	for h := tl.hour.Add(-historyDays * 24 * time.Hour); !h.After(tl.hour); h = h.Add(time.Hour) {
		from, to := h, h.Add(time.Hour)
		if first.After(from) {
			from = first
		}
		if last.Before(to) {
			to = last
		}
		if to.After(from) {
			out = append(out, g.hourFlows(d, tl, h, from, to)...)
		}
	}
	return out
}

func (g *trafficGen) hourFlows(d *device, tl timeline, h, from, to time.Time) []model.FlowSample {
	frac := to.Sub(from).Hours()
	l := d.profile.at(h.Add(30 * time.Minute))
	nb, nc := 0.8+0.4*g.r.Float64(), 0.8+0.4*g.r.Float64() // ±20 % noise on bytes and counts

	if d.id == idVacuum && h.Equal(tl.fanoutHour) {
		// Infected firmware: probes 240 internet hosts within one hour.
		return g.flows(d, from, to, g.pool([]weighted{{awsDE, 1}}, 240, scanPorts), 263, 9*mB*nb, 2.4*mB*nb)
	}

	var out []model.FlowSample
	if tx, rx := l.tx*nb*frac, l.rx*nb*frac; tx+rx >= 2*kB {
		n := max(1, round(l.conns*nc*frac))
		k := min(n, max(1, round(l.dsts*nc*frac)))
		out = g.flows(d, from, to, g.pool(d.destsAt(tl, h), k, nil), n, tx, rx)
	}
	if d.id == idGardenCam {
		china := []weighted{{chinanetCN, 1}}
		switch {
		case h.Equal(tl.cnHour): // first, small contact
			out = append(out, g.flows(d, from, to, g.pool(china, 3, nil), 5, 700*kB*nb, 64*kB*nb)...)
		case h.Equal(tl.spikeHour): // 2.8 GB in total this hour
			var tx float64
			for _, f := range out {
				tx += float64(f.TxBytes)
			}
			total := 2.8 * gB * (0.995 + 0.01*g.r.Float64())
			out = append(out, g.flows(d, from, to, g.pool(china, 4, nil), 14, total-tx, 22*mB)...)
		}
	}
	return out
}

// flows spreads tx/rx over n new connections to the pool addresses (each
// address used at least once) at random times in [from, to).
func (g *trafficGen) flows(d *device, from, to time.Time, pool []endpoint, n int, tx, rx float64) []model.FlowSample {
	if len(pool) == 0 || n <= 0 {
		return nil
	}
	ws := make([]float64, n)
	idx := make([]int, n)
	sum := 0.0
	for i := range n {
		idx[i] = i
		if i >= len(pool) {
			idx[i] = g.r.IntN(len(pool))
		}
		ws[i] = 0.3 + 1.4*g.r.Float64()
		sum += ws[i]
	}
	span := float64(to.Sub(from))
	out := make([]model.FlowSample, n)
	for i := range n {
		e := pool[idx[i]]
		out[i] = model.FlowSample{
			Time:      from.Add(time.Duration(g.r.Float64() * span)).Truncate(time.Second),
			DeviceMAC: d.mac,
			DeviceIP:  d.ip,
			Dst:       e.dst,
			Proto:     e.proto,
			TxBytes:   uint64(tx * ws[i] / sum),
			RxBytes:   uint64(rx * ws[i] / sum),
			NewConn:   true,
			Fasttrack: g.r.Float64() < 0.9,
			Country:   e.d.country,
			ASN:       e.d.asn,
			ASOrg:     e.d.org,
		}
	}
	return out
}
