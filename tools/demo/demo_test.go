package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/collector"
	"github.com/Marteva/routeros-guardian/internal/config"
	"github.com/Marteva/routeros-guardian/internal/fingerprint"
	"github.com/Marteva/routeros-guardian/internal/geo"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/routeros"
	"github.com/Marteva/routeros-guardian/internal/settings"
	"github.com/Marteva/routeros-guardian/internal/store"
	"github.com/Marteva/routeros-guardian/internal/web"
)

// testNow is a Wednesday afternoon.
var testNow = time.Date(2026, 10, 7, 14, 37, 12, 0, time.UTC)

var demoLAN = []netip.Prefix{netip.MustParsePrefix("192.168.88.0/24")}

// seedTemp seeds a fresh database in a temp dir and opens it.
func seedTemp(t *testing.T, now time.Time) (*store.SQLite, *household, dbState) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "demo.db")
	hh := newHousehold()
	state, err := prepareDB(context.Background(), path, false, hh, now)
	if err != nil {
		t.Fatal(err)
	}
	if !state.seeded {
		t.Fatal("database was not seeded")
	}
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, hh, state
}

func loadSettings(t *testing.T, st model.Store) settings.Settings {
	t.Helper()
	mgr, err := settings.NewManager(context.Background(), st, settings.Defaults(config.Config{
		LearnPeriod: time.Hour, DedupWindow: time.Hour, Retention: 30 * 24 * time.Hour}))
	if err != nil {
		t.Fatal(err)
	}
	return mgr.Get()
}

func TestHousehold(t *testing.T) {
	hh := newHousehold()
	again := newHousehold()
	tl := newTimeline(testNow)
	macs, ips := map[string]bool{}, map[netip.Addr]bool{}
	for i, d := range hh.devices {
		if again.devices[i].mac != d.mac {
			t.Errorf("%s: MAC not deterministic", d.id)
		}
		if macs[d.mac] {
			t.Errorf("%s: duplicate MAC %s", d.id, d.mac)
		}
		macs[d.mac] = true
		if !demoLAN[0].Contains(d.ip) || d.ip == routerIP {
			t.Errorf("%s: bad IP %s", d.id, d.ip)
		}
		if d.online() && ips[d.ip] {
			t.Errorf("%s: duplicate IP %s", d.id, d.ip)
		}
		ips[d.ip] = true
		m := d.firstSight(tl)
		if m.Kind != d.wantKind {
			t.Errorf("%s: fingerprint guesses %q, want %q", d.id, m.Kind, d.wantKind)
		}
		if !m.Randomized && d.id != idESP && m.Vendor == "" {
			t.Errorf("%s: no vendor for %s", d.id, d.mac)
		}
		if d.note == "" && d.comment == "" && d.groupID == "" && d.id != idESP && d.id != idIPhone {
			t.Errorf("%s: no friendly name", d.id)
		}
	}
	if got := fingerprint.Vendor(hh.get(idESP).mac); got != "" {
		t.Errorf("ESP device must stay unidentified, vendor %q", got)
	}
	if got, want := hh.displayRows(), 18; got != want {
		t.Errorf("display rows = %d, want %d", got, want)
	}
}

func TestSeed(t *testing.T) {
	ctx := context.Background()
	st, hh, state := seedTemp(t, testNow)
	tl := newTimeline(testNow)
	if state.stats.Devices != 20 || state.stats.Rows != 18 || state.stats.Alerts != 6 || state.stats.HourRows < 2000 {
		t.Errorf("stats = %+v", state.stats)
	}

	devs, err := st.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != len(hh.devices) {
		t.Fatalf("%d devices, want %d", len(devs), len(hh.devices))
	}
	for _, d := range hh.devices {
		got, ok, err := st.Device(ctx, d.mac)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", d.id, ok, err)
		}
		if !got.FirstSeen.Equal(d.joined(tl)) || !got.LastSeen.Equal(d.lastSeen(tl)) {
			t.Errorf("%s: seen %v..%v", d.id, got.FirstSeen, got.LastSeen)
		}
		wantKind := d.wantKind
		if d.kindOverride != "" {
			wantKind = d.kindOverride
		}
		if got.EffectiveKind() != wantKind {
			t.Errorf("%s: kind %q, want %q", d.id, got.EffectiveKind(), wantKind)
		}
	}
	if esp, _, _ := st.Device(ctx, hh.get(idESP).mac); testNow.Sub(esp.FirstSeen) > 2*time.Hour+time.Minute {
		t.Errorf("ESP first seen %v", esp.FirstSeen)
	}

	// learning is over
	set := loadSettings(t, st)
	if !set.LearningStart.Equal(tl.learnStart) || set.LearnPeriod != 7*24*time.Hour || set.Language != "en" {
		t.Errorf("settings = %+v", set)
	}
	e, _ := newDetector(st, set, testNow)
	if until := e.LearningUntil(); !until.Before(testNow) {
		t.Errorf("learning until %v", until)
	}

	// alerts
	as, err := st.Alerts(ctx, model.AlertFilter{})
	if err != nil {
		t.Fatal(err)
	}
	type key struct {
		kind, mac string
		sev       model.Severity
	}
	want := map[key]string{
		{model.AlertUploadSpike, hh.get(idGardenCam).mac, model.SevCritical}: "Garden camera is uploading 2.8 GB/h",
		{model.AlertNewCountry, hh.get(idGardenCam).mac, model.SevWarning}:   "Garden camera is communicating with a new country: CN",
		{model.AlertDestFanout, hh.get(idVacuum).mac, model.SevCritical}:     "Robot vacuum contacted 240 different addresses in one hour",
		{model.AlertNewDevice, hh.get(idESP).mac, model.SevWarning}:          "New device on the network: Device (" + hh.get(idESP).mac + ")",
		{model.AlertNewDevice, hh.get(idGuestTab).mac, model.SevInfo}:        "New device on the network: Phone (android-5d2e8c1f0a7b3e94)",
		{model.AlertNewDevice, "", model.SevInfo}:                            "Initial inventory complete: 17 devices",
	}
	if len(as) != len(want) {
		t.Errorf("%d alerts, want %d", len(as), len(want))
	}
	for i, a := range as {
		k := key{a.Kind, a.DeviceMAC, a.Severity}
		if title, ok := want[k]; !ok || a.Title != title {
			t.Errorf("unexpected alert %+v %q", k, a.Title)
		}
		if a.Acked != (a.Kind == model.AlertNewDevice && a.DeviceMAC == "") {
			t.Errorf("%q acked=%v", a.Title, a.Acked)
		}
		if i > 0 && a.Time.After(as[i-1].Time) {
			t.Errorf("alerts not newest first")
		}
		if a.Time.After(testNow) || (!a.Acked && testNow.Sub(a.Time) > 48*time.Hour) {
			t.Errorf("%q at %v", a.Title, a.Time)
		}
	}

	// the camera's destinations include China, first seen in the story's hour
	ds, err := st.DestStats(ctx, hh.get(idGardenCam).mac)
	if err != nil {
		t.Fatal(err)
	}
	var cn bool
	for _, d := range ds {
		if d.Country == "CN" {
			cn = float64(d.Bytes) > 2.5*gB && d.FirstSeen.Truncate(time.Hour).Equal(tl.cnHour)
		}
	}
	if !cn {
		t.Errorf("camera destinations without the CN story: %+v", ds)
	}
}

// TestSeedWebAPI checks the seeded data through Guardian's own JSON API.
func TestSeedWebAPI(t *testing.T) {
	st, hh, _ := seedTemp(t, time.Now())
	h := web.New(web.Deps{Store: st})
	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}
	var rows []struct {
		MAC, Name, Kind, KindAuto, Group string
		Tx24h, Rx24h                     uint64
		OpenAlerts                       int
		Members                          []struct{ MAC string }
	}
	get("/api/devices", &rows)
	if len(rows) != 18 {
		t.Errorf("%d device rows, want 18", len(rows))
	}
	byName := map[string]int{}
	var total uint64
	for i, r := range rows {
		byName[r.Name] = i
		total += r.Tx24h + r.Rx24h
	}
	for name, group := range map[string]string{"Alex's iPhone": "auto", "Work laptop": "manual"} {
		i, ok := byName[name]
		if !ok || rows[i].Group != group || len(rows[i].Members) != 2 {
			t.Errorf("%s: row %+v", name, rows[i])
		}
	}
	if r := rows[byName["Guest tablet"]]; r.Kind != "tablet" || r.KindAuto != "phone" {
		t.Errorf("guest tablet: %+v", r)
	}
	if r := rows[byName["Garden camera"]]; r.OpenAlerts != 2 || float64(r.Tx24h) < 2.8*gB {
		t.Errorf("garden camera: %+v", r)
	}
	if _, ok := byName[hh.get(idESP).mac]; !ok {
		t.Errorf("unnamed ESP device should be listed by MAC")
	}
	if float64(total) < 10*gB {
		t.Errorf("24 h traffic only %d bytes", total)
	}
	var alerts []struct{ DeviceName string }
	get("/api/alerts", &alerts)
	if len(alerts) != 6 || alerts[0].DeviceName != "Garden camera" {
		t.Errorf("alerts: %+v", alerts)
	}
}

// TestSeedDeterministic: the same "now" gives the same database.
func TestSeedDeterministic(t *testing.T) {
	ctx := context.Background()
	dump := func(st *store.SQLite) string {
		var b bytes.Buffer
		devs, _ := st.Devices(ctx)
		as, _ := st.Alerts(ctx, model.AlertFilter{})
		hs, _ := st.HourStats(ctx, "", testNow.Add(-30*24*time.Hour), testNow.Add(time.Hour))
		ds, _ := st.DestStats(ctx, "")
		for _, x := range []any{devs, as, hs, ds} {
			fmt.Fprintf(&b, "%+v\n", x)
		}
		return b.String()
	}
	a, _, _ := seedTemp(t, testNow)
	b, _, _ := seedTemp(t, testNow)
	if dump(a) != dump(b) {
		t.Error("seeding is not deterministic")
	}
}

// TestSeedAnyTime: the story (exactly these alerts, nothing else from the
// detector) must work whatever time of the week the demo is started.
func TestSeedAnyTime(t *testing.T) {
	for h := 0; h < 7*24; h += 11 {
		now := testNow.Add(time.Duration(h)*time.Hour + time.Duration(h%60)*time.Minute)
		path := filepath.Join(t.TempDir(), "demo.db")
		if _, err := prepareDB(context.Background(), path, false, newHousehold(), now); err != nil {
			t.Errorf("%s: %v", now.Format(time.RFC3339), err)
		}
	}
}

// catalogGeo resolves the catalog's networks like DB-IP would (GeoIP enabled).
type catalogGeo struct{}

func (catalogGeo) Lookup(ip netip.Addr) (string, uint32, string) {
	for _, d := range catalog {
		for _, n := range d.nets {
			if n.Contains(ip) {
				return d.country, d.asn, d.org
			}
		}
	}
	return "", 0, ""
}

// TestGuardianAgainstFakeRouter runs Guardian's poll pipeline (REST client,
// collector, fingerprint, store, detection) against the fake router and the
// seeded database, with and without GeoIP: no device may be new, traffic
// must flow, and the detector must not raise anything that the notification
// sink would not deduplicate against the seeded alerts.
func TestGuardianAgainstFakeRouter(t *testing.T) {
	for _, tc := range []struct {
		name string
		geo  model.GeoLookup
	}{{"noGeoIP", nil}, {"GeoIP", catalogGeo{}}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st, hh, _ := seedTemp(t, testNow)
			tl := newTimeline(testNow)
			clock := testNow.Add(time.Minute)
			srv := httptest.NewServer(newFakeRouter(hh, func() time.Time { return clock }, nil))
			defer srv.Close()
			api, err := routeros.New(routeros.Config{BaseURL: srv.URL, User: "guardian", Password: "demo"})
			if err != nil {
				t.Fatal(err)
			}
			coll := collector.New(api, tc.geo, demoLAN)
			set := loadSettings(t, st)
			eng, sink := newDetector(st, set, clock)

			poll := func(first bool) {
				t.Helper()
				snap, err := coll.Poll(ctx, clock)
				if err != nil {
					t.Fatal(err)
				}
				if len(snap.Devices) != len(hh.online()) {
					t.Errorf("%d devices, want %d", len(snap.Devices), len(hh.online()))
				}
				if snap.ConnCount < 15 || snap.ConnCount > 100 {
					t.Errorf("%d connections", snap.ConnCount)
				}
				if share := float64(snap.FasttrackCount) / float64(snap.ConnCount); share < 0.6 || share > 1 {
					t.Errorf("fasttrack share %.2f", share)
				}
				for _, d := range snap.Devices {
					fingerprint.Enrich(&d)
					isNew, err := st.UpsertDevice(ctx, d)
					if err != nil {
						t.Fatal(err)
					}
					if isNew {
						t.Errorf("%s is treated as a new device", d.MAC)
					}
					eng.DeviceSeen(ctx, d, isNew)
				}
				if !first && (len(snap.Flows) == 0 || snap.VisibleTx == 0) {
					t.Error("no traffic")
				}
				eng.Flows(ctx, snap.Flows)
				if err := st.RecordFlows(ctx, snap.Flows); err != nil {
					t.Fatal(err)
				}
				clock = clock.Add(15 * time.Second)
			}
			for i := range 4 {
				poll(i == 0)
			}
			// cross into the next hour: hourly buckets close, novelty is decided
			clock = tl.hour.Add(time.Hour + time.Minute)
			poll(false)
			poll(false)
			eng.Tick(ctx, clock)

			for _, a := range sink.alerts {
				last, ok, err := st.LastAlertByDedupKey(ctx, a.DedupKey)
				if err != nil || !ok || a.Time.Sub(last) >= set.DedupWindow {
					t.Errorf("runtime alert would be shown: %s %q", a.Kind, a.Title)
				}
			}
			for _, d := range hh.devices {
				got, _, _ := st.Device(ctx, d.mac)
				want := d.stored(tl)
				if !got.FirstSeen.Equal(want.FirstSeen) || got.Kind != want.Kind || got.Vendor != want.Vendor ||
					got.Note != want.Note || got.Comment != want.Comment || got.KindOverride != want.KindOverride ||
					got.GroupID != want.GroupID || got.Hostname != want.Hostname {
					t.Errorf("%s changed by polling:\n got %+v\nwant %+v", d.id, got, want)
				}
			}
		})
	}
}

func TestFakeRouterAPI(t *testing.T) {
	ctx := context.Background()
	hh := newHousehold()
	clock := testNow
	srv := httptest.NewServer(newFakeRouter(hh, func() time.Time { return clock }, nil))
	defer srv.Close()
	api, err := routeros.New(routeros.Config{BaseURL: srv.URL, User: "x", Password: "y"})
	if err != nil {
		t.Fatal(err)
	}

	// every value is a string, as on RouterOS
	for _, path := range []string{"ip/dhcp-server/lease", "ip/arp", "ip/firewall/connection", "ip/firewall/address-list"} {
		var items []map[string]any
		if err := api.Get(ctx, path, nil, &items); err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			for k, v := range it {
				if _, ok := v.(string); !ok {
					t.Errorf("%s: %s is %T", path, k, v)
				}
			}
		}
	}
	var few []map[string]string
	if err := api.Get(ctx, "ip/firewall/connection", map[string][]string{".proplist": {".id,protocol"}}, &few); err != nil {
		t.Fatal(err)
	}
	if len(few) == 0 || len(few[0]) != 2 {
		t.Errorf(".proplist ignored: %v", few[0])
	}
	res, err := api.Resource(ctx)
	if err != nil || res.BoardName != "hAP ax^3" || res.Arch != "arm64" || res.CPULoad < 3 || res.CPULoad > 8 {
		t.Errorf("resource %+v %v", res, err)
	}
	if err := api.Get(ctx, "no/such/menu", nil, nil); err == nil {
		t.Error("unknown menu accepted")
	}

	// counters grow
	conns := func(ip netip.Addr) (n int, bytes uint64) {
		cs, err := api.Connections(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			if c.Src.Addr() == ip {
				n++
				bytes += c.OrigBytes
			}
		}
		return n, bytes
	}
	cam := hh.get(idGardenCam).ip
	_, b1 := conns(cam)
	clock = clock.Add(10 * time.Second)
	_, b2 := conns(cam)
	if rate := float64(b2-b1) / 10 * 3600; rate < 30*mB || rate > 120*mB {
		t.Errorf("camera uploads %.0f MB/h, want ~62", rate/mB)
	}

	// quarantine round trip
	const list = "guardian-quarantine"
	for range 2 { // the second add is "already have such entry" = success
		if err := api.AddressListAdd(ctx, list, cam.String(), "guardian: Garden camera", 0); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := api.DropConnections(ctx, cam); err != nil || n == 0 {
		t.Errorf("dropped %d connections, err %v", n, err)
	}
	clock = clock.Add(30 * time.Minute)
	if n, _ := conns(cam); n != 0 {
		t.Errorf("quarantined camera has %d new connections", n)
	}
	if err := api.AddressListRemove(ctx, list, cam.String()); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(15 * time.Second)
	if n, _ := conns(cam); n == 0 {
		t.Error("camera did not reconnect after quarantine")
	}

	// timeouts expire
	if err := api.AddressListAdd(ctx, list, "192.168.88.144", "", time.Hour); err != nil {
		t.Fatal(err)
	}
	var entries []map[string]string
	_ = api.Get(ctx, "ip/firewall/address-list", map[string][]string{"list": {list}}, &entries)
	if len(entries) != 1 || entries[0]["timeout"] == "" || entries[0]["dynamic"] != "true" {
		t.Errorf("entries %v", entries)
	}
	clock = clock.Add(2 * time.Hour)
	entries = nil
	_ = api.Get(ctx, "ip/firewall/address-list", nil, &entries)
	if len(entries) != 0 {
		t.Errorf("expired entry kept: %v", entries)
	}
}

func TestPrepareDB(t *testing.T) {
	ctx := context.Background()
	hh := newHousehold()

	// A database the demo did not create is never deleted or modified.
	foreign := filepath.Join(t.TempDir(), "guardian.db")
	st, err := store.Open(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertDevice(ctx, model.Device{MAC: "02:00:00:00:00:01"}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	for _, reset := range []bool{false, true} {
		if _, err := prepareDB(ctx, foreign, reset, hh, testNow); err == nil || !strings.Contains(err.Error(), "not a demo database") {
			t.Errorf("reset=%v: err = %v", reset, err)
		}
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign database deleted: %v", err)
	}

	// A demo database is reused, or re-seeded with -reset.
	path := filepath.Join(t.TempDir(), "demo.db")
	if s, err := prepareDB(ctx, path, false, hh, testNow); err != nil || !s.seeded {
		t.Fatalf("first run: %+v %v", s, err)
	}
	later := testNow.Add(3 * time.Hour)
	s, err := prepareDB(ctx, path, false, hh, later)
	if err != nil || s.seeded || !s.seededAt.Equal(testNow) {
		t.Errorf("reuse: %+v %v", s, err)
	}
	s, err = prepareDB(ctx, path, true, hh, later)
	if err != nil || !s.seeded || !s.seededAt.Equal(later) {
		t.Errorf("reset: %+v %v", s, err)
	}
}

func TestInstructions(t *testing.T) {
	hh := newHousehold()
	local := []netip.Addr{netip.MustParseAddr("127.0.0.1"), hh.get(idNAS).ip}
	var b bytes.Buffer
	printInstructions(&b, instructions{
		api: browseURL("[::]:18728"), ui: browseURL(":8080"), uiArg: ":8080",
		db: filepath.Join("some dir", "demo.db"), geo: []string{"c.mmdb", "a.mmdb"},
		state: dbState{seeded: true}, hh: hh, clashes: clashes(hh, local),
	})
	out := b.String()
	for _, s := range []string{
		"192.168.88.10 (NAS)",
		"$env:GUARDIAN_ROS_URL='http://127.0.0.1:18728';",
		" GUARDIAN_ROS_URL=http://127.0.0.1:18728 ",
		"GUARDIAN_DB='some dir/demo.db'",
		"GUARDIAN_GEOIP_ASN=a.mmdb",
		"go run ./cmd/guardian",
		"http://127.0.0.1:8080",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("instructions lack %q:\n%s", s, out)
		}
	}
}

// TestCatalogMatchesGeoIP checks the destination networks against the DB-IP
// Lite files of scripts/update-geoip.* when they are present.
func TestCatalogMatchesGeoIP(t *testing.T) {
	dir := filepath.Join("..", "..", "dist", "geo")
	files := geoFiles(dir)
	if files == nil {
		t.Skip("no GeoIP files in", dir)
	}
	g, err := geo.Open(files[0], files[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range catalog {
		for _, n := range d.nets {
			for _, last := range []byte{2, 99, 180, 253} {
				b := n.Addr().As4()
				b[3] = last
				a := netip.AddrFrom4(b)
				if c, asn, org := g.Lookup(a); c != d.country || asn != d.asn || org != d.org {
					t.Errorf("%s: GeoIP says %s AS%d %q, catalog %s AS%d %q", a, c, asn, org, d.country, d.asn, d.org)
				}
			}
		}
	}
}
