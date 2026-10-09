package detect

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

func TestLearningUntil(t *testing.T) {
	tests := []struct {
		name  string
		first []time.Time
		start time.Time
		want  time.Time
		err   error
	}{
		{"empty store falls back to start", nil, t0, t0.Add(7 * 24 * time.Hour), nil},
		{"restart keeps original learning start", []time.Time{t0.Add(time.Hour), t0}, t0.Add(5 * 24 * time.Hour), t0.Add(7 * 24 * time.Hour), nil},
		{"zero FirstSeen ignored", []time.Time{{}}, t0, t0.Add(7 * 24 * time.Hour), nil},
		{"store error falls back to start", []time.Time{t0}, t0.Add(48 * time.Hour), t0.Add(9 * 24 * time.Hour), errBoom},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeStore()
			for i, f := range tc.first {
				st.addDevice(model.Device{MAC: fmt.Sprintf("AA:00:00:00:00:%02X", i), FirstSeen: f})
			}
			st.errDevices = tc.err
			e, _ := newTestEngine(t, st, tc.start)
			if got := e.LearningUntil(); !got.Equal(tc.want) {
				t.Fatalf("LearningUntil = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLearningRetriesAfterStoreError(t *testing.T) {
	st := newFakeStore()
	st.addDevice(model.Device{MAC: "AA:00:00:00:00:01", FirstSeen: t0})
	st.errDevices = errBoom
	e, _ := newTestEngine(t, st, t0.Add(48*time.Hour))
	_ = e.LearningUntil()
	st.errDevices = nil
	if got, want := e.LearningUntil(), t0.Add(7*24*time.Hour); !got.Equal(want) {
		t.Fatalf("after recovery LearningUntil = %v, want %v", got, want)
	}
}

// First boot with 30 existing devices must not produce 30 alerts, only one
// Info summary after the inventory window, exactly once (even after restart).
func TestFirstBootNoSpam(t *testing.T) {
	st := newFakeStore()
	e, sink := newTestEngine(t, st, t0)
	for i := 0; i < 30; i++ {
		kind := []string{"phone", "camera", "unknown", "tv", "iot"}[i%5]
		d := model.Device{MAC: fmt.Sprintf("AA:BB:CC:00:00:%02X", i), Kind: kind, LastSeen: t0.Add(time.Minute)}
		isNew, _ := st.UpsertDevice(ctx, d)
		e.DeviceSeen(ctx, d, isNew)
	}
	// a device appearing 20h later is still part of the inventory
	late := model.Device{MAC: "AA:BB:CC:00:01:00", Kind: "unknown", LastSeen: t0.Add(20 * time.Hour)}
	isNew, _ := st.UpsertDevice(ctx, late)
	e.DeviceSeen(ctx, late, isNew)
	if n := len(sink.all()); n != 0 {
		t.Fatalf("got %d alerts during inventory, want 0: %+v", n, sink.all())
	}
	e.Tick(ctx, t0.Add(12*time.Hour))
	if n := len(sink.all()); n != 0 {
		t.Fatalf("summary before inventory end: %d alerts", n)
	}
	e.Tick(ctx, t0.Add(25*time.Hour))
	al := sink.all()
	if len(al) != 1 {
		t.Fatalf("got %d alerts after inventory, want 1 summary", len(al))
	}
	a := al[0]
	if a.Severity != model.SevInfo || a.DedupKey != inventoryDedupKey || a.Evidence["devices"] != 31 {
		t.Fatalf("bad summary: %+v", a)
	}
	if !strings.Contains(a.Title, "31 zařízení") {
		t.Fatalf("title %q", a.Title)
	}
	e.Tick(ctx, t0.Add(26*time.Hour))
	// restart: a new engine must not repeat the summary
	e2 := New(st, sink, testConfig(), t0.Add(30*time.Hour))
	e2.Tick(ctx, t0.Add(31*time.Hour))
	if n := len(sink.all()); n != 1 {
		t.Fatalf("summary repeated: %d alerts", n)
	}
}

func TestNewDevice(t *testing.T) {
	tests := []struct {
		name    string
		at      time.Duration // since t0 (learning start)
		dev     model.Device
		isNew   bool
		wantSev model.Severity
		want    bool
	}{
		{"during inventory", 2 * time.Hour, model.Device{Kind: "unknown"}, true, 0, false},
		{"not new", 3 * 24 * time.Hour, model.Device{Kind: "unknown"}, false, 0, false},
		{"guest phone randomized during learning", 3 * 24 * time.Hour, model.Device{Kind: "phone", Randomized: true}, true, model.SevInfo, true},
		{"unknown fixed MAC", 10 * 24 * time.Hour, model.Device{Kind: "unknown"}, true, model.SevWarning, true},
		{"empty kind fixed MAC", 10 * 24 * time.Hour, model.Device{}, true, model.SevWarning, true},
		{"unknown randomized", 10 * 24 * time.Hour, model.Device{Kind: "unknown", Randomized: true}, true, model.SevInfo, true},
		{"new camera", 10 * 24 * time.Hour, model.Device{Kind: "camera", Vendor: "Hikvision"}, true, model.SevInfo, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeStore()
			st.addDevice(model.Device{MAC: "00:00:00:00:00:01", FirstSeen: t0})
			e, sink := newTestEngine(t, st, t0)
			d := tc.dev
			d.MAC = "11:22:33:44:55:66"
			d.LastSeen = t0.Add(tc.at)
			d.IP = netip.MustParseAddr("192.168.88.50")
			e.DeviceSeen(ctx, d, tc.isNew)
			e.DeviceSeen(ctx, d, false) // second poll: nothing more
			al := sink.ofKind(model.AlertNewDevice)
			if !tc.want {
				if len(al) != 0 {
					t.Fatalf("unexpected alert %+v", al)
				}
				return
			}
			if len(al) != 1 {
				t.Fatalf("got %d alerts, want 1", len(al))
			}
			a := al[0]
			if a.Severity != tc.wantSev || a.DedupKey != "new_device:"+d.MAC || a.DeviceMAC != d.MAC {
				t.Fatalf("bad alert %+v", a)
			}
			if !strings.HasPrefix(a.Title, "Nové zařízení v síti") || !strings.Contains(a.Detail, "192.168.88.50") {
				t.Fatalf("bad text %q / %q", a.Title, a.Detail)
			}
		})
	}
}

// --- new country / ASN -----------------------------------------------------

const (
	camMAC   = "C0:00:00:00:00:01"
	phoneMAC = "P0:00:00:00:00:01"
	tvMAC    = "70:00:00:00:00:01"
)

func cz() model.DestStat { return model.DestStat{Country: "CZ", ASN: 5610, ASOrg: "O2"} }

type destCase struct {
	name      string
	setup     func(st *fakeStore)
	flows     func(h time.Time) []model.FlowSample
	wantKinds []string // alert kinds after the hour closes, in order
	wantSev   model.Severity
	check     func(t *testing.T, al []model.Alert)
	immediate bool // alert expected before the hour closes
}

func TestDestinationNovelty(t *testing.T) {
	day10 := t0.Add(10 * 24 * time.Hour)
	H := day10.Add(10 * time.Hour)
	tests := []destCase{
		{
			name:  "camera uploads 2 MB to new country -> warning",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(5*time.Minute), "5.6.7.8:443", "RU", 12389, 2*mB, 10*kB, true)}
			},
			wantKinds: []string{model.AlertNewCountry},
			wantSev:   model.SevWarning,
			check: func(t *testing.T, al []model.Alert) {
				a := al[0]
				if !strings.Contains(a.Title, "novou zemí: RU") || !strings.Contains(a.Detail, "5.6.7.8:443") {
					t.Fatalf("text %q / %q", a.Title, a.Detail)
				}
				if a.Evidence["known_countries"] != 1 {
					t.Fatalf("evidence %+v", a.Evidence)
				}
			},
		},
		{
			name:  "camera uploads 15 MB to new country -> immediate critical",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				var fs []model.FlowSample
				for i := 0; i < 5; i++ {
					fs = append(fs, flow(camMAC, h.Add(time.Duration(5+i)*time.Minute), "5.6.7.8:443", "CN", 4134, 3*mB, 0, i == 0))
				}
				return fs
			},
			wantKinds: []string{model.AlertNewCountry},
			wantSev:   model.SevCritical,
			immediate: true,
		},
		{
			name:  "camera one-off tiny CDN hit -> nothing, learnt",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "1.1.1.1:443", "US", 13335, 10*kB, 50*kB, true)}
			},
		},
		{
			name:  "camera two new countries in one hour -> one aggregated alert",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{
					flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 1*mB, 0, true),
					flow(camMAC, h.Add(2*time.Minute), "9.9.9.9:443", "CN", 4134, 1*mB, 0, true),
					flow(camMAC, h.Add(3*time.Minute), "9.9.9.10:443", "CN", 4134, 1*mB, 0, true),
				}
			},
			wantKinds: []string{model.AlertNewCountry},
			wantSev:   model.SevWarning,
			check: func(t *testing.T, al []model.Alert) {
				if !strings.Contains(al[0].Title, "novými zeměmi: CN, RU") {
					t.Fatalf("title %q", al[0].Title)
				}
				if al[0].DedupKey != "new_country:"+camMAC+":CN,RU" {
					t.Fatalf("dedup %q", al[0].DedupKey)
				}
			},
		},
		{
			name: "camera in device warm-up -> nothing",
			setup: func(st *fakeStore) {
				matureDevice(st, "00:00:00:00:00:AA", "phone", true, cz()) // anchors learning at t0
				warmupDevice(st, camMAC, "camera", day10.Add(-24*time.Hour))
			},
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 30*mB, 0, true)}
			},
		},
		{
			name: "phone streams from CDNs in 10 countries -> nothing",
			setup: func(st *fakeStore) {
				matureDevice(st, phoneMAC, "phone", true, cz())
			},
			flows: func(h time.Time) []model.FlowSample {
				var fs []model.FlowSample
				for i, cc := range []string{"DE", "NL", "US", "IE", "FR", "GB", "SE", "PL", "AT", "SG"} {
					fs = append(fs, flow(phoneMAC, h.Add(time.Duration(i)*time.Minute), fmt.Sprintf("8.8.%d.1:443", i), cc, uint32(100+i), 500*kB, 50*mB, true))
				}
				return fs
			},
		},
		{
			name: "phone uploads to a country the household already uses -> nothing",
			setup: func(st *fakeStore) {
				matureDevice(st, phoneMAC, "phone", true, cz())
				matureDevice(st, "P0:00:00:00:00:02", "computer", false, cz(), model.DestStat{Country: "US", ASN: 15169})
			},
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{
					flow("P0:00:00:00:00:02", h.Add(time.Minute), "8.8.8.8:443", "US", 15169, 1*kB, 1*kB, false), // loads its cache
					flow(phoneMAC, h.Add(2*time.Minute), "8.8.4.4:443", "US", 15169, 300*mB, 1*mB, true),
				}
			},
		},
		{
			name:  "phone uploads 30 MB to a brand new country -> warning",
			setup: func(st *fakeStore) { matureDevice(st, phoneMAC, "phone", true, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(phoneMAC, h.Add(time.Minute), "45.1.1.1:443", "KP", 131279, 30*mB, 1*mB, true)}
			},
			wantKinds: []string{model.AlertNewCountry},
			wantSev:   model.SevWarning,
		},
		{
			name: "globetrotter laptop -> nothing",
			setup: func(st *fakeStore) {
				var ds []model.DestStat
				for i := 0; i < 15; i++ {
					ds = append(ds, model.DestStat{Country: fmt.Sprintf("X%c", 'A'+i), ASN: uint32(i + 1)})
				}
				matureDevice(st, phoneMAC, "computer", false, ds...)
			},
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(phoneMAC, h.Add(time.Minute), "45.1.1.1:443", "KP", 131279, 300*mB, 1*mB, true)}
			},
		},
		{
			name:  "dest stats load failure -> nothing (never assume everything is new)",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()); st.errDest = errBoom },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 30*mB, 0, true)}
			},
		},
		{
			name:  "camera NTP pool servers in new countries -> nothing",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				var fs []model.FlowSample
				for i, cc := range []string{"DE", "DE", "DE", "DE", "DE", "DE", "FI", "SE"} {
					f := flow(camMAC, h.Add(time.Duration(i)*time.Minute), fmt.Sprintf("95.1.1.%d:123", i), cc, uint32(200+i), 76, 76, true)
					f.Proto = "udp"
					fs = append(fs, f)
				}
				return fs
			},
		},
		{
			name:  "unknown country code ignored",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "", 0, 30*mB, 0, true)}
			},
		},
		{
			name:  "camera new ASN in known country -> new_asn warning",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "77.1.1.1:443", "CZ", 6830, 1*mB, 0, true)}
			},
			wantKinds: []string{model.AlertNewASN},
			wantSev:   model.SevWarning,
			check: func(t *testing.T, al []model.Alert) {
				if !strings.Contains(al[0].Title, "AS6830") || al[0].Evidence["known_asns"] != 1 {
					t.Fatalf("bad %q %+v", al[0].Title, al[0].Evidence)
				}
			},
		},
		{
			name:  "new ASN in new country -> only the country alert",
			setup: func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 2*mB, 0, true)}
			},
			wantKinds: []string{model.AlertNewCountry},
			wantSev:   model.SevWarning,
		},
		{
			name:  "phone new ASN -> nothing (ASN novelty off for phones)",
			setup: func(st *fakeStore) { matureDevice(st, phoneMAC, "phone", true, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(phoneMAC, h.Add(time.Minute), "77.1.1.1:443", "CZ", 6830, 50*mB, 0, true)}
			},
		},
		{
			name: "camera with unstable ASN set -> nothing",
			setup: func(st *fakeStore) {
				ds := []model.DestStat{cz()}
				for i := 0; i < 30; i++ {
					ds = append(ds, model.DestStat{Country: "CZ", ASN: uint32(1000 + i)})
				}
				matureDevice(st, camMAC, "camera", false, ds...)
			},
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "77.1.1.1:443", "CZ", 6830, 5*mB, 0, true)}
			},
		},
		{
			name:  "TV downloads 5 MB from new country -> nothing (streaming)",
			setup: func(st *fakeStore) { matureDevice(st, tvMAC, "tv", false, cz()) },
			flows: func(h time.Time) []model.FlowSample {
				return []model.FlowSample{flow(tvMAC, h.Add(time.Minute), "23.1.1.1:443", "NL", 20940, 100*kB, 5*mB, true)}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeStore()
			tc.setup(st)
			e, sink := newTestEngine(t, st, day10)
			feed(e, st, tc.flows(H)...)
			if tc.immediate {
				if n := len(sink.all()); n != 1 {
					t.Fatalf("immediate: got %d alerts, want 1", n)
				}
			} else if n := len(sink.all()); n != 0 {
				t.Fatalf("alert before hour closed: %+v", sink.all())
			}
			e.Tick(ctx, H.Add(65*time.Minute)) // closes hour H
			al := sink.all()
			if len(al) != len(tc.wantKinds) {
				t.Fatalf("got %d alerts %v, want kinds %v", len(al), titles(al), tc.wantKinds)
			}
			for i, k := range tc.wantKinds {
				if al[i].Kind != k {
					t.Fatalf("alert %d kind %s, want %s", i, al[i].Kind, k)
				}
				if al[i].Severity != tc.wantSev {
					t.Fatalf("alert %d severity %v, want %v", i, al[i].Severity, tc.wantSev)
				}
				if len(al[i].Evidence) == 0 || al[i].DeviceMAC == "" {
					t.Fatalf("missing evidence/device: %+v", al[i])
				}
			}
			if tc.check != nil {
				tc.check(t, al)
			}
			// The same destinations next hour must not alert again.
			sink.reset()
			if tc.name != "dest stats load failure -> nothing (never assume everything is new)" {
				feed(e, st, tc.flows(H.Add(time.Hour))...)
				e.Tick(ctx, H.Add(125*time.Minute))
				if al := sink.all(); len(al) != 0 {
					t.Fatalf("repeated alert next hour: %v", titles(al))
				}
			}
		})
	}
}

func TestNoveltySuppressedDuringGlobalLearning(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	cfg := testConfig()
	cfg.LearnPeriod = 30 * 24 * time.Hour
	sink := &fakeSink{store: st}
	e := New(st, sink, cfg, t0.Add(10*24*time.Hour))
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	feed(e, st, flow(camMAC, H.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 50*mB, 0, true))
	e.Tick(ctx, H.Add(65*time.Minute))
	for _, k := range []string{model.AlertNewCountry, model.AlertUploadSpike, model.AlertNewASN} {
		if al := sink.ofKind(k); len(al) != 0 {
			t.Fatalf("alerts during learning: %v", titles(al))
		}
	}
}

func TestNoveltyCacheRecoversAfterStoreError(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	st.errDest = errBoom
	e, sink := newTestEngine(t, st, t0.Add(10*24*time.Hour))
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	feed(e, st, flow(camMAC, H.Add(time.Minute), "1.2.3.4:443", "CZ", 5610, kB, kB, false))
	st.errDest = nil
	// retried after destRetry
	feed(e, st, flow(camMAC, H.Add(10*time.Minute), "5.6.7.8:443", "RU", 12389, 2*mB, 0, true))
	e.Tick(ctx, H.Add(65*time.Minute))
	if al := sink.ofKind(model.AlertNewCountry); len(al) != 1 {
		t.Fatalf("got %v", titles(sink.all()))
	}
}

// warmupDevice: recently first seen, a little history.
func warmupDevice(st *fakeStore, mac, kind string, first time.Time) {
	st.addDevice(model.Device{MAC: mac, Kind: kind, FirstSeen: first})
	st.seedHours(mac, first, 24, func(int, time.Time) model.HourStat {
		return model.HourStat{TxBytes: mB, DistinctDst: 5}
	})
	st.seedDest(mac, first, cz())
}

func titles(al []model.Alert) []string {
	var out []string
	for _, a := range al {
		out = append(out, a.Kind+": "+a.Title)
	}
	return out
}

// --- concurrency / robustness ---------------------------------------------

func TestConcurrentCalls(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	e, _ := newTestEngine(t, st, t0.Add(10*24*time.Hour))
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				at := H.Add(time.Duration(i) * time.Minute)
				switch g % 4 {
				case 0:
					e.Flows(ctx, []model.FlowSample{flow(camMAC, at, "1.2.3.4:443", "CZ", 5610, kB, kB, false)})
				case 1:
					e.DeviceSeen(ctx, model.Device{MAC: camMAC, Kind: "camera", LastSeen: at}, false)
				case 2:
					e.Tick(ctx, at)
				default:
					_ = e.LearningUntil()
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestStoreErrorsNeverPanic(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	st.errDevices, st.errDest, st.errHours, st.errDedup = errBoom, errBoom, errBoom, errBoom
	e, sink := newTestEngine(t, st, t0)
	now := t0.Add(10 * 24 * time.Hour)
	e.DeviceSeen(ctx, model.Device{MAC: camMAC, LastSeen: now}, false)
	e.Flows(ctx, []model.FlowSample{flow(camMAC, now, "5.6.7.8:443", "RU", 1, 5*gB, 0, true)})
	e.Tick(ctx, now.Add(2*time.Hour))
	_ = e.LearningUntil()
	if al := sink.all(); len(al) != 0 {
		t.Fatalf("alerts despite broken store: %v", titles(al))
	}
}

func TestEviction(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	e, _ := newTestEngine(t, st, t0.Add(10*24*time.Hour))
	at := t0.Add(10 * 24 * time.Hour)
	e.Flows(ctx, []model.FlowSample{flow(camMAC, at, "1.2.3.4:443", "CZ", 5610, kB, kB, false)})
	e.Tick(ctx, at.Add(10*24*time.Hour))
	if len(e.devs) != 1 {
		t.Fatalf("evicted too early")
	}
	e.Tick(ctx, at.Add(31*24*time.Hour))
	if len(e.devs) != 0 {
		t.Fatalf("not evicted: %d", len(e.devs))
	}
}

func TestNewDeviceSameHostnameRandomized(t *testing.T) {
	tests := []struct {
		name  string
		known model.Device
		dev   model.Device
		want  bool // alert expected
	}{
		{"same phone other SSID", model.Device{Hostname: "Pixel-8"}, model.Device{Hostname: "pixel-8", Randomized: true, Kind: "phone"}, false},
		{"fixed MAC with same hostname still alerts", model.Device{Hostname: "Pixel-8"}, model.Device{Hostname: "Pixel-8", Kind: "phone"}, true},
		{"different hostname", model.Device{Hostname: "Pixel-8"}, model.Device{Hostname: "Pixel-7", Randomized: true, Kind: "phone"}, true},
		{"empty hostname never matches", model.Device{}, model.Device{Randomized: true, Kind: "phone"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := newFakeStore()
			k := tc.known
			k.MAC, k.FirstSeen = "02:00:00:00:00:01", t0
			st.addDevice(k)
			e, sink := newTestEngine(t, st, t0)
			d := tc.dev
			d.MAC = "06:00:00:00:00:02"
			d.LastSeen = t0.Add(10 * 24 * time.Hour)
			isNew, _ := st.UpsertDevice(ctx, d) // store already contains d itself, as in production
			e.DeviceSeen(ctx, d, isNew)
			if got := len(sink.ofKind(model.AlertNewDevice)) == 1; got != tc.want {
				t.Fatalf("alert = %v, want %v (%+v)", got, tc.want, sink.all())
			}
		})
	}
}

func TestNewDeviceSameHostnameStoreError(t *testing.T) {
	st := newFakeStore()
	st.addDevice(model.Device{MAC: "02:00:00:00:00:01", Hostname: "Pixel-8", FirstSeen: t0})
	e, sink := newTestEngine(t, st, t0)
	_ = e.LearningUntil() // resolve learning before the store breaks
	st.errDevices = errBoom
	d := model.Device{MAC: "06:00:00:00:00:02", Hostname: "Pixel-8", Randomized: true, LastSeen: t0.Add(10 * 24 * time.Hour)}
	e.DeviceSeen(ctx, d, true)
	if n := len(sink.ofKind(model.AlertNewDevice)); n != 1 {
		t.Fatalf("store error must fall back to alerting, got %d", n)
	}
}

func TestNewDeviceUsesComment(t *testing.T) {
	st := newFakeStore()
	st.addDevice(model.Device{MAC: "00:00:00:00:00:01", FirstSeen: t0})
	e, sink := newTestEngine(t, st, t0)
	d := model.Device{MAC: "11:22:33:44:55:66", Hostname: "Televize-v-obyvaku", Kind: "tv", Comment: "TV obývák",
		LastSeen: t0.Add(10 * 24 * time.Hour)}
	e.DeviceSeen(ctx, d, true)
	al := sink.ofKind(model.AlertNewDevice)
	if len(al) != 1 || al[0].Title != "Nové zařízení v síti: TV obývák" || !strings.Contains(al[0].Detail, "komentář TV obývák") {
		t.Fatalf("alerts = %+v", al)
	}
}
