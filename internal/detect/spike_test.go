package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// hourly scenario: device with `days` days of history where fn gives the
// value per hour, then `obs` in the evaluated hour.
type hourCase struct {
	name     string
	kind     string
	random   bool
	first    time.Time // device FirstSeen (default t0)
	histFrom time.Time // default t0
	hist     func(i int, h time.Time) model.HourStat
	histN    int // default up to target
	obs      model.HourStat
	noObs    bool
	wantKind string
	wantSev  model.Severity
	check    func(t *testing.T, a model.Alert)

	override string   // stored KindOverride
	lang     string   // alert language (default cs)
	sens     string   // sensitivity (default normal)
	disabled []string // disabled detectors
}

func noisy(base uint64, i int) uint64 {
	// deterministic ±20 % noise
	return base + base*uint64((i*7)%5)/10 - base/5
}

func runHourCase(t *testing.T, tc hourCase) {
	t.Helper()
	target := t0.Add(12*24*time.Hour + 9*time.Hour)
	st := newFakeStore()
	first := tc.first
	if first.IsZero() {
		first = t0
	}
	st.addDevice(model.Device{MAC: camMAC, Kind: tc.kind, KindOverride: tc.override, Vendor: "Hikvision",
		Randomized: tc.random, FirstSeen: first})
	// the learning period is anchored at t0 by another device
	st.addDevice(model.Device{MAC: "00:00:00:00:00:00", Kind: "phone", FirstSeen: t0})
	from := tc.histFrom
	if from.IsZero() {
		from = t0
	}
	n := tc.histN
	if n == 0 {
		n = int(target.Sub(from).Hours())
	}
	st.seedHours(camMAC, from, n, tc.hist)
	if !tc.noObs {
		st.seedHours(camMAC, target, 1, func(int, time.Time) model.HourStat { return tc.obs })
	}
	e, sink := newTestEngine(t, st, target)
	set := testSettings("cs")
	if tc.lang != "" {
		set.Language = tc.lang
	}
	if tc.sens != "" {
		set.Sensitivity = tc.sens
	}
	set.DisabledDetectors = tc.disabled
	e.SetSettings(set)
	e.Tick(ctx, target.Add(time.Hour+30*time.Minute))
	al := sink.all()
	if tc.wantKind == "" {
		if len(al) != 0 {
			t.Fatalf("unexpected alerts: %v (evidence %+v)", titles(al), al[0].Evidence)
		}
		return
	}
	if len(al) != 1 || al[0].Kind != tc.wantKind {
		t.Fatalf("got %v, want one %s", titles(al), tc.wantKind)
	}
	if al[0].Severity != tc.wantSev {
		t.Fatalf("severity %v, want %v", al[0].Severity, tc.wantSev)
	}
	if tc.check != nil {
		tc.check(t, al[0])
	}
}

func TestUploadSpikeHourly(t *testing.T) {
	cam45 := func(i int, _ time.Time) model.HourStat {
		return model.HourStat{TxBytes: noisy(45*mB, i), DistinctDst: 6}
	}
	tests := []hourCase{
		{
			name: "camera 3.1 GB vs 45 MB -> critical",
			kind: "camera", hist: cam45,
			obs:      model.HourStat{TxBytes: 3174 * mB, DistinctDst: 6},
			wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
			check: func(t *testing.T, a model.Alert) {
				if !strings.Contains(a.Title, "nahrává 3,1 GB/h") || !strings.HasPrefix(a.Title, "Kamera (Hikvision)") {
					t.Fatalf("title %q", a.Title)
				}
				if !strings.Contains(a.Detail, "× více") || !strings.Contains(a.Detail, "medián z 12 dní") {
					t.Fatalf("detail %q", a.Detail)
				}
				r := a.Evidence["ratio"].(float64)
				if r < 60 || r > 80 {
					t.Fatalf("ratio %v", r)
				}
				if a.Evidence["baseline_method"] != "same_hour" || a.DedupKey != "upload_spike:"+camMAC {
					t.Fatalf("evidence %+v", a.Evidence)
				}
			},
		},
		{
			name: "camera spike below absolute minimum -> nothing",
			kind: "camera",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: noisy(1*mB, i)} },
			obs:  model.HourStat{TxBytes: 150 * mB}, // 150× but < 200 MB
		},
		{
			name: "iot 250 MB vs 1 MB -> critical",
			kind: "iot",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: noisy(1*mB, i)} },
			obs:  model.HourStat{TxBytes: 250 * mB}, wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
		},
		{
			name: "camera 400 MB vs 45 MB (9x) -> nothing, ratio too low",
			kind: "camera", hist: cam45,
			obs: model.HourStat{TxBytes: 400 * mB},
		},
		{
			name: "camera did a 3 GB upload before (weekly cloud sync) -> nothing",
			kind: "camera",
			hist: func(i int, h time.Time) model.HourStat {
				if h.Weekday() == time.Sunday && h.Hour() == 3 {
					return model.HourStat{TxBytes: 3 * gB}
				}
				return cam45(i, h)
			},
			obs: model.HourStat{TxBytes: 3 * gB},
		},
		{
			name: "tv 600 MB vs 10 MB -> warning",
			kind: "tv",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: noisy(10*mB, i)} },
			obs:  model.HourStat{TxBytes: 600 * mB}, wantKind: model.AlertUploadSpike, wantSev: model.SevWarning,
		},
		{
			name: "phone 1.5 GB photo backup vs 20 MB -> nothing (lenient absolute 2 GB)",
			kind: "phone", random: true,
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: noisy(20*mB, i)} },
			obs:  model.HourStat{TxBytes: 1536 * mB},
		},
		{
			name: "computer 5 GB vs 50 MB -> warning",
			kind: "computer",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: noisy(50*mB, i)} },
			obs:  model.HourStat{TxBytes: 5 * gB}, wantKind: model.AlertUploadSpike, wantSev: model.SevWarning,
		},
		{
			name: "short history (30 h) -> nothing",
			kind: "camera", first: t0.Add(8 * 24 * time.Hour), histFrom: t0.Add(12*24*time.Hour - 21*time.Hour), histN: 30,
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: mB} },
			obs:  model.HourStat{TxBytes: 5 * gB},
		},
		{
			name: "device in warm-up (first seen 2 days ago) -> nothing",
			kind: "camera", first: t0.Add(10*24*time.Hour + 9*time.Hour), histFrom: t0.Add(10*24*time.Hour + 9*time.Hour),
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: mB} },
			obs:  model.HourStat{TxBytes: 5 * gB},
		},
		{
			name: "intermittent device uses all-hours fallback",
			kind: "camera", histFrom: t0.Add(9 * 24 * time.Hour),
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: 2 * mB} },
			obs:  model.HourStat{TxBytes: 1 * gB}, wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
			check: func(t *testing.T, a model.Alert) {
				if a.Evidence["baseline_method"] != "all_hours" {
					t.Fatalf("method %v", a.Evidence["baseline_method"])
				}
			},
		},
		{
			name: "no row for the hour (offline) -> nothing",
			kind: "camera", hist: cam45, noObs: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { runHourCase(t, tc) })
	}
}

func TestDestFanout(t *testing.T) {
	tests := []hourCase{
		{
			name:     "camera 400 distinct vs 8 -> critical",
			kind:     "camera",
			hist:     func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: 5 * mB, DistinctDst: 6 + i%5} },
			obs:      model.HourStat{TxBytes: 5 * mB, DistinctDst: 400, NewConns: 2000},
			wantKind: model.AlertDestFanout, wantSev: model.SevCritical,
			check: func(t *testing.T, a model.Alert) {
				if !strings.Contains(a.Title, "400 různých adres") || a.Evidence["observed_dst"] != 400 {
					t.Fatalf("%q %+v", a.Title, a.Evidence)
				}
			},
		},
		{
			name: "computer 600 distinct vs 200 -> nothing",
			kind: "computer",
			hist: func(i int, _ time.Time) model.HourStat {
				return model.HourStat{TxBytes: 5 * mB, DistinctDst: 150 + i%100}
			},
			obs: model.HourStat{TxBytes: 5 * mB, DistinctDst: 600},
		},
		{
			name: "tv 150 distinct vs 10 -> nothing (below tv minimum 200)",
			kind: "tv",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: 5 * mB, DistinctDst: 10} },
			obs:  model.HourStat{TxBytes: 5 * mB, DistinctDst: 150},
		},
		{
			name: "tv 300 distinct vs 10 -> warning",
			kind: "tv",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: 5 * mB, DistinctDst: 10} },
			obs:  model.HourStat{TxBytes: 5 * mB, DistinctDst: 300}, wantKind: model.AlertDestFanout, wantSev: model.SevWarning,
		},
		{
			name: "computer 5000 distinct vs 200 -> warning",
			kind: "computer",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: 5 * mB, DistinctDst: 200} },
			obs:  model.HourStat{TxBytes: 5 * mB, DistinctDst: 5000}, wantKind: model.AlertDestFanout, wantSev: model.SevWarning,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { runHourCase(t, tc) })
	}
}

func TestFastSpikeInFlows(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz()) // 5 MB/h history
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	e, sink := newTestEngine(t, st, H)
	// 20 minutes of heavy upload to a known destination: 60 MB per poll
	for i := 0; i < 20; i++ {
		feed(e, st, flow(camMAC, H.Add(time.Duration(i)*time.Minute), "1.2.3.4:443", "CZ", 5610, 60*mB, kB, i == 0))
	}
	al := sink.ofKind(model.AlertUploadSpike)
	if len(al) != 1 {
		t.Fatalf("fast path: got %v", titles(sink.all()))
	}
	a := al[0]
	if a.Severity != model.SevCritical || a.Evidence["path"] != "fast" {
		t.Fatalf("bad fast alert %+v", a)
	}
	if !strings.Contains(a.Title, "právě nahrává") {
		t.Fatalf("title %q", a.Title)
	}
	// rest of the hour + hourly tick must not duplicate
	for i := 20; i < 60; i++ {
		feed(e, st, flow(camMAC, H.Add(time.Duration(i)*time.Minute), "1.2.3.4:443", "CZ", 5610, 60*mB, kB, false))
	}
	e.Tick(ctx, H.Add(70*time.Minute))
	if al := sink.ofKind(model.AlertUploadSpike); len(al) != 1 {
		t.Fatalf("duplicated: %v", titles(al))
	}
}

func TestFastSpikeNotForModerateUpload(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, phoneMAC, "phone", true, cz())
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	e, sink := newTestEngine(t, st, H)
	// 1.2 GB within the hour: above fast min, but phone profile needs 2 GB
	for i := 0; i < 20; i++ {
		feed(e, st, flow(phoneMAC, H.Add(time.Duration(i)*time.Minute), "1.2.3.4:443", "CZ", 5610, 60*mB, kB, false))
	}
	if al := sink.all(); len(al) != 0 {
		t.Fatalf("unexpected %v", titles(al))
	}
}

func TestTickCatchupAndNoDoubleEvaluation(t *testing.T) {
	st := newFakeStore()
	st.addDevice(model.Device{MAC: camMAC, Kind: "camera", FirstSeen: t0})
	target := t0.Add(12*24*time.Hour + 9*time.Hour)
	st.seedHours(camMAC, t0, int(target.Sub(t0).Hours()), func(i int, _ time.Time) model.HourStat {
		return model.HourStat{TxBytes: noisy(5*mB, i)}
	})
	st.seedHours(camMAC, target, 1, func(int, time.Time) model.HourStat { return model.HourStat{TxBytes: gB} })
	e, sink := newTestEngine(t, st, target)
	e.Tick(ctx, target.Add(70*time.Minute))
	e.Tick(ctx, target.Add(75*time.Minute)) // same hour again: no re-evaluation
	if al := sink.all(); len(al) != 1 {
		t.Fatalf("got %v", titles(al))
	}
	// Tick that skipped two hours evaluates the missing ones (catch-up)
	sink.reset()
	st.seedHours(camMAC, target.Add(2*time.Hour), 1, func(int, time.Time) model.HourStat { return model.HourStat{TxBytes: 2 * gB} })
	e.Tick(ctx, target.Add(3*time.Hour+10*time.Minute))
	if al := sink.ofKind(model.AlertUploadSpike); len(al) != 1 {
		t.Fatalf("catch-up: got %v", titles(sink.all()))
	}
}
