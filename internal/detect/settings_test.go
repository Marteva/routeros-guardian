package detect

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

func TestSetSettingsLearning(t *testing.T) {
	st := newFakeStore()
	st.addDevice(model.Device{MAC: "AA:00:00:00:00:01", FirstSeen: t0})
	e, _ := newTestEngine(t, st, t0.Add(48*time.Hour))
	check := func(want time.Time) {
		t.Helper()
		if got := e.LearningUntil(); !got.Equal(want) {
			t.Fatalf("LearningUntil = %v, want %v", got, want)
		}
	}
	check(t0.Add(7 * 24 * time.Hour)) // derived from the earliest FirstSeen

	s := testSettings("en")
	s.LearnPeriod = 3 * 24 * time.Hour
	e.SetSettings(s)
	check(t0.Add(3 * 24 * time.Hour))

	// An explicit learning start wins over the data (later or earlier).
	R := t0.Add(20 * 24 * time.Hour)
	s.LearningStart = R
	e.SetSettings(s)
	check(R.Add(3 * 24 * time.Hour))
	s.LearningStart = t0.Add(-24 * time.Hour)
	e.SetSettings(s)
	check(t0.Add(2 * 24 * time.Hour))

	// LearnPeriod 0 keeps the configured period.
	s.LearnPeriod = 0
	s.LearningStart = R
	e.SetSettings(s)
	check(R.Add(7 * 24 * time.Hour))

	// Back to "derive from the data".
	s.LearningStart = time.Time{}
	e.SetSettings(s)
	check(t0.Add(7 * 24 * time.Hour))
}

// The inventory window (no per-device new-device alerts) is anchored on the
// explicit learning start.
func TestInventoryAnchoredOnLearningStart(t *testing.T) {
	st := newFakeStore()
	st.addDevice(model.Device{MAC: "00:00:00:00:00:01", FirstSeen: t0})
	e, sink := newTestEngine(t, st, t0)
	R := t0.Add(30 * 24 * time.Hour)
	s := testSettings("cs")
	s.LearningStart = R
	e.SetSettings(s)
	seen := func(mac string, at time.Time) {
		d := model.Device{MAC: mac, Kind: "unknown", LastSeen: at}
		isNew, _ := st.UpsertDevice(ctx, d)
		e.DeviceSeen(ctx, d, isNew)
	}
	seen("11:00:00:00:00:01", R.Add(-time.Hour))
	seen("11:00:00:00:00:02", R.Add(2*time.Hour))
	if al := sink.ofKind(model.AlertNewDevice); len(al) != 0 {
		t.Fatalf("new-device alerts inside the inventory window: %v", titles(al))
	}
	seen("11:00:00:00:00:03", R.Add(25*time.Hour))
	if al := sink.ofKind(model.AlertNewDevice); len(al) != 1 || al[0].DeviceMAC != "11:00:00:00:00:03" {
		t.Fatalf("want one alert after the inventory: %v", titles(al))
	}
}

// A learning period shorter than the inventory window caps the window; the
// summary then says learning is complete.
func TestShortLearnPeriodCapsInventory(t *testing.T) {
	st := newFakeStore()
	e, sink := newTestEngine(t, st, t0)
	s := testSettings("cs")
	s.LearnPeriod = 12 * time.Hour
	s.LearningStart = t0
	e.SetSettings(s)
	for i := 0; i < 3; i++ {
		d := model.Device{MAC: fmt.Sprintf("AA:00:00:00:00:%02X", i), Kind: "phone", LastSeen: t0.Add(time.Minute)}
		isNew, _ := st.UpsertDevice(ctx, d)
		e.DeviceSeen(ctx, d, isNew)
	}
	late := model.Device{MAC: "AA:00:00:00:01:00", Kind: "camera", LastSeen: t0.Add(13 * time.Hour)}
	isNew, _ := st.UpsertDevice(ctx, late)
	e.DeviceSeen(ctx, late, isNew)
	if al := sink.ofKind(model.AlertNewDevice); len(al) != 1 {
		t.Fatalf("got %v, want one new-device alert after the 12 h inventory", titles(al))
	}
	sink.reset()
	e.Tick(ctx, t0.Add(14*time.Hour))
	al := sink.all()
	if len(al) != 1 || al[0].DedupKey != inventoryKey(t0) || al[0].Evidence["devices"] != 3 {
		t.Fatalf("summary: %+v", al)
	}
	if !strings.Contains(al[0].Detail, "prvních 12 hodin") || !strings.Contains(al[0].Detail, "je dokončeno") {
		t.Fatalf("detail %q", al[0].Detail)
	}
}

func TestReset(t *testing.T) {
	macs := []string{"AA:00:00:00:00:01", "AA:00:00:00:00:02", "AA:00:00:00:00:03", "AA:00:00:00:00:04", "AA:00:00:00:00:05"}
	install := func(t *testing.T) (*fakeStore, *Engine, *fakeSink) {
		st := newFakeStore()
		e, sink := newTestEngine(t, st, t0)
		for _, mac := range macs {
			d := model.Device{MAC: mac, Kind: "camera", LastSeen: t0.Add(time.Minute)}
			isNew, _ := st.UpsertDevice(ctx, d)
			e.DeviceSeen(ctx, d, isNew)
		}
		e.Tick(ctx, t0.Add(25*time.Hour))
		if al := sink.all(); len(al) != 1 || al[0].DedupKey != inventoryDedupKey {
			t.Fatalf("first inventory: %v", titles(al))
		}
		day10 := t0.Add(10 * 24 * time.Hour)
		feed(e, st, flow(macs[0], day10, "1.2.3.4:443", "CZ", 5610, kB, kB, false))
		e.Tick(ctx, day10.Add(2*time.Hour))
		if len(e.devs) == 0 || e.lastEval.IsZero() || e.globalHour.IsZero() || len(e.household) == 0 {
			t.Fatalf("precondition: no cached state")
		}
		return st, e, sink
	}
	R := t0.Add(11 * 24 * time.Hour)

	t.Run("reset all: no new-device burst, summary again", func(t *testing.T) {
		st, e, sink := install(t)
		_ = st.ResetAll(ctx)
		before := time.Now()
		e.Reset()
		if len(e.devs) != 0 || len(e.household) != 0 || !e.lastEval.IsZero() || !e.globalHour.IsZero() || !e.summaryFor.IsZero() {
			t.Fatalf("state not dropped")
		}
		if lu := e.LearningUntil(); lu.Before(before.Add(7*24*time.Hour)) || lu.After(time.Now().Add(7*24*time.Hour)) {
			t.Fatalf("Reset must restart learning now, LearningUntil = %v", lu)
		}
		s := testSettings("cs")
		s.LearningStart = R
		e.SetSettings(s)
		if lu := e.LearningUntil(); !lu.Equal(R.Add(7 * 24 * time.Hour)) {
			t.Fatalf("LearningUntil = %v", lu)
		}
		sink.reset()
		for _, mac := range macs { // every device comes back as new
			d := model.Device{MAC: mac, Kind: "camera", LastSeen: R.Add(time.Minute)}
			isNew, _ := st.UpsertDevice(ctx, d)
			if !isNew {
				t.Fatal("fake store: expected isNew")
			}
			e.DeviceSeen(ctx, d, isNew)
		}
		e.Tick(ctx, R.Add(12*time.Hour))
		if al := sink.all(); len(al) != 0 {
			t.Fatalf("alerts during the new inventory: %v", titles(al))
		}
		e.Tick(ctx, R.Add(25*time.Hour))
		al := sink.all()
		if len(al) != 1 || al[0].DedupKey != inventoryKey(R) || al[0].Evidence["devices"] != 5 {
			t.Fatalf("summary after reset: %+v", al)
		}
		nd := model.Device{MAC: "BB:00:00:00:00:01", Kind: "tv", LastSeen: R.Add(30 * time.Hour)}
		isNew, _ := st.UpsertDevice(ctx, nd)
		e.DeviceSeen(ctx, nd, isNew)
		if al := sink.ofKind(model.AlertNewDevice); len(al) != 2 {
			t.Fatalf("new device after the inventory: %v", titles(al))
		}
		// restart with the persisted learning start: no second summary
		e2 := New(st, sink, testConfig(), R.Add(40*time.Hour))
		e2.SetSettings(s)
		e2.Tick(ctx, R.Add(41*time.Hour))
		if n := len(sink.all()); n != 2 {
			t.Fatalf("summary repeated after restart: %v", titles(sink.all()))
		}
	})

	t.Run("old summary still stored: re-armed by the new learning start", func(t *testing.T) {
		_, e, sink := install(t)
		e.Reset()
		s := testSettings("en")
		s.LearningStart = R
		e.SetSettings(s)
		sink.reset()
		e.Tick(ctx, R.Add(25*time.Hour))
		al := sink.all()
		if len(al) != 1 || al[0].DedupKey != inventoryKey(R) || al[0].Title != "Initial inventory complete: 5 devices" {
			t.Fatalf("summary: %v", titles(al))
		}
	})
}

func TestWithSensitivity(t *testing.T) {
	c := DefaultConfig()
	high := c.withSensitivity("high")
	low := c.withSensitivity("low")
	if same := c.withSensitivity("normal"); same.Profiles["camera"] != c.Profiles["camera"] {
		t.Fatal("normal must not change thresholds")
	}
	if same := c.withSensitivity("bogus"); same.Profiles["camera"] != c.Profiles["camera"] {
		t.Fatal("unknown sensitivity must behave as normal")
	}
	cam, camH, camL := c.Profiles["camera"], high.Profiles["camera"], low.Profiles["camera"]
	tests := []struct {
		name      string
		got, want float64
	}{
		{"high spike min", float64(camH.SpikeMinTx), 100 * mB},
		{"high spike ratio", camH.SpikeRatio, 5},
		{"high z", camH.SpikeMinZ, 4.5},
		{"high fanout ratio floored", camH.FanoutRatio, floorRatio},
		{"high fanout min", float64(camH.FanoutMin), 50},
		{"high country tx", float64(camH.CountryMinTx), 128 * kB},
		{"high conns floored", float64(camH.CountryMinConns), floorDestConns},
		{"high critical tx", float64(camH.CountryCriticalTx), 5 * mB},
		{"high fast min", float64(high.FastSpikeMinTx), 512 * mB},
		{"high fast ratio", high.FastSpikeRatio, 25},
		{"high lenient z", high.Profiles["phone"].SpikeMinZ, 6.5},
		{"low spike min", float64(camL.SpikeMinTx), 400 * mB},
		{"low spike ratio", camL.SpikeRatio, 20},
		{"low z", camL.SpikeMinZ, 8},
		{"low fanout min", float64(camL.FanoutMin), 200},
		{"low country conns", float64(camL.CountryMinConns), 10},
		{"low fast min", float64(low.FastSpikeMinTx), 2 * gB},
		// disabled criteria stay disabled
		{"high lenient total stays 0", float64(high.Profiles["phone"].CountryMinTotal), 0},
		{"low lenient asn stays 0", float64(low.Profiles["phone"].ASNMinTx), 0},
		// structural knobs untouched
		{"asn max known", float64(camH.ASNMaxKnown), float64(cam.ASNMaxKnown)},
		{"hist max factor", high.HistMaxFactor, c.HistMaxFactor},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if c.Profiles["camera"].SpikeMinTx != 200*mB || DefaultConfig().Profiles["camera"].SpikeMinTx != 200*mB {
		t.Fatal("scaling mutated the original profiles")
	}
	// A threshold configured below its floor is not raised by "high".
	p := Profile{SpikeMinTx: 10 * mB, SpikeRatio: 2, SpikeMinZ: 2, FanoutMin: 20}.scaled(sensHighFactor, -sensHighZ)
	if p.SpikeMinTx != 10*mB || p.SpikeRatio != 2 || p.SpikeMinZ != 2 || p.FanoutMin != 20 {
		t.Fatalf("below-floor thresholds raised: %+v", p)
	}
}

func TestSensitivityDisabledOverrideHourly(t *testing.T) {
	cam45 := func(i int, _ time.Time) model.HourStat {
		return model.HourStat{TxBytes: noisy(45*mB, i), DistinctDst: 6}
	}
	tiny := func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: noisy(1*mB, i)} }
	tests := []hourCase{
		{
			name: "high: camera 400 MB vs 45 MB (9x) -> critical",
			kind: "camera", hist: cam45, sens: "high",
			obs:      model.HourStat{TxBytes: 400 * mB, DistinctDst: 6},
			wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
		},
		{
			name: "low: iot 250 MB vs 1 MB -> nothing (min 400 MB)",
			kind: "iot", hist: tiny, sens: "low",
			obs: model.HourStat{TxBytes: 250 * mB},
		},
		{
			name: "low: camera 3.1 GB vs 45 MB -> still critical",
			kind: "camera", hist: cam45, sens: "low",
			obs:      model.HourStat{TxBytes: 3174 * mB, DistinctDst: 6},
			wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
		},
		{
			name: "upload_spike disabled -> nothing",
			kind: "camera", hist: cam45, disabled: []string{model.AlertUploadSpike},
			obs: model.HourStat{TxBytes: 3174 * mB, DistinctDst: 6},
		},
		{
			name: "high: tv 150 distinct vs 10 -> warning",
			kind: "tv", sens: "high",
			hist:     func(int, time.Time) model.HourStat { return model.HourStat{TxBytes: 5 * mB, DistinctDst: 10} },
			obs:      model.HourStat{TxBytes: 5 * mB, DistinctDst: 150},
			wantKind: model.AlertDestFanout, wantSev: model.SevWarning,
		},
		{
			name: "dest_fanout disabled -> nothing",
			kind: "camera", disabled: []string{model.AlertDestFanout},
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: 5 * mB, DistinctDst: 6 + i%5} },
			obs:  model.HourStat{TxBytes: 5 * mB, DistinctDst: 400},
		},
		{
			name: "phone 250 MB vs 1 MB -> nothing (lenient)",
			kind: "phone", hist: tiny,
			obs: model.HourStat{TxBytes: 250 * mB},
		},
		{
			name: "phone overridden to camera: 250 MB vs 1 MB -> critical (strict profile)",
			kind: "phone", override: "camera", hist: tiny, lang: "en",
			obs:      model.HourStat{TxBytes: 250 * mB},
			wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
			check: func(t *testing.T, a model.Alert) {
				if a.Title != "Camera (Hikvision) is uploading 250 MB/h" || a.Evidence["device_kind"] != "camera" {
					t.Fatalf("title %q evidence %+v", a.Title, a.Evidence)
				}
				if !strings.Contains(a.Detail, "Camera: such devices do not usually upload") {
					t.Fatalf("detail %q", a.Detail)
				}
			},
		},
		{
			name: "english texts",
			kind: "camera", hist: cam45, lang: "en",
			obs:      model.HourStat{TxBytes: 3174 * mB, DistinctDst: 6},
			wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
			check: func(t *testing.T, a model.Alert) {
				if a.Title != "Camera (Hikvision) is uploading 3.1 GB/h" {
					t.Fatalf("title %q", a.Title)
				}
				if !strings.Contains(a.Detail, "usually 45 MB/h at this time of day (median of 12 days)") ||
					!strings.Contains(a.Detail, "× more") || !strings.Contains(a.Detail, "Maximum over the last 28 days") {
					t.Fatalf("detail %q", a.Detail)
				}
				assertNoCzech(t, []model.Alert{a})
			},
		},
		{
			name: "czech texts",
			kind: "camera", hist: cam45, lang: "cs",
			obs:      model.HourStat{TxBytes: 3174 * mB, DistinctDst: 6},
			wantKind: model.AlertUploadSpike, wantSev: model.SevCritical,
			check: func(t *testing.T, a model.Alert) {
				if a.Title != "Kamera (Hikvision) nahrává 3,1 GB/h" {
					t.Fatalf("title %q", a.Title)
				}
				if !strings.Contains(a.Detail, "obvykle 45 MB/h v tuto denní dobu (medián z 12 dní)") ||
					!strings.Contains(a.Detail, "Dosavadní maximum za posledních 28 dní") ||
					!strings.Contains(a.Detail, "Kamera takto obvykle nenahrává") {
					t.Fatalf("detail %q", a.Detail)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { runHourCase(t, tc) })
	}
}

// noveltyRun: one hour of flows at day 10 for a store prepared by setup,
// with settings s; returns all alerts after the hour closed.
func noveltyRun(t *testing.T, s settings.Settings, setup func(st *fakeStore), flows func(h time.Time) []model.FlowSample) (*Engine, *fakeStore, *fakeSink, time.Time) {
	t.Helper()
	day10 := t0.Add(10 * 24 * time.Hour)
	H := day10.Add(10 * time.Hour)
	st := newFakeStore()
	setup(st)
	e, sink := newTestEngine(t, st, day10)
	e.SetSettings(s)
	feed(e, st, flows(H)...)
	e.Tick(ctx, H.Add(65*time.Minute))
	return e, st, sink, H
}

func TestNoveltySettings(t *testing.T) {
	phoneKP := func(tx uint64) func(h time.Time) []model.FlowSample {
		return func(h time.Time) []model.FlowSample {
			return []model.FlowSample{flow(phoneMAC, h.Add(time.Minute), "45.1.1.1:443", "KP", 131279, tx, 1*mB, true)}
		}
	}
	phone := func(st *fakeStore) { matureDevice(st, phoneMAC, "phone", true, cz()) }
	cam := func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) }

	t.Run("phone 15 MB to new country: normal nothing, high warning", func(t *testing.T) {
		_, _, sink, _ := noveltyRun(t, testSettings("cs"), phone, phoneKP(15*mB))
		if al := sink.all(); len(al) != 0 {
			t.Fatalf("normal: %v", titles(al))
		}
		s := testSettings("cs")
		s.Sensitivity = "high"
		_, _, sink, _ = noveltyRun(t, s, phone, phoneKP(15*mB))
		if al := sink.ofKind(model.AlertNewCountry); len(al) != 1 || al[0].Severity != model.SevWarning {
			t.Fatalf("high: %v", titles(sink.all()))
		}
	})

	t.Run("phone 30 MB to new country: low nothing", func(t *testing.T) {
		s := testSettings("cs")
		s.Sensitivity = "low"
		_, _, sink, _ := noveltyRun(t, s, phone, phoneKP(30*mB))
		if al := sink.all(); len(al) != 0 {
			t.Fatalf("low: %v", titles(al))
		}
	})

	t.Run("new_country disabled: no alert, still learnt, re-enable works", func(t *testing.T) {
		s := testSettings("cs")
		s.DisabledDetectors = []string{model.AlertNewCountry}
		ru := func(h time.Time) []model.FlowSample {
			var fs []model.FlowSample
			for i := 0; i < 5; i++ { // 15 MB: would be an immediate critical
				fs = append(fs, flow(camMAC, h.Add(time.Duration(5+i)*time.Minute), "5.6.7.8:443", "RU", 12389, 3*mB, 0, i == 0))
			}
			return fs
		}
		e, st, sink, H := noveltyRun(t, s, cam, ru)
		if al := sink.all(); len(al) != 0 {
			t.Fatalf("disabled: %v", titles(al))
		}
		s.DisabledDetectors = nil
		e.SetSettings(s)
		feed(e, st, ru(H.Add(time.Hour))...)
		feed(e, st, flow(camMAC, H.Add(time.Hour+30*time.Minute), "9.9.9.9:443", "CN", 4134, 2*mB, 0, true))
		e.Tick(ctx, H.Add(125*time.Minute))
		al := sink.all()
		if len(al) != 1 || al[0].Kind != model.AlertNewCountry || !strings.Contains(al[0].Title, "novou zemí: CN") {
			t.Fatalf("after re-enable: %v", titles(al))
		}
	})

	t.Run("new_asn disabled", func(t *testing.T) {
		s := testSettings("cs")
		s.DisabledDetectors = []string{model.AlertNewASN}
		_, _, sink, _ := noveltyRun(t, s, cam, func(h time.Time) []model.FlowSample {
			return []model.FlowSample{flow(camMAC, h.Add(time.Minute), "77.1.1.1:443", "CZ", 6830, 1*mB, 0, true)}
		})
		if al := sink.all(); len(al) != 0 {
			t.Fatalf("disabled: %v", titles(al))
		}
	})

	t.Run("english country and ASN texts", func(t *testing.T) {
		_, _, sink, _ := noveltyRun(t, testSettings("en"), cam, func(h time.Time) []model.FlowSample {
			return []model.FlowSample{
				flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 2*mB, 10*kB, true),
				flow(camMAC, h.Add(2*time.Minute), "77.1.1.1:443", "CZ", 6830, 1536*kB, 0, true),
			}
		})
		al := sink.all()
		if len(al) != 2 {
			t.Fatalf("got %v", titles(al))
		}
		if al[0].Title != "Camera (Vendorcamera) is communicating with a new country: RU" ||
			!strings.Contains(al[0].Detail, "First contact with country RU (AS12389 OrgRU): sent 2 MB, received 10 kB, 1 new connection, e.g. 5.6.7.8:443.") ||
			!strings.Contains(al[0].Detail, "So far it has communicated with 1 country (CZ).") {
			t.Fatalf("country alert %q / %q", al[0].Title, al[0].Detail)
		}
		if al[1].Title != "Camera (Vendorcamera) is communicating with a new network: AS6830 OrgCZ" ||
			!strings.Contains(al[1].Detail, "sent 1.5 MB") || strings.Contains(al[1].Detail, "OrgCZ [CZ] (AS6830") {
			t.Fatalf("asn alert %q / %q", al[1].Title, al[1].Detail)
		}
		assertNoCzech(t, al)
	})
}

// A kind override set in the UI after the device was cached takes effect:
// a "phone" (no ASN novelty) overridden to "camera" gets strict ASN alerts.
func TestKindOverrideRefresh(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, phoneMAC, "phone", false, cz())
	day10 := t0.Add(10 * 24 * time.Hour)
	H := day10.Add(10 * time.Hour)
	e, sink := newTestEngine(t, st, day10)
	feed(e, st, flow(phoneMAC, H.Add(time.Minute), "1.2.3.4:443", "CZ", 5610, kB, kB, false))
	if e.devs[phoneMAC].asns != nil {
		t.Fatal("phone must not track ASNs")
	}
	if err := st.SetKindOverride(ctx, phoneMAC, "camera"); err != nil {
		t.Fatal(err)
	}
	// lazily, via the TTL refresh in Flows
	feed(e, st, flow(phoneMAC, H.Add(10*time.Minute), "1.2.3.4:443", "CZ", 5610, kB, kB, false))
	if k := e.devs[phoneMAC].dev.EffectiveKind(); k != "camera" {
		t.Fatalf("override not picked up: %q", k)
	}
	e.Tick(ctx, H.Add(65*time.Minute))
	feed(e, st, flow(phoneMAC, H.Add(61*time.Minute), "77.1.1.1:443", "CZ", 6830, 1*mB, 0, true))
	e.Tick(ctx, H.Add(125*time.Minute))
	al := sink.ofKind(model.AlertNewASN)
	if len(al) != 1 || !strings.HasPrefix(al[0].Title, "Kamera (Vendorphone)") || al[0].Evidence["device_kind"] != "camera" {
		t.Fatalf("got %v", titles(sink.all()))
	}

	// and back to automatic via the hourly refresh in Tick
	if err := st.SetKindOverride(ctx, phoneMAC, ""); err != nil {
		t.Fatal(err)
	}
	e.Tick(ctx, H.Add(185*time.Minute))
	if k := e.devs[phoneMAC].dev.EffectiveKind(); k != "phone" {
		t.Fatalf("override removal not picked up: %q", k)
	}
}

func TestNewDeviceSettings(t *testing.T) {
	at := t0.Add(10 * 24 * time.Hour)
	run := func(s *settings.Settings, d model.Device) []model.Alert {
		st := newFakeStore()
		st.addDevice(model.Device{MAC: "00:00:00:00:00:01", FirstSeen: t0})
		sink := &fakeSink{store: st}
		e := New(st, sink, testConfig(), t0)
		if s != nil {
			e.SetSettings(*s)
		}
		d.MAC, d.LastSeen = "11:22:33:44:55:66", at
		e.DeviceSeen(ctx, d, true)
		return sink.ofKind(model.AlertNewDevice)
	}
	cam := model.Device{Kind: "camera", Vendor: "Hikvision"}

	// default before SetSettings: English
	al := run(nil, cam)
	if len(al) != 1 || al[0].Title != "New device on the network: Camera (Hikvision)" {
		t.Fatalf("default: %v", titles(al))
	}
	if !strings.Contains(al[0].Detail, "type (guess) Camera") {
		t.Fatalf("detail %q", al[0].Detail)
	}
	assertNoCzech(t, al)

	cs := testSettings("cs")
	if al := run(&cs, cam); len(al) != 1 || al[0].Title != "Nové zařízení v síti: Kamera (Hikvision)" {
		t.Fatalf("cs: %v", titles(al))
	}
	de := testSettings("de")
	if al := run(&de, cam); len(al) != 1 || al[0].Title != "Neues Gerät im Netzwerk: Kamera (Hikvision)" {
		t.Fatalf("de: %v", titles(al))
	}
	bogus := testSettings("xx")
	if al := run(&bogus, cam); len(al) != 1 || !strings.HasPrefix(al[0].Title, "New device") {
		t.Fatalf("unknown language falls back to en: %v", titles(al))
	}

	off := testSettings("cs")
	off.DisabledDetectors = []string{model.AlertNewDevice}
	if al := run(&off, model.Device{Kind: "unknown"}); len(al) != 0 {
		t.Fatalf("disabled: %v", titles(al))
	}
}

func TestInventorySummaryDisabled(t *testing.T) {
	st := newFakeStore()
	e, sink := newTestEngine(t, st, t0)
	s := testSettings("cs")
	s.DisabledDetectors = []string{model.AlertNewDevice}
	e.SetSettings(s)
	d := model.Device{MAC: "AA:00:00:00:00:01", Kind: "phone", LastSeen: t0.Add(time.Minute)}
	isNew, _ := st.UpsertDevice(ctx, d)
	e.DeviceSeen(ctx, d, isNew)
	e.Tick(ctx, t0.Add(25*time.Hour))
	if al := sink.all(); len(al) != 0 {
		t.Fatalf("summary despite disabled new_device: %v", titles(al))
	}
}

func TestEnglishFastSpikeAndInventory(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	e, sink := newTestEngine(t, st, H)
	e.SetSettings(testSettings("en"))
	for i := 0; i < 20; i++ {
		feed(e, st, flow(camMAC, H.Add(time.Duration(i)*time.Minute), "1.2.3.4:443", "CZ", 5610, 60*mB, kB, i == 0))
	}
	al := sink.ofKind(model.AlertUploadSpike)
	if len(al) != 1 || !strings.Contains(al[0].Title, "is uploading an unusual amount of data right now") ||
		!strings.Contains(al[0].Detail, "for the whole hour") {
		t.Fatalf("fast: %v", titles(sink.all()))
	}
	assertNoCzech(t, al)

	st2 := newFakeStore()
	e2, sink2 := newTestEngine(t, st2, t0)
	e2.SetSettings(testSettings("en"))
	for i := 0; i < 3; i++ {
		d := model.Device{MAC: fmt.Sprintf("AA:00:00:00:00:%02X", i), Kind: []string{"phone", "camera", ""}[i], LastSeen: t0.Add(time.Minute)}
		isNew, _ := st2.UpsertDevice(ctx, d)
		e2.DeviceSeen(ctx, d, isNew)
	}
	e2.Tick(ctx, t0.Add(25*time.Hour))
	al = sink2.all()
	if len(al) != 1 || al[0].Title != "Initial inventory complete: 3 devices" ||
		!strings.Contains(al[0].Detail, "During the first 24 hours Guardian found 3 devices on the network (Phone: 1, Camera: 1, Device: 1).") ||
		al[0].Evidence["kind_camera"] != 1 {
		t.Fatalf("inventory: %+v", al)
	}
	assertNoCzech(t, al)
}

func TestSettingsResetConcurrent(t *testing.T) {
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	e, _ := newTestEngine(t, st, t0.Add(10*24*time.Hour))
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				at := H.Add(time.Duration(i) * time.Minute)
				switch g % 6 {
				case 0:
					e.Flows(ctx, []model.FlowSample{flow(camMAC, at, "1.2.3.4:443", "CZ", 5610, kB, kB, false)})
				case 1:
					e.DeviceSeen(ctx, model.Device{MAC: camMAC, Kind: "camera", LastSeen: at}, false)
				case 2:
					e.Tick(ctx, at)
				case 3:
					s := testSettings([]string{"en", "cs", "ru"}[i%3])
					s.Sensitivity = settings.Sensitivities[i%3]
					e.SetSettings(s)
				case 4:
					if i%10 == 0 {
						e.Reset()
					}
				default:
					_ = e.LearningUntil()
				}
			}
		}(g)
	}
	wg.Wait()
}

func assertNoCzech(t *testing.T, al []model.Alert) {
	t.Helper()
	for _, a := range al {
		for _, s := range []string{a.Title, a.Detail} {
			if strings.ContainsAny(s, "ěščřžýáíéůúňťďĚŠČŘŽÝÁÍÉŮÚŇŤĎ") {
				t.Errorf("czech text in a non-czech alert: %q", s)
			}
		}
	}
}
