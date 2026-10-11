package detect

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// raised is an alert as a detector raised it and the device it is about
// (as the store holds it; nil for the inventory summary).
type raised struct {
	name string
	a    model.Alert
	dev  *model.Device
}

// raiseAll runs one scenario per alert kind/variant with alert texts in lang.
// The scenarios are deterministic, so the lists of two languages align.
func raiseAll(t *testing.T, lang string) []raised {
	t.Helper()
	var out []raised
	add := func(name string, st *fakeStore, al []model.Alert, want int) {
		t.Helper()
		if len(al) != want {
			t.Fatalf("%s/%s: got %v, want %d alerts", lang, name, titles(al), want)
		}
		for _, a := range al {
			r := raised{name: name, a: a}
			if a.DeviceMAC != "" {
				d, ok, _ := st.Device(ctx, a.DeviceMAC)
				if !ok {
					t.Fatalf("%s: device %s not stored", name, a.DeviceMAC)
				}
				r.dev = &d
			}
			out = append(out, r)
		}
	}

	// new devices: warning (unknown, fixed MAC), randomized phone, DHCP comment
	for i, d := range []model.Device{
		{Kind: "unknown", IP: netip.MustParseAddr("192.168.88.51")},
		{Kind: "phone", Randomized: true, Hostname: "Pixel-8", Vendor: "Google", IP: netip.MustParseAddr("192.168.88.52")},
		{Kind: "tv", Hostname: "Televize-v-obyvaku", Comment: "TV obývák", Vendor: "Samsung"},
	} {
		st := newFakeStore()
		st.addDevice(model.Device{MAC: "00:00:00:00:00:01", FirstSeen: t0})
		e, sink := newTestEngine(t, st, t0)
		e.SetSettings(testSettings(lang))
		d.MAC, d.LastSeen = fmt.Sprintf("11:22:33:44:55:%02X", i), t0.Add(10*24*time.Hour)
		isNew, _ := st.UpsertDevice(ctx, d)
		e.DeviceSeen(ctx, d, isNew)
		add("new device", st, sink.all(), 1)
	}

	// inventory summary while learning and after a short learning period
	for _, lp := range []time.Duration{7 * 24 * time.Hour, 12 * time.Hour} {
		st := newFakeStore()
		e, sink := newTestEngine(t, st, t0)
		s := testSettings(lang)
		s.LearnPeriod, s.LearningStart = lp, t0
		e.SetSettings(s)
		for i, k := range []string{"phone", "camera", "", "tv", "phone"} {
			d := model.Device{MAC: fmt.Sprintf("AA:00:00:00:00:%02X", i), Kind: k, LastSeen: t0.Add(time.Minute)}
			isNew, _ := st.UpsertDevice(ctx, d)
			e.DeviceSeen(ctx, d, isNew)
		}
		e.Tick(ctx, t0.Add(min(lp, 24*time.Hour)+2*time.Hour))
		add("inventory", st, sink.all(), 1)
	}

	// new country / new ASN
	cam := func(st *fakeStore) { matureDevice(st, camMAC, "camera", false, cz()) }
	for _, sc := range []struct {
		name  string
		want  int
		flows func(h time.Time) []model.FlowSample
	}{
		{"country and asn", 2, func(h time.Time) []model.FlowSample {
			return []model.FlowSample{
				flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 2*mB, 10*kB, true),
				flow(camMAC, h.Add(2*time.Minute), "77.1.1.1:443", "CZ", 6830, 1536*kB, 0, true),
			}
		}},
		{"two countries", 1, func(h time.Time) []model.FlowSample {
			return []model.FlowSample{
				flow(camMAC, h.Add(time.Minute), "5.6.7.8:443", "RU", 12389, 1*mB, 0, true),
				flow(camMAC, h.Add(2*time.Minute), "9.9.9.9:443", "CN", 4134, 1*mB, 0, true),
				flow(camMAC, h.Add(3*time.Minute), "9.9.9.10:443", "CN", 4134, 1*mB, 0, true),
			}
		}},
		{"critical country", 1, func(h time.Time) []model.FlowSample {
			var fs []model.FlowSample
			for i := 0; i < 5; i++ {
				fs = append(fs, flow(camMAC, h.Add(time.Duration(5+i)*time.Minute), "5.6.7.8:443", "CN", 4134, 3*mB, 0, i == 0))
			}
			return fs
		}},
		{"two asns", 1, func(h time.Time) []model.FlowSample {
			return []model.FlowSample{
				flow(camMAC, h.Add(time.Minute), "77.1.1.1:443", "CZ", 6830, 1*mB, 0, true),
				flow(camMAC, h.Add(2*time.Minute), "77.1.1.2:443", "CZ", 6831, 3*mB, 0, true),
			}
		}},
	} {
		_, st, sink, _ := noveltyRun(t, testSettings(lang), cam, sc.flows)
		add(sc.name, st, sink.all(), sc.want)
	}

	// hourly upload spike (same hour, all hours) and fan-out
	cam45 := func(i int, _ time.Time) model.HourStat {
		return model.HourStat{TxBytes: noisy(45*mB, i), DistinctDst: 6}
	}
	for _, tc := range []hourCase{
		{name: "spike", kind: "camera", hist: cam45, obs: model.HourStat{TxBytes: 3174 * mB, DistinctDst: 6},
			wantKind: model.AlertUploadSpike, wantSev: model.SevCritical},
		{name: "spike all hours", kind: "tv", histFrom: t0.Add(9 * 24 * time.Hour),
			hist: func(int, time.Time) model.HourStat { return model.HourStat{TxBytes: 2 * mB} },
			obs:  model.HourStat{TxBytes: 1 * gB}, wantKind: model.AlertUploadSpike, wantSev: model.SevWarning},
		{name: "fanout", kind: "camera",
			hist: func(i int, _ time.Time) model.HourStat { return model.HourStat{TxBytes: 5 * mB, DistinctDst: 6 + i%5} },
			obs:  model.HourStat{TxBytes: 5 * mB, DistinctDst: 400, NewConns: 2000}, wantKind: model.AlertDestFanout, wantSev: model.SevCritical},
	} {
		tc.lang = lang
		tc.check = func(t *testing.T, a model.Alert) {
			// the device as runHourCase stores it
			d := model.Device{MAC: camMAC, Kind: tc.kind, Vendor: "Hikvision", FirstSeen: t0}
			out = append(out, raised{name: tc.name, a: a, dev: &d})
		}
		runHourCase(t, tc)
	}

	// fast-path upload spike
	st := newFakeStore()
	matureDevice(st, camMAC, "camera", false, cz())
	H := t0.Add(10*24*time.Hour + 10*time.Hour)
	e, sink := newTestEngine(t, st, H)
	e.SetSettings(testSettings(lang))
	for i := 0; i < 20; i++ {
		feed(e, st, flow(camMAC, H.Add(time.Duration(i)*time.Minute), "1.2.3.4:443", "CZ", 5610, 60*mB, kB, i == 0))
	}
	add("fast spike", st, sink.all(), 1)
	return out
}

// stored returns a as it comes back from the store: Evidence through JSON.
func stored(t *testing.T, a model.Alert) model.Alert {
	t.Helper()
	js, err := json.Marshal(a.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	a.Evidence = nil
	if err := json.Unmarshal(js, &a.Evidence); err != nil {
		t.Fatal(err)
	}
	return a
}

func checkRender(t *testing.T, what string, a model.Alert, d *model.Device, lang, wantTitle, wantDetail string) {
	t.Helper()
	title, detail, ok := RenderAlert(a, d, lang)
	if !ok {
		t.Errorf("%s: not rendered", what)
		return
	}
	if title != wantTitle || detail != wantDetail {
		t.Errorf("%s:\n got %q\n     %q\nwant %q\n     %q", what, title, detail, wantTitle, wantDetail)
	}
}

// The text a detector stored equals a later rendering of the stored evidence
// in the same language – with the current device, with the device snapshot,
// and with evidence fresh from the detector or back from the store (JSON).
func TestRenderAlertRoundTrip(t *testing.T) {
	kinds := map[string]bool{}
	for _, lang := range []string{"en", "cs"} {
		for _, r := range raiseAll(t, lang) {
			kinds[r.a.Kind] = true
			what := lang + " " + r.name + " " + r.a.Kind
			if r.a.Title == "" || r.a.Detail == "" || r.a.Title == r.a.Kind {
				t.Fatalf("%s: detector produced no text: %+v", what, r.a)
			}
			s := stored(t, r.a)
			checkRender(t, what+" (fresh evidence)", r.a, r.dev, lang, r.a.Title, r.a.Detail)
			checkRender(t, what+" (stored)", s, r.dev, lang, r.a.Title, r.a.Detail)
			checkRender(t, what+" (snapshot)", s, nil, lang, r.a.Title, r.a.Detail)
		}
	}
	for _, k := range []string{model.AlertNewDevice, model.AlertNewCountry, model.AlertNewASN, model.AlertUploadSpike, model.AlertDestFanout} {
		if !kinds[k] {
			t.Errorf("kind %s not covered", k)
		}
	}
}

// An alert raised in one language renders exactly like the same alert raised
// in another language (what the UI language switch relies on).
func TestRenderAlertOtherLanguage(t *testing.T) {
	en := raiseAll(t, "en")
	for _, lang := range settings.Languages {
		other := raiseAll(t, lang)
		if len(other) != len(en) {
			t.Fatalf("%s: %d alerts, en %d", lang, len(other), len(en))
		}
		for i, r := range en {
			o := other[i]
			if o.name != r.name || o.a.Kind != r.a.Kind {
				t.Fatalf("scenarios do not align: %s/%s vs %s/%s", r.name, r.a.Kind, o.name, o.a.Kind)
			}
			checkRender(t, "en→"+lang+" "+r.name, stored(t, r.a), r.dev, lang, o.a.Title, o.a.Detail)
		}
	}
}

func TestRenderAlertCzechWording(t *testing.T) {
	want := map[string][2]string{
		"spike": {"Kamera (Hikvision) nahrává 3,1 GB/h",
			"V hodině %s odeslalo zařízení do internetu 3,1 GB, obvykle 45 MB/h v tuto denní dobu (medián z 12 dní), tj. 71× více. " +
				"Dosavadní maximum za posledních 28 dní: 54 MB/h. Kamera takto obvykle nenahrává – může jít o odesílání záznamů cizí osobě " +
				"nebo o zneužité zařízení. Pokud to nečekáte, zvažte karanténu."},
		"two countries": {"Kamera (Vendorcamera) komunikuje s novými zeměmi: CN, RU",
			"Poprvé komunikuje se zemí CN (AS4134 OrgCN): odesláno 2 MB, přijato 0 B, 2 nová spojení, např. 9.9.9.9:443, 9.9.9.10:443. " +
				"Poprvé komunikuje se zemí RU (AS12389 OrgRU): odesláno 1 MB, přijato 0 B, 1 nové spojení, např. 5.6.7.8:443. " +
				"Dosud komunikovalo s 1 zemí (CZ). Může jít o aktualizaci nebo novou službu; pokud to nečekáte, zkontrolujte zařízení."},
	}
	for _, r := range raiseAll(t, "en") {
		w, ok := want[r.name]
		if !ok {
			continue
		}
		delete(want, r.name)
		if r.name == "spike" {
			w[1] = fmt.Sprintf(w[1], hourRange(t0.Add(12*24*time.Hour+9*time.Hour)))
		}
		checkRender(t, "cs "+r.name, stored(t, r.a), r.dev, "cs", w[0], w[1])
	}
	if len(want) != 0 {
		t.Fatalf("scenarios not found: %v", want)
	}
}

// The device is named by its current state (note set later, kind changed);
// the explanation keeps the kind the decision was based on.
func TestRenderAlertCurrentDevice(t *testing.T) {
	for _, r := range raiseAll(t, "cs") {
		if r.dev == nil {
			continue
		}
		d := *r.dev
		d.Note = "Kamera na zahradě"
		title, detail, ok := RenderAlert(stored(t, r.a), &d, "cs")
		if !ok || !strings.Contains(title, "Kamera na zahradě") {
			t.Errorf("%s: title %q (ok %v)", r.name, title, ok)
		}
		if r.a.Kind == model.AlertNewDevice && !strings.HasPrefix(detail, "V síti se poprvé objevilo zařízení Kamera na zahradě.") {
			t.Errorf("%s: detail %q", r.name, detail)
		}
		if r.name == "spike" {
			d.Note, d.KindOverride = "", "phone"
			title, detail, _ := RenderAlert(stored(t, r.a), &d, "cs")
			if title != "Telefon (Hikvision) nahrává 3,1 GB/h" || !strings.Contains(detail, "Kamera takto obvykle nenahrává") {
				t.Errorf("kind override: %q / %q", title, detail)
			}
		}
	}
}

func TestRenderAlertLanguageFallback(t *testing.T) {
	for _, r := range raiseAll(t, "en")[:1] {
		for _, lang := range []string{"", "xx", "EN"} {
			checkRender(t, "lang "+lang, stored(t, r.a), r.dev, lang, r.a.Title, r.a.Detail)
		}
	}
}

// v0.3.1 stored neither the device snapshot nor the baseline window nor the
// inventory hours/learning flag: such alerts still render (exactly) when the
// device is known; without the device there is no name, so ok is false.
func TestRenderAlertLegacyEvidence(t *testing.T) {
	newKeys := []string{"device", "baseline_days", "inventory_hours", "learning"}
	for _, lang := range []string{"en", "cs"} {
		for _, r := range raiseAll(t, lang) {
			a := stored(t, r.a)
			for _, k := range newKeys {
				delete(a.Evidence, k)
			}
			what := lang + " legacy " + r.name
			checkRender(t, what, a, r.dev, lang, r.a.Title, r.a.Detail)
			switch {
			case r.a.Kind == model.AlertNewDevice: // named from the evidence itself
				checkRender(t, what+" (no device)", a, nil, lang, r.a.Title, r.a.Detail)
			default:
				if _, _, ok := RenderAlert(a, nil, lang); ok {
					t.Errorf("%s: rendered without device and snapshot", what)
				}
			}
		}
	}
}

func TestRenderAlertIncompleteEvidence(t *testing.T) {
	var spike, country model.Alert
	for _, r := range raiseAll(t, "en") {
		switch r.name {
		case "spike":
			spike = stored(t, r.a)
		case "two countries":
			country = stored(t, r.a)
		}
	}
	without := func(a model.Alert, key string) model.Alert {
		ev := map[string]any{}
		for k, v := range a.Evidence {
			if k != key {
				ev[k] = v
			}
		}
		a.Evidence = ev
		return a
	}
	dev := &model.Device{MAC: camMAC, Kind: "camera"}
	tests := []struct {
		name string
		a    model.Alert
	}{
		{"no evidence", model.Alert{Kind: model.AlertNewCountry, DeviceMAC: camMAC}},
		{"pre-0.3 evidence", model.Alert{Kind: model.AlertNewCountry, DeviceMAC: camMAC, Evidence: map[string]any{"bytes": 1234.0}}},
		{"unknown kind", model.Alert{Kind: model.AlertBehaviorDrift, DeviceMAC: camMAC, Evidence: spike.Evidence}},
		{"spike without ratio", without(spike, "ratio")},
		{"spike without hour", without(spike, "hour")},
		{"country without known list", without(country, "known_list")},
		{"country without destinations", without(country, "new")},
		{"wrong type", func() model.Alert {
			a := without(country, "new")
			a.Evidence["new"] = "RU"
			return a
		}()},
		{"inventory without hours", model.Alert{Kind: model.AlertNewDevice, Evidence: map[string]any{
			"devices": 3.0, "learning_until": t0.Format(time.RFC3339)}}},
	}
	for _, tc := range tests {
		if title, detail, ok := RenderAlert(tc.a, dev, "cs"); ok {
			t.Errorf("%s: rendered %q / %q", tc.name, title, detail)
		}
	}
}

func TestLegacyBaselineDays(t *testing.T) {
	if got := int(DefaultConfig().BaselineWindow.Hours() / 24); got != legacyBaselineDays {
		t.Fatalf("legacyBaselineDays = %d, default window %d days", legacyBaselineDays, got)
	}
}
