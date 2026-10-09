package detect

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

func TestRobust(t *testing.T) {
	tests := []struct {
		in             []float64
		med, mad, maxv float64
	}{
		{nil, 0, 0, 0},
		{[]float64{5}, 5, 0, 5},
		{[]float64{1, 2, 3, 4, 100}, 3, 1, 100},
		{[]float64{1, 2, 3, 4}, 2.5, 1, 4},
	}
	for _, tc := range tests {
		b := robust(tc.in)
		if b.Median != tc.med || b.MAD != tc.mad || b.Max != tc.maxv {
			t.Errorf("robust(%v) = %+v", tc.in, b)
		}
	}
}

func TestSigmaFloor(t *testing.T) {
	b := baseline{Median: 100, MAD: 0}
	if s := b.sigma(1); s != 10 {
		t.Fatalf("sigma = %v, want 10 (10%% of median)", s)
	}
	if s := (baseline{}).sigma(5); s != 5 {
		t.Fatalf("sigma floor = %v", s)
	}
}

func TestHourBaseline(t *testing.T) {
	target := t0.Add(10*24*time.Hour + 9*time.Hour)
	var hist []model.HourStat
	for h := t0; h.Before(target.Add(5 * time.Hour)); h = h.Add(time.Hour) {
		v := uint64(1)
		if h.Hour() == 9 {
			v = 100
		}
		hist = append(hist, model.HourStat{Hour: h, TxBytes: v})
	}
	b := hourBaseline(hist, target, 7, txVal)
	if b.Method != "same_hour" || b.Median != 100 || b.Samples != 10 {
		t.Fatalf("same hour baseline %+v", b)
	}
	b = hourBaseline(hist, target, 11, txVal)
	if b.Method != "all_hours" || b.Median != 1 || b.Samples != 249 {
		t.Fatalf("fallback baseline %+v", b)
	}
}

func TestSpikeTest(t *testing.T) {
	c := DefaultConfig()
	p := c.Profiles["camera"]
	base := baseline{Median: 45 * mB, MAD: 5 * mB, Max: 80 * mB, Samples: 20}
	tests := []struct {
		name   string
		obs    float64
		b      baseline
		want   bool
		reason string
	}{
		{"big spike", 3 * gB, base, true, ""},
		{"below absolute", 150 * mB, baseline{Median: 1 * mB, MAD: 0.1 * mB}, false, "below absolute minimum"},
		{"ratio low", 300 * mB, base, false, "ratio too low"},
		{"noisy history -> z low", 500 * mB, baseline{Median: 10 * mB, MAD: 60 * mB, Max: 100 * mB}, false, "z-score too low"},
		{"seen before", 1 * gB, baseline{Median: 10 * mB, MAD: 1 * mB, Max: 900 * mB}, false, "seen similar before"},
		{"zero baseline uses floor", 300 * mB, baseline{}, true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := spikeTest(p, &c, tc.obs, tc.b)
			if v.Alert != tc.want || v.Reason != tc.reason {
				t.Fatalf("got %+v", v)
			}
			if math.IsInf(v.Ratio, 0) || math.IsNaN(v.Z) {
				t.Fatalf("bad numbers %+v", v)
			}
		})
	}
}

func TestFanoutTest(t *testing.T) {
	c := DefaultConfig()
	p := c.Profiles["camera"]
	tests := []struct {
		obs  int
		b    baseline
		want bool
	}{
		{400, baseline{Median: 8, Max: 15}, true},
		{90, baseline{Median: 2, Max: 5}, false},      // below 100
		{400, baseline{Median: 100, Max: 150}, false}, // 4x
		{400, baseline{Median: 20, Max: 380}, false},  // seen before
		{120, baseline{}, true},                       // floor 10 -> 12x
	}
	for _, tc := range tests {
		if v := fanoutTest(p, &c, tc.obs, tc.b); v.Alert != tc.want {
			t.Errorf("fanoutTest(%d, %+v) = %+v", tc.obs, tc.b, v)
		}
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		b    float64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{45 * mB, "45 MB"},
		{3174 * mB, "3,1 GB"},
		{1.5 * kB, "1,5 kB"},
		{2 * gB, "2 GB"},
	}
	for _, tc := range tests {
		if got := loc("cs").bytes(tc.b); got != tc.want {
			t.Errorf("cs bytes(%v) = %q, want %q", tc.b, got, tc.want)
		}
		if got, want := loc("en").bytes(tc.b), strings.Replace(tc.want, ",", ".", 1); got != want {
			t.Errorf("en bytes(%v) = %q, want %q", tc.b, got, want)
		}
	}
	if got := loc("cs").ratio(68.4); got != "68×" {
		t.Errorf("ratio = %q", got)
	}
	if got := loc("de").perHour(3174 * mB); got != "3,1 GB/h" {
		t.Errorf("de perHour = %q", got)
	}
	if got := loc("en").perHour(3174 * mB); got != "3.1 GB/h" {
		t.Errorf("en perHour = %q", got)
	}
	if got := loc("ru").perHour(45 * mB); got != "45 МБ/ч" {
		t.Errorf("ru perHour = %q", got)
	}
}

func TestDeviceName(t *testing.T) {
	tests := []struct {
		d    model.Device
		want string
	}{
		{model.Device{Kind: "camera", Vendor: "Hikvision"}, "Kamera (Hikvision)"},
		{model.Device{Kind: "camera", Vendor: "Hikvision", Note: "Kamera na zahradě"}, "Kamera na zahradě"},
		{model.Device{Kind: "phone", Hostname: "Pixel-8", Vendor: "Google"}, "Telefon (Pixel-8, Google)"},
		{model.Device{MAC: "AA:BB:CC:DD:EE:FF"}, "Zařízení (AA:BB:CC:DD:EE:FF)"},
		{model.Device{Kind: "tv", Hostname: "Televize-v-obyvaku", Comment: "TV obývák"}, "TV obývák"},
		{model.Device{Kind: "tv", Comment: "TV obývák", Note: "Televize u babičky"}, "Televize u babičky"},
		{model.Device{Kind: "phone", Hostname: "Pixel-8", Note: "  "}, "Telefon (Pixel-8)"},
	}
	for _, tc := range tests {
		if got := loc("cs").deviceName(tc.d); got != tc.want {
			t.Errorf("deviceName = %q, want %q", got, tc.want)
		}
	}
	en := []struct {
		d    model.Device
		want string
	}{
		{model.Device{Kind: "camera", Vendor: "Hikvision"}, "Camera (Hikvision)"},
		{model.Device{Kind: "phone", KindOverride: "camera", Vendor: "Hikvision"}, "Camera (Hikvision)"},
		{model.Device{Kind: "weird", MAC: "AA:BB:CC:DD:EE:FF"}, "Device (AA:BB:CC:DD:EE:FF)"},
		{model.Device{Kind: "speaker", Hostname: "kitchen"}, "Speaker (kitchen)"},
	}
	for _, tc := range en {
		if got := loc("en").deviceName(tc.d); got != tc.want {
			t.Errorf("en deviceName = %q, want %q", got, tc.want)
		}
	}
}

func TestPluralForm(t *testing.T) {
	tests := []struct {
		lang string
		n    int
		want string
	}{
		{"cs", 1, "one"}, {"cs", 3, "few"}, {"cs", 5, "many"}, {"cs", 22, "many"}, {"cs", 0, "many"},
		{"pl", 1, "one"}, {"pl", 22, "few"}, {"pl", 12, "many"}, {"pl", 21, "many"},
		{"ru", 1, "one"}, {"ru", 21, "one"}, {"ru", 11, "many"}, {"ru", 23, "few"}, {"ru", 13, "many"},
		{"en", 1, "one"}, {"en", 2, "many"}, {"en", 0, "many"}, {"de", 3, "many"},
	}
	for _, tc := range tests {
		if got := pluralForm(tc.lang, tc.n); got != tc.want {
			t.Errorf("pluralForm(%s, %d) = %s, want %s", tc.lang, tc.n, got, tc.want)
		}
	}
	if got := loc("pl").word("device", 5); got != "urządzeń" {
		t.Errorf("pl word = %q", got)
	}
}

func TestProfileFor(t *testing.T) {
	c := DefaultConfig()
	if p := c.profileFor("unknown", true); p.SpikeMinTx != 2*gB {
		t.Errorf("randomized unknown should be lenient")
	}
	if p := c.profileFor("unknown", false); p.SpikeMinTx != 500*mB {
		t.Errorf("fixed unknown should use unknown profile")
	}
	if p := c.profileFor("nas", false); p.SpikeMinTx != 2*gB {
		t.Errorf("unlisted kind should use default (lenient)")
	}
	if p := c.profileFor("camera", true); !p.SpikeCritical {
		t.Errorf("camera should be critical")
	}
}

func TestJaccard(t *testing.T) {
	a := map[string]struct{}{"CZ": {}, "DE": {}}
	b := map[string]struct{}{"CZ": {}, "US": {}}
	if d := jaccard(a, b); math.Abs(d-2.0/3) > 1e-9 {
		t.Fatalf("jaccard = %v", d)
	}
	if d := jaccard(map[string]struct{}{}, map[string]struct{}{}); d != 0 {
		t.Fatalf("empty jaccard = %v", d)
	}
}
