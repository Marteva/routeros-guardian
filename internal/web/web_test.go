package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

type fakeStore struct {
	mu      sync.Mutex
	devices map[string]model.Device
	hours   []model.HourStat
	dests   []model.DestStat
	alerts  []model.Alert
	acked   []int64
	lastF   model.AlertFilter
	kv      map[string]string
	failPut bool
}

func (f *fakeStore) UpsertDevice(ctx context.Context, d model.Device) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.devices[d.MAC]
	f.devices[d.MAC] = d
	return !ok, nil
}
func (f *fakeStore) Device(ctx context.Context, mac string) (model.Device, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.devices[mac]
	return d, ok, nil
}
func (f *fakeStore) Devices(ctx context.Context) ([]model.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.Device
	for _, d := range f.devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}
func (f *fakeStore) SetQuarantined(ctx context.Context, mac string, q bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.devices[mac]
	d.Quarantined = q
	f.devices[mac] = d
	return nil
}
func (f *fakeStore) SetNote(ctx context.Context, mac, note string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := f.devices[mac]
	d.Note = note
	f.devices[mac] = d
	return nil
}
func (f *fakeStore) SetKindOverride(ctx context.Context, mac, kind string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.devices[mac]
	if !ok {
		return model.ErrNotFound
	}
	d.KindOverride = kind
	f.devices[mac] = d
	return nil
}
func (f *fakeStore) SetGroup(ctx context.Context, macs []string, groupID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, mac := range macs {
		d, ok := f.devices[mac]
		if !ok {
			return model.ErrNotFound
		}
		d.GroupID = groupID
		f.devices[mac] = d
	}
	return nil
}
func (f *fakeStore) Settings(ctx context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]string{}
	for k, v := range f.kv {
		out[k] = v
	}
	return out, nil
}
func (f *fakeStore) PutSettings(ctx context.Context, kv map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPut {
		return errors.New("disk full")
	}
	if f.kv == nil {
		f.kv = map[string]string{}
	}
	for k, v := range kv {
		if v == "" {
			delete(f.kv, k)
		} else {
			f.kv[k] = v
		}
	}
	return nil
}
func (f *fakeStore) ResetLearned(ctx context.Context) error                          { return nil }
func (f *fakeStore) ResetAll(ctx context.Context) error                              { return nil }
func (f *fakeStore) RecordFlows(ctx context.Context, flows []model.FlowSample) error { return nil }
func (f *fakeStore) HourStats(ctx context.Context, mac string, from, to time.Time) ([]model.HourStat, error) {
	var out []model.HourStat
	for _, h := range f.hours {
		if h.MAC == mac && !h.Hour.Before(from) && !h.Hour.After(to) {
			out = append(out, h)
		}
	}
	return out, nil
}
func (f *fakeStore) DestStats(ctx context.Context, mac string) ([]model.DestStat, error) {
	var out []model.DestStat
	for _, d := range f.dests {
		if d.MAC == mac {
			out = append(out, d)
		}
	}
	return out, nil
}
func (f *fakeStore) InsertAlert(ctx context.Context, a *model.Alert) error {
	f.alerts = append(f.alerts, *a)
	return nil
}
func (f *fakeStore) Alerts(ctx context.Context, fl model.AlertFilter) ([]model.Alert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastF = fl
	var out []model.Alert
	for _, a := range f.alerts {
		if fl.DeviceMAC != "" && a.DeviceMAC != fl.DeviceMAC {
			continue
		}
		if fl.OnlyOpen && a.Acked {
			continue
		}
		out = append(out, a)
	}
	if fl.Limit > 0 && len(out) > fl.Limit {
		out = out[:fl.Limit]
	}
	return out, nil
}
func (f *fakeStore) AckAlert(ctx context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked = append(f.acked, id)
	for i := range f.alerts {
		if f.alerts[i].ID == id {
			f.alerts[i].Acked = true
		}
	}
	return nil
}
func (f *fakeStore) LastAlertByDedupKey(ctx context.Context, key string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}
func (f *fakeStore) Prune(ctx context.Context, olderThan time.Time) error { return nil }
func (f *fakeStore) Close() error                                         { return nil }

type addrCall struct {
	op, list, address, comment string
	timeout                    time.Duration
}

type fakeAPI struct {
	mu    sync.Mutex
	calls []addrCall
	err   error
}

func (f *fakeAPI) DHCPLeases(ctx context.Context) ([]model.Lease, error) { return nil, nil }
func (f *fakeAPI) ARP(ctx context.Context) ([]model.ARPEntry, error)     { return nil, nil }
func (f *fakeAPI) Connections(ctx context.Context) ([]model.Conn, error) { return nil, nil }
func (f *fakeAPI) Resource(ctx context.Context) (model.Resource, error)  { return model.Resource{}, nil }
func (f *fakeAPI) AddressListAdd(ctx context.Context, list, address, comment string, timeout time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, addrCall{"add", list, address, comment, timeout})
	return f.err
}
func (f *fakeAPI) AddressListRemove(ctx context.Context, list, address string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, addrCall{op: "remove", list: list, address: address})
	return f.err
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

var now = time.Date(2026, 10, 2, 12, 30, 0, 0, time.UTC)

const (
	macA = "AA:BB:CC:00:00:01"
	macB = "AA:BB:CC:00:00:02"
)

type fixture struct {
	st  *fakeStore
	api *fakeAPI
	set *settings.Manager
	h   http.Handler

	testErr   error  // returned by TestNotify
	tests     int    // TestNotify calls
	resetErr  error  // returned by Reset
	resets    []bool // Reset calls (all?)
	learnTill time.Time
}

func testDefaults() settings.Settings {
	return settings.Settings{
		NotifyMin: model.SevWarning, Language: "en", LearnPeriod: 7 * 24 * time.Hour,
		Sensitivity: "normal", DedupWindow: 6 * time.Hour, Retention: 60 * 24 * time.Hour,
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := &fakeStore{devices: map[string]model.Device{
		macA: {MAC: macA, IP: netip.MustParseAddr("192.168.88.10"), Hostname: "tv-obyvak", Vendor: "Samsung", Kind: "tv",
			FirstSeen: now.Add(-48 * time.Hour), LastSeen: now.Add(-10 * time.Minute)},
		macB: {MAC: macB, IP: netip.MustParseAddr("192.168.88.11"), Vendor: "Apple", Kind: "phone", Note: "Janin iPhone",
			FirstSeen: now.Add(-1 * time.Hour), LastSeen: now},
	}}
	st.hours = []model.HourStat{
		{MAC: macA, Hour: now.Truncate(time.Hour), TxBytes: 100, RxBytes: 1000},
		{MAC: macA, Hour: now.Add(-5 * time.Hour).Truncate(time.Hour), TxBytes: 50, RxBytes: 500},
		{MAC: macA, Hour: now.Add(-30 * time.Hour).Truncate(time.Hour), TxBytes: 7, RxBytes: 7},     // outside 24h
		{MAC: macA, Hour: now.Add(-9 * 24 * time.Hour).Truncate(time.Hour), TxBytes: 9, RxBytes: 9}, // outside 7d
	}
	st.dests = []model.DestStat{
		{MAC: macA, Country: "US", ASN: 15169, ASOrg: "Google", Bytes: 10},
		{MAC: macA, Country: "KR", ASN: 4766, ASOrg: "Korea Telecom", Bytes: 900},
	}
	st.alerts = []model.Alert{
		{ID: 1, Time: now, DeviceMAC: macA, Kind: model.AlertNewCountry, Severity: model.SevWarning, Title: "Nová země"},
		{ID: 2, Time: now, DeviceMAC: macA, Kind: model.AlertUploadSpike, Severity: model.SevCritical, Title: "Upload", Acked: true},
		{ID: 3, Time: now, DeviceMAC: macB, Kind: model.AlertNewDevice, Severity: model.SevInfo, Title: "Nové"},
	}
	api := &fakeAPI{}
	set, err := settings.NewManager(context.Background(), st, testDefaults())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{st: st, api: api, set: set, learnTill: now.Add(4 * 24 * time.Hour)}
	f.h = newServer(Deps{
		Store: st, API: api, QuarantineList: "guardian-quarantine",
		Status: func() Status {
			return Status{Version: "test", LastPoll: now, LearningUntil: f.learnTill,
				LastPollDuration: 250 * time.Millisecond, ConnCount: 100, FasttrackCount: 80, RouterCPU: 7}
		},
		Log:      slog.New(slog.DiscardHandler),
		Settings: set,
		TestNotify: func(ctx context.Context) error {
			f.tests++
			return f.testErr
		},
		Reset: func(ctx context.Context, all bool) error {
			f.resets = append(f.resets, all)
			return f.resetErr
		},
	}, func() time.Time { return now })
	return f
}

type reqOpt func(*http.Request)

func noCSRF(r *http.Request) { r.Header.Del("X-Guardian") }
func withOrigin(o string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Origin", o) }
}

func (f *fixture) do(t *testing.T, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://guardian.lan:8080"+path, rd)
	if method != http.MethodGet {
		req.Header.Set("X-Guardian", "1")
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status %d, want %d; body %s", rec.Code, code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

func TestStatus(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/status", "")
	wantCode(t, rec, 200)
	st := decode[statusDTO](t, rec)
	if !st.Learning || st.Version != "test" || st.LastPollMs != 250 || st.FasttrackCount != 80 || st.RouterCPU != 7 {
		t.Errorf("%+v", st)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type %q", ct)
	}
}

func TestDevicesList(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/devices", "")
	wantCode(t, rec, 200)
	ds := decode[[]deviceDTO](t, rec)
	if len(ds) != 2 {
		t.Fatalf("got %d", len(ds))
	}
	if ds[0].MAC != macB {
		t.Errorf("not sorted by last seen: %s first", ds[0].MAC)
	}
	if ds[0].Name != "Janin iPhone" || ds[1].Name != "tv-obyvak" {
		t.Errorf("names %q %q", ds[0].Name, ds[1].Name)
	}
	a := ds[1]
	if a.Tx24h != 150 || a.Rx24h != 1500 {
		t.Errorf("24h sums tx=%d rx=%d", a.Tx24h, a.Rx24h)
	}
	if a.OpenAlerts != 1 || ds[0].OpenAlerts != 1 {
		t.Errorf("open alerts %d %d", a.OpenAlerts, ds[0].OpenAlerts)
	}
	if a.IP != "192.168.88.10" {
		t.Errorf("ip %q", a.IP)
	}
}

func TestDeviceDetail(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/devices/aa-bb-cc-00-00-01", "") // lower-case, dashes accepted
	wantCode(t, rec, 200)
	d := decode[deviceDetailDTO](t, rec)
	if d.Device.MAC != macA {
		t.Fatalf("mac %s", d.Device.MAC)
	}
	if len(d.Hours) != 3 {
		t.Errorf("hours = %d, want 3 (7 day window)", len(d.Hours))
	}
	if len(d.Dests) != 2 || d.Dests[0].Country != "KR" {
		t.Errorf("dests not sorted by bytes: %+v", d.Dests)
	}
	if len(d.Alerts) != 2 || d.Device.OpenAlerts != 1 {
		t.Errorf("alerts %d open %d", len(d.Alerts), d.Device.OpenAlerts)
	}
	if d.Device.Tx24h != 150 {
		t.Errorf("tx24h %d", d.Device.Tx24h)
	}
}

func TestDeviceNotFoundAndBadMAC(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/devices/AA:BB:CC:00:00:99", "")
	wantCode(t, rec, 404)
	if e := decode[map[string]string](t, rec); e["error"] == "" {
		t.Error("missing error field")
	}
	wantCode(t, f.do(t, "GET", "/api/devices/notamac", ""), 400)
}

func TestPatchDeviceNote(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "PATCH", "/api/devices/"+macA, `{"note":"  Televize v obýváku "}`)
	wantCode(t, rec, 200)
	if got := f.st.devices[macA].Note; got != "Televize v obýváku" {
		t.Errorf("note %q", got)
	}
	if d := decode[deviceDTO](t, rec); d.Name != "Televize v obýváku" {
		t.Errorf("name %q", d.Name)
	}
	wantCode(t, f.do(t, "PATCH", "/api/devices/"+macA, `{bad`), 400)
	wantCode(t, f.do(t, "PATCH", "/api/devices/"+macA, `{}`), 400)
	wantCode(t, f.do(t, "PATCH", "/api/devices/"+macA, `{"note":"`+strings.Repeat("x", 201)+`"}`), 400)
	wantCode(t, f.do(t, "PATCH", "/api/devices/AA:BB:CC:00:00:99", `{"note":"x"}`), 404)
}

func TestCSRF(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name   string
		method string
		path   string
		opts   []reqOpt
	}{
		{"patch no header", "PATCH", "/api/devices/" + macA, []reqOpt{noCSRF}},
		{"quarantine no header", "POST", "/api/devices/" + macA + "/quarantine", []reqOpt{noCSRF}},
		{"unquarantine no header", "DELETE", "/api/devices/" + macA + "/quarantine", []reqOpt{noCSRF}},
		{"ack no header", "POST", "/api/alerts/1/ack", []reqOpt{noCSRF}},
		{"settings no header", "PUT", "/api/settings", []reqOpt{noCSRF}},
		{"test notify no header", "POST", "/api/settings/test-notify", []reqOpt{noCSRF}},
		{"reset no header", "POST", "/api/reset", []reqOpt{noCSRF}},
		{"merge no header", "POST", "/api/devices/merge", []reqOpt{noCSRF}},
		{"unmerge no header", "POST", "/api/devices/" + macA + "/unmerge", []reqOpt{noCSRF}},
		{"reset foreign origin", "POST", "/api/reset", []reqOpt{withOrigin("http://evil.example")}},
		{"foreign origin", "POST", "/api/devices/" + macA + "/quarantine", []reqOpt{withOrigin("http://evil.example")}},
		{"null origin", "POST", "/api/alerts/1/ack", []reqOpt{withOrigin("null")}},
		{"cross-site fetch", "POST", "/api/alerts/1/ack", []reqOpt{func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := f.do(t, c.method, c.path, `{"note":"x","scope":"all","sensitivity":"high","macs":["`+macA+`","`+macB+`"]}`, c.opts...)
			wantCode(t, rec, http.StatusForbidden)
		})
	}
	if len(f.api.calls) != 0 || len(f.st.acked) != 0 || f.st.devices[macA].Note != "" ||
		f.tests != 0 || len(f.resets) != 0 || f.set.Get().Sensitivity != "normal" || f.st.devices[macA].GroupID != "" {
		t.Errorf("rejected request had side effects: %+v %v", f.api.calls, f.st.acked)
	}
	// same origin passes
	wantCode(t, f.do(t, "POST", "/api/alerts/1/ack", "", withOrigin("http://guardian.lan:8080")), 200)
}

func TestQuarantine(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "POST", "/api/devices/"+macA+"/quarantine", "")
	wantCode(t, rec, 200)
	if len(f.api.calls) != 1 {
		t.Fatalf("calls %+v", f.api.calls)
	}
	c := f.api.calls[0]
	if c.op != "add" || c.list != "guardian-quarantine" || c.address != "192.168.88.10" || c.comment != "guardian: tv-obyvak" || c.timeout != 0 {
		t.Errorf("call %+v", c)
	}
	if !f.st.devices[macA].Quarantined {
		t.Error("store not updated")
	}
	if d := decode[deviceDTO](t, rec); !d.Quarantined {
		t.Error("response not quarantined")
	}

	rec = f.do(t, "DELETE", "/api/devices/"+macA+"/quarantine", "")
	wantCode(t, rec, 200)
	if c := f.api.calls[1]; c.op != "remove" || c.address != "192.168.88.10" || c.list != "guardian-quarantine" {
		t.Errorf("call %+v", c)
	}
	if f.st.devices[macA].Quarantined {
		t.Error("store not cleared")
	}
}

func TestQuarantineRouterError(t *testing.T) {
	f := newFixture(t)
	f.api.err = errors.New("no route")
	rec := f.do(t, "POST", "/api/devices/"+macA+"/quarantine", "")
	wantCode(t, rec, http.StatusBadGateway)
	if f.st.devices[macA].Quarantined {
		t.Error("store must not be updated when router call fails")
	}
}

func TestQuarantineNoIP(t *testing.T) {
	f := newFixture(t)
	d := f.st.devices[macA]
	d.IP = netip.Addr{}
	f.st.devices[macA] = d
	wantCode(t, f.do(t, "POST", "/api/devices/"+macA+"/quarantine", ""), http.StatusConflict)
	if len(f.api.calls) != 0 {
		t.Error("router called")
	}
	wantCode(t, f.do(t, "POST", "/api/devices/AA:BB:CC:00:00:99/quarantine", ""), 404)
}

func TestAlerts(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/alerts", "")
	wantCode(t, rec, 200)
	if as := decode[[]alertDTO](t, rec); len(as) != 3 {
		t.Errorf("all = %d", len(as))
	}

	rec = f.do(t, "GET", "/api/alerts?open=1&mac=aa:bb:cc:00:00:01&limit=5", "")
	wantCode(t, rec, 200)
	as := decode[[]alertDTO](t, rec)
	if len(as) != 1 || as[0].ID != 1 || as[0].Severity != "warning" || as[0].DeviceName != "tv-obyvak" {
		t.Errorf("filtered %+v", as)
	}
	if f.st.lastF.Limit != 5 || !f.st.lastF.OnlyOpen || f.st.lastF.DeviceMAC != macA {
		t.Errorf("filter %+v", f.st.lastF)
	}

	wantCode(t, f.do(t, "GET", "/api/alerts?limit=abc", ""), 400)
	wantCode(t, f.do(t, "GET", "/api/alerts?mac=xyz", ""), 400)
	f.do(t, "GET", "/api/alerts?limit=99999", "")
	if f.st.lastF.Limit != 1000 {
		t.Errorf("limit not capped: %d", f.st.lastF.Limit)
	}
}

func TestAck(t *testing.T) {
	f := newFixture(t)
	wantCode(t, f.do(t, "POST", "/api/alerts/1/ack", ""), 200)
	if len(f.st.acked) != 1 || f.st.acked[0] != 1 {
		t.Errorf("acked %v", f.st.acked)
	}
	wantCode(t, f.do(t, "POST", "/api/alerts/abc/ack", ""), 400)
	wantCode(t, f.do(t, "GET", "/api/alerts/1/ack", ""), http.StatusNotFound)
}

func TestUnknownAPIIsJSON404(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "GET", "/api/nope", "")
	wantCode(t, rec, 404)
	_ = decode[map[string]string](t, rec)
}

func TestStaticUI(t *testing.T) {
	f := newFixture(t)
	for path, want := range map[string]string{
		"/":            "<title>Guardian for RouterOS</title>",
		"/app.js":      "X-Guardian",
		"/i18n.js":     "GUARDIAN_I18N",
		"/theme.js":    "data-theme",
		"/style.css":   "prefers-color-scheme",
		"/favicon.svg": "<svg",
	} {
		rec := f.do(t, "GET", path, "")
		wantCode(t, rec, 200)
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s does not contain %q", path, want)
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("%s: missing CSP", path)
		}
	}
	wantCode(t, f.do(t, "GET", "/secret.txt", ""), 404)
	wantCode(t, f.do(t, "GET", "/static/app.js", ""), 404)
	wantCode(t, f.do(t, "POST", "/", ""), http.StatusMethodNotAllowed)
}

// Every embedded static file is served with the right content type (the
// nosniff header makes browsers reject scripts/styles/images with a wrong one).
func TestStaticFilesServed(t *testing.T) {
	f := newFixture(t)
	types := map[string]string{
		".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
	}
	entries, err := fs.ReadDir(staticFS, "static")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 6 {
		t.Fatalf("only %d static files", len(entries))
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("static/%s: sub-directories are not served (the handler serves top-level files only)", e.Name())
			continue
		}
		p := "/" + e.Name()
		if e.Name() == "index.html" {
			p = "/"
		}
		rec := f.do(t, "GET", p, "")
		wantCode(t, rec, 200)
		want, ok := types[path.Ext(e.Name())]
		if !ok {
			t.Errorf("static/%s: unexpected file type", e.Name())
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, want) {
			t.Errorf("%s: Content-Type %q, want %s", p, ct, want)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing nosniff", p)
		}
	}
}

// The CSP allows only this origin (plus inline styles and data: images used by
// the UI): no external hosts, no inline or eval'd scripts.
func TestCSPHasNoExternalSources(t *testing.T) {
	f := newFixture(t)
	csp := f.do(t, "GET", "/", "").Header().Get("Content-Security-Policy")
	allowed := map[string]bool{"'self'": true, "'none'": true, "'unsafe-inline'": true, "data:": true}
	directives := map[string][]string{}
	for _, d := range strings.Split(csp, ";") {
		fields := strings.Fields(d)
		if len(fields) == 0 {
			continue
		}
		directives[fields[0]] = fields[1:]
		for _, src := range fields[1:] {
			if !allowed[src] {
				t.Errorf("CSP %s allows %q", fields[0], src)
			}
		}
	}
	for _, name := range []string{"default-src", "script-src", "img-src", "frame-ancestors"} {
		if directives[name] == nil {
			t.Errorf("CSP has no %s: %q", name, csp)
		}
	}
	if !slices.Equal(directives["script-src"], []string{"'self'"}) {
		t.Errorf("script-src = %v, want only 'self'", directives["script-src"])
	}
}

func TestNewDefaults(t *testing.T) {
	h := New(Deps{Store: &fakeStore{devices: map[string]model.Device{}}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	wantCode(t, rec, 200)
	// quarantine without API configured → 503
	st := &fakeStore{devices: map[string]model.Device{macA: {MAC: macA, IP: netip.MustParseAddr("10.0.0.1")}}}
	h = New(Deps{Store: st})
	req := httptest.NewRequest("POST", "/api/devices/"+macA+"/quarantine", nil)
	req.Header.Set("X-Guardian", "1")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	wantCode(t, rec, http.StatusServiceUnavailable)
}

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"aa:bb:cc:dd:ee:ff": "AA:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF": "AA:BB:CC:DD:EE:FF",
	} {
		if got, ok := normalizeMAC(in); !ok || got != want {
			t.Errorf("%s → %s %v", in, got, ok)
		}
	}
	if _, ok := normalizeMAC("00:00:5e:00:53:01:02:03"); ok {
		t.Error("EUI-64 accepted")
	}
}

func TestDevicesGroupRandomizedPhone(t *testing.T) {
	f := newFixture(t)
	const (
		p1 = "DA:00:00:00:00:01" // home Wi-Fi, seen now
		p2 = "DA:00:00:00:00:02" // guest Wi-Fi, seen earlier
		p3 = "DA:00:00:00:00:03" // other phone, same vendor, different hostname
		p4 = "AA:BB:CC:00:00:04" // same hostname, but not randomized
	)
	f.st.devices[p1] = model.Device{MAC: p1, IP: netip.MustParseAddr("192.168.88.50"), Hostname: "Galaxy-Z-Flip-of-Alex",
		Randomized: true, Kind: "phone", FirstSeen: now.Add(-2 * time.Hour), LastSeen: now.Add(-1 * time.Minute)}
	f.st.devices[p2] = model.Device{MAC: p2, IP: netip.MustParseAddr("192.168.89.7"), Hostname: "galaxy-z-flip-of-alex",
		Randomized: true, Kind: "phone", FirstSeen: now.Add(-20 * time.Hour), LastSeen: now.Add(-3 * time.Hour),
		Quarantined: true, Comment: "Evin telefon"}
	f.st.devices[p3] = model.Device{MAC: p3, Hostname: "Pixel-8", Randomized: true, LastSeen: now.Add(-2 * time.Minute)}
	f.st.devices[p4] = model.Device{MAC: p4, Hostname: "Galaxy-Z-Flip-of-Alex", LastSeen: now.Add(-4 * time.Hour)}
	f.st.hours = append(f.st.hours,
		model.HourStat{MAC: p1, Hour: now.Truncate(time.Hour), TxBytes: 10, RxBytes: 100},
		model.HourStat{MAC: p2, Hour: now.Add(-3 * time.Hour).Truncate(time.Hour), TxBytes: 5, RxBytes: 50},
	)
	f.st.alerts = append(f.st.alerts,
		model.Alert{ID: 10, Time: now, DeviceMAC: p1, Kind: model.AlertNewDevice},
		model.Alert{ID: 11, Time: now, DeviceMAC: p2, Kind: model.AlertNewDevice},
		model.Alert{ID: 12, Time: now, DeviceMAC: p2, Kind: model.AlertNewCountry, Acked: true},
	)

	rec := f.do(t, "GET", "/api/devices", "")
	wantCode(t, rec, 200)
	ds := decode[[]deviceDTO](t, rec)
	// macA, macB, p3, p4 and one row for p1+p2
	if len(ds) != 5 {
		t.Fatalf("got %d rows: %+v", len(ds), ds)
	}
	var g *deviceDTO
	for i := range ds {
		switch ds[i].MAC {
		case p2:
			t.Fatalf("secondary member listed as its own row")
		case p1:
			g = &ds[i]
		case p3, p4, macA, macB:
			if len(ds[i].Members) != 0 {
				t.Errorf("%s: unexpected members %+v", ds[i].MAC, ds[i].Members)
			}
		}
	}
	if g == nil {
		t.Fatal("group row missing")
	}
	if g.IP != "192.168.88.50" || g.Hostname != "Galaxy-Z-Flip-of-Alex" {
		t.Errorf("primary fields not from newest member: %+v", g)
	}
	if g.Name != "Evin telefon" {
		t.Errorf("name %q, want member's DHCP comment", g.Name)
	}
	if g.Tx24h != 15 || g.Rx24h != 150 || g.OpenAlerts != 2 {
		t.Errorf("sums tx=%d rx=%d alerts=%d", g.Tx24h, g.Rx24h, g.OpenAlerts)
	}
	if g.Quarantined || !g.PartiallyQuarantined {
		t.Errorf("quarantined=%v partially=%v", g.Quarantined, g.PartiallyQuarantined)
	}
	if !g.FirstSeen.Equal(now.Add(-20 * time.Hour)) {
		t.Errorf("firstSeen %v, want earliest member", g.FirstSeen)
	}
	if len(g.Members) != 2 || g.Members[0].MAC != p1 || g.Members[1].MAC != p2 {
		t.Fatalf("members %+v", g.Members)
	}
	if m := g.Members[1]; m.IP != "192.168.89.7" || !m.Quarantined || m.Tx24h != 5 || m.Rx24h != 50 || !m.LastSeen.Equal(now.Add(-3*time.Hour)) {
		t.Errorf("member %+v", m)
	}

	// All members quarantined → group quarantined, not partial.
	d := f.st.devices[p1]
	d.Quarantined = true
	f.st.devices[p1] = d
	ds = decode[[]deviceDTO](t, f.do(t, "GET", "/api/devices", ""))
	for _, x := range ds {
		if x.MAC == p1 && (!x.Quarantined || x.PartiallyQuarantined) {
			t.Errorf("all quarantined: %+v", x)
		}
	}

	// Detail by MAC still works per member.
	det := decode[deviceDetailDTO](t, f.do(t, "GET", "/api/devices/"+p2, ""))
	if det.Device.MAC != p2 || det.Device.Name != "Evin telefon" || det.Device.Comment != "Evin telefon" || len(det.Device.Members) != 0 {
		t.Errorf("detail %+v", det.Device)
	}
}

func TestGroupDevicesUnit(t *testing.T) {
	t0 := now
	in := []deviceDTO{
		{MAC: "02:00:00:00:00:01", Hostname: "phone", Randomized: true, LastSeen: t0.Add(-time.Hour), Name: "phone"},
		{MAC: "02:00:00:00:00:02", Hostname: "PHONE ", Randomized: true, LastSeen: t0, Name: "PHONE", Note: ""},
		{MAC: "02:00:00:00:00:03", Hostname: "", Randomized: true, LastSeen: t0},
		{MAC: "02:00:00:00:00:04", Hostname: "", Randomized: true, LastSeen: t0},
	}
	out := groupDevices(in)
	if len(out) != 3 {
		t.Fatalf("got %d rows: %+v", len(out), out)
	}
	if out[0].MAC != "02:00:00:00:00:02" || len(out[0].Members) != 2 {
		t.Errorf("group %+v", out[0])
	}
	for _, x := range out[1:] {
		if len(x.Members) != 0 {
			t.Errorf("empty hostname grouped: %+v", x)
		}
	}
}

func TestHealthz(t *testing.T) {
	cases := []struct {
		name string
		st   Status
		max  time.Duration
		want int
		body string
	}{
		{"fresh", Status{LastPoll: now.Add(-30 * time.Second)}, 0, 200, "ok"},
		{"never polled", Status{}, 0, 503, "no poll yet"},
		{"error", Status{LastPoll: now, LastError: "dial tcp 192.168.88.1:443: secret detail"}, 0, 503, "last poll failed"},
		{"stale default 2m", Status{LastPoll: now.Add(-3 * time.Minute)}, 0, 503, "too old"},
		{"custom max age", Status{LastPoll: now.Add(-3 * time.Minute)}, 5 * time.Minute, 200, "ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := c.st
			h := newServer(Deps{Store: &fakeStore{devices: map[string]model.Device{}}, HealthMaxAge: c.max,
				Status: func() Status { return st }}, func() time.Time { return now })
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
			wantCode(t, rec, c.want)
			if !strings.Contains(rec.Body.String(), c.body) {
				t.Errorf("body %q, want %q", rec.Body.String(), c.body)
			}
			if strings.Contains(rec.Body.String(), "secret") {
				t.Error("error detail leaked")
			}
		})
	}
	// Through BasicAuth without credentials.
	h := BasicAuth(newServer(Deps{Store: &fakeStore{devices: map[string]model.Device{}},
		Status: func() Status { return Status{LastPoll: now} }}, func() time.Time { return now }), "admin", "pw")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	wantCode(t, rec, 200)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status", nil))
	wantCode(t, rec, 401)
}

func TestNamesUseDisplayName(t *testing.T) {
	f := newFixture(t)
	d := f.st.devices[macA]
	d.Comment = "Televize obývák"
	f.st.devices[macA] = d
	ds := decode[[]deviceDTO](t, f.do(t, "GET", "/api/devices", ""))
	for _, x := range ds {
		if x.MAC == macA && (x.Name != "Televize obývák" || x.Comment != "Televize obývák" || x.Hostname != "tv-obyvak") {
			t.Errorf("%+v", x)
		}
	}
	as := decode[[]alertDTO](t, f.do(t, "GET", "/api/alerts?mac="+macA, ""))
	if len(as) == 0 || as[0].DeviceName != "Televize obývák" {
		t.Errorf("alerts %+v", as)
	}
	wantCode(t, f.do(t, "POST", "/api/devices/"+macA+"/quarantine", ""), 200)
	if c := f.api.calls[0].comment; c != "guardian: Televize obývák" {
		t.Errorf("comment %q", c)
	}
}
