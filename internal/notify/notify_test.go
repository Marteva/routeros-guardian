package notify

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/i18n"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// ---------------------------------------------------------------------------
// fake store
// ---------------------------------------------------------------------------

type fakeStore struct {
	mu      sync.Mutex
	alerts  []model.Alert
	devices map[string]model.Device
	nextID  int64
	slowIns time.Duration
}

func newFakeStore() *fakeStore { return &fakeStore{devices: map[string]model.Device{}} }

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
func (f *fakeStore) Devices(ctx context.Context) ([]model.Device, error)             { return nil, nil }
func (f *fakeStore) SetQuarantined(ctx context.Context, mac string, q bool) error    { return nil }
func (f *fakeStore) SetNote(ctx context.Context, mac, note string) error             { return nil }
func (f *fakeStore) RecordFlows(ctx context.Context, flows []model.FlowSample) error { return nil }
func (f *fakeStore) HourStats(ctx context.Context, mac string, from, to time.Time) ([]model.HourStat, error) {
	return nil, nil
}
func (f *fakeStore) DestStats(ctx context.Context, mac string) ([]model.DestStat, error) {
	return nil, nil
}
func (f *fakeStore) InsertAlert(ctx context.Context, a *model.Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	a.ID = f.nextID
	f.alerts = append(f.alerts, *a)
	return nil
}
func (f *fakeStore) Alerts(ctx context.Context, fl model.AlertFilter) ([]model.Alert, error) {
	return nil, nil
}
func (f *fakeStore) AckAlert(ctx context.Context, id int64) error { return nil }
func (f *fakeStore) LastAlertByDedupKey(ctx context.Context, key string) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var t time.Time
	ok := false
	for _, a := range f.alerts {
		if a.DedupKey == key && (!ok || a.Time.After(t)) {
			t, ok = a.Time, true
		}
	}
	return t, ok, nil
}
func (f *fakeStore) Prune(ctx context.Context, olderThan time.Time) error { return nil }
func (f *fakeStore) Close() error                                         { return nil }
func (f *fakeStore) SetKindOverride(ctx context.Context, mac, kind string) error {
	return nil
}
func (f *fakeStore) SetGroup(ctx context.Context, macs []string, groupID string) error {
	return nil
}
func (f *fakeStore) Settings(ctx context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}
func (f *fakeStore) PutSettings(ctx context.Context, kv map[string]string) error { return nil }
func (f *fakeStore) ResetLearned(ctx context.Context) error                      { return nil }
func (f *fakeStore) ResetAll(ctx context.Context) error                          { return nil }

var _ model.Store = (*fakeStore)(nil)

func (f *fakeStore) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.alerts)
}

// ---------------------------------------------------------------------------
// fake notifier
// ---------------------------------------------------------------------------

type fakeNotifier struct {
	name    string // "" = "fake"
	err     error  // returned by Send
	mu      sync.Mutex
	sent    []model.Alert
	devs    []model.Device
	langs   []string      // language found on the Send context
	entered chan struct{} // if set, signalled when Send starts
	block   chan struct{}
	got     chan struct{}
}

func newFakeNotifier() *fakeNotifier { return &fakeNotifier{got: make(chan struct{}, 100)} }

func (n *fakeNotifier) Name() string {
	if n.name != "" {
		return n.name
	}
	return "fake"
}
func (n *fakeNotifier) Send(ctx context.Context, a model.Alert, d model.Device) error {
	if n.entered != nil {
		n.entered <- struct{}{}
	}
	if n.block != nil {
		<-n.block
	}
	n.mu.Lock()
	n.sent = append(n.sent, a)
	n.devs = append(n.devs, d)
	n.langs = append(n.langs, langFrom(ctx))
	n.mu.Unlock()
	n.got <- struct{}{}
	return n.err
}
func (n *fakeNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.sent)
}
func (n *fakeNotifier) wait(t *testing.T, k int) {
	t.Helper()
	for i := 0; i < k; i++ {
		select {
		case <-n.got:
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for notification %d/%d", i+1, k)
		}
	}
}

// ---------------------------------------------------------------------------
// ntfy
// ---------------------------------------------------------------------------

func TestNtfySend(t *testing.T) {
	var gotHdr http.Header
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/topic" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotHdr = r.Header.Clone()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
	}))
	defer srv.Close()

	n := NewNtfy(srv.URL+"/topic", "tk_secret")
	a := model.Alert{Title: "Nové zařízení", Detail: "Objevilo se nové zařízení", Severity: model.SevCritical, DeviceMAC: "AA:BB:CC:DD:EE:FF"}
	d := model.Device{MAC: "AA:BB:CC:DD:EE:FF", Hostname: "kamera", IP: netip.MustParseAddr("192.168.88.10")}
	if err := n.Send(context.Background(), a, d); err != nil {
		t.Fatal(err)
	}
	if got := gotHdr.Get("Priority"); got != "5" {
		t.Errorf("priority = %q", got)
	}
	if got := gotHdr.Get("Tags"); got != "rotating_light" {
		t.Errorf("tags = %q", got)
	}
	if got := gotHdr.Get("Authorization"); got != "Bearer tk_secret" {
		t.Errorf("auth = %q", got)
	}
	title, err := new(mime.WordDecoder).DecodeHeader(gotHdr.Get("Title"))
	if err != nil || title != "Nové zařízení" {
		t.Errorf("title = %q (%v)", title, err)
	}
	if !strings.HasPrefix(gotBody, "Objevilo se nové zařízení") || !strings.Contains(gotBody, "kamera (192.168.88.10, AA:BB:CC:DD:EE:FF)") {
		t.Errorf("body = %q", gotBody)
	}
}

func TestNtfyPriorities(t *testing.T) {
	cases := map[model.Severity][2]string{
		model.SevInfo:     {"3", "information_source"},
		model.SevWarning:  {"4", "warning"},
		model.SevCritical: {"5", "rotating_light"},
	}
	for s, want := range cases {
		if ntfyPriority(s) != want[0] || ntfyTags(s) != want[1] {
			t.Errorf("%v: %s %s", s, ntfyPriority(s), ntfyTags(s))
		}
	}
}

func TestNtfyNoTokenASCIITitle(t *testing.T) {
	var hdr http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hdr = r.Header.Clone() }))
	defer srv.Close()
	if err := NewNtfy(srv.URL, "").Send(context.Background(), model.Alert{Title: "Upload spike\nx", Severity: model.SevWarning}, model.Device{}); err != nil {
		t.Fatal(err)
	}
	if hdr.Get("Authorization") != "" {
		t.Error("unexpected auth header")
	}
	if hdr.Get("Title") != "Upload spike x" {
		t.Errorf("title %q", hdr.Get("Title"))
	}
}

func TestRetryOnceOn5xx(t *testing.T) {
	old := retryDelay
	retryDelay = 10 * time.Millisecond
	defer func() { retryDelay = old }()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()
	err := NewNtfy(srv.URL, "").Send(context.Background(), model.Alert{Title: "x"}, model.Device{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := calls.Load(); c != 2 {
		t.Errorf("calls = %d, want 2", c)
	}
}

func TestNoRetryOn4xx(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	if err := NewNtfy(srv.URL, "").Send(context.Background(), model.Alert{Title: "x"}, model.Device{}); err == nil {
		t.Fatal("expected error")
	}
	if c := calls.Load(); c != 1 {
		t.Errorf("calls = %d, want 1", c)
	}
}

// ---------------------------------------------------------------------------
// Telegram
// ---------------------------------------------------------------------------

func TestTelegramSend(t *testing.T) {
	var got map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type %q", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := NewTelegram("123:ABC", "-1001").(*telegram)
	n.baseURL = srv.URL
	a := model.Alert{Title: "Upload <script> & co", Detail: `5 GB > baseline "x"`, Severity: model.SevWarning, DeviceMAC: "AA:BB:CC:DD:EE:01"}
	d := model.Device{MAC: "AA:BB:CC:DD:EE:01", Note: "Tomův <PC>"}
	if err := n.Send(context.Background(), a, d); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123:ABC/sendMessage" {
		t.Errorf("path %q", path)
	}
	if got["chat_id"] != "-1001" || got["parse_mode"] != "HTML" {
		t.Errorf("payload %v", got)
	}
	text, _ := got["text"].(string)
	for _, want := range []string{"<b>Upload &lt;script&gt; &amp; co</b>", "5 GB &gt; baseline &#34;x&#34;", "Tomův &lt;PC&gt;"} {
		if !strings.Contains(text, want) {
			t.Errorf("text %q missing %q", text, want)
		}
	}
	if strings.Contains(text, "<script>") || strings.Contains(text, "<PC>") {
		t.Errorf("unescaped html in %q", text)
	}
}

func TestTelegramErrorHidesToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"ok":false,"description":"chat not found"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	n := NewTelegram("999:SECRET", "1").(*telegram)
	n.baseURL = srv.URL
	err := n.Send(context.Background(), model.Alert{Title: "x"}, model.Device{})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("token leaked: %v", err)
	}
}

func TestTruncate(t *testing.T) {
	s := truncate(strings.Repeat("č", 10), 5)
	if !strings.HasSuffix(s, "…") || len(s) > 5+len("…") {
		t.Errorf("%q", s)
	}
}

func TestDeviceName(t *testing.T) {
	cases := []struct {
		d    model.Device
		want string
	}{
		{model.Device{MAC: "M", Vendor: "V", Hostname: "H", Comment: "C", Note: "N"}, "N"},
		{model.Device{MAC: "M", Vendor: "V", Hostname: "H", Comment: "C", Note: "  "}, "C"},
		{model.Device{MAC: "M", Vendor: "V", Hostname: "H"}, "H"},
		{model.Device{MAC: "M", Vendor: "V", Hostname: " "}, "V"},
		{model.Device{}, "unknown device"},
		{model.Device{MAC: " ", Note: " "}, "unknown device"},
		{model.Device{MAC: "M", Vendor: "V"}, "V"},
		{model.Device{MAC: "M"}, "M"},
	}
	for _, c := range cases {
		if got := DeviceName(c.d); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
	for lang, want := range map[string]string{"cs": "neznámé zařízení", "de": "unbekanntes Gerät",
		"ru": "неизвестное устройство", "xx": "unknown device", "": "unknown device"} {
		if got := DeviceNameLang(model.Device{}, lang); got != want {
			t.Errorf("%q: got %q want %q", lang, got, want)
		}
	}
	if got := DeviceNameLang(model.Device{MAC: "M", Hostname: "pc"}, "cs"); got != "pc" {
		t.Errorf("named device: %q", got)
	}
}

func TestDeviceLineLanguages(t *testing.T) {
	ip := netip.MustParseAddr("192.168.88.10")
	cases := []struct {
		lang string
		a    model.Alert
		d    model.Device
		want string
	}{
		{"en", model.Alert{}, model.Device{MAC: "AA", Hostname: "tv", IP: ip}, "Device: tv (192.168.88.10, AA)"},
		{"cs", model.Alert{}, model.Device{MAC: "AA", Hostname: "tv", IP: ip}, "Zařízení: tv (192.168.88.10, AA)"},
		{"de", model.Alert{}, model.Device{MAC: "AA", Hostname: "tv"}, "Gerät: tv (AA)"},
		{"pl", model.Alert{}, model.Device{MAC: "AA", IP: ip}, "Urządzenie: AA (192.168.88.10)"},
		{"es", model.Alert{DeviceMAC: "BB"}, model.Device{}, "Dispositivo: BB"},
		{"ru", model.Alert{}, model.Device{MAC: "AA"}, "Устройство: AA"},
		{"pt", model.Alert{}, model.Device{}, ""},                    // no device at all
		{"xx", model.Alert{}, model.Device{MAC: "AA"}, "Device: AA"}, // unknown language → English
	}
	for _, c := range cases {
		if got := deviceLine(c.lang, c.a, c.d); got != c.want {
			t.Errorf("%s: got %q want %q", c.lang, got, c.want)
		}
	}
}

func TestAllLanguagesTranslated(t *testing.T) {
	for _, lang := range settings.Languages {
		for _, k := range messageKeys {
			got := i18n.T(lang, k)
			if got == k {
				t.Errorf("%s: %s missing", lang, k)
			}
			if lang != i18n.Fallback && got == i18n.T(i18n.Fallback, k) {
				t.Errorf("%s: %s not translated (%q)", lang, k, got)
			}
			if strings.Count(got, "%s") != strings.Count(i18n.T(i18n.Fallback, k), "%s") {
				t.Errorf("%s: %s has different verbs: %q", lang, k, got)
			}
		}
	}
}

func TestNotifiersUseContextLanguage(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer srv.Close()
	a := model.Alert{Title: "x", DeviceMAC: "AA:BB:CC:DD:EE:FF"}
	d := model.Device{MAC: "AA:BB:CC:DD:EE:FF", Hostname: "kamera"}

	if err := NewNtfy(srv.URL, "").Send(withLang(context.Background(), "cs"), a, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "Zařízení: kamera (AA:BB:CC:DD:EE:FF)") {
		t.Errorf("ntfy cs body %q", body)
	}
	if err := NewNtfy(srv.URL, "").Send(context.Background(), a, d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "Device: kamera") {
		t.Errorf("ntfy default body %q", body)
	}

	tg := NewTelegram("1:X", "2").(*telegram)
	tg.baseURL = srv.URL
	if err := tg.Send(withLang(context.Background(), "ru"), a, d); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatal(err)
	}
	if text, _ := payload["text"].(string); !strings.Contains(text, "<i>Устройство: kamera (AA:BB:CC:DD:EE:FF)</i>") {
		t.Errorf("telegram ru text %q", text)
	}
}

func TestBuildNotifiers(t *testing.T) {
	names := func(ns []Notifier) string {
		var out []string
		for _, n := range ns {
			out = append(out, n.Name())
		}
		return strings.Join(out, ",")
	}
	cases := []struct {
		s    settings.Settings
		want string
	}{
		{settings.Settings{}, ""},
		{settings.Settings{TelegramToken: "t"}, ""},
		{settings.Settings{TelegramChatID: "c"}, ""},
		{settings.Settings{TelegramToken: "t", TelegramChatID: "c"}, "telegram"},
		{settings.Settings{NtfyURL: "https://ntfy.sh/x"}, "ntfy"},
		{settings.Settings{NtfyURL: "https://ntfy.sh/x", NtfyToken: "tk", TelegramToken: "t", TelegramChatID: "c"}, "telegram,ntfy"},
	}
	for i, c := range cases {
		if got := names(BuildNotifiers(c.s)); got != c.want {
			t.Errorf("case %d: got %q want %q", i, got, c.want)
		}
	}
	ns := BuildNotifiers(settings.Settings{NtfyURL: "https://ntfy.sh/x", NtfyToken: "tk",
		TelegramToken: "t", TelegramChatID: "c"})
	if tg := ns[0].(*telegram); tg.token != "t" || tg.chatID != "c" {
		t.Errorf("telegram %+v", tg)
	}
	if n := ns[1].(*ntfy); n.topicURL != "https://ntfy.sh/x" || n.token != "tk" {
		t.Errorf("ntfy %+v", n)
	}
}
