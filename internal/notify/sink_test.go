package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

func TestSinkDedup(t *testing.T) {
	st := newFakeStore()
	n := newFakeNotifier()
	s := NewSink(st, []Notifier{n}, time.Hour, nil)
	defer s.Close(context.Background())

	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	emit := func(at time.Time, key string) {
		s.Emit(context.Background(), model.Alert{Time: at, Kind: model.AlertNewASN, Severity: model.SevWarning, DedupKey: key, DeviceMAC: "AA"})
	}
	emit(t0, "k1")
	emit(t0.Add(30*time.Minute), "k1") // suppressed
	emit(t0.Add(30*time.Minute), "k2") // different key
	emit(t0.Add(61*time.Minute), "k1") // window passed
	emit(t0.Add(62*time.Minute), "")   // no key: never deduped
	emit(t0.Add(62*time.Minute), "")
	if got := st.count(); got != 5 {
		t.Fatalf("stored %d alerts, want 5", got)
	}
	n.wait(t, 5)
}

func TestSinkInfoStoredOnly(t *testing.T) {
	st := newFakeStore()
	n := newFakeNotifier()
	s := NewSink(st, []Notifier{n}, time.Hour, nil)
	s.Emit(context.Background(), model.Alert{Kind: "x", Severity: model.SevInfo})
	s.Emit(context.Background(), model.Alert{Kind: "y", Severity: model.SevCritical})
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st.count() != 2 {
		t.Fatalf("stored %d", st.count())
	}
	if len(n.sent) != 1 || n.sent[0].Kind != "y" {
		t.Fatalf("sent %+v", n.sent)
	}
	if n.sent[0].ID == 0 || n.sent[0].Time.IsZero() {
		t.Errorf("alert not completed before notify: %+v", n.sent[0])
	}
}

func TestSinkMinNotifyConfigurable(t *testing.T) {
	st := newFakeStore()
	n := newFakeNotifier()
	s := NewSink(st, []Notifier{n}, 0, nil)
	s.Configure([]Notifier{n}, model.SevInfo, "")
	s.Emit(context.Background(), model.Alert{Kind: "x", Severity: model.SevInfo})
	n.wait(t, 1)
	s.Close(context.Background())
	if n.langs[0] != "en" {
		t.Errorf("default language %q", n.langs[0])
	}
}

func TestSinkDeviceLookup(t *testing.T) {
	st := newFakeStore()
	st.devices["AA:BB"] = model.Device{MAC: "AA:BB", Note: "Babiččin tablet"}
	n := newFakeNotifier()
	s := NewSink(st, []Notifier{n}, 0, nil)
	s.Emit(context.Background(), model.Alert{DeviceMAC: "AA:BB", Severity: model.SevWarning})
	s.Emit(context.Background(), model.Alert{DeviceMAC: "CC:DD", Severity: model.SevWarning})
	s.Close(context.Background())
	if len(n.devs) != 2 {
		t.Fatalf("got %d", len(n.devs))
	}
	if DeviceName(n.devs[0]) != "Babiččin tablet" {
		t.Errorf("dev0 %+v", n.devs[0])
	}
	if n.devs[1].MAC != "CC:DD" {
		t.Errorf("unknown device should carry MAC: %+v", n.devs[1])
	}
}

func TestSinkNonBlockingWhenNotifierHangs(t *testing.T) {
	st := newFakeStore()
	n := newFakeNotifier()
	n.block = make(chan struct{})
	s := NewSink(st, []Notifier{n}, 0, nil)

	start := time.Now()
	total := defaultQueueSize + 20
	for i := 0; i < total; i++ {
		s.Emit(context.Background(), model.Alert{Kind: "x", Severity: model.SevWarning})
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("Emit blocked for %v", el)
	}
	if st.count() != total {
		t.Errorf("all alerts must be stored even when queue is full: %d", st.count())
	}
	close(n.block)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	sent := len(n.sent)
	n.mu.Unlock()
	// queue capacity + the one in flight; the rest was dropped
	if sent > defaultQueueSize+1 || sent < defaultQueueSize {
		t.Errorf("sent %d, expected about %d", sent, defaultQueueSize+1)
	}
}

func TestSinkNoNotifiers(t *testing.T) {
	st := newFakeStore()
	s := NewSink(st, nil, time.Hour, nil)
	s.Emit(context.Background(), model.Alert{Severity: model.SevCritical})
	s.Close(context.Background())
	if st.count() != 1 {
		t.Fatal("not stored")
	}
}

// ntfyServer is an ntfy endpoint recording request bodies and titles.
type ntfyServer struct {
	*httptest.Server
	status int // response status, 0 = 200
	mu     sync.Mutex
	bodies []string
	titles []string
	got    chan struct{}
}

func newNtfyServer(t *testing.T, status int) *ntfyServer {
	t.Helper()
	ns := &ntfyServer{status: status, got: make(chan struct{}, 100)}
	ns.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		title, _ := new(mime.WordDecoder).DecodeHeader(r.Header.Get("Title"))
		ns.mu.Lock()
		ns.bodies = append(ns.bodies, string(b))
		ns.titles = append(ns.titles, title)
		ns.mu.Unlock()
		if ns.status != 0 {
			http.Error(w, "nope", ns.status)
		}
		ns.got <- struct{}{}
	}))
	t.Cleanup(ns.Close)
	return ns
}

func (ns *ntfyServer) wait(t *testing.T) {
	t.Helper()
	select {
	case <-ns.got:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for ntfy request")
	}
}

func (ns *ntfyServer) snapshot() (bodies, titles []string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	return slices.Clone(ns.bodies), slices.Clone(ns.titles)
}

func TestSinkConfigureHotSwap(t *testing.T) {
	st := newFakeStore()
	st.devices["AA:BB:CC:DD:EE:FF"] = model.Device{MAC: "AA:BB:CC:DD:EE:FF", Hostname: "kamera"}
	srvA, srvB := newNtfyServer(t, 0), newNtfyServer(t, 0)
	s := NewSink(st, []Notifier{NewNtfy(srvA.URL, "")}, 0, nil)
	defer s.Close(context.Background())
	emit := func(sev model.Severity) {
		s.Emit(context.Background(), model.Alert{Title: "t", DeviceMAC: "AA:BB:CC:DD:EE:FF", Severity: sev})
	}

	emit(model.SevWarning)
	srvA.wait(t)
	if b, _ := srvA.snapshot(); !strings.Contains(b[0], "Device: kamera (AA:BB:CC:DD:EE:FF)") {
		t.Fatalf("default (English) body %q", b[0])
	}

	// Swap to B, Czech, info and above.
	s.Configure([]Notifier{NewNtfy(srvB.URL, "")}, model.SevInfo, "cs")
	emit(model.SevInfo)
	srvB.wait(t)
	if b, _ := srvB.snapshot(); !strings.Contains(b[0], "Zařízení: kamera (AA:BB:CC:DD:EE:FF)") {
		t.Fatalf("Czech body %q", b[0])
	}

	// Raise the minimum: a warning is stored but not pushed.
	s.Configure([]Notifier{NewNtfy(srvB.URL, "")}, model.SevCritical, "de")
	emit(model.SevWarning)
	emit(model.SevCritical)
	srvB.wait(t)
	if b, _ := srvB.snapshot(); len(b) != 2 || !strings.Contains(b[1], "Gerät: kamera") {
		t.Fatalf("after raising minimum: %q", b)
	}

	// No notifiers: alerts are stored only.
	s.Configure(nil, model.SevInfo, "en")
	emit(model.SevCritical)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, _ := srvA.snapshot(); len(a) != 1 {
		t.Errorf("A got %d requests after the swap", len(a))
	}
	if b, _ := srvB.snapshot(); len(b) != 2 {
		t.Errorf("B got %d requests", len(b))
	}
	if st.count() != 5 {
		t.Errorf("stored %d alerts, want 5", st.count())
	}
}

func TestSinkQueuedMessageUsesCurrentConfig(t *testing.T) {
	st := newFakeStore()
	slow, n1, n2 := newFakeNotifier(), newFakeNotifier(), newFakeNotifier()
	slow.block = make(chan struct{})
	slow.entered = make(chan struct{}, 10)
	s := NewSink(st, []Notifier{slow, n1}, 0, nil)
	s.Emit(context.Background(), model.Alert{Kind: "first", Severity: model.SevWarning})
	// Wait until the worker is stuck delivering the first alert, then queue
	// another one and swap the configuration.
	select {
	case <-slow.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not start delivering")
	}
	s.Emit(context.Background(), model.Alert{Kind: "second", Severity: model.SevWarning})
	s.Configure([]Notifier{n2}, model.SevWarning, "pl")
	close(slow.block)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n1.count() != 1 || n1.sent[0].Kind != "first" {
		t.Errorf("n1 sent %+v", n1.sent)
	}
	if n2.count() != 1 || n2.sent[0].Kind != "second" || n2.langs[0] != "pl" {
		t.Errorf("n2 sent %+v langs %v", n2.sent, n2.langs)
	}
}

func TestSinkSetDedup(t *testing.T) {
	st := newFakeStore()
	s := NewSink(st, nil, 0, nil)
	defer s.Close(context.Background())
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	emit := func(at time.Time) {
		s.Emit(context.Background(), model.Alert{Time: at, Kind: "x", DedupKey: "k"})
	}
	emit(t0)
	emit(t0.Add(time.Minute)) // dedup disabled
	if st.count() != 2 {
		t.Fatalf("stored %d, want 2", st.count())
	}
	s.SetDedup(time.Hour)
	emit(t0.Add(2 * time.Minute)) // suppressed
	if st.count() != 2 {
		t.Fatalf("stored %d after SetDedup, want 2", st.count())
	}
	s.SetDedup(time.Minute)
	emit(t0.Add(3 * time.Minute)) // window passed
	if st.count() != 3 {
		t.Fatalf("stored %d, want 3", st.count())
	}
}

func TestSinkConcurrentReconfigure(t *testing.T) {
	st := newFakeStore()
	n := newFakeNotifier()
	n.got = make(chan struct{}, 10000)
	s := NewSink(st, []Notifier{n}, time.Minute, nil)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.Emit(context.Background(), model.Alert{Kind: "x", Severity: model.SevCritical, DedupKey: "k"})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.Configure([]Notifier{n}, model.SevWarning, settings.Languages[j%len(settings.Languages)])
				s.SetDedup(time.Duration(j%2) * time.Minute)
				_ = s.SendTest(context.Background())
			}
		}()
	}
	wg.Wait()
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSendTest(t *testing.T) {
	ok := newNtfyServer(t, 0)
	var tgText string
	tgSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]any
		_ = json.NewDecoder(r.Body).Decode(&p)
		tgText, _ = p["text"].(string)
	}))
	defer tgSrv.Close()
	tg := NewTelegram("1:SECRET", "42").(*telegram)
	tg.baseURL = tgSrv.URL

	st := newFakeStore()
	s := NewSink(st, nil, 0, nil)
	defer s.Close(context.Background())
	s.Configure([]Notifier{NewNtfy(ok.URL, ""), tg}, model.SevCritical, "cs")

	if err := s.SendTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	bodies, titles := ok.snapshot()
	if len(titles) != 1 || titles[0] != "Guardian for RouterOS: testovací zpráva" ||
		bodies[0] != "Pokud tohle čteš, upozornění fungují." {
		t.Errorf("ntfy titles %q bodies %q", titles, bodies)
	}
	if !strings.Contains(tgText, "<b>Guardian for RouterOS: testovací zpráva</b>") {
		t.Errorf("telegram text %q", tgText)
	}
	if st.count() != 0 {
		t.Errorf("test message must not be stored as an alert")
	}

	s.Configure([]Notifier{NewNtfy(ok.URL, "")}, model.SevWarning, "es")
	if err := s.SendTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, titles := ok.snapshot(); titles[1] != "Guardian for RouterOS: notificación de prueba" {
		t.Errorf("es title %q", titles[1])
	}
}

func TestSendTestFailures(t *testing.T) {
	bad := newNtfyServer(t, http.StatusForbidden)
	good := newFakeNotifier()
	tgFail := newFakeNotifier()
	tgFail.name, tgFail.err = "telegram", errors.New("chat not found")

	s := NewSink(newFakeStore(), nil, 0, nil)
	defer s.Close(context.Background())

	if err := s.SendTest(context.Background()); !errors.Is(err, ErrNoNotifiers) {
		t.Fatalf("no notifiers: %v", err)
	}

	s.Configure([]Notifier{NewNtfy(bad.URL, ""), good}, model.SevWarning, "en")
	err := s.SendTest(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "ntfy: http 403") || strings.Contains(err.Error(), "fake") {
		t.Fatalf("one failure: %v", err)
	}
	if good.count() != 1 || good.sent[0].Kind != testAlertKind || good.langs[0] != "en" {
		t.Errorf("working notifier must still get the message: %+v", good.sent)
	}

	s.Configure([]Notifier{NewNtfy(bad.URL, ""), tgFail}, model.SevWarning, "en")
	err = s.SendTest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ntfy: ") || !strings.Contains(err.Error(), "telegram: chat not found") {
		t.Fatalf("two failures: %v", err)
	}
	if !errors.Is(err, tgFail.err) {
		t.Errorf("errors must be wrapped: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Configure([]Notifier{NewNtfy(bad.URL, "")}, model.SevWarning, "en")
	if err := s.SendTest(ctx); err == nil {
		t.Error("cancelled context must fail")
	}
}
