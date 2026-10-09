package detect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// fakeStore is an in-memory model.Store with error injection.
type fakeStore struct {
	mu      sync.Mutex
	devices map[string]model.Device
	hours   map[string]map[time.Time]*model.HourStat
	hourDst map[string]map[time.Time]map[netip.Addr]struct{}
	dests   map[string]map[string]*model.DestStat
	alerts  []model.Alert

	errDevices, errDest, errHours, errDedup error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		devices: map[string]model.Device{},
		hours:   map[string]map[time.Time]*model.HourStat{},
		hourDst: map[string]map[time.Time]map[netip.Addr]struct{}{},
		dests:   map[string]map[string]*model.DestStat{},
	}
}

func (s *fakeStore) UpsertDevice(_ context.Context, d model.Device) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.devices[d.MAC]
	if ok {
		d.FirstSeen = old.FirstSeen
		d.Note = old.Note
		d.Quarantined = old.Quarantined
	} else if d.FirstSeen.IsZero() {
		d.FirstSeen = d.LastSeen
	}
	s.devices[d.MAC] = d
	return !ok, nil
}

func (s *fakeStore) Device(_ context.Context, mac string) (model.Device, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errDevices != nil {
		return model.Device{}, false, s.errDevices
	}
	d, ok := s.devices[mac]
	return d, ok, nil
}

func (s *fakeStore) Devices(context.Context) ([]model.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errDevices != nil {
		return nil, s.errDevices
	}
	var out []model.Device
	for _, d := range s.devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}

func (s *fakeStore) SetQuarantined(context.Context, string, bool) error { return nil }
func (s *fakeStore) SetNote(context.Context, string, string) error      { return nil }

func (s *fakeStore) SetKindOverride(_ context.Context, mac, kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[mac]
	if !ok {
		return model.ErrNotFound
	}
	d.KindOverride = kind
	s.devices[mac] = d
	return nil
}

func (s *fakeStore) SetGroup(_ context.Context, macs []string, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, mac := range macs {
		if d, ok := s.devices[mac]; ok {
			d.GroupID = groupID
			s.devices[mac] = d
		}
	}
	return nil
}

func (s *fakeStore) Settings(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}
func (s *fakeStore) PutSettings(context.Context, map[string]string) error { return nil }

func (s *fakeStore) ResetLearned(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hours = map[string]map[time.Time]*model.HourStat{}
	s.hourDst = map[string]map[time.Time]map[netip.Addr]struct{}{}
	s.dests = map[string]map[string]*model.DestStat{}
	s.alerts = nil
	return nil
}

func (s *fakeStore) ResetAll(ctx context.Context) error {
	_ = s.ResetLearned(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices = map[string]model.Device{}
	return nil
}

func (s *fakeStore) RecordFlows(_ context.Context, flows []model.FlowSample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range flows {
		h := f.Time.UTC().Truncate(time.Hour)
		if s.hours[f.DeviceMAC] == nil {
			s.hours[f.DeviceMAC] = map[time.Time]*model.HourStat{}
			s.hourDst[f.DeviceMAC] = map[time.Time]map[netip.Addr]struct{}{}
		}
		hs := s.hours[f.DeviceMAC][h]
		if hs == nil {
			hs = &model.HourStat{MAC: f.DeviceMAC, Hour: h}
			s.hours[f.DeviceMAC][h] = hs
			s.hourDst[f.DeviceMAC][h] = map[netip.Addr]struct{}{}
		}
		hs.TxBytes += f.TxBytes
		hs.RxBytes += f.RxBytes
		if f.NewConn {
			hs.NewConns++
		}
		s.hourDst[f.DeviceMAC][h][f.Dst.Addr()] = struct{}{}
		hs.DistinctDst = len(s.hourDst[f.DeviceMAC][h])
		s.addDestLocked(f.DeviceMAC, f.Country, f.ASN, f.ASOrg, f.Time, f.TxBytes+f.RxBytes)
	}
	return nil
}

func (s *fakeStore) addDestLocked(mac, cc string, asn uint32, org string, t time.Time, b uint64) {
	if s.dests[mac] == nil {
		s.dests[mac] = map[string]*model.DestStat{}
	}
	k := fmt.Sprintf("%s/%d", cc, asn)
	d := s.dests[mac][k]
	if d == nil {
		d = &model.DestStat{MAC: mac, Country: cc, ASN: asn, ASOrg: org, FirstSeen: t}
		s.dests[mac][k] = d
	}
	d.LastSeen = t
	d.Bytes += b
}

func (s *fakeStore) HourStats(_ context.Context, mac string, from, to time.Time) ([]model.HourStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errHours != nil {
		return nil, s.errHours
	}
	var out []model.HourStat
	for h, v := range s.hours[mac] {
		if !h.Before(from) && h.Before(to) {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hour.Before(out[j].Hour) })
	return out, nil
}

func (s *fakeStore) DestStats(_ context.Context, mac string) ([]model.DestStat, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errDest != nil {
		return nil, s.errDest
	}
	var out []model.DestStat
	for _, d := range s.dests[mac] {
		out = append(out, *d)
	}
	return out, nil
}

func (s *fakeStore) InsertAlert(_ context.Context, a *model.Alert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.ID = int64(len(s.alerts) + 1)
	s.alerts = append(s.alerts, *a)
	return nil
}

func (s *fakeStore) Alerts(context.Context, model.AlertFilter) ([]model.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.Alert(nil), s.alerts...), nil
}
func (s *fakeStore) AckAlert(context.Context, int64) error { return nil }

func (s *fakeStore) LastAlertByDedupKey(_ context.Context, key string) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errDedup != nil {
		return time.Time{}, false, s.errDedup
	}
	var last time.Time
	found := false
	for _, a := range s.alerts {
		if a.DedupKey == key && (!found || a.Time.After(last)) {
			last, found = a.Time, true
		}
	}
	return last, found, nil
}

func (s *fakeStore) Prune(context.Context, time.Time) error { return nil }
func (s *fakeStore) Close() error                           { return nil }

// --- seeding helpers ---

func (s *fakeStore) addDevice(d model.Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[d.MAC] = d
}

// seedHours writes n hourly rows starting at from with values from fn(i).
func (s *fakeStore) seedHours(mac string, from time.Time, n int, fn func(i int, h time.Time) model.HourStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hours[mac] == nil {
		s.hours[mac] = map[time.Time]*model.HourStat{}
		s.hourDst[mac] = map[time.Time]map[netip.Addr]struct{}{}
	}
	for i := 0; i < n; i++ {
		h := from.UTC().Truncate(time.Hour).Add(time.Duration(i) * time.Hour)
		v := fn(i, h)
		v.MAC, v.Hour = mac, h
		s.hours[mac][h] = &v
	}
}

func (s *fakeStore) seedDest(mac string, at time.Time, dests ...model.DestStat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range dests {
		s.addDestLocked(mac, d.Country, d.ASN, d.ASOrg, at, 1000)
	}
}

// fakeSink records alerts and stores them (so LastAlertByDedupKey works).
type fakeSink struct {
	mu     sync.Mutex
	store  *fakeStore
	alerts []model.Alert
}

func (k *fakeSink) Emit(ctx context.Context, a model.Alert) {
	k.mu.Lock()
	k.alerts = append(k.alerts, a)
	k.mu.Unlock()
	if k.store != nil {
		_ = k.store.InsertAlert(ctx, &a)
	}
}

func (k *fakeSink) all() []model.Alert {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]model.Alert(nil), k.alerts...)
}

func (k *fakeSink) ofKind(kind string) []model.Alert {
	var out []model.Alert
	for _, a := range k.all() {
		if a.Kind == kind {
			out = append(out, a)
		}
	}
	return out
}

func (k *fakeSink) reset() {
	k.mu.Lock()
	k.alerts = nil
	k.mu.Unlock()
}

// --- common fixtures ---

var (
	t0      = time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC) // Monday
	errBoom = errors.New("boom")
	ctx     = context.Background()
)

func testConfig() Config {
	c := DefaultConfig()
	c.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return c
}

// testSettings mirrors testConfig (normal sensitivity, 7 days of learning).
func testSettings(lang string) settings.Settings {
	return settings.Settings{Language: lang, LearnPeriod: 7 * 24 * time.Hour, Sensitivity: "normal"}
}

// newTestEngine returns an engine with Czech alert texts (most tests assert
// the original Czech wording).
func newTestEngine(t *testing.T, st *fakeStore, start time.Time) (*Engine, *fakeSink) {
	t.Helper()
	sink := &fakeSink{store: st}
	e := New(st, sink, testConfig(), start)
	e.SetSettings(testSettings("cs"))
	return e, sink
}

// feed mimics main.ingest for flows: engine first, store second.
func feed(e *Engine, st *fakeStore, flows ...model.FlowSample) {
	e.Flows(ctx, flows)
	_ = st.RecordFlows(ctx, flows)
}

func flow(mac string, at time.Time, dst string, cc string, asn uint32, tx, rx uint64, newConn bool) model.FlowSample {
	return model.FlowSample{
		Time:      at,
		DeviceMAC: mac,
		Dst:       netip.MustParseAddrPort(dst),
		Proto:     "tcp",
		TxBytes:   tx,
		RxBytes:   rx,
		NewConn:   newConn,
		Country:   cc,
		ASN:       asn,
		ASOrg:     "Org" + cc,
	}
}

// matureDevice adds a device first seen at t0 with 10 days of flat history
// and the given known destinations.
func matureDevice(st *fakeStore, mac, kind string, randomized bool, dests ...model.DestStat) model.Device {
	d := model.Device{MAC: mac, Kind: kind, Vendor: "Vendor" + kind, Randomized: randomized,
		FirstSeen: t0, LastSeen: t0.Add(10 * 24 * time.Hour), IP: netip.MustParseAddr("192.168.88.10")}
	st.addDevice(d)
	st.seedHours(mac, t0, 10*24, func(int, time.Time) model.HourStat {
		return model.HourStat{TxBytes: 5 * mB, RxBytes: 20 * mB, NewConns: 20, DistinctDst: 8}
	})
	st.seedDest(mac, t0, dests...)
	return d
}
