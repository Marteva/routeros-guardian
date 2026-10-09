package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

var t0 = time.Date(2026, 10, 1, 10, 15, 0, 0, time.UTC)

func openTest(t *testing.T) *SQLite {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return t0 }
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenReopenAndPragmas(t *testing.T) {
	path := filepath.Join(t.TempDir(), "g.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode=%q err=%v", mode, err)
	}
	var av int
	if err := s.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&av); err != nil || av != 2 {
		t.Fatalf("auto_vacuum=%d err=%v", av, err)
	}
	s.Close()

	s, err = Open(path) // migrations must be idempotent
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var v int
	if err := s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil || v != len(migrations) {
		t.Fatalf("version=%d err=%v", v, err)
	}
}

func TestUpsertDevice(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	d := model.Device{
		MAC: "aa:bb:cc:dd:ee:ff", IP: netip.MustParseAddr("192.168.88.10"),
		Hostname: "tv", Vendor: "LG", Kind: "tv", ClassID: "udhcp",
		FirstSeen: t0, LastSeen: t0,
		Quarantined: true, Note: "ignored on update but used on insert",
	}
	isNew, err := s.UpsertDevice(ctx, d)
	if err != nil || !isNew {
		t.Fatalf("first upsert isNew=%v err=%v", isNew, err)
	}
	if err := s.SetNote(ctx, d.MAC, "Obývák TV"); err != nil {
		t.Fatal(err)
	}

	upd := model.Device{
		MAC: "AA:BB:CC:DD:EE:FF", IP: netip.MustParseAddr("192.168.88.11"),
		Kind: "unknown", Randomized: true,
		FirstSeen: t0.Add(time.Hour), LastSeen: t0.Add(time.Hour),
	}
	isNew, err = s.UpsertDevice(ctx, upd)
	if err != nil || isNew {
		t.Fatalf("second upsert isNew=%v err=%v", isNew, err)
	}
	got, ok, err := s.Device(ctx, "aa:bb:cc:dd:ee:ff")
	if err != nil || !ok {
		t.Fatalf("Device ok=%v err=%v", ok, err)
	}
	want := model.Device{
		MAC: "AA:BB:CC:DD:EE:FF", IP: netip.MustParseAddr("192.168.88.11"),
		Hostname: "tv", Vendor: "LG", Kind: "tv", ClassID: "udhcp", Randomized: true,
		FirstSeen: t0, LastSeen: t0.Add(time.Hour), Quarantined: true, Note: "Obývák TV",
	}
	if got != want {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}

	// LastSeen never goes backwards.
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: d.MAC, LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.Device(ctx, d.MAC)
	if !got.LastSeen.Equal(t0.Add(time.Hour)) || got.IP != want.IP {
		t.Fatalf("after stale upsert: %+v", got)
	}

	if _, err := s.UpsertDevice(ctx, model.Device{}); err == nil {
		t.Fatal("expected error for empty MAC")
	}
	if _, ok, _ := s.Device(ctx, "00:00:00:00:00:00"); ok {
		t.Fatal("unexpected device")
	}
}

func TestDevicesAndSetters(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	for i, mac := range []string{"00:00:00:00:00:01", "00:00:00:00:00:02"} {
		if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, LastSeen: t0.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetQuarantined(ctx, "00:00:00:00:00:01", true); err != nil {
		t.Fatal(err)
	}
	// Quarantine survives an upsert that says false.
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: "00:00:00:00:00:01", LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	ds, err := s.Devices(ctx)
	if err != nil || len(ds) != 2 {
		t.Fatalf("Devices=%v err=%v", ds, err)
	}
	if ds[0].MAC != "00:00:00:00:00:02" || !ds[1].Quarantined {
		t.Fatalf("order/quarantine wrong: %+v", ds)
	}
	if ds[0].FirstSeen.IsZero() || ds[0].IP.IsValid() {
		t.Fatalf("unexpected defaults: %+v", ds[0])
	}
	if err := s.SetQuarantined(ctx, "FF:FF:FF:FF:FF:FF", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.SetNote(ctx, "FF:FF:FF:FF:FF:FF", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func flow(mac, dst string, at time.Time, tx, rx uint64, newConn bool, country string, asn uint32, org string) model.FlowSample {
	return model.FlowSample{
		Time: at, DeviceMAC: mac, Dst: netip.MustParseAddrPort(dst), Proto: "tcp",
		TxBytes: tx, RxBytes: rx, NewConn: newConn, Country: country, ASN: asn, ASOrg: org,
	}
}

func TestRecordFlows(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	mac := "AA:AA:AA:AA:AA:AA"
	h0 := t0.Truncate(time.Hour)
	batch1 := []model.FlowSample{
		flow(mac, "1.1.1.1:443", t0, 100, 1000, true, "AU", 13335, "Cloudflare"),
		flow(mac, "1.1.1.1:443", t0.Add(time.Minute), 50, 500, false, "AU", 13335, ""),
		flow(mac, "8.8.8.8:53", t0, 10, 20, true, "US", 15169, "Google"),
		flow(mac, "9.9.9.9:53", t0.Add(time.Hour), 1, 2, true, "CH", 19281, "Quad9"),
		flow("", "9.9.9.9:53", t0, 1, 2, true, "", 0, ""), // ignored
	}
	if err := s.RecordFlows(ctx, batch1); err != nil {
		t.Fatal(err)
	}
	// Second poll: same destination again (not distinct), one new one, and a
	// lower-case MAC that must merge with the first.
	batch2 := []model.FlowSample{
		flow("aa:aa:aa:aa:aa:aa", "1.1.1.1:80", t0.Add(2*time.Minute), 5, 5, true, "AU", 13335, ""),
		flow(mac, "[2606:4700::1111]:443", t0.Add(3*time.Minute), 1, 1, true, "AU", 13335, ""),
	}
	if err := s.RecordFlows(ctx, batch2); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFlows(ctx, nil); err != nil {
		t.Fatal(err)
	}

	hs, err := s.HourStats(ctx, mac, h0, h0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := []model.HourStat{
		{MAC: mac, Hour: h0, TxBytes: 166, RxBytes: 1526, NewConns: 4, DistinctDst: 3},
		{MAC: mac, Hour: h0.Add(time.Hour), TxBytes: 1, RxBytes: 2, NewConns: 1, DistinctDst: 1},
	}
	if len(hs) != len(want) {
		t.Fatalf("HourStats=%+v", hs)
	}
	for i := range want {
		if hs[i] != want[i] {
			t.Errorf("hour[%d] got %+v want %+v", i, hs[i], want[i])
		}
	}
	// to is exclusive
	if hs, _ := s.HourStats(ctx, mac, h0, h0.Add(time.Hour)); len(hs) != 1 {
		t.Errorf("exclusive to: %+v", hs)
	}
	if hs, _ := s.HourStats(ctx, "", h0, h0.Add(time.Hour)); len(hs) != 1 {
		t.Errorf("all macs: %+v", hs)
	}

	ds, err := s.DestStats(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 3 {
		t.Fatalf("DestStats=%+v", ds)
	}
	cf := ds[0]
	wantCF := model.DestStat{MAC: mac, Country: "AU", ASN: 13335, ASOrg: "Cloudflare",
		FirstSeen: t0, LastSeen: t0.Add(3 * time.Minute), Bytes: 1650 + 10 + 2}
	if cf != wantCF {
		t.Fatalf("cloudflare got %+v want %+v", cf, wantCF)
	}
	if all, _ := s.DestStats(ctx, ""); len(all) != 3 {
		t.Fatalf("all dest stats: %+v", all)
	}
}

func TestAlerts(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	mk := func(mac, key string, at time.Time) *model.Alert {
		a := &model.Alert{
			Time: at, DeviceMAC: mac, Kind: model.AlertNewCountry, Severity: model.SevWarning,
			Title: "Nová země", Detail: "CN", Evidence: map[string]any{"bytes": 1234, "country": "CN"},
			DedupKey: key,
		}
		if err := s.InsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		if a.ID == 0 {
			t.Fatal("ID not set")
		}
		return a
	}
	a1 := mk("AA:00:00:00:00:01", "k1", t0)
	mk("AA:00:00:00:00:01", "k1", t0.Add(time.Hour))
	a3 := mk("AA:00:00:00:00:02", "k2", t0.Add(2*time.Hour))

	all, err := s.Alerts(ctx, model.AlertFilter{})
	if err != nil || len(all) != 3 {
		t.Fatalf("Alerts=%v err=%v", all, err)
	}
	if all[0].ID != a3.ID || all[2].ID != a1.ID {
		t.Fatalf("not newest first: %+v", all)
	}
	if all[0].Severity != model.SevWarning || all[0].Evidence["bytes"] != float64(1234) || all[0].Title != "Nová země" {
		t.Fatalf("roundtrip: %+v", all[0])
	}

	if err := s.AckAlert(ctx, a1.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.AckAlert(ctx, 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	cases := []struct {
		name string
		f    model.AlertFilter
		n    int
	}{
		{"open", model.AlertFilter{OnlyOpen: true}, 2},
		{"mac", model.AlertFilter{DeviceMAC: "aa:00:00:00:00:01"}, 2},
		{"since", model.AlertFilter{Since: t0.Add(time.Hour)}, 2},
		{"limit", model.AlertFilter{Limit: 1}, 1},
	}
	for _, c := range cases {
		got, err := s.Alerts(ctx, c.f)
		if err != nil || len(got) != c.n {
			t.Errorf("%s: got %d err=%v", c.name, len(got), err)
		}
	}

	last, ok, err := s.LastAlertByDedupKey(ctx, "k1")
	if err != nil || !ok || !last.Equal(t0.Add(time.Hour)) {
		t.Fatalf("LastAlertByDedupKey=%v ok=%v err=%v", last, ok, err)
	}
	if _, ok, err := s.LastAlertByDedupKey(ctx, "nope"); ok || err != nil {
		t.Fatalf("missing key ok=%v err=%v", ok, err)
	}

	// Default time and nil evidence.
	a := &model.Alert{Kind: model.AlertNewDevice}
	if err := s.InsertAlert(ctx, a); err != nil || !a.Time.Equal(t0) {
		t.Fatalf("default time %v err=%v", a.Time, err)
	}
}

func TestDefaultAlertLimit(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	for i := 0; i < defaultAlertLimit+5; i++ {
		if err := s.InsertAlert(ctx, &model.Alert{Time: t0, Kind: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Alerts(ctx, model.AlertFilter{})
	if err != nil || len(got) != defaultAlertLimit {
		t.Fatalf("got %d err=%v", len(got), err)
	}
}

func TestPrune(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	mac := "AA:AA:AA:AA:AA:AA"
	old := t0.Add(-72 * time.Hour)
	if err := s.RecordFlows(ctx, []model.FlowSample{
		flow(mac, "1.1.1.1:443", old, 1, 1, true, "AU", 13335, ""),
		flow(mac, "1.1.1.1:443", t0.Add(-30*time.Hour), 1, 1, true, "AU", 13335, ""),
		flow(mac, "1.1.1.1:443", t0, 1, 1, true, "AU", 13335, ""),
	}); err != nil {
		t.Fatal(err)
	}
	oldAcked := &model.Alert{Time: old, Kind: "x", Acked: true}
	oldOpen := &model.Alert{Time: old, Kind: "x"}
	newAcked := &model.Alert{Time: t0, Kind: "x", Acked: true}
	for _, a := range []*model.Alert{oldAcked, oldOpen, newAcked} {
		if err := s.InsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}

	if err := s.Prune(ctx, t0.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	hs, _ := s.HourStats(ctx, mac, time.Time{}, t0.Add(time.Hour))
	if len(hs) != 2 {
		t.Fatalf("hour_stats after prune: %+v", hs)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM hour_dst`).Scan(&n)
	if n != 2 {
		t.Fatalf("hour_dst rows=%d, want 2", n)
	}
	al, _ := s.Alerts(ctx, model.AlertFilter{})
	if len(al) != 2 {
		t.Fatalf("alerts after prune: %+v", al)
	}
	for _, a := range al {
		if a.ID == oldAcked.ID {
			t.Fatal("old acked alert not pruned")
		}
	}
	if ds, _ := s.DestStats(ctx, mac); len(ds) != 1 {
		t.Fatalf("dest_stats must be kept: %+v", ds)
	}

	// Long retention still drops hour_dst older than 48 h.
	if err := s.Prune(ctx, t0.Add(-365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM hour_dst`).Scan(&n)
	if n != 2 {
		t.Fatalf("hour_dst rows=%d", n)
	}
	s.now = func() time.Time { return t0.Add(40 * time.Hour) }
	if err := s.Prune(ctx, t0.Add(-365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM hour_dst`).Scan(&n)
	if n != 1 {
		t.Fatalf("hour_dst rows=%d, want 1", n)
	}
}

func TestConcurrentUse(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	var wg sync.WaitGroup
	errc := make(chan error, 64)
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				fs := []model.FlowSample{flow("AA:AA:AA:AA:AA:AA", "1.1.1.1:443", t0, 1, 1, true, "AU", 1, "")}
				if err := s.RecordFlows(ctx, fs); err != nil {
					errc <- err
					return
				}
				if _, err := s.UpsertDevice(ctx, model.Device{MAC: "AA:AA:AA:AA:AA:AA", LastSeen: t0}); err != nil {
					errc <- err
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if _, err := s.Devices(ctx); err != nil {
					errc <- err
					return
				}
				if _, err := s.HourStats(ctx, "", time.Time{}, t0.Add(time.Hour)); err != nil {
					errc <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
	hs, _ := s.HourStats(ctx, "AA:AA:AA:AA:AA:AA", time.Time{}, t0.Add(time.Hour))
	if len(hs) != 1 || hs[0].NewConns != 100 || hs[0].DistinctDst != 1 {
		t.Fatalf("aggregate after concurrent writes: %+v", hs)
	}
}

func TestUpsertDeviceComment(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	mac := "AA:BB:CC:DD:EE:01"
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, LastSeen: t0, Comment: "Tiskárna"}); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := s.Device(ctx, mac); d.Comment != "Tiskárna" {
		t.Fatalf("insert comment = %q", d.Comment)
	}
	// Empty incoming comment never blanks the stored one.
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := s.Device(ctx, mac); d.Comment != "Tiskárna" {
		t.Fatalf("after empty upsert comment = %q", d.Comment)
	}
	// Non-empty incoming comment replaces it.
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, LastSeen: t0, Comment: "Tiskárna HP"}); err != nil {
		t.Fatal(err)
	}
	ds, err := s.Devices(ctx)
	if err != nil || len(ds) != 1 || ds[0].Comment != "Tiskárna HP" {
		t.Fatalf("Devices = %+v err=%v", ds, err)
	}
}

// createOldDB builds a database exactly as a binary with schema `version`
// left it (the first `version` migrations), then runs seed statements.
func createOldDB(t *testing.T, path string, version int, seed ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stmts := append([]string{}, migrations[:version]...)
	stmts = append(stmts,
		`CREATE TABLE schema_version (version INTEGER NOT NULL)`,
		fmt.Sprintf(`INSERT INTO schema_version (version) VALUES (%d)`, version))
	for _, q := range append(stmts, seed...) {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func schemaVersion(t *testing.T, s *SQLite) int {
	t.Helper()
	var v int
	if err := s.db.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMigrateFromV1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	createOldDB(t, path, 1,
		`INSERT INTO devices (mac, hostname, first_seen, last_seen) VALUES ('AA:00:00:00:00:01', 'old', 1, 2)`)

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v := schemaVersion(t, s); v != len(migrations) {
		t.Fatalf("version = %d", v)
	}
	d, ok, err := s.Device(context.Background(), "AA:00:00:00:00:01")
	if err != nil || !ok || d.Hostname != "old" || d.Comment != "" || d.KindOverride != "" || d.GroupID != "" {
		t.Fatalf("migrated device = %+v ok=%v err=%v", d, ok, err)
	}
}

func TestMigrateFromV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.db")
	createOldDB(t, path, 2,
		`INSERT INTO devices (mac, hostname, kind, first_seen, last_seen, quarantined, note, comment)
			VALUES ('AA:00:00:00:00:02', 'cam', 'camera', 10, 20, 1, 'Garáž', 'Kamera')`,
		`INSERT INTO hour_stats (mac, hour, tx, rx) VALUES ('AA:00:00:00:00:02', 3600, 5, 6)`)

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if v := schemaVersion(t, s); v != len(migrations) {
		t.Fatalf("version = %d, want %d", v, len(migrations))
	}
	d, ok, err := s.Device(ctx, "AA:00:00:00:00:02")
	want := model.Device{MAC: "AA:00:00:00:00:02", Hostname: "cam", Kind: "camera",
		FirstSeen: fromUnix(10), LastSeen: fromUnix(20), Quarantined: true, Note: "Garáž", Comment: "Kamera"}
	if err != nil || !ok || d != want {
		t.Fatalf("migrated device = %+v ok=%v err=%v", d, ok, err)
	}
	if hs, _ := s.HourStats(ctx, "", time.Time{}, t0); len(hs) != 1 || hs[0].TxBytes != 5 {
		t.Fatalf("hour stats lost: %+v", hs)
	}
	var idx int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'devices_group'`).Scan(&idx); err != nil || idx != 1 {
		t.Fatalf("devices_group index: %d err=%v", idx, err)
	}
	// New columns and the settings table are usable.
	if err := s.SetKindOverride(ctx, d.MAC, "tv"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroup(ctx, []string{d.MAC}, d.MAC); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSettings(ctx, map[string]string{"language": "cs"}); err != nil {
		t.Fatal(err)
	}
	if kv, err := s.Settings(ctx); err != nil || kv["language"] != "cs" {
		t.Fatalf("settings = %v err=%v", kv, err)
	}
	s.Close()

	// Reopening a v3 database applies nothing and keeps the data.
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d, _, _ = s.Device(ctx, "AA:00:00:00:00:02")
	if d.KindOverride != "tv" || d.GroupID != "AA:00:00:00:00:02" || d.EffectiveKind() != "tv" {
		t.Fatalf("after reopen: %+v", d)
	}
}

func TestMigrateRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.db")
	createOldDB(t, path, len(migrations), `UPDATE schema_version SET version = 99`)
	if s, err := Open(path); err == nil {
		s.Close()
		t.Fatal("expected error for a newer schema")
	}
}

func TestKindOverride(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	mac := "AA:BB:CC:00:00:01"
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, Kind: "phone", LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetKindOverride(ctx, strings.ToLower(mac), "tv"); err != nil {
		t.Fatal(err)
	}
	// An upsert with a new guess (and an empty override) keeps the user's choice.
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, Kind: "computer", LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	d, _, _ := s.Device(ctx, mac)
	if d.Kind != "computer" || d.KindOverride != "tv" || d.EffectiveKind() != "tv" {
		t.Fatalf("after upsert: %+v", d)
	}
	if err := s.SetKindOverride(ctx, mac, "toaster"); !errors.Is(err, ErrInvalidKind) {
		t.Fatalf("invalid kind: %v", err)
	}
	if d, _, _ := s.Device(ctx, mac); d.KindOverride != "tv" {
		t.Fatalf("invalid kind changed the row: %+v", d)
	}
	if err := s.SetKindOverride(ctx, "FF:FF:FF:FF:FF:FF", "tv"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown mac: %v", err)
	}
	if err := s.SetKindOverride(ctx, mac, ""); err != nil {
		t.Fatal(err)
	}
	ds, err := s.Devices(ctx)
	if err != nil || len(ds) != 1 || ds[0].KindOverride != "" || ds[0].EffectiveKind() != "computer" {
		t.Fatalf("after clear: %+v err=%v", ds, err)
	}

	// Insert takes the user fields from the device (invalid override dropped).
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: "AA:BB:CC:00:00:02", KindOverride: "nas",
		GroupID: "aa:bb:cc:00:00:01", LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := s.Device(ctx, "AA:BB:CC:00:00:02"); d.KindOverride != "nas" || d.GroupID != "AA:BB:CC:00:00:01" {
		t.Fatalf("insert user fields: %+v", d)
	}
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: "AA:BB:CC:00:00:03", KindOverride: "bogus", LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := s.Device(ctx, "AA:BB:CC:00:00:03"); d.KindOverride != "" {
		t.Fatalf("invalid override stored on insert: %+v", d)
	}
}

func TestSetGroup(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	a, b, c := "AA:00:00:00:00:0A", "AA:00:00:00:00:0B", "AA:00:00:00:00:0C"
	for _, mac := range []string{a, b, c} {
		if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, LastSeen: t0}); err != nil {
			t.Fatal(err)
		}
	}
	groups := func() map[string]string {
		t.Helper()
		ds, err := s.Devices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, d := range ds {
			m[d.MAC] = d.GroupID
		}
		return m
	}

	// Lower-case input, duplicates allowed.
	if err := s.SetGroup(ctx, []string{strings.ToLower(a), b, b}, strings.ToLower(a)); err != nil {
		t.Fatal(err)
	}
	if g := groups(); g[a] != a || g[b] != a || g[c] != "" {
		t.Fatalf("after merge: %v", g)
	}
	// Upsert never touches the group.
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: b, Hostname: "x", LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	// One unknown MAC: ErrNotFound and nothing changes (c is listed first).
	if err := s.SetGroup(ctx, []string{c, b, "FF:FF:FF:FF:FF:FF"}, c); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if g := groups(); g[a] != a || g[b] != a || g[c] != "" {
		t.Fatalf("partial update leaked: %v", g)
	}
	// "" removes only the listed devices from their group.
	if err := s.SetGroup(ctx, []string{b}, ""); err != nil {
		t.Fatal(err)
	}
	if g := groups(); g[a] != a || g[b] != "" {
		t.Fatalf("after unmerge: %v", g)
	}
	if err := s.SetGroup(ctx, nil, "X"); err != nil {
		t.Fatalf("empty list: %v", err)
	}
}

func TestSettingsKV(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	kv, err := s.Settings(ctx)
	if err != nil || kv == nil || len(kv) != 0 {
		t.Fatalf("empty settings = %v err=%v", kv, err)
	}
	if err := s.PutSettings(ctx, map[string]string{"a": "1", "b": "2", "c": ""}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSettings(ctx, map[string]string{"a": "", "b": "3", "d": "Žluťoučký"}); err != nil {
		t.Fatal(err)
	}
	kv, err = s.Settings(ctx)
	if err != nil || len(kv) != 2 || kv["b"] != "3" || kv["d"] != "Žluťoučký" {
		t.Fatalf("settings = %v err=%v", kv, err)
	}
	// An invalid key aborts the whole batch.
	if err := s.PutSettings(ctx, map[string]string{"e": "5", "": "x"}); err == nil {
		t.Fatal("expected error for empty key")
	}
	if kv, _ := s.Settings(ctx); len(kv) != 2 || kv["e"] != "" {
		t.Fatalf("partial settings write: %v", kv)
	}
	if err := s.PutSettings(ctx, nil); err != nil {
		t.Fatal(err)
	}
}

func seedForReset(t *testing.T, s *SQLite) {
	t.Helper()
	ctx := context.Background()
	mac := "AA:AA:AA:AA:AA:01"
	if _, err := s.UpsertDevice(ctx, model.Device{MAC: mac, LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	for _, err := range []error{
		s.SetNote(ctx, mac, "Router"),
		s.SetKindOverride(ctx, mac, "network"),
		s.SetGroup(ctx, []string{mac}, mac),
		s.PutSettings(ctx, map[string]string{"language": "de"}),
		s.RecordFlows(ctx, []model.FlowSample{flow(mac, "1.1.1.1:443", t0, 10, 10, true, "AU", 13335, "CF")}),
		s.InsertAlert(ctx, &model.Alert{Time: t0, DeviceMAC: mac, Kind: "x"}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func tableCount(t *testing.T, s *SQLite, table string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestResetLearned(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	seedForReset(t, s)
	for _, tb := range learnedTables {
		if tableCount(t, s, tb) == 0 {
			t.Fatalf("seed: %s empty", tb)
		}
	}
	if err := s.ResetLearned(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tb := range learnedTables {
		if n := tableCount(t, s, tb); n != 0 {
			t.Errorf("%s has %d rows after ResetLearned", tb, n)
		}
	}
	d, ok, err := s.Device(ctx, "AA:AA:AA:AA:AA:01")
	if err != nil || !ok || d.Note != "Router" || d.KindOverride != "network" || d.GroupID != d.MAC {
		t.Fatalf("device after ResetLearned: %+v ok=%v err=%v", d, ok, err)
	}
	if kv, _ := s.Settings(ctx); kv["language"] != "de" {
		t.Fatalf("settings lost: %v", kv)
	}
	// The store keeps working after the wipe.
	seedForReset(t, s)
}

func TestResetAll(t *testing.T) {
	s, ctx := openTest(t), context.Background()
	seedForReset(t, s)
	if err := s.ResetAll(ctx); err != nil {
		t.Fatal(err)
	}
	for _, tb := range append([]string{"devices"}, learnedTables...) {
		if n := tableCount(t, s, tb); n != 0 {
			t.Errorf("%s has %d rows after ResetAll", tb, n)
		}
	}
	if kv, _ := s.Settings(ctx); kv["language"] != "de" {
		t.Fatalf("settings lost: %v", kv)
	}
	var free int
	if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&free); err != nil || free != 0 {
		t.Fatalf("freelist after vacuum = %d err=%v", free, err)
	}
}
