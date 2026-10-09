// Package store is the SQLite persistence layer (pure Go, modernc.org/sqlite).
//
// The database lives on a USB flash disk, so writes are kept few and batched:
// every RecordFlows call is pre-aggregated in memory and written in a single
// transaction using UPSERTs. Raw flow samples are never stored.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/Marteva/routeros-guardian/internal/model"
)

// ErrNotFound is returned by setters (SetQuarantined, SetNote, SetKindOverride,
// SetGroup, AckAlert) when the target row does not exist.
var ErrNotFound = model.ErrNotFound

// ErrInvalidKind is returned by SetKindOverride for a kind outside model.Kinds.
var ErrInvalidKind = errors.New("store: invalid device kind")

const (
	defaultAlertLimit = 100
	// hourDstKeep is how long per-hour destination sets are kept. They are only
	// needed to compute distinct_dst of hours that are still being written.
	hourDstKeep = 48 * time.Hour
)

// SQLite implements model.Store.
type SQLite struct {
	db  *sql.DB
	now func() time.Time // injectable clock (tests)
}

var _ model.Store = (*SQLite)(nil)

// Open opens (creating if needed) the database at path and applies migrations.
//
// A single connection is used: SQLite allows one writer anyway, and with one
// connection there is no SQLITE_BUSY/lock-upgrade contention between the poll
// loop and web handlers — callers simply queue on database/sql's pool. All
// operations are short, so this is fine for Guardian's load.
func Open(path string) (*SQLite, error) {
	// auto_vacuum only takes effect on a fresh database (sorted before
	// journal_mode by the driver, so it applies before page 1 is written).
	dsn := path + "?_pragma=busy_timeout(5000)" +
		"&_pragma=auto_vacuum(INCREMENTAL)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &SQLite{db: db, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

// ---------------------------------------------------------------------------
// helpers

func toUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func hourOf(t time.Time) int64 { return t.UTC().Truncate(time.Hour).Unix() }

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func parseAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s) // invalid/empty → zero Addr
	return a
}

func normMAC(mac string) string { return strings.ToUpper(strings.TrimSpace(mac)) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// devices

const deviceCols = `mac, ip, hostname, vendor, kind, class_id, randomized,
	first_seen, last_seen, quarantined, note, comment, kind_override, group_id`

// UpsertDevice inserts or updates by MAC. On update FirstSeen and the user
// edits (Quarantined, Note, KindOverride, GroupID) are kept; empty
// Hostname/Vendor/ClassID/Comment, empty or "unknown" Kind and an invalid IP
// never blank stored values; LastSeen only moves forward. On insert the user
// fields are taken from d (an invalid KindOverride is dropped).
func (s *SQLite) UpsertDevice(ctx context.Context, d model.Device) (bool, error) {
	mac := normMAC(d.MAC)
	if mac == "" {
		return false, errors.New("store: device without MAC")
	}
	last := d.LastSeen
	if last.IsZero() {
		last = s.now()
	}
	first := d.FirstSeen
	if first.IsZero() || first.After(last) {
		first = last
	}
	kind := d.Kind
	if kind == "unknown" {
		kind = "" // treated as "no information" on update
	}
	override := d.KindOverride
	if override != "" && !model.ValidKind(override) {
		override = ""
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `INSERT INTO devices (`+deviceCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(mac) DO NOTHING`,
		mac, addrText(d.IP), d.Hostname, d.Vendor, d.Kind, d.ClassID, b2i(d.Randomized),
		toUnix(first), toUnix(last), b2i(d.Quarantined), d.Note, d.Comment,
		override, normMAC(d.GroupID))
	if err != nil {
		return false, fmt.Errorf("store: insert device: %w", err)
	}
	n, _ := res.RowsAffected()
	isNew := n == 1
	if !isNew {
		_, err = tx.ExecContext(ctx, `UPDATE devices SET
			ip       = CASE WHEN ?1 = '' THEN ip ELSE ?1 END,
			hostname = CASE WHEN ?2 = '' THEN hostname ELSE ?2 END,
			vendor   = CASE WHEN ?3 = '' THEN vendor ELSE ?3 END,
			kind     = CASE WHEN ?4 = '' THEN kind ELSE ?4 END,
			class_id = CASE WHEN ?5 = '' THEN class_id ELSE ?5 END,
			randomized = ?6,
			last_seen  = MAX(last_seen, ?7),
			comment  = CASE WHEN ?9 = '' THEN comment ELSE ?9 END
			WHERE mac = ?8`,
			addrText(d.IP), d.Hostname, d.Vendor, kind, d.ClassID, b2i(d.Randomized),
			toUnix(last), mac, d.Comment)
		if err != nil {
			return false, fmt.Errorf("store: update device: %w", err)
		}
	}
	return isNew, tx.Commit()
}

type scanner interface{ Scan(dest ...any) error }

func scanDevice(r scanner) (model.Device, error) {
	var d model.Device
	var ip string
	var rnd, q int
	var first, last int64
	err := r.Scan(&d.MAC, &ip, &d.Hostname, &d.Vendor, &d.Kind, &d.ClassID, &rnd,
		&first, &last, &q, &d.Note, &d.Comment, &d.KindOverride, &d.GroupID)
	d.IP = parseAddr(ip)
	d.Randomized = rnd != 0
	d.Quarantined = q != 0
	d.FirstSeen = fromUnix(first)
	d.LastSeen = fromUnix(last)
	return d, err
}

// Device returns one device by MAC.
func (s *SQLite) Device(ctx context.Context, mac string) (model.Device, bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE mac = ?`, normMAC(mac))
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, false, nil
	}
	if err != nil {
		return model.Device{}, false, err
	}
	return d, true, nil
}

// Devices returns all devices, most recently seen first.
func (s *SQLite) Devices(ctx context.Context) ([]model.Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices ORDER BY last_seen DESC, mac`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLite) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetQuarantined sets the quarantine flag. Unknown MAC → ErrNotFound.
func (s *SQLite) SetQuarantined(ctx context.Context, mac string, q bool) error {
	return s.execOne(ctx, `UPDATE devices SET quarantined = ? WHERE mac = ?`, b2i(q), normMAC(mac))
}

// SetNote sets the user note. Unknown MAC → ErrNotFound.
func (s *SQLite) SetNote(ctx context.Context, mac, note string) error {
	return s.execOne(ctx, `UPDATE devices SET note = ? WHERE mac = ?`, note, normMAC(mac))
}

// SetKindOverride sets the user-chosen kind ("" = back to the automatic
// guess). A kind outside model.Kinds → ErrInvalidKind; unknown MAC → ErrNotFound.
func (s *SQLite) SetKindOverride(ctx context.Context, mac, kind string) error {
	if kind != "" && !model.ValidKind(kind) {
		return fmt.Errorf("%w: %q", ErrInvalidKind, kind)
	}
	return s.execOne(ctx, `UPDATE devices SET kind_override = ? WHERE mac = ?`, kind, normMAC(mac))
}

// SetGroup assigns groupID to all macs in one transaction ("" removes them
// from any group). MACs and groupID are normalised to upper case. If any MAC
// is unknown, ErrNotFound is returned and nothing changes.
func (s *SQLite) SetGroup(ctx context.Context, macs []string, groupID string) error {
	if len(macs) == 0 {
		return nil
	}
	gid := normMAC(groupID)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `UPDATE devices SET group_id = ? WHERE mac = ?`)
	if err != nil {
		return err
	}
	defer st.Close()
	seen := make(map[string]bool, len(macs))
	for _, m := range macs {
		mac := normMAC(m)
		if seen[mac] {
			continue
		}
		seen[mac] = true
		res, err := st.ExecContext(ctx, gid, mac)
		if err != nil {
			return fmt.Errorf("store: set group: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%w: device %q", ErrNotFound, mac)
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------------
// settings

// Settings returns all stored runtime settings (never nil).
func (s *SQLite) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, fmt.Errorf("store: settings: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// PutSettings upserts the given keys in one transaction; an empty value
// deletes the key. An empty key is rejected (and nothing changes).
func (s *SQLite) PutSettings(ctx context.Context, kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for k, v := range kv {
		if k == "" {
			return errors.New("store: settings: empty key")
		}
		if v == "" {
			_, err = tx.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, k)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?)
				ON CONFLICT(key) DO UPDATE SET value = excluded.value`, k, v)
		}
		if err != nil {
			return fmt.Errorf("store: settings %q: %w", k, err)
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------------------
// flows / aggregates

type hourKey struct {
	mac  string
	hour int64
}

type hourAgg struct {
	tx, rx   uint64
	newConns int
	dsts     map[string]struct{}
}

type destKey struct {
	mac     string
	country string
	asn     uint32
}

type destAgg struct {
	asOrg       string
	first, last int64
	bytes       uint64
}

// RecordFlows folds the samples into hour_stats, hour_dst and dest_stats in a
// single transaction. Samples without DeviceMAC are ignored.
func (s *SQLite) RecordFlows(ctx context.Context, flows []model.FlowSample) error {
	if len(flows) == 0 {
		return nil
	}
	hours := map[hourKey]*hourAgg{}
	dests := map[destKey]*destAgg{}
	nowT := s.now()
	for _, f := range flows {
		mac := normMAC(f.DeviceMAC)
		if mac == "" {
			continue
		}
		t := f.Time
		if t.IsZero() {
			t = nowT
		}
		hk := hourKey{mac, hourOf(t)}
		h := hours[hk]
		if h == nil {
			h = &hourAgg{dsts: map[string]struct{}{}}
			hours[hk] = h
		}
		h.tx += f.TxBytes
		h.rx += f.RxBytes
		if f.NewConn {
			h.newConns++
		}
		if a := f.Dst.Addr(); a.IsValid() {
			h.dsts[a.Unmap().String()] = struct{}{}
		}

		dk := destKey{mac, f.Country, f.ASN}
		ts := t.Unix()
		d := dests[dk]
		if d == nil {
			d = &destAgg{first: ts, last: ts}
			dests[dk] = d
		}
		if f.ASOrg != "" {
			d.asOrg = f.ASOrg
		}
		d.first = min(d.first, ts)
		d.last = max(d.last, ts)
		d.bytes += f.TxBytes + f.RxBytes
	}
	if len(hours) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insDst, err := tx.PrepareContext(ctx,
		`INSERT INTO hour_dst (mac, hour, dst_ip) VALUES (?,?,?) ON CONFLICT DO NOTHING`)
	if err != nil {
		return err
	}
	defer insDst.Close()
	upHour, err := tx.PrepareContext(ctx, `INSERT INTO hour_stats
		(mac, hour, tx, rx, new_conns, distinct_dst) VALUES (?,?,?,?,?,?)
		ON CONFLICT(mac, hour) DO UPDATE SET
			tx = tx + excluded.tx,
			rx = rx + excluded.rx,
			new_conns = new_conns + excluded.new_conns,
			distinct_dst = distinct_dst + excluded.distinct_dst`)
	if err != nil {
		return err
	}
	defer upHour.Close()
	upDest, err := tx.PrepareContext(ctx, `INSERT INTO dest_stats
		(mac, country, asn, as_org, first_seen, last_seen, bytes) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(mac, country, asn) DO UPDATE SET
			as_org = CASE WHEN excluded.as_org = '' THEN as_org ELSE excluded.as_org END,
			first_seen = MIN(first_seen, excluded.first_seen),
			last_seen = MAX(last_seen, excluded.last_seen),
			bytes = bytes + excluded.bytes`)
	if err != nil {
		return err
	}
	defer upDest.Close()

	for k, h := range hours {
		added := 0
		for ip := range h.dsts {
			res, err := insDst.ExecContext(ctx, k.mac, k.hour, ip)
			if err != nil {
				return fmt.Errorf("store: hour_dst: %w", err)
			}
			if n, _ := res.RowsAffected(); n > 0 {
				added++
			}
		}
		if _, err := upHour.ExecContext(ctx, k.mac, k.hour, int64(h.tx), int64(h.rx), h.newConns, added); err != nil {
			return fmt.Errorf("store: hour_stats: %w", err)
		}
	}
	for k, d := range dests {
		if _, err := upDest.ExecContext(ctx, k.mac, k.country, int64(k.asn), d.asOrg, d.first, d.last, int64(d.bytes)); err != nil {
			return fmt.Errorf("store: dest_stats: %w", err)
		}
	}
	return tx.Commit()
}

// HourStats returns hourly aggregates with from <= Hour < to, oldest first.
// mac "" returns all devices.
func (s *SQLite) HourStats(ctx context.Context, mac string, from, to time.Time) ([]model.HourStat, error) {
	q := `SELECT mac, hour, tx, rx, new_conns, distinct_dst FROM hour_stats
		WHERE hour >= ? AND hour < ?`
	args := []any{from.Unix(), to.Unix()}
	if mac != "" {
		q += ` AND mac = ?`
		args = append(args, normMAC(mac))
	}
	q += ` ORDER BY hour, mac`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.HourStat
	for rows.Next() {
		var h model.HourStat
		var hour, tx, rx int64
		if err := rows.Scan(&h.MAC, &hour, &tx, &rx, &h.NewConns, &h.DistinctDst); err != nil {
			return nil, err
		}
		h.Hour, h.TxBytes, h.RxBytes = fromUnix(hour), uint64(tx), uint64(rx)
		out = append(out, h)
	}
	return out, rows.Err()
}

// DestStats returns destination aggregates (key country+ASN), biggest first.
// mac "" returns all devices.
func (s *SQLite) DestStats(ctx context.Context, mac string) ([]model.DestStat, error) {
	q := `SELECT mac, country, asn, as_org, first_seen, last_seen, bytes FROM dest_stats`
	var args []any
	if mac != "" {
		q += ` WHERE mac = ?`
		args = append(args, normMAC(mac))
	}
	q += ` ORDER BY bytes DESC, mac, country, asn`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DestStat
	for rows.Next() {
		var d model.DestStat
		var asn, first, last, bytes int64
		if err := rows.Scan(&d.MAC, &d.Country, &asn, &d.ASOrg, &first, &last, &bytes); err != nil {
			return nil, err
		}
		d.ASN, d.FirstSeen, d.LastSeen, d.Bytes = uint32(asn), fromUnix(first), fromUnix(last), uint64(bytes)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// alerts

// InsertAlert stores the alert and sets a.ID. Zero Time defaults to now.
func (s *SQLite) InsertAlert(ctx context.Context, a *model.Alert) error {
	if a.Time.IsZero() {
		a.Time = s.now().UTC().Truncate(time.Second)
	}
	ev := []byte("null")
	if a.Evidence != nil {
		var err error
		if ev, err = json.Marshal(a.Evidence); err != nil {
			return fmt.Errorf("store: evidence: %w", err)
		}
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO alerts
		(time, mac, kind, severity, title, detail, evidence_json, dedup_key, acked)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		a.Time.Unix(), normMAC(a.DeviceMAC), a.Kind, int(a.Severity), a.Title, a.Detail,
		string(ev), a.DedupKey, b2i(a.Acked))
	if err != nil {
		return fmt.Errorf("store: insert alert: %w", err)
	}
	a.ID, err = res.LastInsertId()
	return err
}

// Alerts lists alerts newest first (default limit 100).
func (s *SQLite) Alerts(ctx context.Context, f model.AlertFilter) ([]model.Alert, error) {
	q := `SELECT id, time, mac, kind, severity, title, detail, evidence_json, dedup_key, acked
		FROM alerts WHERE 1=1`
	var args []any
	if f.DeviceMAC != "" {
		q += ` AND mac = ?`
		args = append(args, normMAC(f.DeviceMAC))
	}
	if !f.Since.IsZero() {
		q += ` AND time >= ?`
		args = append(args, f.Since.Unix())
	}
	if f.OnlyOpen {
		q += ` AND acked = 0`
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultAlertLimit
	}
	q += ` ORDER BY time DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Alert
	for rows.Next() {
		var a model.Alert
		var t int64
		var sev, acked int
		var ev string
		if err := rows.Scan(&a.ID, &t, &a.DeviceMAC, &a.Kind, &sev, &a.Title, &a.Detail, &ev, &a.DedupKey, &acked); err != nil {
			return nil, err
		}
		a.Time, a.Severity, a.Acked = fromUnix(t), model.Severity(sev), acked != 0
		if ev != "" && ev != "null" {
			_ = json.Unmarshal([]byte(ev), &a.Evidence) // best effort; numbers become float64
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AckAlert marks an alert acknowledged. Unknown id → ErrNotFound.
func (s *SQLite) AckAlert(ctx context.Context, id int64) error {
	return s.execOne(ctx, `UPDATE alerts SET acked = 1 WHERE id = ?`, id)
}

// LastAlertByDedupKey returns the time of the newest alert with this key.
func (s *SQLite) LastAlertByDedupKey(ctx context.Context, key string) (time.Time, bool, error) {
	var t sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(time) FROM alerts WHERE dedup_key = ?`, key).Scan(&t)
	if err != nil || !t.Valid {
		return time.Time{}, false, err
	}
	return time.Unix(t.Int64, 0).UTC(), true, nil
}

// ---------------------------------------------------------------------------
// maintenance

// Prune deletes hour_stats and acknowledged alerts older than olderThan, and
// hour_dst rows older than 48 h (or olderThan, whichever is later). Devices and
// dest_stats (the novelty baseline) are kept. Freed pages are returned to the
// filesystem with a bounded incremental vacuum.
func (s *SQLite) Prune(ctx context.Context, olderThan time.Time) error {
	cut := olderThan.Unix()
	dstCut := hourOf(s.now().Add(-hourDstKeep))
	if cut > dstCut {
		dstCut = cut
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, st := range []struct {
		q   string
		arg int64
	}{
		{`DELETE FROM hour_stats WHERE hour < ?`, cut},
		{`DELETE FROM hour_dst WHERE hour < ?`, dstCut},
		{`DELETE FROM alerts WHERE acked = 1 AND time < ?`, cut},
	} {
		if _, err := tx.ExecContext(ctx, st.q, st.arg); err != nil {
			return fmt.Errorf("store: prune: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// No-op unless the DB was created with auto_vacuum=INCREMENTAL.
	_, err = s.db.ExecContext(ctx, `PRAGMA incremental_vacuum(2000)`)
	return err
}

// learnedTables are wiped by ResetLearned (everything derived from traffic).
var learnedTables = []string{"hour_stats", "hour_dst", "dest_stats", "alerts"}

// ResetLearned deletes all traffic aggregates and alerts in one transaction.
// Devices (with their user edits) and settings stay.
func (s *SQLite) ResetLearned(ctx context.Context) error {
	return s.wipe(ctx, learnedTables)
}

// ResetAll deletes everything ResetLearned does plus all devices. Settings stay.
func (s *SQLite) ResetAll(ctx context.Context) error {
	return s.wipe(ctx, append(learnedTables[:len(learnedTables):len(learnedTables)], "devices"))
}

// wipe empties tables in one transaction and returns all freed pages to the
// filesystem (no-op unless the DB was created with auto_vacuum=INCREMENTAL).
func (s *SQLite) wipe(ctx context.Context, tables []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tables {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t); err != nil {
			return fmt.Errorf("store: reset %s: %w", t, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: reset commit: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
		return fmt.Errorf("store: reset vacuum: %w", err)
	}
	return nil
}
