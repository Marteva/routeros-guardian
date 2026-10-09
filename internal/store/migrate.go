package store

import (
	"context"
	"fmt"
)

// migrations are applied in order; index+1 is the schema version.
// Never edit an applied migration — append a new one.
var migrations = []string{
	// v1: initial schema. Times are unix seconds UTC, IPs are text.
	`
CREATE TABLE devices (
	mac         TEXT PRIMARY KEY,
	ip          TEXT NOT NULL DEFAULT '',
	hostname    TEXT NOT NULL DEFAULT '',
	vendor      TEXT NOT NULL DEFAULT '',
	kind        TEXT NOT NULL DEFAULT '',
	class_id    TEXT NOT NULL DEFAULT '',
	randomized  INTEGER NOT NULL DEFAULT 0,
	first_seen  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL,
	quarantined INTEGER NOT NULL DEFAULT 0,
	note        TEXT NOT NULL DEFAULT ''
) WITHOUT ROWID;

CREATE TABLE hour_stats (
	mac          TEXT NOT NULL,
	hour         INTEGER NOT NULL,
	tx           INTEGER NOT NULL DEFAULT 0,
	rx           INTEGER NOT NULL DEFAULT 0,
	new_conns    INTEGER NOT NULL DEFAULT 0,
	distinct_dst INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (mac, hour)
) WITHOUT ROWID;
CREATE INDEX hour_stats_hour ON hour_stats(hour);

CREATE TABLE hour_dst (
	mac    TEXT NOT NULL,
	hour   INTEGER NOT NULL,
	dst_ip TEXT NOT NULL,
	PRIMARY KEY (mac, hour, dst_ip)
) WITHOUT ROWID;

CREATE TABLE dest_stats (
	mac        TEXT NOT NULL,
	country    TEXT NOT NULL,
	asn        INTEGER NOT NULL,
	as_org     TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen  INTEGER NOT NULL,
	bytes      INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (mac, country, asn)
) WITHOUT ROWID;

CREATE TABLE alerts (
	id            INTEGER PRIMARY KEY,
	time          INTEGER NOT NULL,
	mac           TEXT NOT NULL DEFAULT '',
	kind          TEXT NOT NULL,
	severity      INTEGER NOT NULL DEFAULT 0,
	title         TEXT NOT NULL DEFAULT '',
	detail        TEXT NOT NULL DEFAULT '',
	evidence_json TEXT NOT NULL DEFAULT 'null',
	dedup_key     TEXT NOT NULL DEFAULT '',
	acked         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alerts_dedup_time ON alerts(dedup_key, time);
CREATE INDEX alerts_time ON alerts(time);
CREATE INDEX alerts_mac_time ON alerts(mac, time);
`,
	// v2: DHCP lease comment (admin's friendly name from RouterOS).
	`ALTER TABLE devices ADD COLUMN comment TEXT NOT NULL DEFAULT '';`,
	// v3: user kind override, manual merge groups, runtime settings (KV).
	`
ALTER TABLE devices ADD COLUMN kind_override TEXT NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN group_id TEXT NOT NULL DEFAULT '';
CREATE INDEX devices_group ON devices(group_id);

CREATE TABLE settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
) WITHOUT ROWID;
`,
}

func (s *SQLite) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: schema_version: %w", err)
	}
	var v int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if v > len(migrations) {
		return fmt.Errorf("store: database schema v%d is newer than this binary (v%d)", v, len(migrations))
	}
	for i := v; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration v%d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM schema_version`); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: migration v%d commit: %w", i+1, err)
		}
	}
	return nil
}
