// Package config loads Guardian configuration from environment variables
// (RouterOS passes them via /container/envs).
package config

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	RouterURL      string        // GUARDIAN_ROS_URL, e.g. http://172.17.0.1
	RouterUser     string        // GUARDIAN_ROS_USER
	RouterPassword string        // GUARDIAN_ROS_PASS
	RouterInsecure bool          // GUARDIAN_ROS_INSECURE_TLS (self-signed www-ssl)
	PollInterval   time.Duration // GUARDIAN_POLL_INTERVAL
	LANPrefixes    []netip.Prefix
	DBPath         string        // GUARDIAN_DB
	BackupPath     string        // GUARDIAN_BACKUP (snapshot on NAS share; empty = off)
	BackupInterval time.Duration // GUARDIAN_BACKUP_INTERVAL
	GeoCountryDB   string        // GUARDIAN_GEOIP_COUNTRY (mmdb, optional)
	GeoASNDB       string        // GUARDIAN_GEOIP_ASN (mmdb, optional)
	Listen         string        // GUARDIAN_LISTEN
	LearnPeriod    time.Duration
	Retention      time.Duration
	QuarantineList string
	DedupWindow    time.Duration

	WebUser string // GUARDIAN_WEB_USER; empty = UI without login
	WebPass string // GUARDIAN_WEB_PASS

	Language string // GUARDIAN_LANGUAGE: alerts/notifications language (en, cs, de, pl, ru, es, pt); "" = en, UI follows the browser

	NtfyURL        string // full topic URL, e.g. https://ntfy.sh/my-secret-topic
	NtfyToken      string
	TelegramToken  string
	TelegramChatID string
}

func Load() (Config, error) {
	c := Config{
		RouterURL:      env("GUARDIAN_ROS_URL", "http://172.17.0.1"),
		RouterUser:     env("GUARDIAN_ROS_USER", "guardian"),
		RouterPassword: os.Getenv("GUARDIAN_ROS_PASS"),
		RouterInsecure: envBool("GUARDIAN_ROS_INSECURE_TLS", true),
		DBPath:         env("GUARDIAN_DB", "/data/guardian.db"),
		BackupPath:     os.Getenv("GUARDIAN_BACKUP"),
		GeoCountryDB:   env("GUARDIAN_GEOIP_COUNTRY", "/data/geo/country.mmdb"),
		GeoASNDB:       env("GUARDIAN_GEOIP_ASN", "/data/geo/asn.mmdb"),
		Listen:         env("GUARDIAN_LISTEN", ":8080"),
		QuarantineList: env("GUARDIAN_QUARANTINE_LIST", "guardian-quarantine"),
		WebUser:        os.Getenv("GUARDIAN_WEB_USER"),
		WebPass:        os.Getenv("GUARDIAN_WEB_PASS"),
		Language:       os.Getenv("GUARDIAN_LANGUAGE"),
		NtfyURL:        os.Getenv("GUARDIAN_NTFY_URL"),
		NtfyToken:      os.Getenv("GUARDIAN_NTFY_TOKEN"),
		TelegramToken:  os.Getenv("GUARDIAN_TELEGRAM_TOKEN"),
		TelegramChatID: os.Getenv("GUARDIAN_TELEGRAM_CHAT"),
	}
	var err error
	if c.PollInterval, err = envDur("GUARDIAN_POLL_INTERVAL", 15*time.Second); err != nil {
		return c, err
	}
	if c.LearnPeriod, err = envDur("GUARDIAN_LEARN_PERIOD", 7*24*time.Hour); err != nil {
		return c, err
	}
	if c.Retention, err = envDur("GUARDIAN_RETENTION", 60*24*time.Hour); err != nil {
		return c, err
	}
	if c.DedupWindow, err = envDur("GUARDIAN_DEDUP_WINDOW", 6*time.Hour); err != nil {
		return c, err
	}
	if c.BackupInterval, err = envDur("GUARDIAN_BACKUP_INTERVAL", time.Hour); err != nil {
		return c, err
	}
	if c.BackupPath != "" && c.BackupInterval < time.Minute {
		return c, fmt.Errorf("GUARDIAN_BACKUP_INTERVAL must be >= 1m")
	}
	for _, p := range strings.Split(env("GUARDIAN_LAN", "192.168.88.0/24"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return c, fmt.Errorf("GUARDIAN_LAN: %w", err)
		}
		c.LANPrefixes = append(c.LANPrefixes, pfx.Masked())
	}
	if c.RouterPassword == "" {
		return c, fmt.Errorf("GUARDIAN_ROS_PASS is required")
	}
	if c.WebUser != "" && c.WebPass == "" {
		return c, fmt.Errorf("GUARDIAN_WEB_PASS is required when GUARDIAN_WEB_USER is set")
	}
	if c.PollInterval < 5*time.Second {
		return c, fmt.Errorf("GUARDIAN_POLL_INTERVAL must be >= 5s")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// envDur accepts Go durations ("15s", "168h") and a "d" suffix for days ("7d").
func envDur(k string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	if strings.HasSuffix(v, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", k, err)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	return d, nil
}
