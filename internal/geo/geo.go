// Package geo resolves internet IPs to country and ASN using MaxMind-format
// (.mmdb) databases.
//
// Recommended source: DB-IP Lite (free, monthly, CC BY 4.0 — attribution
// "IP Geolocation by DB-IP" with a link to https://db-ip.com is required in
// the UI/docs). Download from https://db-ip.com/db/lite.php:
//
//	dbip-country-lite-YYYY-MM.mmdb.gz → /data/geo/country.mmdb
//	dbip-asn-lite-YYYY-MM.mmdb.gz     → /data/geo/asn.mmdb
//
// (gunzip, rename, restart the container). MaxMind GeoLite2-Country/ASN files
// work too — they use the same field names.
package geo

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// Noop is a GeoLookup that knows nothing.
type Noop struct{}

// Lookup always returns zero values.
func (Noop) Lookup(netip.Addr) (string, uint32, string) { return "", 0, "" }

var _ model.GeoLookup = Noop{}

// cacheSize bounds the result cache. When full it is simply reset, which is
// cheap and good enough for the working set of a home network.
const cacheSize = 4096

type result struct {
	country string
	asn     uint32
	asOrg   string
}

// DB is a GeoLookup backed by up to two mmdb readers. Safe for concurrent use.
type DB struct {
	country *maxminddb.Reader // nil = unavailable
	asn     *maxminddb.Reader

	mu    sync.Mutex
	cache map[netip.Addr]result
}

var _ model.GeoLookup = (*DB)(nil)

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	// Fallback for networks without a physical country (anycast, EU-wide …).
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// Open opens the country and ASN databases. A missing (or empty-path) file
// disables that half silently; it is an error only if both are missing or a
// present file cannot be opened/parsed.
func Open(countryMMDB, asnMMDB string) (model.GeoLookup, error) {
	c, err := openOptional(countryMMDB)
	if err != nil {
		return nil, err
	}
	a, err := openOptional(asnMMDB)
	if err != nil {
		if c != nil {
			c.Close()
		}
		return nil, err
	}
	if c == nil && a == nil {
		return nil, fmt.Errorf("geo: no database found (%q, %q)", countryMMDB, asnMMDB)
	}
	return &DB{country: c, asn: a, cache: make(map[netip.Addr]result)}, nil
}

func openOptional(path string) (*maxminddb.Reader, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geo: open %s: %w", path, err)
	}
	return r, nil
}

// Lookup returns country ISO code, ASN and AS organisation; zero values when
// unknown or for non-public addresses.
func (g *DB) Lookup(ip netip.Addr) (string, uint32, string) {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return "", 0, ""
	}
	g.mu.Lock()
	r, ok := g.cache[ip]
	g.mu.Unlock()
	if ok {
		return r.country, r.asn, r.asOrg
	}

	nip := net.IP(ip.AsSlice())
	if g.country != nil {
		var rec countryRecord
		if g.country.Lookup(nip, &rec) == nil {
			r.country = rec.Country.ISOCode
			if r.country == "" {
				r.country = rec.RegisteredCountry.ISOCode
			}
		}
	}
	if g.asn != nil {
		var rec asnRecord
		if g.asn.Lookup(nip, &rec) == nil {
			r.asn, r.asOrg = rec.Number, rec.Org
		}
	}

	g.mu.Lock()
	if len(g.cache) >= cacheSize {
		clear(g.cache)
	}
	g.cache[ip] = r
	g.mu.Unlock()
	return r.country, r.asn, r.asOrg
}

// Close releases the database files.
func (g *DB) Close() error {
	var errs []error
	for _, r := range []*maxminddb.Reader{g.country, g.asn} {
		if r != nil {
			errs = append(errs, r.Close())
		}
	}
	return errors.Join(errs...)
}
