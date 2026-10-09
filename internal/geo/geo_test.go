package geo

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Minimal MMDB writer (IPv6 tree, 24-bit records) – just enough for fixtures.

type mmNode struct{ rec [2]int } // >=0 node index, -1 empty, <=-2 data: -(off+2)

type mmWriter struct {
	nodes []mmNode
	data  bytes.Buffer
}

func newMM() *mmWriter { return &mmWriter{nodes: []mmNode{{rec: [2]int{-1, -1}}}} }

func ctrl(buf *bytes.Buffer, typ, size int) {
	if size >= 29+256 {
		panic("fixture: size too big")
	}
	sb := size
	if size >= 29 {
		sb = 29
	}
	if typ <= 7 {
		buf.WriteByte(byte(typ<<5 | sb))
	} else {
		buf.WriteByte(byte(sb))
		buf.WriteByte(byte(typ - 7))
	}
	if size >= 29 {
		buf.WriteByte(byte(size - 29))
	}
}

func encode(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case string:
		ctrl(buf, 2, len(x))
		buf.WriteString(x)
	case uint16, uint32, uint64:
		var n uint64
		typ := 5
		switch y := x.(type) {
		case uint16:
			n = uint64(y)
		case uint32:
			n, typ = uint64(y), 6
		case uint64:
			n, typ = y, 9
		}
		var b []byte
		for ; n > 0; n >>= 8 {
			b = append([]byte{byte(n)}, b...)
		}
		ctrl(buf, typ, len(b))
		buf.Write(b)
	case []string:
		ctrl(buf, 11, len(x))
		for _, s := range x {
			encode(buf, s)
		}
	case map[string]any:
		ctrl(buf, 7, len(x))
		for k, val := range x {
			encode(buf, k)
			encode(buf, val)
		}
	default:
		panic("fixture: unsupported type")
	}
}

// insert stores rec for prefix (IPv4 prefixes are mapped into ::/96).
func (w *mmWriter) insert(p netip.Prefix, rec map[string]any) {
	off := w.data.Len()
	encode(&w.data, rec)
	addr, bits := p.Addr().As16(), p.Bits()
	if p.Addr().Is4() {
		addr = [16]byte{}
		v4 := p.Addr().As4()
		copy(addr[12:], v4[:])
		bits += 96
	}
	n := 0
	for i := 0; i < bits; i++ {
		bit := int(addr[i/8]>>(7-i%8)) & 1
		if i == bits-1 {
			w.nodes[n].rec[bit] = -(off + 2)
			return
		}
		next := w.nodes[n].rec[bit]
		if next < 0 {
			w.nodes = append(w.nodes, mmNode{rec: [2]int{-1, -1}})
			next = len(w.nodes) - 1
			w.nodes[n].rec[bit] = next
		}
		n = next
	}
}

func (w *mmWriter) write(t *testing.T, path, dbType string) {
	t.Helper()
	nc := len(w.nodes)
	var out bytes.Buffer
	for _, n := range w.nodes {
		for _, r := range n.rec {
			v := nc // empty
			switch {
			case r >= 0:
				v = r
			case r <= -2:
				v = nc + 16 + (-r - 2)
			}
			out.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(w.data.Bytes())
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	encode(&out, map[string]any{
		"node_count":                  uint32(nc),
		"record_size":                 uint16(24),
		"ip_version":                  uint16(6),
		"database_type":               dbType,
		"languages":                   []string{"en"},
		"binary_format_major_version": uint16(2),
		"binary_format_minor_version": uint16(0),
		"build_epoch":                 uint64(1700000000),
		"description":                 map[string]any{"en": "test"},
	})
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixtures(t *testing.T) (country, asn string) {
	dir := t.TempDir()
	country, asn = filepath.Join(dir, "country.mmdb"), filepath.Join(dir, "asn.mmdb")

	c := newMM()
	c.insert(netip.MustParsePrefix("1.1.1.0/24"), map[string]any{
		"country": map[string]any{"iso_code": "AU"},
	})
	c.insert(netip.MustParsePrefix("8.8.8.0/24"), map[string]any{
		"country": map[string]any{"iso_code": "US"},
	})
	c.insert(netip.MustParsePrefix("5.0.0.0/8"), map[string]any{ // registered_country fallback
		"registered_country": map[string]any{"iso_code": "CZ"},
	})
	c.insert(netip.MustParsePrefix("2a00:1450::/32"), map[string]any{
		"country": map[string]any{"iso_code": "IE"},
	})
	c.write(t, country, "DBIP-Country-Lite")

	a := newMM()
	a.insert(netip.MustParsePrefix("1.1.1.0/24"), map[string]any{
		"autonomous_system_number":       uint32(13335),
		"autonomous_system_organization": "Cloudflare, Inc.",
	})
	a.insert(netip.MustParsePrefix("2a00:1450::/32"), map[string]any{
		"autonomous_system_number":       uint32(15169),
		"autonomous_system_organization": "Google LLC",
	})
	a.write(t, asn, "DBIP-ASN-Lite")
	return country, asn
}

// ---------------------------------------------------------------------------

type res struct {
	c   string
	asn uint32
	org string
}

func lookup(g interface {
	Lookup(netip.Addr) (string, uint32, string)
}, ip string) res {
	c, a, o := g.Lookup(netip.MustParseAddr(ip))
	return res{c, a, o}
}

func TestNoop(t *testing.T) {
	if r := lookup(Noop{}, "1.1.1.1"); r != (res{}) {
		t.Fatalf("Noop returned %+v", r)
	}
}

func TestOpenMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(filepath.Join(dir, "a.mmdb"), filepath.Join(dir, "b.mmdb")); err == nil {
		t.Fatal("expected error when both files are missing")
	}
	if _, err := Open("", ""); err == nil {
		t.Fatal("expected error for empty paths")
	}
}

func TestOpenCorrupt(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.mmdb")
	if err := os.WriteFile(bad, []byte("not an mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad, filepath.Join(dir, "missing.mmdb")); err == nil {
		t.Fatal("expected error for corrupt file")
	}
	country, _ := fixtures(t)
	if _, err := Open(country, bad); err == nil {
		t.Fatal("expected error for corrupt asn file")
	}
}

func TestLookup(t *testing.T) {
	country, asn := fixtures(t)
	g, err := Open(country, asn)
	if err != nil {
		t.Fatal(err)
	}
	defer g.(*DB).Close()

	cases := []struct {
		ip   string
		want res
	}{
		{"1.1.1.1", res{"AU", 13335, "Cloudflare, Inc."}},
		{"::ffff:1.1.1.1", res{"AU", 13335, "Cloudflare, Inc."}},
		{"8.8.8.8", res{"US", 0, ""}},
		{"5.6.7.8", res{"CZ", 0, ""}},
		{"2a00:1450:4001::1", res{"IE", 15169, "Google LLC"}},
		{"9.9.9.9", res{}},
		{"192.168.1.1", res{}},
		{"10.0.0.1", res{}},
		{"127.0.0.1", res{}},
		{"fe80::1", res{}},
	}
	for _, c := range cases {
		for i := 0; i < 2; i++ { // second round hits the cache
			if got := lookup(g, c.ip); got != c.want {
				t.Errorf("%s: got %+v want %+v", c.ip, got, c.want)
			}
		}
	}
	if got := lookup(g, "1.1.1.1"); got.c != "AU" {
		t.Fatal(got)
	}
	var zero netip.Addr
	if c, a, o := g.Lookup(zero); c != "" || a != 0 || o != "" {
		t.Fatal("zero addr")
	}
}

func TestHalfMissing(t *testing.T) {
	country, asn := fixtures(t)
	missing := filepath.Join(t.TempDir(), "none.mmdb")

	g, err := Open(country, missing)
	if err != nil {
		t.Fatal(err)
	}
	if got := lookup(g, "1.1.1.1"); got != (res{c: "AU"}) {
		t.Errorf("country only: %+v", got)
	}
	g.(*DB).Close()

	g, err = Open("", asn)
	if err != nil {
		t.Fatal(err)
	}
	if got := lookup(g, "1.1.1.1"); got != (res{"", 13335, "Cloudflare, Inc."}) {
		t.Errorf("asn only: %+v", got)
	}
	g.(*DB).Close()
}

func TestConcurrentAndCacheBound(t *testing.T) {
	country, asn := fixtures(t)
	g, err := Open(country, asn)
	if err != nil {
		t.Fatal(err)
	}
	db := g.(*DB)
	defer db.Close()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 3000; i++ {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], 0x05000000+uint32(i)+uint32(w)<<16)
				g.Lookup(netip.AddrFrom4(b))
			}
		}(w)
	}
	wg.Wait()
	db.mu.Lock()
	n := len(db.cache)
	db.mu.Unlock()
	if n > cacheSize {
		t.Fatalf("cache grew to %d", n)
	}
}
