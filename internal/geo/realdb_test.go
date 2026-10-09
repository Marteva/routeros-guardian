package geo

import (
	"net/netip"
	"os"
	"testing"
)

// TestRealDB runs only when GUARDIAN_TEST_GEO_DIR points at downloaded mmdb files.
func TestRealDB(t *testing.T) {
	dir := os.Getenv("GUARDIAN_TEST_GEO_DIR")
	if dir == "" {
		t.Skip("GUARDIAN_TEST_GEO_DIR not set")
	}
	g, err := Open(dir+"/country.mmdb", dir+"/asn.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "77.75.75.172", "114.114.114.114"} {
		c, asn, org := g.Lookup(netip.MustParseAddr(ip))
		t.Logf("%-16s %s AS%d %s", ip, c, asn, org)
		if c == "" || asn == 0 {
			t.Errorf("%s: empty result", ip)
		}
	}
}
