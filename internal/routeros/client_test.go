package routeros

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL + "/", User: "guardian", Password: "s3cret", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewValidation(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "http://", "::bad"} {
		if _, err := New(Config{BaseURL: u}); err == nil {
			t.Errorf("New(%q) = nil error", u)
		}
	}
	c, err := New(Config{BaseURL: "https://192.168.88.1/rest/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.endpoint("/ip/arp", nil); got != "https://192.168.88.1/rest/ip/arp" {
		t.Errorf("endpoint = %q", got)
	}
}

func TestAuthAndGet(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "guardian" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":401,"message":"Unauthorized"}`)
			return
		}
		if r.URL.Path != "/rest/system/identity" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"name":"hap"}`)
	})
	var out struct {
		Name string `json:"name"`
	}
	if err := c.Get(context.Background(), "system/identity", nil, &out); err != nil {
		t.Fatal(err)
	}
	if out.Name != "hap" {
		t.Errorf("name = %q", out.Name)
	}

	c.pass = "wrong"
	err := c.Get(context.Background(), "system/identity", nil, &out)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 || ae.Message != "Unauthorized" {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIErrorNonJSON(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "<html>oops</html>")
	})
	err := c.Get(context.Background(), "x", nil, nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 500 || ae.Detail != "<html>oops</html>" {
		t.Fatalf("err = %#v", err)
	}
}

func TestDHCPLeases(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[
		 {".id":"*1","mac-address":"aa:bb:cc:dd:ee:01","address":"192.168.88.10","active-address":"192.168.88.11",
		  "host-name":"phone","class-id":"android-dhcp-14","client-id":"1:aa:bb","status":"bound","dynamic":"true","server":"defconf","comment":" Obyvak TV "},
		 {".id":"*2","mac-address":"AA-BB-CC-DD-EE-02","address":"192.168.88.20","status":"waiting","dynamic":"false"},
		 {".id":"*3","address":"192.168.88.30"},
		 {".id":"*4","active-mac-address":"aabb.ccdd.ee04","address":"pool1","status":"bound"}
		]`)
	})
	ls, err := c.DHCPLeases(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 3 {
		t.Fatalf("got %d leases: %+v", len(ls), ls)
	}
	l := ls[0]
	if l.MAC != "AA:BB:CC:DD:EE:01" || l.IP != netip.MustParseAddr("192.168.88.11") || l.Hostname != "phone" ||
		l.ClassID != "android-dhcp-14" || !l.Dynamic || l.Status != "bound" || l.Server != "defconf" || l.ID != "*1" || l.Comment != "Obyvak TV" {
		t.Errorf("lease0 = %+v", l)
	}
	if ls[1].MAC != "AA:BB:CC:DD:EE:02" || ls[1].IP != netip.MustParseAddr("192.168.88.20") || ls[1].Dynamic || ls[1].Comment != "" {
		t.Errorf("lease1 = %+v", ls[1])
	}
	if ls[2].MAC != "AA:BB:CC:DD:EE:04" || ls[2].IP.IsValid() {
		t.Errorf("lease2 = %+v", ls[2])
	}
}

func TestARP(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `[
		 {".id":"*1","address":"192.168.88.5","mac-address":"02:00:00:00:00:05","interface":"bridge","complete":"true","status":"reachable"},
		 {".id":"*2","address":"192.168.88.6","interface":"bridge","status":"failed"},
		 {".id":"*3","address":"192.168.88.7","mac-address":"02:00:00:00:00:07","interface":"bridge","status":"incomplete"},
		 {".id":"*4","address":"192.168.88.8","mac-address":"02:00:00:00:00:08","interface":"bridge","status":"stale"}
		]`)
	})
	as, err := c.ARP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(as) != 3 {
		t.Fatalf("got %d: %+v", len(as), as)
	}
	if !as[0].Complete || as[0].Interface != "bridge" || as[0].IP != netip.MustParseAddr("192.168.88.5") {
		t.Errorf("arp0 = %+v", as[0])
	}
	if as[1].Complete || !as[2].Complete {
		t.Errorf("complete flags wrong: %+v", as)
	}
}

func TestConnections(t *testing.T) {
	var gotQuery string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = io.WriteString(w, `[
		 {".id":"*A1","protocol":"tcp","src-address":"192.168.88.10:51234","dst-address":"142.250.1.1:443",
		  "orig-bytes":"12345","repl-bytes":"987654","fasttrack":"true","srcnat":"true","dstnat":"false"},
		 {".id":"*A2","protocol":"icmp","src-address":"192.168.88.10","dst-address":"1.1.1.1","orig-bytes":"84","repl-bytes":"84"},
		 {".id":"*A3","protocol":"tcp","src-address":"[2001:db8::10]:40000","dst-address":"[2a00:1450::1]:443"},
		 {".id":"*A4","protocol":"udp","src-address":"fd00::5","dst-address":"2a00:1450::2"},
		 {".id":"*A5","protocol":"gre","src-address":"garbage","orig-bytes":"x","dstnat":"true"},
		 {".id":"*A6","protocol":"udp","src-address":"192.168.88.10:5353","dst-address":"8.8.8.8:53","orig-bytes":1000,"fasttrack":false}
		]`)
	})
	cs, size, err := c.ConnectionsWithSize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, ".proplist=.id,protocol,src-address,dst-address,orig-bytes,repl-bytes,fasttrack,srcnat,dstnat") {
		t.Errorf("query = %q", gotQuery)
	}
	if size <= 0 {
		t.Errorf("size = %d", size)
	}
	if len(cs) != 6 {
		t.Fatalf("got %d conns", len(cs))
	}
	c0 := cs[0]
	if c0.ID != "*A1" || c0.Proto != "tcp" || c0.Src != netip.MustParseAddrPort("192.168.88.10:51234") ||
		c0.Dst != netip.MustParseAddrPort("142.250.1.1:443") || c0.OrigBytes != 12345 || c0.ReplBytes != 987654 ||
		!c0.Fasttrack || !c0.SrcNAT || c0.DstNAT {
		t.Errorf("conn0 = %+v", c0)
	}
	if cs[1].Src.Addr() != netip.MustParseAddr("192.168.88.10") || cs[1].Src.Port() != 0 || cs[1].Dst.Addr() != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("icmp = %+v", cs[1])
	}
	if cs[2].Src != netip.MustParseAddrPort("[2001:db8::10]:40000") || cs[2].Dst.Port() != 443 || cs[2].Fasttrack {
		t.Errorf("ipv6 = %+v", cs[2])
	}
	if cs[3].Src.Addr() != netip.MustParseAddr("fd00::5") || cs[3].Dst.Addr() != netip.MustParseAddr("2a00:1450::2") {
		t.Errorf("bare ipv6 = %+v", cs[3])
	}
	if cs[4].Src.IsValid() || cs[4].Dst.IsValid() || cs[4].OrigBytes != 0 || !cs[4].DstNAT {
		t.Errorf("garbage = %+v", cs[4])
	}
	if cs[5].OrigBytes != 1000 || cs[5].Fasttrack {
		t.Errorf("non-string values = %+v", cs[5])
	}
}

func TestConnectionsBadJSON(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"not":"an array"}`)
	})
	if _, err := c.Connections(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestResource(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"cpu-load":"7","cpu-count":"4","free-memory":"800000000","total-memory":"1073741824",
		 "uptime":"1w2d3h","version":"7.20.1 (stable)","board-name":"hAP ax^3","architecture-name":"arm64"}`)
	})
	r, err := c.Resource(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.CPULoad != 7 || r.CPUCount != 4 || r.FreeMemory != 800000000 || r.TotalMemory != 1073741824 ||
		r.Uptime != "1w2d3h" || r.Version != "7.20.1 (stable)" || r.BoardName != "hAP ax^3" || r.Arch != "arm64" {
		t.Errorf("resource = %+v", r)
	}
}

// fakeAddressList emulates /ip/firewall/address-list (and the ipv6 variant).
type fakeAddressList struct {
	mu      sync.Mutex
	entries map[string]map[string]string // id -> fields
	next    int
	deletes []string // raw request URIs
	puts    []map[string]string
}

func (f *fakeAddressList) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		const v4 = "/rest/ip/firewall/address-list"
		const v6 = "/rest/ipv6/firewall/address-list"
		base := v4
		if strings.HasPrefix(r.URL.Path, v6) {
			base = v6
		}
		switch {
		case r.Method == http.MethodPut && r.URL.Path == base:
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("bad body: %v", err)
			}
			f.puts = append(f.puts, body)
			for _, e := range f.entries {
				if e["list"] == body["list"] && normalizeListAddress(e["address"]) == normalizeListAddress(body["address"]) {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = io.WriteString(w, `{"error":400,"message":"Bad Request","detail":"failure: already have such entry"}`)
					return
				}
			}
			f.next++
			id := "*" + strings.ToUpper(string(rune('A'+f.next)))
			e := map[string]string{".id": id, "list": body["list"], "address": body["address"]}
			if base == v6 && !strings.Contains(e["address"], "/") {
				e["address"] += "/128" // RouterOS stores IPv6 entries as prefixes
			}
			f.entries[id] = e
			_ = json.NewEncoder(w).Encode(e)
		case r.Method == http.MethodGet && r.URL.Path == base:
			list := r.URL.Query().Get("list")
			out := []map[string]string{}
			for _, e := range f.entries {
				if list == "" || e["list"] == list {
					out = append(out, e)
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/"):
			f.deletes = append(f.deletes, r.RequestURI)
			id := strings.TrimPrefix(r.URL.Path, base+"/")
			if _, ok := f.entries[id]; !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":404,"message":"Not Found"}`)
				return
			}
			delete(f.entries, id)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func TestAddressListIdempotent(t *testing.T) {
	f := &fakeAddressList{entries: map[string]map[string]string{}}
	c := newTestClient(t, f.handler(t))
	ctx := context.Background()

	if err := c.AddressListAdd(ctx, "q", "192.168.88.50", "guardian: test", 90*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := c.AddressListAdd(ctx, "q", "192.168.88.50", "guardian: test", 0); err != nil {
		t.Fatalf("second add: %v", err)
	}
	if len(f.entries) != 1 {
		t.Fatalf("entries = %v", f.entries)
	}
	if f.puts[0]["timeout"] != "1h30m" || f.puts[0]["comment"] != "guardian: test" {
		t.Errorf("put body = %v", f.puts[0])
	}
	if _, ok := f.puts[1]["timeout"]; ok {
		t.Errorf("timeout must be omitted for 0: %v", f.puts[1])
	}

	if err := c.AddressListRemove(ctx, "q", "192.168.88.50/32"); err != nil {
		t.Fatal(err)
	}
	if len(f.entries) != 0 {
		t.Fatalf("not removed: %v", f.entries)
	}
	if len(f.deletes) != 1 || !strings.HasSuffix(f.deletes[0], "/rest/ip/firewall/address-list/*B") {
		t.Errorf("deletes = %v (id must keep literal '*')", f.deletes)
	}
	if err := c.AddressListRemove(ctx, "q", "192.168.88.50"); err != nil {
		t.Fatalf("remove missing: %v", err)
	}

	// IPv6 goes to the ipv6 menu and matches the stored /128 prefix.
	if err := c.AddressListAdd(ctx, "q", "2a00:1450::1", "", 0); err != nil {
		t.Fatal(err)
	}
	if err := c.AddressListRemove(ctx, "q", "2a00:1450::1"); err != nil {
		t.Fatal(err)
	}
	if len(f.entries) != 0 {
		t.Fatalf("ipv6 not removed: %v", f.entries)
	}
}

func TestAddressListAddOtherError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":400,"message":"Bad Request","detail":"invalid value for argument address"}`)
	})
	err := c.AddressListAdd(context.Background(), "q", "nonsense", "", 0)
	var ae *APIError
	if !errors.As(err, &ae) || !strings.Contains(ae.Detail, "invalid value") {
		t.Fatalf("err = %v", err)
	}
}

func TestFormatDuration(t *testing.T) {
	cases := map[time.Duration]string{
		0:                                  "",
		-time.Second:                       "",
		500 * time.Millisecond:             "1s",
		90 * time.Second:                   "1m30s",
		26*time.Hour + 3*time.Minute + 4e9: "1d2h3m4s",
		7 * 24 * time.Hour:                 "7d",
	}
	for d, want := range cases {
		if got := FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"aa:bb:cc:dd:ee:ff": "AA:BB:CC:DD:EE:FF",
		"AA-BB-CC-DD-EE-FF": "AA:BB:CC:DD:EE:FF",
		"aabb.ccdd.eeff":    "AA:BB:CC:DD:EE:FF",
		"":                  "",
		"zz":                "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}
