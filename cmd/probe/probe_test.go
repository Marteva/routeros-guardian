package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// fakeRouter serves the endpoints the probe uses. Non-fasttracked connections
// grow every poll; fasttracked ones grow only if ftMoves is set.
type fakeRouter struct {
	mu      sync.Mutex
	polls   int
	ftMoves bool
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/rest/system/resource":
		_, _ = io.WriteString(w, `{"cpu-load":"4","cpu-count":"4","free-memory":"700000000","total-memory":"1073741824","version":"7.20.1","board-name":"hAP ax^3","architecture-name":"arm64"}`)
	case "/rest/ip/firewall/filter":
		_, _ = io.WriteString(w, `[{".id":"*1","chain":"forward","action":"accept"},
			{".id":"*5","chain":"forward","action":"fasttrack-connection","hw-offload":"true","comment":"defconf: fasttrack"}]`)
	case "/rest/ipv6/firewall/connection":
		_, _ = io.WriteString(w, `[{".id":"*1"},{".id":"*2"}]`)
	case "/rest/ip/route":
		_, _ = io.WriteString(w, `[{"dst-address":"0.0.0.0/0","gateway":"100.64.0.1","immediate-gateway":"100.64.0.1%ether1","active":"true"}]`)
	case "/rest/interface":
		n := uint64(f.polls) * 10_000_000
		fmt.Fprintf(w, `[{"name":"ether1","rx-byte":"%d","tx-byte":"%d"}]`, n, n/10)
	case "/rest/ip/dhcp-server/lease":
		_, _ = io.WriteString(w, `[{".id":"*1","mac-address":"AA:AA:AA:AA:AA:01","address":"192.168.88.10","status":"bound"}]`)
	case "/rest/ip/arp":
		_, _ = io.WriteString(w, `[{"address":"100.64.0.1","mac-address":"EE:EE:EE:EE:EE:01","interface":"ether1","complete":"true"}]`)
	case "/rest/ip/firewall/connection":
		f.polls++
		var b strings.Builder
		b.WriteString("[")
		for i := 0; i < 60; i++ {
			ft := i < 30
			bytes := 1000 + f.polls*100
			if ft && !f.ftMoves {
				bytes = 1000
			}
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{".id":"*%X","protocol":"tcp","src-address":"192.168.88.10:%d","dst-address":"1.1.1.1:443","orig-bytes":"%d","repl-bytes":"%d","fasttrack":"%t"}`,
				i+1, 10000+i, bytes, bytes, ft)
		}
		b.WriteString("]")
		_, _ = io.WriteString(w, b.String())
	default:
		http.NotFound(w, r)
	}
}

func runProbe(t *testing.T, f *fakeRouter) (string, [][]string) {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	out := t.TempDir()
	o := options{
		url: srv.URL, user: "u", pass: "p", interval: 40 * time.Millisecond, duration: 300 * time.Millisecond,
		timeout: time.Second, out: out, lan: []netip.Prefix{netip.MustParsePrefix("192.168.88.0/24")},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Silence the summary printed to stdout.
	stdout := os.Stdout
	devnull, _ := os.Open(os.DevNull)
	os.Stdout = devnull
	err := run(context.Background(), log, o)
	os.Stdout = stdout
	devnull.Close()
	if err != nil {
		t.Fatal(err)
	}
	summary, err := os.ReadFile(filepath.Join(out, "summary.txt"))
	if err != nil {
		t.Fatal(err)
	}
	fh, err := os.Open(filepath.Join(out, "samples.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	rows, err := csv.NewReader(fh).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return string(summary), rows
}

func TestProbeStuckFasttrackCounters(t *testing.T) {
	summary, rows := runProbe(t, &fakeRouter{})
	t.Log("\n" + summary)
	if len(rows) < 3 || strings.Join(rows[0], ",") != strings.Join(csvHeader, ",") {
		t.Fatalf("csv rows = %v", rows)
	}
	for _, want := range []string{
		"FastTrack: ZAPNUT", "čítače fasttrack spojení se aktualizují: NE", "NEJSOU použitelná",
		"hw-offload=yes", "IPv6:              2 spojení", "ether1", "max položek: 60",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
}

func TestProbeMovingCounters(t *testing.T) {
	summary, _ := runProbe(t, &fakeRouter{ftMoves: true})
	if !strings.Contains(summary, "aktualizují: ANO") {
		t.Errorf("summary:\n%s", summary)
	}
}

func TestCounterTracker(t *testing.T) {
	ap := netip.MustParseAddrPort
	tr := newCounterTracker()
	c := []model.Conn{
		{ID: "*1", Src: ap("192.168.88.10:1"), Dst: ap("1.1.1.1:443"), OrigBytes: 10, Fasttrack: true},
		{ID: "*2", Src: ap("192.168.88.10:2"), Dst: ap("1.1.1.1:443"), OrigBytes: 10, Fasttrack: true},
		{ID: "*3", Src: ap("192.168.88.10:3"), Dst: ap("1.1.1.1:443"), OrigBytes: 10},
		{ID: "*4", Src: ap("192.168.88.10:4"), Dst: ap("1.1.1.1:443"), OrigBytes: 10},
	}
	if a, b, x, y := tr.update(c); a+b+x+y != 0 {
		t.Fatalf("first poll must not count: %d %d %d %d", a, b, x, y)
	}
	c[0].ReplBytes = 5          // ft moved
	c[2].OrigBytes = 20         // non-ft moved
	c[3].Fasttrack = true       // flag flip: ignored
	c[1].Src = ap("10.0.0.1:9") // id reuse: ignored
	ft, ftm, non, nonm := tr.update(c)
	if ft != 1 || ftm != 1 || non != 1 || nonm != 1 {
		t.Errorf("got %d/%d %d/%d", ftm, ft, nonm, non)
	}
}

func TestRecommendationsInterval(t *testing.T) {
	info := runInfo{Interval: 15 * time.Second}
	m := metrics{Polls: 10, P95Conn: 10 * time.Second, Coverage: -1, Counters: triYes}
	recs := strings.Join(recommendations(info, m), "\n")
	if !strings.Contains(recs, "zvyšte interval na 50s") {
		t.Errorf("recs = %s", recs)
	}
	m.P95Conn = 200 * time.Millisecond
	if recs := strings.Join(recommendations(info, m), "\n"); !strings.Contains(recs, "je v pořádku") {
		t.Errorf("recs = %s", recs)
	}
}
