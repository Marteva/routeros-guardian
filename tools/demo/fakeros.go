package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fakeRouter serves the subset of the RouterOS v7 REST API that Guardian
// uses, for the fictional household: DHCP leases, ARP, connection tracking
// (with byte counters that grow with every request at the devices' usual
// rates), system resources and firewall address lists. Like RouterOS it
// encodes every value as a string, supports .proplist and field filters in
// the query, and answers errors as {"error":…,"message":…,"detail":…}.
// Authentication is not checked.
type fakeRouter struct {
	mu      sync.Mutex
	now     func() time.Time
	r       *rand.Rand
	log     *slog.Logger
	devices []*device // online devices
	booted  time.Time
	last    time.Time // last counter update
	nextID  uint64
	conns   []*fakeConn
	lists   []*listEntry
}

type fakeConn struct {
	id         string
	dev        *device
	proto      string
	src, dst   netip.AddrPort
	weight     float64 // share of the device's traffic (relative to its other connections)
	orig, repl float64 // byte counters
	txRate     float64 // current bytes/s (for orig-rate / repl-rate)
	rxRate     float64
	fasttrack  bool
	lan        bool // DNS to the router: not internet traffic
	expires    time.Time
}

type listEntry struct {
	id, list, address, comment string
	created                    time.Time
	expires                    time.Time // zero = permanent
}

// wanAddr is the router's (fictional) public address, from a documentation range.
const wanAddr = "203.0.113.45"

var routerIP = netip.AddrFrom4([4]byte{192, 168, 88, 1})

func newFakeRouter(hh *household, now func() time.Time, log *slog.Logger) *fakeRouter {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	t := now()
	f := &fakeRouter{
		now:     now,
		r:       rand.New(rand.NewPCG(0x726f73, 0x6465)), // "ros", "de"
		log:     log,
		devices: hh.online(),
		booted:  t.Add(-(12*24*time.Hour + 3*time.Hour + 17*time.Minute)),
		last:    t,
		nextID:  0x3A00,
	}
	f.refresh(t, 600) // the first connections are up to 10 minutes old
	return f
}

// ServeHTTP implements http.Handler.
func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path, ok := strings.CutPrefix(r.URL.Path, "/rest/")
	if !ok {
		writeROSError(w, http.StatusNotFound, "Not Found", "")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.advance(f.now())

	menu, id, _ := strings.Cut(path, "/*")
	if id != "" {
		id = "*" + id
	}
	switch {
	case menu == "ip/dhcp-server/lease" && id == "" && r.Method == http.MethodGet:
		writeList(w, r, f.leases())
	case menu == "ip/arp" && id == "" && r.Method == http.MethodGet:
		writeList(w, r, f.arp())
	case menu == "ip/firewall/connection" && id == "" && r.Method == http.MethodGet:
		writeList(w, r, f.connections())
	case menu == "ip/firewall/connection" && id != "" && r.Method == http.MethodDelete:
		f.deleteConn(w, id)
	case menu == "system/resource" && id == "" && r.Method == http.MethodGet:
		writeObject(w, r, f.resource())
	case menu == "ip/firewall/address-list" || menu == "ipv6/firewall/address-list":
		f.addressList(w, r, id)
	default:
		writeROSError(w, http.StatusBadRequest, "Bad Request", "no such command or directory ("+path+")")
	}
}

// ---------------------------------------------------------------------------
// simulation

// advance grows the counters of all connections to now and replaces the
// ones that ended.
func (f *fakeRouter) advance(now time.Time) {
	dt := now.Sub(f.last).Seconds()
	if dt <= 0 {
		return
	}
	dt = min(dt, 300) // a suspended laptop must not produce a huge burst
	f.last = now
	for _, c := range f.conns {
		c.orig += c.txRate * dt
		c.repl += c.rxRate * dt
	}
	f.expireLists(now)
	f.refresh(now, dt)
}

// refresh drops ended connections, opens new ones so that every online,
// non-quarantined device has as many as its current activity needs, and
// recomputes the per-connection rates. New connections opened up to maxAge
// seconds ago: their counters already hold that much traffic.
func (f *fakeRouter) refresh(now time.Time, maxAge float64) {
	alive := f.conns[:0]
	for _, c := range f.conns {
		if now.Before(c.expires) {
			alive = append(alive, c)
		}
	}
	clear(f.conns[len(alive):])
	f.conns = alive

	for i, d := range f.devices {
		l := d.profile.at(now)
		blocked := f.quarantined(d.ip)
		want := 0
		if l.tx+l.rx >= 50*kB && !blocked {
			want = min(6, max(1, round(l.conns/15)))
		}
		var mine []*fakeConn
		for _, c := range f.conns {
			if c.dev == d && !c.lan {
				mine = append(mine, c)
			}
		}
		var opened []*fakeConn
		for len(mine) < want {
			c := f.open(d, now, maxAge > 60)
			mine = append(mine, c)
			opened = append(opened, c)
			f.conns = append(f.conns, c)
		}
		total := 0.0
		for _, c := range mine {
			total += c.weight
		}
		for _, c := range mine {
			c.txRate, c.rxRate = 0, 0 // quarantined: the router drops the packets
			if !blocked {
				c.txRate = l.tx / 3600 * c.weight / total
				c.rxRate = l.rx / 3600 * c.weight / total
			}
		}
		for _, c := range opened {
			age := f.r.Float64() * maxAge
			c.orig, c.repl = c.txRate*age, c.rxRate*age
		}
		// a few devices also have a DNS query to the router in flight
		if i%4 == 0 && want > 0 && !slices.ContainsFunc(f.conns, func(c *fakeConn) bool { return c.dev == d && c.lan }) {
			f.conns = append(f.conns, f.openDNS(d, now))
		}
	}
}

func (f *fakeRouter) newID() string {
	f.nextID++
	return "*" + strings.ToUpper(strconv.FormatUint(f.nextID, 16))
}

// open starts a connection of d. A backdated one (the router was already
// running) has some of its lifetime behind it.
func (f *fakeRouter) open(d *device, now time.Time, backdated bool) *fakeConn {
	dst := pick(f.r, d.liveDestinations())
	proto := "tcp"
	if f.r.Float64() < dst.udp {
		proto = "udp"
	}
	life := time.Duration(3+f.r.IntN(15)) * time.Minute
	if proto == "udp" {
		life = time.Duration(1+f.r.IntN(4)) * time.Minute
	}
	if backdated {
		life = time.Duration(f.r.Float64() * float64(life))
	}
	return &fakeConn{
		id:        f.newID(),
		dev:       d,
		proto:     proto,
		src:       netip.AddrPortFrom(d.ip, uint16(40000+f.r.IntN(25000))),
		dst:       netip.AddrPortFrom(dst.randomAddr(f.r), dst.ports[f.r.IntN(len(dst.ports))]),
		weight:    0.2 + f.r.Float64(),
		fasttrack: f.r.Float64() < 0.9,
		expires:   now.Add(life + time.Minute),
	}
}

func (f *fakeRouter) openDNS(d *device, now time.Time) *fakeConn {
	return &fakeConn{
		id:      f.newID(),
		dev:     d,
		proto:   "udp",
		src:     netip.AddrPortFrom(d.ip, uint16(40000+f.r.IntN(25000))),
		dst:     netip.AddrPortFrom(routerIP, 53),
		orig:    float64(60 + f.r.IntN(40)),
		repl:    float64(120 + f.r.IntN(200)),
		lan:     true,
		expires: now.Add(time.Duration(10+f.r.IntN(50)) * time.Second),
	}
}

// ---------------------------------------------------------------------------
// menus

func yesNo(b bool) string { return strconv.FormatBool(b) }

func (f *fakeRouter) leases() []map[string]string {
	var out []map[string]string
	for i, d := range f.devices {
		if d.lease == arpOnly {
			continue
		}
		mac, clientID := d.mac, "1:"+strings.ToLower(d.mac)
		m := map[string]string{
			".id":                "*" + strconv.FormatInt(int64(i+1), 16),
			"address":            d.ip.String(),
			"mac-address":        mac,
			"client-id":          clientID,
			"server":             "defconf",
			"status":             "bound",
			"active-address":     d.ip.String(),
			"active-mac-address": mac,
			"active-client-id":   clientID,
			"active-server":      "defconf",
			"expires-after":      fmt.Sprintf("%dm%ds", 3+i%7, (i*13)%60),
			"last-seen":          fmt.Sprintf("%ds", 5+(i*7)%50),
			"address-lists":      "",
			"dhcp-option":        "",
			"age":                "1w5d3h",
			"dynamic":            yesNo(d.lease == dynamicLease),
			"blocked":            "false",
			"disabled":           "false",
			"radius":             "false",
		}
		if d.hostname != "" {
			m["host-name"] = d.hostname
		}
		if d.classID != "" {
			m["class-id"] = d.classID
		}
		if d.comment != "" {
			m["comment"] = d.comment
		}
		out = append(out, m)
	}
	return out
}

func (f *fakeRouter) arp() []map[string]string {
	var out []map[string]string
	for i, d := range f.devices {
		out = append(out, map[string]string{
			".id":         "*" + strconv.FormatInt(int64(0x100+i), 16),
			"address":     d.ip.String(),
			"mac-address": d.mac,
			"interface":   "bridge",
			"status":      "reachable",
			"complete":    "true",
			"dynamic":     "true",
			"published":   "false",
			"invalid":     "false",
			"DHCP":        yesNo(d.lease != arpOnly),
			"disabled":    "false",
		})
	}
	return out
}

func (f *fakeRouter) connections() []map[string]string {
	out := make([]map[string]string, 0, len(f.conns))
	for _, c := range f.conns {
		orig, repl := uint64(c.orig), uint64(c.repl)
		m := map[string]string{
			".id":               c.id,
			"protocol":          c.proto,
			"src-address":       c.src.String(),
			"dst-address":       c.dst.String(),
			"reply-src-address": c.dst.String(),
			"reply-dst-address": c.src.String(),
			"orig-bytes":        strconv.FormatUint(orig, 10),
			"repl-bytes":        strconv.FormatUint(repl, 10),
			"orig-packets":      strconv.FormatUint(orig/1100+1, 10),
			"repl-packets":      strconv.FormatUint(repl/1100+1, 10),
			"orig-rate":         strconv.FormatUint(uint64(c.txRate*8), 10) + "bps",
			"repl-rate":         strconv.FormatUint(uint64(c.rxRate*8), 10) + "bps",
			"timeout":           "23h59m58s",
			"assured":           "true",
			"confirmed":         "true",
			"seen-reply":        "true",
			"expected":          "false",
			"dying":             "false",
			"fasttrack":         yesNo(c.fasttrack),
			"hw-offload":        "false",
			"srcnat":            yesNo(!c.lan),
			"dstnat":            "false",
		}
		if !c.lan {
			m["reply-dst-address"] = wanAddr + ":" + strconv.Itoa(int(c.src.Port()))
		}
		switch c.proto {
		case "tcp":
			m["tcp-state"] = "established"
		case "udp":
			m["timeout"] = "2m58s"
		}
		out = append(out, m)
	}
	return out
}

func (f *fakeRouter) deleteConn(w http.ResponseWriter, id string) {
	for i, c := range f.conns {
		if c.id == id {
			f.conns = slices.Delete(f.conns, i, i+1)
			f.log.Info("connection removed", "id", id, "src", c.src, "dst", c.dst)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	writeROSError(w, http.StatusNotFound, "Not Found", "no such item")
}

func (f *fakeRouter) resource() map[string]string {
	const total = 1 << 30
	return map[string]string{
		"uptime":                  formatUptime(f.now().Sub(f.booted)),
		"version":                 "7.20.4 (stable)",
		"build-time":              "2025-11-03 09:14:52",
		"factory-software":        "7.5",
		"free-memory":             strconv.Itoa(total - 260<<20 - f.r.IntN(12<<20)),
		"total-memory":            strconv.Itoa(total),
		"cpu":                     "ARM64",
		"cpu-count":               "4",
		"cpu-frequency":           "864",
		"cpu-load":                strconv.Itoa(3 + f.r.IntN(6)),
		"free-hdd-space":          "83431424",
		"total-hdd-space":         "134217728",
		"write-sect-since-reboot": "41730",
		"write-sect-total":        "1906815",
		"bad-blocks":              "0",
		"architecture-name":       "arm64",
		"board-name":              "hAP ax^3",
		"platform":                "MikroTik",
	}
}

// formatUptime renders d like RouterOS: "1w5d3h17m2s".
func formatUptime(d time.Duration) string {
	s := int64(d / time.Second)
	var b strings.Builder
	for _, u := range []struct {
		n    int64
		unit string
	}{{7 * 86400, "w"}, {86400, "d"}, {3600, "h"}, {60, "m"}, {1, "s"}} {
		if v := s / u.n; v > 0 {
			b.WriteString(strconv.FormatInt(v, 10) + u.unit)
			s -= v * u.n
		}
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}

// parseROSDuration parses "1d2h3m4s" (and Go-style "90s").
func parseROSDuration(s string) (time.Duration, bool) {
	var total time.Duration
	num := ""
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			num += string(r)
		case num != "" && strings.ContainsRune("wdhms", r):
			n, _ := strconv.Atoi(num)
			unit := map[rune]time.Duration{'w': 7 * 24 * time.Hour, 'd': 24 * time.Hour, 'h': time.Hour, 'm': time.Minute, 's': time.Second}[r]
			total += time.Duration(n) * unit
			num = ""
		default:
			return 0, false
		}
	}
	return total, num == "" && total > 0
}

// ---------------------------------------------------------------------------
// address lists (quarantine)

func listKey(address string) string {
	if p, err := netip.ParsePrefix(address); err == nil && p.IsSingleIP() {
		return p.Addr().Unmap().String()
	}
	if a, err := netip.ParseAddr(address); err == nil {
		return a.Unmap().String()
	}
	return strings.ToLower(strings.TrimSpace(address))
}

func (f *fakeRouter) quarantined(ip netip.Addr) bool {
	return slices.ContainsFunc(f.lists, func(e *listEntry) bool { return listKey(e.address) == ip.String() })
}

func (f *fakeRouter) expireLists(now time.Time) {
	f.lists = slices.DeleteFunc(f.lists, func(e *listEntry) bool {
		return !e.expires.IsZero() && !now.Before(e.expires)
	})
}

func (e *listEntry) object(now time.Time) map[string]string {
	m := map[string]string{
		".id":           e.id,
		"list":          e.list,
		"address":       e.address,
		"creation-time": e.created.Local().Format("2006-01-02 15:04:05"),
		"dynamic":       yesNo(!e.expires.IsZero()),
		"disabled":      "false",
	}
	if e.comment != "" {
		m["comment"] = e.comment
	}
	if !e.expires.IsZero() {
		m["timeout"] = formatUptime(e.expires.Sub(now))
	}
	return m
}

func (f *fakeRouter) addressList(w http.ResponseWriter, r *http.Request, id string) {
	now := f.now()
	switch {
	case r.Method == http.MethodGet && id == "":
		items := make([]map[string]string, 0, len(f.lists))
		for _, e := range f.lists {
			items = append(items, e.object(now))
		}
		writeList(w, r, items)
	case r.Method == http.MethodPut && id == "":
		var body map[string]string
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
			writeROSError(w, http.StatusBadRequest, "Bad Request", "invalid JSON")
			return
		}
		if body["list"] == "" || body["address"] == "" {
			writeROSError(w, http.StatusBadRequest, "Bad Request", "failure: list and address are required")
			return
		}
		for _, e := range f.lists {
			if e.list == body["list"] && listKey(e.address) == listKey(body["address"]) {
				writeROSError(w, http.StatusBadRequest, "Bad Request", "failure: already have such entry")
				return
			}
		}
		e := &listEntry{id: f.newID(), list: body["list"], address: body["address"], comment: body["comment"], created: now}
		if t := body["timeout"]; t != "" {
			d, ok := parseROSDuration(t)
			if !ok {
				writeROSError(w, http.StatusBadRequest, "Bad Request", "invalid value for argument timeout")
				return
			}
			e.expires = now.Add(d)
		}
		f.lists = append(f.lists, e)
		f.log.Info("address-list entry added", "list", e.list, "address", e.address, "comment", e.comment)
		writeJSON(w, http.StatusCreated, e.object(now))
	case r.Method == http.MethodDelete && id != "":
		for i, e := range f.lists {
			if e.id == id {
				f.lists = slices.Delete(f.lists, i, i+1)
				f.log.Info("address-list entry removed", "list", e.list, "address", e.address)
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		writeROSError(w, http.StatusNotFound, "Not Found", "no such item")
	default:
		writeROSError(w, http.StatusBadRequest, "Bad Request", "no such command")
	}
}

// ---------------------------------------------------------------------------
// responses

// filter applies RouterOS query semantics: "name=value" keeps matching items,
// ".proplist=a,b" limits the returned fields.
func filter(r *http.Request, items []map[string]string) []map[string]string {
	q := r.URL.Query()
	out := make([]map[string]string, 0, len(items))
next:
	for _, it := range items {
		for k, vs := range q {
			if !strings.HasPrefix(k, ".") && it[k] != vs[0] {
				continue next
			}
		}
		out = append(out, proplist(q.Get(".proplist"), it))
	}
	return out
}

func proplist(pl string, it map[string]string) map[string]string {
	if pl == "" {
		return it
	}
	m := map[string]string{}
	for _, k := range strings.Split(pl, ",") {
		if v, ok := it[k]; ok {
			m[k] = v
		}
	}
	return m
}

func writeList(w http.ResponseWriter, r *http.Request, items []map[string]string) {
	writeJSON(w, http.StatusOK, filter(r, items))
}

func writeObject(w http.ResponseWriter, r *http.Request, it map[string]string) {
	writeJSON(w, http.StatusOK, proplist(r.URL.Query().Get(".proplist"), it))
}

func writeROSError(w http.ResponseWriter, code int, msg, detail string) {
	body := map[string]any{"error": code, "message": msg}
	if detail != "" {
		body["detail"] = detail
	}
	writeJSON(w, code, body)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
