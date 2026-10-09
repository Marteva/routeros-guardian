// Package collector turns raw RouterOS tables into Guardian snapshots: a merged
// device list (DHCP leases + ARP) and per-connection traffic deltas for
// LAN -> internet flows.
package collector

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// Snapshot is the result of one poll.
type Snapshot struct {
	Time                 time.Time
	Devices              []model.Device     // merged DHCP leases + ARP, MAC upper-case, LastSeen=Time
	Flows                []model.FlowSample // only LAN->internet, deltas since previous poll, geo filled
	ConnCount            int                // whole conntrack table
	FasttrackCount       int                // fasttracked entries in the table
	VisibleTx, VisibleRx uint64             // sum of emitted deltas this poll
}

// Collector polls a RouterAPI and keeps per-connection counter state between
// polls. It is safe for concurrent use (polls are serialized).
type Collector struct {
	api model.RouterAPI
	geo model.GeoLookup
	lan []netip.Prefix

	mu     sync.Mutex
	gen    uint64
	primed bool // first successful Poll done (baseline counters recorded)
	conns  map[string]connState
	ignore map[netip.Addr]struct{}
}

// connState is the last seen counters of one tracked conntrack entry.
type connState struct {
	src, dst   netip.AddrPort
	orig, repl uint64
	gen        uint64 // poll generation in which the entry was last seen
}

// New creates a Collector. geo may be nil (no geo enrichment).
func New(api model.RouterAPI, geo model.GeoLookup, lan []netip.Prefix) *Collector {
	ps := make([]netip.Prefix, 0, len(lan))
	for _, p := range lan {
		if p.IsValid() {
			ps = append(ps, p.Masked())
		}
	}
	return &Collector{api: api, geo: geo, lan: ps, conns: make(map[string]connState), ignore: make(map[netip.Addr]struct{})}
}

// IgnoreIPs excludes the given addresses (typically Guardian's own container
// interfaces) from monitoring: devices with such an IP are dropped from
// Snapshot.Devices and connections originating from them produce no flows.
// Calls are cumulative; invalid addresses are ignored.
func (c *Collector) IgnoreIPs(ips ...netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, ip := range ips {
		if ip.IsValid() {
			c.ignore[ip.Unmap()] = struct{}{}
		}
	}
}

func (c *Collector) ignored(ip netip.Addr) bool {
	_, ok := c.ignore[ip.Unmap()]
	return ok
}

// Poll fetches leases, ARP and the connection table and computes a Snapshot.
// On error the per-connection state is left untouched.
//
// The first successful Poll after New only primes the per-connection counters:
// connections that already exist then may be hours old, and emitting their
// whole history as one delta would poison the detection baselines. It returns
// devices and table counts but no flows. Connections first seen by later polls
// started within one poll interval and are emitted in full with NewConn=true.
func (c *Collector) Poll(ctx context.Context, now time.Time) (Snapshot, error) {
	leases, err := c.api.DHCPLeases(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("dhcp leases: %w", err)
	}
	arp, err := c.api.ARP(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("arp: %w", err)
	}
	conns, err := c.api.Connections(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("connections: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	devices, ipToMAC := c.mergeDevices(leases, arp, now)
	snap := Snapshot{Time: now, Devices: devices, ConnCount: len(conns)}
	priming := !c.primed
	c.primed = true
	c.gen++
	for i := range conns {
		cn := &conns[i]
		if cn.Fasttrack {
			snap.FasttrackCount++
		}
		if cn.ID == "" || !c.outbound(cn) {
			continue
		}
		src := cn.Src.Addr()
		prev, seen := c.conns[cn.ID]
		// A changed tuple or a counter decrease means RouterOS reused the id.
		isNew := !seen || prev.src != cn.Src || prev.dst != cn.Dst ||
			cn.OrigBytes < prev.orig || cn.ReplBytes < prev.repl
		tx, rx := cn.OrigBytes, cn.ReplBytes
		if !isNew {
			tx -= prev.orig
			rx -= prev.repl
		}
		c.conns[cn.ID] = connState{src: cn.Src, dst: cn.Dst, orig: cn.OrigBytes, repl: cn.ReplBytes, gen: c.gen}

		if priming {
			continue // baseline only, see Poll doc
		}
		mac, ok := ipToMAC[src]
		if !ok || (!isNew && tx == 0 && rx == 0) || c.ignored(src) {
			continue // unknown device, idle connection or ignored source
		}
		fs := model.FlowSample{
			Time:      now,
			DeviceMAC: mac,
			DeviceIP:  src,
			Dst:       cn.Dst,
			Proto:     cn.Proto,
			TxBytes:   tx,
			RxBytes:   rx,
			NewConn:   isNew,
			Fasttrack: cn.Fasttrack,
		}
		if c.geo != nil {
			fs.Country, fs.ASN, fs.ASOrg = c.geo.Lookup(cn.Dst.Addr())
		}
		snap.Flows = append(snap.Flows, fs)
		snap.VisibleTx += tx
		snap.VisibleRx += rx
	}
	for id, st := range c.conns {
		if st.gen != c.gen {
			delete(c.conns, id)
		}
	}
	return snap, nil
}

// TrackedConns reports how many connection entries are currently tracked.
func (c *Collector) TrackedConns() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.conns)
}

// outbound reports whether cn was originated in the LAN towards a public
// internet address. Inbound dst-NAT (port forwards, hairpin) is ignored.
func (c *Collector) outbound(cn *model.Conn) bool {
	if cn.DstNAT || !cn.Src.IsValid() || !cn.Dst.IsValid() {
		return false
	}
	return c.inLAN(cn.Src.Addr()) && !c.inLAN(cn.Dst.Addr()) && IsPublic(cn.Dst.Addr())
}

func (c *Collector) inLAN(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range c.lan {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// nonPublic lists special-purpose ranges that netip's predicates do not cover.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), // reserved + broadcast
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("100::/64"),
}

// IsPublic reports whether ip is a globally routable unicast address
// (not private, loopback, link-local, multicast, CGNAT or documentation).
func IsPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// mergeDevices merges leases and ARP by MAC. A device is present when it has a
// bound lease or a complete ARP entry with an IP inside the LAN. Lease metadata
// (hostname, class-id) is applied even from non-bound leases.
func (c *Collector) mergeDevices(leases []model.Lease, arp []model.ARPEntry, now time.Time) ([]model.Device, map[netip.Addr]string) {
	meta := make(map[string]model.Lease, len(leases))
	comment := make(map[string]string)
	byMAC := make(map[string]*model.Device)
	ipToMAC := make(map[netip.Addr]string, len(leases)+len(arp))
	get := func(mac string) *model.Device {
		d, ok := byMAC[mac]
		if !ok {
			d = &model.Device{MAC: mac, FirstSeen: now, LastSeen: now}
			byMAC[mac] = d
		}
		return d
	}

	for _, l := range leases {
		mac := strings.ToUpper(l.MAC)
		if mac == "" {
			continue
		}
		bound := l.Status == "bound" || l.Status == ""
		if old, ok := meta[mac]; !ok || bound || old.Hostname == "" {
			meta[mac] = l
		}
		if l.Comment != "" && comment[mac] == "" {
			comment[mac] = l.Comment
		}
		ip := l.IP.Unmap()
		if bound && c.inLAN(ip) {
			get(mac).IP = ip
			ipToMAC[ip] = mac
		}
	}
	for _, a := range arp {
		mac := strings.ToUpper(a.MAC)
		ip := a.IP.Unmap()
		if mac == "" || !a.Complete || !c.inLAN(ip) {
			continue
		}
		d := get(mac)
		if !d.IP.IsValid() {
			d.IP = ip
		}
		ipToMAC[ip] = mac // ARP reflects the live binding, it wins over leases
	}

	// Ignored IPs (Guardian itself) drop the whole device, including its other
	// addresses, so none of its connections are attributed to anyone.
	if len(c.ignore) > 0 {
		for ip, mac := range ipToMAC {
			if c.ignored(ip) {
				delete(byMAC, mac)
			}
		}
		for ip, mac := range ipToMAC {
			if _, ok := byMAC[mac]; !ok {
				delete(ipToMAC, ip)
			}
		}
	}

	out := make([]model.Device, 0, len(byMAC))
	for mac, d := range byMAC {
		if l, ok := meta[mac]; ok {
			d.Hostname = l.Hostname
			d.ClassID = l.ClassID
		}
		d.Comment = comment[mac]
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, ipToMAC
}
