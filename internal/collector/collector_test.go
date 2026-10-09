package collector

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

type fakeAPI struct {
	leases []model.Lease
	arp    []model.ARPEntry
	conns  []model.Conn
	err    error
}

func (f *fakeAPI) DHCPLeases(context.Context) ([]model.Lease, error) { return f.leases, nil }
func (f *fakeAPI) ARP(context.Context) ([]model.ARPEntry, error)     { return f.arp, nil }
func (f *fakeAPI) Connections(context.Context) ([]model.Conn, error) {
	return f.conns, f.err
}
func (f *fakeAPI) Resource(context.Context) (model.Resource, error) { return model.Resource{}, nil }
func (f *fakeAPI) AddressListAdd(context.Context, string, string, string, time.Duration) error {
	return nil
}
func (f *fakeAPI) AddressListRemove(context.Context, string, string) error { return nil }

type fakeGeo struct{}

func (fakeGeo) Lookup(ip netip.Addr) (string, uint32, string) {
	if ip.Is6() {
		return "DE", 15169, "Google"
	}
	return "US", 13335, "Cloudflare"
}

var (
	lan  = []netip.Prefix{netip.MustParsePrefix("192.168.88.0/24"), netip.MustParsePrefix("2a01:5f0:1:2::/64")}
	macA = "AA:AA:AA:AA:AA:01"
	macB = "02:BB:BB:BB:BB:02"
	ipA  = netip.MustParseAddr("192.168.88.10")
	ipB  = netip.MustParseAddr("192.168.88.20")
	ipA6 = netip.MustParseAddr("2a01:5f0:1:2::10")
	t0   = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ap   = netip.MustParseAddrPort
)

func baseAPI() *fakeAPI {
	return &fakeAPI{
		leases: []model.Lease{
			{MAC: macA, IP: ipA, Hostname: "phone", ClassID: "android-dhcp-14", Status: "bound"},
			{MAC: "CC:CC:CC:CC:CC:03", IP: netip.MustParseAddr("192.168.88.30"), Hostname: "tv", Status: "waiting"},
			{MAC: "DD:DD:DD:DD:DD:04", IP: netip.MustParseAddr("10.0.0.5"), Status: "bound"}, // outside LAN
		},
		arp: []model.ARPEntry{
			{MAC: macB, IP: ipB, Interface: "bridge", Complete: true},                         // static client
			{MAC: "EE:EE:EE:EE:EE:05", IP: netip.MustParseAddr("100.64.0.1"), Complete: true}, // WAN gateway
			{MAC: "FF:FF:FF:FF:FF:06", IP: netip.MustParseAddr("192.168.88.40"), Complete: false},
			{MAC: macA, IP: ipA6, Complete: true}, // pretend IPv6 neighbour
		},
	}
}

func TestDevicesMerge(t *testing.T) {
	c := New(baseAPI(), nil, lan)
	s, err := c.Poll(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Devices) != 2 {
		t.Fatalf("devices = %+v", s.Devices)
	}
	a, b := s.Devices[0], s.Devices[1]
	if b.MAC != macA || b.IP != ipA || b.Hostname != "phone" || b.ClassID != "android-dhcp-14" || !b.LastSeen.Equal(t0) {
		t.Errorf("device A = %+v", b)
	}
	if a.MAC != macB || a.IP != ipB || a.Hostname != "" {
		t.Errorf("device B = %+v", a)
	}
}

func TestFlowDeltas(t *testing.T) {
	api := baseAPI()
	c := New(api, fakeGeo{}, lan)
	ctx := context.Background()
	// Priming poll with an empty table: everything below is "seen later".
	if _, err := c.Poll(ctx, t0.Add(-15*time.Second)); err != nil {
		t.Fatal(err)
	}

	api.conns = []model.Conn{
		{ID: "*1", Proto: "tcp", Src: ap("192.168.88.10:5000"), Dst: ap("1.1.1.1:443"), OrigBytes: 100, ReplBytes: 1000, Fasttrack: true, SrcNAT: true},
		{ID: "*2", Proto: "udp", Src: ap("192.168.88.20:6000"), Dst: ap("8.8.8.8:53"), OrigBytes: 50, ReplBytes: 70},
		{ID: "*3", Proto: "tcp", Src: ap("192.168.88.10:5001"), Dst: ap("192.168.88.20:22"), OrigBytes: 5, ReplBytes: 5}, // LAN->LAN
		{ID: "*4", Proto: "tcp", Src: ap("203.0.114.9:4444"), Dst: ap("192.168.88.10:80"), OrigBytes: 9, DstNAT: true},   // inbound
		{ID: "*5", Proto: "tcp", Src: ap("192.168.88.10:5002"), Dst: ap("10.1.1.1:443"), OrigBytes: 9},                   // private dst
		{ID: "*6", Proto: "tcp", Src: ap("192.168.88.10:5003"), Dst: ap("100.64.1.1:443"), OrigBytes: 9},                 // CGNAT dst
		{ID: "*7", Proto: "tcp", Src: ap("192.168.88.99:5004"), Dst: ap("9.9.9.9:443"), OrigBytes: 9},                    // unknown MAC
		{ID: "*8", Proto: "icmp", Src: netip.AddrPortFrom(ipA, 0), Dst: netip.AddrPortFrom(netip.MustParseAddr("9.9.9.9"), 0), OrigBytes: 84, ReplBytes: 84},
		{ID: "*9", Proto: "tcp", Src: netip.AddrPortFrom(ipA6, 40000), Dst: ap("[2a00:1450:4001::1]:443"), OrigBytes: 10, ReplBytes: 20},
		{ID: "*10", Proto: "tcp", Src: netip.AddrPortFrom(ipA6, 40001), Dst: ap("[2a01:5f0:1:2::99]:443"), OrigBytes: 10}, // v6 LAN->LAN (global prefix)
		{ID: "*11", Proto: "udp", Src: ap("192.168.88.10:5005"), Dst: ap("224.0.0.251:5353"), OrigBytes: 9},               // multicast
	}
	s1, err := c.Poll(ctx, t0)
	if err != nil {
		t.Fatal(err)
	}
	if s1.ConnCount != 11 || s1.FasttrackCount != 1 {
		t.Errorf("counts = %d/%d", s1.ConnCount, s1.FasttrackCount)
	}
	got := byDst(s1.Flows)
	if len(s1.Flows) != 4 {
		t.Fatalf("flows = %+v", s1.Flows)
	}
	f1 := got["1.1.1.1:443"]
	if !f1.NewConn || f1.TxBytes != 100 || f1.RxBytes != 1000 || f1.DeviceMAC != macA || !f1.Fasttrack ||
		f1.Country != "US" || f1.ASN != 13335 || f1.ASOrg != "Cloudflare" || !f1.Time.Equal(t0) {
		t.Errorf("f1 = %+v", f1)
	}
	if f := got["8.8.8.8:53"]; f.DeviceMAC != macB || f.TxBytes != 50 {
		t.Errorf("f2 = %+v", f)
	}
	if f := got["9.9.9.9:0"]; f.Proto != "icmp" || f.TxBytes != 84 {
		t.Errorf("icmp = %+v", f)
	}
	if f := got["[2a00:1450:4001::1]:443"]; f.DeviceMAC != macA || f.Country != "DE" || f.DeviceIP != ipA6 {
		t.Errorf("ipv6 = %+v", f)
	}
	if s1.VisibleTx != 100+50+84+10 || s1.VisibleRx != 1000+70+84+20 {
		t.Errorf("visible = %d/%d", s1.VisibleTx, s1.VisibleRx)
	}

	// Poll 2: *1 grows, *2 idle (not emitted), *8 gone, *9 counters decreased (id reuse).
	api.conns = []model.Conn{
		{ID: "*1", Proto: "tcp", Src: ap("192.168.88.10:5000"), Dst: ap("1.1.1.1:443"), OrigBytes: 150, ReplBytes: 3000, Fasttrack: true},
		{ID: "*2", Proto: "udp", Src: ap("192.168.88.20:6000"), Dst: ap("8.8.8.8:53"), OrigBytes: 50, ReplBytes: 70},
		{ID: "*9", Proto: "tcp", Src: netip.AddrPortFrom(ipA6, 40000), Dst: ap("[2a00:1450:4001::1]:443"), OrigBytes: 5, ReplBytes: 5}, // counter decrease
	}
	s2, err := c.Poll(ctx, t0.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	got = byDst(s2.Flows)
	if len(s2.Flows) != 2 {
		t.Fatalf("flows2 = %+v", s2.Flows)
	}
	if f := got["1.1.1.1:443"]; f.NewConn || f.TxBytes != 50 || f.RxBytes != 2000 {
		t.Errorf("delta = %+v", f)
	}
	if f := got["[2a00:1450:4001::1]:443"]; !f.NewConn || f.TxBytes != 5 || f.RxBytes != 5 {
		t.Errorf("reuse by decrease = %+v", f)
	}
	if s2.VisibleTx != 55 || s2.VisibleRx != 2005 {
		t.Errorf("visible2 = %d/%d", s2.VisibleTx, s2.VisibleRx)
	}
	// *1, *2, *9 tracked; *7 (unknown MAC) evicted because it vanished.
	if n := c.TrackedConns(); n != 3 {
		t.Errorf("tracked = %d", n)
	}

	// Poll 3: id *1 reused for a different tuple with larger counters -> new.
	api.conns = []model.Conn{
		{ID: "*1", Proto: "tcp", Src: ap("192.168.88.20:7000"), Dst: ap("1.0.0.1:443"), OrigBytes: 500, ReplBytes: 5000},
	}
	s3, err := c.Poll(ctx, t0.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(s3.Flows) != 1 || !s3.Flows[0].NewConn || s3.Flows[0].TxBytes != 500 || s3.Flows[0].DeviceMAC != macB {
		t.Errorf("reuse by tuple = %+v", s3.Flows)
	}
	if n := c.TrackedConns(); n != 1 {
		t.Errorf("tracked after eviction = %d", n)
	}

	// Eviction: a conn that disappears and comes back counts as new.
	api.conns = nil
	if _, err := c.Poll(ctx, t0.Add(45*time.Second)); err != nil {
		t.Fatal(err)
	}
	if n := c.TrackedConns(); n != 0 {
		t.Errorf("tracked after empty = %d", n)
	}
}

func TestPollErrorKeepsState(t *testing.T) {
	api := baseAPI()
	c := New(api, nil, lan)
	api.conns = []model.Conn{{ID: "*1", Proto: "tcp", Src: ap("192.168.88.10:5000"), Dst: ap("1.1.1.1:443"), OrigBytes: 100}}
	if _, err := c.Poll(context.Background(), t0); err != nil {
		t.Fatal(err)
	}
	api.err = errors.New("boom")
	if _, err := c.Poll(context.Background(), t0); err == nil {
		t.Fatal("expected error")
	}
	api.err = nil
	api.conns[0].OrigBytes = 130
	s, err := c.Poll(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Flows) != 1 || s.Flows[0].NewConn || s.Flows[0].TxBytes != 30 {
		t.Errorf("flows = %+v", s.Flows)
	}
}

func TestIsPublic(t *testing.T) {
	cases := map[string]bool{
		"1.1.1.1": true, "8.8.8.8": true, "2a00:1450::1": true, "::ffff:1.1.1.1": true,
		"10.0.0.1": false, "172.16.0.1": false, "192.168.1.1": false, "127.0.0.1": false,
		"169.254.1.1": false, "224.0.0.1": false, "100.64.0.1": false, "255.255.255.255": false,
		"0.0.0.0": false, "fe80::1": false, "fd00::1": false, "ff02::1": false, "::1": false, "2001:db8::1": false,
	}
	for s, want := range cases {
		if got := IsPublic(netip.MustParseAddr(s)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", s, got, want)
		}
	}
}

func byDst(fs []model.FlowSample) map[string]model.FlowSample {
	m := make(map[string]model.FlowSample, len(fs))
	for _, f := range fs {
		m[f.Dst.String()] = f
	}
	return m
}

func TestFirstPollPrimesOnly(t *testing.T) {
	api := baseAPI()
	c := New(api, fakeGeo{}, lan)
	ctx := context.Background()
	api.conns = []model.Conn{
		// Long-lived connection with a big history (e.g. a cloud plug).
		{ID: "*1", Proto: "tcp", Src: ap("192.168.88.10:5000"), Dst: ap("1.1.1.1:443"), OrigBytes: 18_800_000, ReplBytes: 5_000_000, Fasttrack: true},
		{ID: "*2", Proto: "udp", Src: ap("192.168.88.20:6000"), Dst: ap("8.8.8.8:53"), OrigBytes: 50, ReplBytes: 70},
	}
	s1, err := c.Poll(ctx, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s1.Flows) != 0 || s1.VisibleTx != 0 || s1.VisibleRx != 0 {
		t.Errorf("first poll emitted flows: %+v", s1)
	}
	if len(s1.Devices) != 2 || s1.ConnCount != 2 || s1.FasttrackCount != 1 {
		t.Errorf("first poll devices/counts = %d %d/%d", len(s1.Devices), s1.ConnCount, s1.FasttrackCount)
	}
	if n := c.TrackedConns(); n != 2 {
		t.Errorf("tracked = %d", n)
	}

	// Poll 2: *1 grows by a small delta, *2 idle, *3 is genuinely new.
	api.conns = []model.Conn{
		{ID: "*1", Proto: "tcp", Src: ap("192.168.88.10:5000"), Dst: ap("1.1.1.1:443"), OrigBytes: 18_800_100, ReplBytes: 5_000_200, Fasttrack: true},
		{ID: "*2", Proto: "udp", Src: ap("192.168.88.20:6000"), Dst: ap("8.8.8.8:53"), OrigBytes: 50, ReplBytes: 70},
		{ID: "*3", Proto: "tcp", Src: ap("192.168.88.20:6001"), Dst: ap("9.9.9.9:443"), OrigBytes: 300, ReplBytes: 400},
	}
	s2, err := c.Poll(ctx, t0.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	got := byDst(s2.Flows)
	if len(s2.Flows) != 2 {
		t.Fatalf("flows2 = %+v", s2.Flows)
	}
	if f := got["1.1.1.1:443"]; f.NewConn || f.TxBytes != 100 || f.RxBytes != 200 {
		t.Errorf("primed conn = %+v", f)
	}
	if f := got["9.9.9.9:443"]; !f.NewConn || f.TxBytes != 300 || f.RxBytes != 400 {
		t.Errorf("new conn = %+v", f)
	}
}

func TestFirstPollErrorDoesNotPrime(t *testing.T) {
	api := baseAPI()
	c := New(api, nil, lan)
	api.err = errors.New("boom")
	if _, err := c.Poll(context.Background(), t0); err == nil {
		t.Fatal("expected error")
	}
	api.err = nil
	api.conns = []model.Conn{{ID: "*1", Proto: "tcp", Src: ap("192.168.88.10:5000"), Dst: ap("1.1.1.1:443"), OrigBytes: 1 << 30}}
	s, err := c.Poll(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Flows) != 0 {
		t.Errorf("first successful poll must only prime: %+v", s.Flows)
	}
}

func TestIgnoreIPs(t *testing.T) {
	api := baseAPI()
	c := New(api, nil, lan)
	c.IgnoreIPs(ipB, netip.Addr{}) // invalid address is a no-op
	ctx := context.Background()
	if _, err := c.Poll(ctx, t0); err != nil { // prime
		t.Fatal(err)
	}
	api.conns = []model.Conn{
		{ID: "*1", Proto: "tcp", Src: ap("192.168.88.20:6000"), Dst: ap("1.1.1.1:443"), OrigBytes: 10},
		{ID: "*2", Proto: "tcp", Src: ap("192.168.88.10:6000"), Dst: ap("1.1.1.1:443"), OrigBytes: 20},
	}
	s, err := c.Poll(ctx, t0.Add(15*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Devices) != 1 || s.Devices[0].MAC != macA {
		t.Errorf("devices = %+v", s.Devices)
	}
	if len(s.Flows) != 1 || s.Flows[0].DeviceMAC != macA || s.VisibleTx != 20 {
		t.Errorf("flows = %+v", s.Flows)
	}

	// Ignoring one address of a dual-stack device drops the device and all its flows.
	c.IgnoreIPs(netip.MustParseAddr("::ffff:192.168.88.10"))
	api.conns = append(api.conns, model.Conn{ID: "*3", Proto: "tcp", Src: netip.AddrPortFrom(ipA6, 4000), Dst: ap("[2a00:1450:4001::1]:443"), OrigBytes: 5})
	s, err = c.Poll(ctx, t0.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Devices) != 0 || len(s.Flows) != 0 {
		t.Errorf("after ignoring A: devices=%+v flows=%+v", s.Devices, s.Flows)
	}
}

func TestLeaseComment(t *testing.T) {
	api := baseAPI()
	api.leases = append(api.leases,
		model.Lease{MAC: macB, IP: ipB, Status: "waiting", Comment: "Tiskarna"},
	)
	api.leases[0].Comment = "Alexuv telefon"
	c := New(api, nil, lan)
	s, err := c.Poll(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	cm := map[string]string{}
	for _, d := range s.Devices {
		cm[d.MAC] = d.Comment
	}
	if cm[macA] != "Alexuv telefon" || cm[macB] != "Tiskarna" {
		t.Errorf("comments = %v", cm)
	}
}
