package main

import (
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Everything in this file is fictional: the household, its device names and
// MAC suffixes are made up. MAC prefixes are real vendor OUIs (so the vendor
// column looks like on a real network) and the destinations are public
// networks of well-known operators.

const (
	kB = float64(1 << 10)
	mB = float64(1 << 20)
	gB = float64(1 << 30)
)

// destination is a set of internet servers of one operator in one country.
// Every /24 below resolves to exactly this country and ASN in DB-IP Lite
// (see TestCatalogMatchesGeoIP), so the seeded statistics and the live
// traffic of the fake router agree whether or not Guardian has GeoIP files.
type destination struct {
	nets    []netip.Prefix
	country string
	asn     uint32
	org     string
	ports   []uint16
	udp     float64 // share of UDP flows (QUIC)
}

func dest(country string, asn uint32, org string, ports []uint16, udp float64, nets ...string) *destination {
	d := &destination{country: country, asn: asn, org: org, ports: ports, udp: udp}
	for _, n := range nets {
		d.nets = append(d.nets, netip.MustParsePrefix(n+".0/24"))
	}
	return d
}

var (
	https  = []uint16{443}
	iotTLS = []uint16{443, 8883} // HTTPS and MQTT over TLS

	googleUS     = dest("US", 15169, "Google LLC", https, 0.4, "209.85.233", "216.239.38")
	googleDE     = dest("DE", 15169, "Google LLC", https, 0.4, "172.217.18")
	gcpUS        = dest("US", 396982, "Google LLC", https, 0, "35.186.224", "104.199.65")
	awsDE        = dest("DE", 16509, "Amazon.com, Inc.", iotTLS, 0, "3.120.0", "52.28.10", "18.192.0", "3.64.0", "35.156.0", "54.93.0", "52.57.0")
	awsUS        = dest("US", 16509, "Amazon.com, Inc.", https, 0, "54.239.28", "52.94.236", "52.84.0", "143.204.0")
	awsIE        = dest("IE", 16509, "Amazon.com, Inc.", iotTLS, 0, "52.208.0", "34.240.0", "18.66.0")
	cloudflareUS = dest("US", 395747, "Cloudflare, Inc.", https, 0.3, "198.41.128")
	netflixUS    = dest("US", 2906, "Netflix Streaming Services Inc.", https, 0, "37.77.184", "108.175.32", "192.173.64")
	microsoftIE  = dest("IE", 8075, "Microsoft Corporation", https, 0, "20.190.159", "52.169.0", "20.54.0")
	microsoftUS  = dest("US", 8068, "Microsoft Corporation", https, 0.2, "13.107.42", "52.113.194")
	microsoftNL  = dest("NL", 8075, "Microsoft Corporation", https, 0, "20.50.0", "13.69.0")
	appleUS      = dest("US", 714, "Apple Inc.", https, 0.2, "17.57.144", "17.248.0", "17.142.0")
	appleNL      = dest("NL", 6185, "Apple Inc.", https, 0, "17.253.53")
	akamaiDE     = dest("DE", 20940, "Akamai International B.V.", https, 0, "2.18.0")
	akamaiUS     = dest("US", 20940, "Akamai International B.V.", https, 0, "23.48.0", "23.200.0")
	metaDE       = dest("DE", 32934, "Facebook, Inc.", https, 0.5, "157.240.0")
	hetznerDE    = dest("DE", 24940, "Hetzner Online GmbH", []uint16{22, 443}, 0, "88.198.0", "78.46.0", "136.243.0", "116.202.0")
	seznamCZ     = dest("CZ", 43037, "Seznam.cz, a.s.", https, 0, "77.75.75", "77.75.77")
	cesnetCZ     = dest("CZ", 2852, "CESNET z.s.p.o.", []uint16{123}, 1, "195.113.144") // NTP
	valveNL      = dest("NL", 32590, "Valve Corporation", []uint16{443, 27036}, 0.3, "155.133.248")
	zoomUS       = dest("US", 30103, "Zoom Video Communications, Inc", []uint16{443, 8801}, 0.5, "206.247.0", "144.195.0")
	mikrotikLV   = dest("LV", 51894, "Mikrotikls SIA", https, 0, "159.148.147", "159.148.172")
	chinanetCN   = dest("CN", 4134, "Chinanet", []uint16{443, 7661}, 0, "218.92.0", "61.160.0")

	// catalog lists every destination (tests check it against GeoIP).
	catalog = []*destination{googleUS, googleDE, gcpUS, awsDE, awsUS, awsIE, cloudflareUS, netflixUS,
		microsoftIE, microsoftUS, microsoftNL, appleUS, appleNL, akamaiDE, akamaiUS, metaDE, hetznerDE,
		seznamCZ, cesnetCZ, valveNL, zoomUS, mikrotikLV, chinanetCN}

	// scanPorts are the ports the "infected" robot vacuum probes.
	scanPorts = []uint16{22, 23, 80, 2323, 7547, 8080}
)

// randomAddr returns a random host address in one of d's networks.
func (d *destination) randomAddr(r *rand.Rand) netip.Addr {
	b := d.nets[r.IntN(len(d.nets))].Addr().As4()
	b[3] = byte(2 + r.IntN(252))
	return netip.AddrFrom4(b)
}

type weighted struct {
	d *destination
	w float64
}

func pick(r *rand.Rand, ws []weighted) *destination {
	total := 0.0
	for _, w := range ws {
		total += w.w
	}
	x := r.Float64() * total
	for _, w := range ws {
		if x < w.w {
			return w.d
		}
		x -= w.w
	}
	return ws[len(ws)-1].d
}

// ---------------------------------------------------------------------------
// activity patterns (local time, 0..1)

func weekend(t time.Time) bool { return t.Weekday() == time.Saturday || t.Weekday() == time.Sunday }

func always(time.Time) float64 { return 1 }

// evenings: TV and game console.
func evenings(t time.Time) float64 {
	t = t.Local()
	switch h := t.Hour(); {
	case h >= 19 && h <= 22:
		return 1
	case h == 18 || h == 23:
		return 0.5
	case weekend(t) && h >= 10 && h < 18:
		return 0.4
	}
	return 0
}

// phoneHours: at home in the morning and evening, away on weekdays.
func phoneHours(t time.Time) float64 {
	t = t.Local()
	switch h := t.Hour(); {
	case h < 6:
		return 0
	case h < 9:
		return 0.7
	case h < 17:
		if weekend(t) {
			return 0.6
		}
		return 0.05
	case h < 23:
		return 1
	}
	return 0.3
}

// officeHours: the work laptop on its dock.
func officeHours(t time.Time) float64 {
	t = t.Local()
	h := t.Hour()
	switch {
	case weekend(t) || h < 8 || h >= 17:
		return 0
	case h == 12:
		return 0.5
	}
	return 1
}

// laptopAtHome: the work laptop on Wi-Fi after work.
func laptopAtHome(t time.Time) float64 {
	t = t.Local()
	h := t.Hour()
	switch {
	case weekend(t) && h >= 10 && h < 18:
		return 0.3
	case !weekend(t) && h >= 19 && h < 22:
		return 0.5
	}
	return 0
}

// pcHours: the family PC.
func pcHours(t time.Time) float64 {
	t = t.Local()
	h := t.Hour()
	switch {
	case weekend(t) && h >= 10 && h < 24:
		return 0.8
	case h >= 17 && h < 23:
		return 1
	}
	return 0
}

// backupWindow: nightly NAS backup.
func backupWindow(t time.Time) float64 {
	if h := t.Local().Hour(); h >= 1 && h < 4 {
		return 1
	}
	return 0
}

// speakerHours: music at breakfast and dinner.
func speakerHours(t time.Time) float64 {
	t = t.Local()
	switch h := t.Hour(); {
	case h >= 6 && h < 8:
		return 1
	case h >= 17 && h < 21:
		return 0.8
	case weekend(t) && h >= 9 && h < 12:
		return 0.6
	}
	return 0
}

// daylight: motion events at the front door.
func daylight(t time.Time) float64 {
	if h := t.Local().Hour(); h >= 7 && h < 21 {
		return 1
	}
	return 0
}

// cleaning: the robot vacuum runs on weekday mornings.
func cleaning(t time.Time) float64 {
	t = t.Local()
	if !weekend(t) && t.Hour() == 10 {
		return 1
	}
	return 0
}

// load is traffic per hour.
type load struct{ tx, rx, conns, dsts float64 }

// profile: base + pattern(t) * peak, per hour.
type profile struct {
	pattern    func(time.Time) float64
	base, peak load
}

func (p profile) at(t time.Time) load {
	a := 0.0
	if p.pattern != nil {
		a = p.pattern(t)
	}
	return load{
		tx:    p.base.tx + a*p.peak.tx,
		rx:    p.base.rx + a*p.peak.rx,
		conns: p.base.conns + a*p.peak.conns,
		dsts:  p.base.dsts + a*p.peak.dsts,
	}
}

// ---------------------------------------------------------------------------
// timeline

// timeline anchors the story to "now". All seeded times derive from it.
type timeline struct {
	now        time.Time
	hour       time.Time // start of the current clock hour
	learnStart time.Time // Guardian installed, learning started (12 days ago)
	rotate     time.Time // Alex's iPhone switched to a new private MAC
	guestJoin  time.Time // the guest tablet joined
	espJoin    time.Time // the unknown ESP device joined
	cnHour     time.Time // the garden camera first talks to China
	spikeHour  time.Time // ... and uploads 2.8 GB (last completed hour)
	fanoutHour time.Time // the robot vacuum scans the internet
}

func newTimeline(now time.Time) timeline {
	now = now.UTC().Truncate(time.Second)
	h := now.Truncate(time.Hour)
	return timeline{
		now:        now,
		hour:       h,
		learnStart: now.Add(-12 * 24 * time.Hour).Truncate(time.Minute),
		rotate:     h.Add(-4*24*time.Hour + 17*time.Minute),
		guestJoin:  now.Add(-30 * time.Hour).Truncate(time.Minute),
		espJoin:    now.Add(-2 * time.Hour).Truncate(time.Minute),
		cnHour:     h.Add(-3 * time.Hour),
		spikeHour:  h.Add(-time.Hour),
		fanoutHour: h.Add(-27 * time.Hour),
	}
}

// inventoryEnd is when the detector's initial inventory (first 24 h) ended.
func (tl timeline) inventoryEnd() time.Time { return tl.learnStart.Add(24 * time.Hour) }

func atInstall(after time.Duration) func(timeline) time.Time {
	return func(tl timeline) time.Time { return tl.learnStart.Add(after) }
}

// ---------------------------------------------------------------------------
// devices

type leaseKind int

const (
	arpOnly leaseKind = iota
	staticLease
	dynamicLease
)

// Device ids used by the story (seeding, alerts, tests).
const (
	idTV         = "tv"
	idGardenCam  = "garden-camera"
	idDoorbell   = "doorbell"
	idSpeaker    = "speaker"
	idIPhoneOld  = "iphone-old"
	idIPhone     = "iphone"
	idGalaxy     = "galaxy"
	idLaptopWiFi = "laptop-wifi"
	idLaptopDock = "laptop-dock"
	idPC         = "pc"
	idNAS        = "nas"
	idPrinter    = "printer"
	idThermostat = "thermostat"
	idVacuum     = "vacuum"
	idPlug       = "plug"
	idHue        = "hue"
	idConsole    = "console"
	idGuestTab   = "guest-tablet"
	idESP        = "esp"
	idAP         = "ap"
)

type device struct {
	id           string
	mac          string
	ip           netip.Addr
	hostname     string
	classID      string
	comment      string // static DHCP lease comment (friendly name on the router)
	note         string // friendly name typed in the Guardian UI
	kindOverride string // kind chosen in the UI
	groupID      string // manual merge (MAC of the primary)
	lease        leaseKind
	wantKind     string // what fingerprint.Enrich guesses (checked by tests)

	joined func(timeline) time.Time
	left   func(timeline) time.Time // nil = online now

	profile profile
	dests   []weighted
	// liveDests replace dests for the current hour and the fake router
	// (nil = dests): the garden camera keeps talking to China.
	liveDests []weighted
}

func (d *device) online() bool { return d.left == nil }

func (d *device) lastSeen(tl timeline) time.Time {
	if d.left == nil {
		return tl.now
	}
	return d.left(tl)
}

func (d *device) destsAt(tl timeline, hour time.Time) []weighted {
	if d.liveDests != nil && !hour.Before(tl.hour) {
		return d.liveDests
	}
	return d.dests
}

func (d *device) liveDestinations() []weighted {
	if d.liveDests != nil {
		return d.liveDests
	}
	return d.dests
}

// household is the fictional home network.
type household struct {
	devices []*device
	byID    map[string]*device
}

func (h *household) get(id string) *device { return h.byID[id] }

func (h *household) online() []*device {
	var out []*device
	for _, d := range h.devices {
		if d.online() {
			out = append(out, d)
		}
	}
	return out
}

// vendorMAC returns oui (6 hex digits) followed by a random suffix.
func vendorMAC(r *rand.Rand, oui string) string {
	return fmt.Sprintf("%s:%s:%s:%02X:%02X:%02X", oui[0:2], oui[2:4], oui[4:6], r.IntN(256), r.IntN(256), r.IntN(256))
}

// privateMAC returns a random locally administered unicast MAC, as phones
// use per network.
func privateMAC(r *rand.Rand) string {
	b := make([]byte, 6)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	b[0] = b[0]&^0x01 | 0x02
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", b[0], b[1], b[2], b[3], b[4], b[5])
}

func ip(last byte) netip.Addr { return netip.AddrFrom4([4]byte{192, 168, 88, last}) }

// newHousehold builds the fictional household. MACs come from a fixed seed,
// so they are the same on every run (the fake router and a reused database
// must agree).
func newHousehold() *household {
	r := rand.New(rand.NewPCG(0x6775617264, 0x69616e)) // "guard", "ian"
	start := atInstall(0)
	devs := []*device{
		{
			id: idTV, mac: vendorMAC(r, "64995D"), ip: ip(30), hostname: "LGwebOSTV",
			comment: "Living room TV", lease: staticLease, wantKind: "tv", joined: start,
			profile: profile{evenings, load{1 * mB, 4 * mB, 4, 3}, load{45 * mB, 2.3 * gB, 60, 12}},
			dests:   []weighted{{netflixUS, 5}, {googleUS, 2.5}, {awsIE, 1}, {akamaiDE, 1}},
		},
		{
			id: idGardenCam, mac: vendorMAC(r, "BCAD28"), ip: ip(20),
			comment: "Garden camera", lease: staticLease, wantKind: "camera", joined: start,
			profile:   profile{always, load{62 * mB, 2.5 * mB, 6, 2}, load{}},
			dests:     []weighted{{awsDE, 8}, {awsIE, 2}},
			liveDests: []weighted{{awsDE, 7}, {awsIE, 1.5}, {chinanetCN, 1.5}},
		},
		{
			id: idDoorbell, mac: vendorMAC(r, "EC71DB"), ip: ip(21), hostname: "Reolink-Doorbell",
			comment: "Doorbell camera", lease: staticLease, wantKind: "camera", joined: start,
			profile: profile{daylight, load{14 * mB, 1 * mB, 4, 2}, load{10 * mB, 0.5 * mB, 4, 0}},
			dests:   []weighted{{awsUS, 6}, {awsDE, 4}},
		},
		{
			id: idSpeaker, mac: vendorMAC(r, "48A6B8"), ip: ip(118), hostname: "SonosZP",
			note: "Kitchen speaker", lease: dynamicLease, wantKind: "speaker", joined: start,
			profile: profile{speakerHours, load{0.4 * mB, 1 * mB, 3, 2}, load{3 * mB, 110 * mB, 20, 4}},
			dests:   []weighted{{gcpUS, 8}, {awsUS, 2}},
		},
		{
			id: idIPhoneOld, mac: privateMAC(r), ip: ip(127), hostname: "Alexs-iPhone",
			note: "Alex's iPhone", lease: dynamicLease, wantKind: "phone", joined: atInstall(time.Minute),
			left:    func(tl timeline) time.Time { return tl.rotate.Add(-3 * time.Minute) },
			profile: phone(),
			dests:   iphoneDests(),
		},
		{
			id: idIPhone, mac: privateMAC(r), ip: ip(164), hostname: "Alexs-iPhone",
			lease: dynamicLease, wantKind: "phone", joined: func(tl timeline) time.Time { return tl.rotate },
			profile: phone(),
			dests:   iphoneDests(),
		},
		{
			id: idGalaxy, mac: privateMAC(r), ip: ip(173), hostname: "Galaxy-S23", classID: "android-dhcp-14",
			note: "Emma's Galaxy", lease: dynamicLease, wantKind: "phone", joined: start,
			profile: profile{phoneHours, load{2 * mB, 6 * mB, 10, 6}, load{28 * mB, 300 * mB, 70, 35}},
			dests: []weighted{{googleDE, 3.5}, {googleUS, 1}, {metaDE, 2}, {awsIE, 1}, {akamaiDE, 1},
				{seznamCZ, 1}, {cloudflareUS, 0.5}},
		},
		{
			id: idLaptopWiFi, mac: vendorMAC(r, "A0A8CD"), ip: ip(40), hostname: "LAPTOP-7H2K9QF", classID: "MSFT 5.0",
			comment: "Work laptop", lease: staticLease, wantKind: "computer", joined: atInstall(2 * time.Hour),
			profile: profile{laptopAtHome, load{}, load{15 * mB, 120 * mB, 50, 20}},
			dests:   laptopDests(),
		},
		{
			id: idLaptopDock, mac: vendorMAC(r, "D4BED9"), ip: ip(132), hostname: "LAPTOP-7H2K9QF", classID: "MSFT 5.0",
			lease: dynamicLease, wantKind: "computer", joined: atInstall(20 * time.Hour),
			profile: profile{officeHours, load{}, load{180 * mB, 650 * mB, 140, 45}},
			dests:   laptopDests(),
		},
		{
			id: idPC, mac: vendorMAC(r, "047C16"), ip: ip(50), hostname: "DESKTOP-4J8M2RT", classID: "MSFT 5.0",
			comment: "Family PC", lease: staticLease, wantKind: "computer", joined: atInstall(5 * time.Hour),
			profile: profile{pcHours, load{}, load{40 * mB, 1.6 * gB, 80, 30}},
			dests: []weighted{{valveNL, 3.5}, {microsoftNL, 1.5}, {akamaiUS, 1}, {googleDE, 1.5}, {netflixUS, 1},
				{seznamCZ, 1}, {cloudflareUS, 0.5}},
		},
		{
			id: idNAS, mac: vendorMAC(r, "9009D0"), ip: ip(10), hostname: "DiskStation",
			comment: "NAS", lease: staticLease, wantKind: "nas", joined: start,
			profile: profile{backupWindow, load{12 * mB, 18 * mB, 6, 3}, load{4.6 * gB, 60 * mB, 25, 0}},
			dests:   []weighted{{hetznerDE, 8.5}, {awsUS, 1}, {awsDE, 0.5}},
		},
		{
			id: idPrinter, mac: vendorMAC(r, "3C2AF4"), ip: ip(11),
			comment: "Office printer", lease: staticLease, wantKind: "printer", joined: start,
			profile: profile{daylight, load{0.15 * mB, 0.1 * mB, 1, 1}, load{0.3 * mB, 0.2 * mB, 1, 0}},
			dests:   []weighted{{awsUS, 1}},
		},
		{
			id: idThermostat, mac: vendorMAC(r, "641666"), ip: ip(121), hostname: "Nest-Thermostat-4E1A",
			note: "Thermostat", lease: dynamicLease, wantKind: "iot", joined: start,
			profile: profile{always, load{0.6 * mB, 0.4 * mB, 2, 1}, load{}},
			dests:   []weighted{{googleUS, 1}},
		},
		{
			id: idVacuum, mac: vendorMAC(r, "50642B"), ip: ip(144), hostname: "roborock-vacuum-a75",
			note: "Robot vacuum", lease: dynamicLease, wantKind: "iot", joined: start,
			profile: profile{cleaning, load{0.8 * mB, 0.5 * mB, 2, 2}, load{18 * mB, 6 * mB, 8, 1}},
			dests:   []weighted{{awsDE, 1}},
		},
		{
			id: idPlug, ip: ip(139), note: "Washer plug", lease: dynamicLease, wantKind: "iot", joined: start,
			profile: profile{always, load{0.25 * mB, 0.12 * mB, 1, 1}, load{}},
			dests:   []weighted{{awsDE, 1}},
		},
		{
			id: idHue, mac: vendorMAC(r, "ECB5FA"), ip: ip(31), hostname: "Philips-hue",
			comment: "Smart bulbs bridge", lease: staticLease, wantKind: "iot", joined: start,
			profile: profile{always, load{0.9 * mB, 0.6 * mB, 2, 1}, load{}},
			dests:   []weighted{{awsIE, 1}},
		},
		{
			id: idConsole, mac: vendorMAC(r, "709E29"), ip: ip(152), hostname: "PS5-753",
			note: "Game console", lease: dynamicLease, wantKind: "console", joined: atInstall(9 * time.Hour),
			profile: profile{evenings, load{1 * mB, 3 * mB, 3, 2}, load{220 * mB, 2.8 * gB, 70, 20}},
			dests:   []weighted{{akamaiUS, 4}, {awsUS, 4}, {googleDE, 1}, {cloudflareUS, 1}},
		},
		{
			id: idGuestTab, mac: privateMAC(r), ip: ip(186), hostname: "android-5d2e8c1f0a7b3e94", classID: "android-dhcp-13",
			note: "Guest tablet", kindOverride: "tablet", lease: dynamicLease, wantKind: "phone",
			joined:  func(tl timeline) time.Time { return tl.guestJoin },
			profile: profile{phoneHours, load{1 * mB, 3 * mB, 6, 4}, load{12 * mB, 240 * mB, 50, 25}},
			dests:   []weighted{{googleDE, 4}, {googleUS, 2}, {akamaiDE, 2}, {metaDE, 2}},
		},
		{
			// A real Espressif OUI that is not in Guardian's curated OUI table:
			// no vendor, no hostname - an unidentified device.
			id: idESP, mac: vendorMAC(r, "349454"), ip: ip(197), lease: dynamicLease, wantKind: "unknown",
			joined:  func(tl timeline) time.Time { return tl.espJoin },
			profile: profile{always, load{2.5 * mB, 0.8 * mB, 3, 2}, load{}},
			dests:   []weighted{{awsDE, 1}},
		},
		{
			id: idAP, mac: vendorMAC(r, "48A98A"), ip: ip(62), note: "MikroTik AP", lease: arpOnly,
			wantKind: "network", joined: start,
			profile: profile{always, load{0.1 * mB, 0.15 * mB, 1, 1}, load{}},
			dests:   []weighted{{mikrotikLV, 1}, {cesnetCZ, 1}},
		},
	}
	h := &household{devices: devs, byID: map[string]*device{}}
	for _, d := range devs {
		h.byID[d.id] = d
	}
	// The washer plug is a Shelly-style ESP device; its hostname embeds the MAC.
	plug := h.get(idPlug)
	plug.mac = vendorMAC(r, "E8DB84")
	plug.hostname = "shellyplug-s-" + strings.ReplaceAll(plug.mac[9:], ":", "")
	// Brother printers call themselves BRW<MAC>.
	pr := h.get(idPrinter)
	pr.hostname = "BRW" + strings.ReplaceAll(pr.mac, ":", "")
	// The user merged the laptop's Wi-Fi and dock MACs in the UI.
	gid := h.get(idLaptopWiFi).mac
	h.get(idLaptopWiFi).groupID = gid
	h.get(idLaptopDock).groupID = gid
	return h
}

func phone() profile {
	return profile{phoneHours, load{3 * mB, 8 * mB, 10, 6}, load{35 * mB, 380 * mB, 90, 40}}
}

func iphoneDests() []weighted {
	return []weighted{{appleUS, 3}, {appleNL, 1}, {googleDE, 1.5}, {metaDE, 1.5}, {akamaiDE, 1},
		{cloudflareUS, 1}, {seznamCZ, 1}}
}

func laptopDests() []weighted {
	return []weighted{{microsoftIE, 3.5}, {microsoftUS, 1.5}, {zoomUS, 1.5}, {googleDE, 1.5}, {awsDE, 1},
		{cloudflareUS, 1}}
}

// displayRows counts the rows the device list shows: randomized MACs with
// the same hostname and manually merged devices share one row.
func (h *household) displayRows() int {
	keys := map[string]bool{}
	for _, d := range h.devices {
		k := d.mac
		switch {
		case d.groupID != "":
			k = "m:" + d.groupID
		case d.hostname != "" && isPrivateMAC(d.mac):
			k = "h:" + strings.ToLower(d.hostname)
		}
		keys[k] = true
	}
	return len(keys)
}

func isPrivateMAC(mac string) bool {
	b, err := strconv.ParseUint(mac[:2], 16, 8)
	return err == nil && b&0x02 != 0
}

func round(x float64) int { return int(math.Round(x)) }
