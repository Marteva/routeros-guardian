// Package fingerprint derives best-effort device metadata (vendor, kind,
// randomized MAC) from the MAC address, DHCP hostname and DHCP class-id.
//
// Kind guess order (first match wins):
//  1. hostname keywords (most specific: "iphone", "bravia", "shelly", ...)
//  2. strong DHCP class-id ("android-dhcp-*" → phone, "MSFT 5.0" → computer)
//  3. vendor from the OUI table (Espressif/Tuya → iot, Hikvision → camera, ...)
//  4. weak class-id ("udhcp" busybox client → iot)
//  5. randomized MAC without other hints → "phone": iOS 14+ and Android 10+
//     randomize per network by default, desktop OSes do not, so a private MAC
//     is far more likely a phone/tablet than anything else.
//  6. "unknown"
package fingerprint

import (
	"bufio"
	_ "embed"
	"strings"
	"sync"

	"github.com/Marteva/routeros-guardian/internal/model"
)

//go:embed oui.txt
var ouiText string

var ouiTable = sync.OnceValue(func() map[string]string { return parseOUI(ouiText) })

func parseOUI(text string) map[string]string {
	m := make(map[string]string, 1024)
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		prefix, vendor, ok := strings.Cut(line, " ")
		if !ok || len(prefix) != 6 {
			continue
		}
		m[strings.ToUpper(prefix)] = strings.TrimSpace(vendor)
	}
	return m
}

// Kinds produced by Enrich.
const (
	KindPhone    = "phone"
	KindTablet   = "tablet"
	KindComputer = "computer"
	KindTV       = "tv"
	KindCamera   = "camera"
	KindIoT      = "iot"
	KindSpeaker  = "speaker"
	KindConsole  = "console"
	KindPrinter  = "printer"
	KindNAS      = "nas"
	KindNetwork  = "network"
	KindUnknown  = "unknown"
)

// Enrich sets d.Randomized from the MAC and fills d.Vendor and d.Kind when they
// are empty (Kind "unknown" counts as empty and may be upgraded).
func Enrich(d *model.Device) {
	oui, randomized, ok := parseMAC(d.MAC)
	if ok {
		d.Randomized = randomized
	}
	if d.Vendor == "" && ok && !randomized {
		d.Vendor = ouiTable()[oui]
	}
	if d.Kind == "" || d.Kind == KindUnknown {
		d.Kind = guessKind(d.Vendor, d.Hostname, d.ClassID, d.Randomized)
	}
}

// Vendor returns the vendor for a MAC address, "" if unknown or randomized.
func Vendor(mac string) string {
	oui, randomized, ok := parseMAC(mac)
	if !ok || randomized {
		return ""
	}
	return ouiTable()[oui]
}

// parseMAC extracts the upper-case 6-hex-digit OUI and the locally-administered
// bit. Accepts ":" / "-" / "." separators or none.
func parseMAC(mac string) (oui string, randomized, ok bool) {
	var b strings.Builder
	for i := 0; i < len(mac) && b.Len() < 12; i++ {
		c := mac[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F':
			b.WriteByte(c)
		case c >= 'a' && c <= 'f':
			b.WriteByte(c - 'a' + 'A')
		case c == ':' || c == '-' || c == '.':
		default:
			return "", false, false
		}
	}
	h := b.String()
	if len(h) != 12 {
		return "", false, false
	}
	first := hexVal(h[0])<<4 | hexVal(h[1])
	return h[:6], first&0x02 != 0, true
}

func hexVal(c byte) byte {
	if c <= '9' {
		return c - '0'
	}
	return c - 'A' + 10
}

// rule matches a lower-cased hostname. Keywords are matched as substrings
// unless prefixed with "^" (token must start with it) or wrapped "=" (whole
// token). Tokens are split on non-alphanumerics.
type rule struct {
	kind string
	keys []string
}

// Order matters: more specific kinds first (e.g. "androidtv" before "android").
var hostRules = []rule{
	{KindTablet, []string{"ipad", "galaxy-tab", "galaxytab", "kindle", "=tab"}},
	{KindTV, []string{"bravia", "webos", "tizen", "androidtv", "android-tv", "appletv", "apple-tv",
		"firetv", "fire-tv", "chromecast", "roku", "smarttv", "smart-tv", "shield", "mibox", "mi-box", "=tv", "^tv", "lgtv", "samsungtv", "philipstv",
		// Localised "television" (cs/sk televize/televizor, de, pl, es/pt/ro, nl, it/fi).
		"televiz", "fernseher", "telewizor", "televisor", "televisie", "televisio"}},
	{KindConsole, []string{"xbox", "playstation", "=ps4", "=ps5", "nintendo"}},
	{KindPhone, []string{"iphone", "android", "galaxy", "pixel", "redmi", "oneplus", "=poco", "huawei-p", "phone", "=mi"}},
	{KindCamera, []string{"ipcam", "=ipc", "^ipc", "camera", "^cam", "webcam", "ezviz", "reolink", "hikvision", "dahua",
		"=nvr", "=dvr", "doorbell", "tapo-c", "tapo_c", "wyze"}},
	{KindPrinter, []string{"printer", "^npi", "^brw", "^brn", "epson", "canon", "officejet", "laserjet", "deskjet"}},
	{KindNAS, []string{"=nas", "synology", "diskstation", "qnap"}},
	{KindSpeaker, []string{"sonos", "echo", "homepod", "google-home", "googlehome", "nest-mini", "nest-audio"}},
	{KindIoT, []string{"^esp", "tasmota", "shelly", "sonoff", "tuya", "wled", "espressif", "zigbee", "kasa", "tapo",
		"=hue", "philips-hue", "=nest", "ecobee", "thermostat", "smartplug", "^plug", "vacuum", "roborock", "roomba", "^lumi", "aqara", "yeelink", "miio"}},
	{KindComputer, []string{"macbook", "imac", "mac-mini", "macmini", "mbp", "^desktop", "^laptop", "thinkpad", "latitude",
		"=pc", "-pc", "windows", "ubuntu", "debian", "fedora", "raspberrypi", "workstation"}},
	{KindNetwork, []string{"mikrotik", "unifi", "ubnt", "router", "=ap", "repeater", "extender", "fritz"}},
}

var vendorKind = map[string]string{
	"Espressif":        KindIoT,
	"Tuya":             KindIoT,
	"Aqara":            KindIoT,
	"Philips Hue":      KindIoT,
	"Nest":             KindIoT,
	"Amazon":           KindIoT, // Echo / Fire / Ring – mostly smart-home gear
	"Hikvision":        KindCamera,
	"Dahua":            KindCamera,
	"Reolink":          KindCamera,
	"Wyze":             KindCamera,
	"Roku":             KindTV,
	"Sonos":            KindSpeaker,
	"Sony PlayStation": KindConsole,
	"Nintendo":         KindConsole,
	"Synology":         KindNAS,
	"QNAP":             KindNAS,
	"MikroTik":         KindNetwork,
	"Ubiquiti":         KindNetwork,
	"Netgear":          KindNetwork,
	"AVM":              KindNetwork,
	"Raspberry Pi":     KindComputer,
	"Intel":            KindComputer,
	"Dell":             KindComputer,
	"MSI":              KindComputer,
	"Microsoft":        KindComputer,
	"VMware":           KindComputer,
	"VirtualBox":       KindComputer,
	"OnePlus":          KindPhone,
	"Brother":          KindPrinter,
	"Canon":            KindPrinter,
	"Epson":            KindPrinter,
	// Deliberately absent (too ambiguous): Apple, Samsung, Xiaomi, Google,
	// Huawei, LG, Sony, HP, ASUS, TP-Link, Realtek.
}

func guessKind(vendor, hostname, classID string, randomized bool) string {
	if k := matchHost(strings.ToLower(hostname)); k != "" {
		return k
	}
	cid := strings.ToLower(classID)
	switch {
	case strings.HasPrefix(cid, "android-dhcp"):
		return KindPhone
	case strings.HasPrefix(cid, "msft"):
		return KindComputer
	}
	if k, ok := vendorKind[vendor]; ok {
		return k
	}
	if strings.HasPrefix(cid, "udhcp") {
		return KindIoT
	}
	if randomized {
		return KindPhone
	}
	return KindUnknown
}

func matchHost(h string) string {
	if h == "" {
		return ""
	}
	tokens := strings.FieldsFunc(h, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	for _, r := range hostRules {
		for _, k := range r.keys {
			if matchKey(h, tokens, k) {
				return r.kind
			}
		}
	}
	return ""
}

func matchKey(h string, tokens []string, k string) bool {
	switch k[0] {
	case '=':
		for _, t := range tokens {
			if t == k[1:] {
				return true
			}
		}
		return false
	case '^':
		for _, t := range tokens {
			if strings.HasPrefix(t, k[1:]) {
				return true
			}
		}
		return false
	default:
		return strings.Contains(h, k)
	}
}
