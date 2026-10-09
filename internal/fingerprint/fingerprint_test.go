package fingerprint

import (
	"bufio"
	"strings"
	"testing"

	"github.com/Marteva/routeros-guardian/internal/model"
)

func TestOUITableWellFormed(t *testing.T) {
	seen := map[string]int{}
	sc := bufio.NewScanner(strings.NewReader(ouiText))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		prefix, vendor, ok := strings.Cut(line, " ")
		if !ok || len(prefix) != 6 || strings.TrimSpace(vendor) == "" {
			t.Errorf("line %d malformed: %q", n, line)
			continue
		}
		for _, c := range prefix {
			if !strings.ContainsRune("0123456789ABCDEF", c) {
				t.Errorf("line %d: bad hex %q", n, prefix)
			}
		}
		if hexVal(prefix[1])&0x02 != 0 {
			t.Errorf("line %d: %s has the locally-administered bit set", n, prefix)
		}
		if prev, dup := seen[prefix]; dup {
			t.Errorf("line %d: duplicate %s (first on line %d)", n, prefix, prev)
		}
		seen[prefix] = n
	}
	if len(ouiTable()) != len(seen) || len(seen) < 300 {
		t.Fatalf("table has %d entries, parsed %d", len(ouiTable()), len(seen))
	}
	for v := range vendorKind {
		found := false
		for _, tv := range ouiTable() {
			if tv == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("vendorKind references %q which is not in oui.txt", v)
		}
	}
}

func TestParseMAC(t *testing.T) {
	cases := []struct {
		mac        string
		oui        string
		randomized bool
		ok         bool
	}{
		{"B8:27:EB:12:34:56", "B827EB", false, true},
		{"b8-27-eb-12-34-56", "B827EB", false, true},
		{"b827.eb12.3456", "B827EB", false, true},
		{"DA:A1:19:00:00:01", "DAA119", true, true}, // 0xDA = 1101 1010 → LA bit set
		{"02:00:00:00:00:00", "020000", true, true},
		{"03:00:00:00:00:00", "030000", true, true}, // multicast+LA
		{"01:00:5E:00:00:01", "01005E", false, true},
		{"", "", false, false},
		{"zz:zz:zz:zz:zz:zz", "", false, false},
		{"AA:BB:CC", "", false, false},
	}
	for _, c := range cases {
		oui, r, ok := parseMAC(c.mac)
		if oui != c.oui || r != c.randomized || ok != c.ok {
			t.Errorf("%q: got (%q,%v,%v) want (%q,%v,%v)", c.mac, oui, r, ok, c.oui, c.randomized, c.ok)
		}
	}
}

func TestEnrich(t *testing.T) {
	cases := []struct {
		name   string
		in     model.Device
		vendor string
		kind   string
		rnd    bool
	}{
		{"raspberry", model.Device{MAC: "B8:27:EB:01:02:03", Hostname: "pihole"}, "Raspberry Pi", KindComputer, false},
		{"espressif by vendor", model.Device{MAC: "24:0A:C4:01:02:03"}, "Espressif", KindIoT, false},
		{"shelly hostname wins", model.Device{MAC: "24:0A:C4:01:02:03", Hostname: "shellyplus1pm-a8032ab"}, "Espressif", KindIoT, false},
		{"tasmota", model.Device{MAC: "00:00:00:00:00:01", Hostname: "tasmota-1A2B3C"}, "", KindIoT, false},
		{"esp token", model.Device{MAC: "00:00:00:00:00:01", Hostname: "ESP_1A2B3C"}, "", KindIoT, false},
		{"tuya", model.Device{MAC: "D8:1F:12:00:00:01", Hostname: "wlan0"}, "Tuya", KindIoT, false},
		{"hikvision", model.Device{MAC: "44:19:B6:00:00:01"}, "Hikvision", KindCamera, false},
		{"camera hostname", model.Device{MAC: "00:00:00:00:00:01", Hostname: "IPC-front"}, "", KindCamera, false},
		{"ezviz hostname", model.Device{MAC: "44:19:B6:00:00:01", Hostname: "EZVIZ-C6N"}, "Hikvision", KindCamera, false},
		{"tapo camera", model.Device{MAC: "50:C7:BF:00:00:01", Hostname: "Tapo_C200_ABCD"}, "TP-Link", KindCamera, false},
		{"tapo plug", model.Device{MAC: "50:C7:BF:00:00:01", Hostname: "Tapo_P100"}, "TP-Link", KindIoT, false},
		{"iphone randomized", model.Device{MAC: "DA:A1:19:00:00:01", Hostname: "Alexs-iPhone"}, "", KindPhone, true},
		{"ipad", model.Device{MAC: "DA:A1:19:00:00:01", Hostname: "iPad-Sam"}, "", KindTablet, true},
		{"android class-id", model.Device{MAC: "5C:0A:5B:00:00:01", ClassID: "android-dhcp-14"}, "Samsung", KindPhone, false},
		{"android tv beats class-id", model.Device{MAC: "00:00:00:00:00:01", Hostname: "AndroidTV-Living", ClassID: "android-dhcp-11"}, "", KindTV, false},
		{"galaxy", model.Device{MAC: "5C:0A:5B:00:00:01", Hostname: "Galaxy-S23"}, "Samsung", KindPhone, false},
		{"windows", model.Device{MAC: "00:1B:21:00:00:01", Hostname: "DESKTOP-AB12CD", ClassID: "MSFT 5.0"}, "Intel", KindComputer, false},
		{"msft class-id only", model.Device{MAC: "00:00:00:00:00:01", ClassID: "MSFT 5.0"}, "", KindComputer, false},
		{"macbook", model.Device{MAC: "A4:5E:60:00:00:01", Hostname: "Alexs-MacBook-Pro"}, "Apple", KindComputer, false},
		{"lg webos", model.Device{MAC: "A8:23:FE:00:00:01", Hostname: "LGwebOSTV"}, "LG", KindTV, false},
		{"bravia", model.Device{MAC: "00:00:00:00:00:01", Hostname: "BRAVIA-4K-GB"}, "", KindTV, false},
		{"samsung tizen", model.Device{MAC: "5C:0A:5B:00:00:01", Hostname: "Samsung-Tizen"}, "Samsung", KindTV, false},
		{"tv token", model.Device{MAC: "00:00:00:00:00:01", Hostname: "living-tv"}, "", KindTV, false},
		{"roku vendor", model.Device{MAC: "B0:A7:37:00:00:01"}, "Roku", KindTV, false},
		{"sonos", model.Device{MAC: "00:0E:58:00:00:01"}, "Sonos", KindSpeaker, false},
		{"playstation", model.Device{MAC: "00:D9:D1:00:00:01"}, "Sony PlayStation", KindConsole, false},
		{"printer hostname", model.Device{MAC: "00:00:00:00:00:01", Hostname: "NPI3A4B5C"}, "", KindPrinter, false},
		{"brother printer", model.Device{MAC: "00:80:77:00:00:01", Hostname: "BRW008077123456"}, "Brother", KindPrinter, false},
		{"synology", model.Device{MAC: "00:11:32:00:00:01", Hostname: "DiskStation"}, "Synology", KindNAS, false},
		{"nas hostname", model.Device{MAC: "00:00:00:00:00:01", Hostname: "home-nas"}, "", KindNAS, false},
		{"mikrotik", model.Device{MAC: "48:8F:5A:00:00:01"}, "MikroTik", KindNetwork, false},
		{"mikrotik d401c3", model.Device{MAC: "D4:01:C3:12:34:56"}, "MikroTik", KindNetwork, false},
		{"czech android tv", model.Device{MAC: "00:00:00:00:00:01", Hostname: "Televize-v-obyvaku", ClassID: "android-dhcp-11"}, "", KindTV, false},
		{"czech televizor randomized", model.Device{MAC: "3A:00:00:00:00:01", Hostname: "televizor-loznice", ClassID: "android-dhcp-12"}, "", KindTV, true},
		{"german fernseher", model.Device{MAC: "00:00:00:00:00:01", Hostname: "Fernseher-Wohnzimmer"}, "", KindTV, false},
		{"obyvak is not tv", model.Device{MAC: "00:00:00:00:00:01", Hostname: "obyvak-repro", ClassID: "android-dhcp-13"}, "", KindPhone, false},
		{"xiaomi", model.Device{MAC: "04:CF:8C:00:00:01"}, "Xiaomi", KindUnknown, false},
		{"msi", model.Device{MAC: "04:7C:16:00:00:01"}, "MSI", KindComputer, false},
		{"espressif 485519", model.Device{MAC: "48:55:19:00:00:01"}, "Espressif", KindIoT, false},
		{"espressif c8c9a3", model.Device{MAC: "C8:C9:A3:00:00:01"}, "Espressif", KindIoT, false},
		{"dell", model.Device{MAC: "AC:1A:3D:00:00:01"}, "Dell", KindComputer, false},
		{"intel", model.Device{MAC: "DC:46:28:00:00:01"}, "Intel", KindComputer, false},
		{"apple hostname not network", model.Device{MAC: "00:00:00:00:00:01", Hostname: "apple-watch"}, "", KindUnknown, false},
		{"udhcp weak", model.Device{MAC: "00:00:00:00:00:01", ClassID: "udhcp 1.36.1"}, "", KindIoT, false},
		{"vendor beats udhcp", model.Device{MAC: "44:19:B6:00:00:01", ClassID: "udhcp 1.20"}, "Hikvision", KindCamera, false},
		{"randomized no hints", model.Device{MAC: "3A:00:00:00:00:01"}, "", KindPhone, true},
		{"randomized ignores OUI", model.Device{MAC: "BA:27:EB:00:00:01"}, "", KindPhone, true},
		{"unknown", model.Device{MAC: "00:00:00:00:00:01"}, "", KindUnknown, false},
		{"bad mac", model.Device{MAC: "garbage"}, "", KindUnknown, false},
		{"keep existing", model.Device{MAC: "24:0A:C4:01:02:03", Vendor: "Custom", Kind: "tv"}, "Custom", "tv", false},
		{"upgrade unknown kind", model.Device{MAC: "24:0A:C4:01:02:03", Kind: KindUnknown}, "Espressif", KindIoT, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := c.in
			Enrich(&d)
			if d.Vendor != c.vendor || d.Kind != c.kind || d.Randomized != c.rnd {
				t.Fatalf("got vendor=%q kind=%q rnd=%v, want %q %q %v", d.Vendor, d.Kind, d.Randomized, c.vendor, c.kind, c.rnd)
			}
		})
	}
}

func TestVendor(t *testing.T) {
	if v := Vendor("00:0c:42:aa:bb:cc"); v != "MikroTik" {
		t.Fatalf("got %q", v)
	}
	if v := Vendor("02:0c:42:aa:bb:cc"); v != "" {
		t.Fatalf("randomized got %q", v)
	}
}
