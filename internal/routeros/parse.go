package routeros

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// str decodes any JSON scalar into a string. RouterOS sends everything as
// strings, but tolerating numbers/bools/null keeps us robust across versions.
type str string

func (s *str) UnmarshalJSON(b []byte) error {
	switch {
	case len(b) >= 2 && b[0] == '"':
		inner := b[1 : len(b)-1]
		if !containsByte(inner, '\\') {
			*s = str(inner) // fast path: no escapes
			return nil
		}
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = str(v)
	case string(b) == "null":
		*s = ""
	default:
		*s = str(b) // number, bool
	}
	return nil
}

func containsByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

func parseBool(s str) bool {
	switch strings.ToLower(strings.TrimSpace(string(s))) {
	case "true", "yes", "1":
		return true
	}
	return false
}

func parseUint(s str) uint64 {
	v, err := strconv.ParseUint(strings.TrimSpace(string(s)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func parseInt(s str) int {
	v, err := strconv.Atoi(strings.TrimSpace(string(s)))
	if err != nil {
		return 0
	}
	return v
}

// parseAddr parses an IP, tolerating a "/32"-style suffix. IPv4-mapped IPv6 is unmapped.
func parseAddr(s str) netip.Addr {
	t := strings.TrimSpace(string(s))
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	a, err := netip.ParseAddr(strings.Trim(t, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// parseEndpoint parses a conntrack address: "1.2.3.4:80", "1.2.3.4" (icmp),
// "[2001:db8::1]:443" or bare "2001:db8::1". Port 0 means "no port".
// An unparsable value yields the zero AddrPort.
func parseEndpoint(s str) netip.AddrPort {
	t := strings.TrimSpace(string(s))
	if t == "" {
		return netip.AddrPort{}
	}
	if ap, err := netip.ParseAddrPort(t); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	if a, err := netip.ParseAddr(strings.Trim(t, "[]")); err == nil {
		return netip.AddrPortFrom(a.Unmap(), 0)
	}
	return netip.AddrPort{}
}

// NormalizeMAC returns the upper-case colon form of a 6-byte MAC address
// ("aa-bb-cc-dd-ee-ff" and "aabb.ccdd.eeff" are accepted), or "" if invalid.
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	return strings.ToUpper(hw.String())
}
