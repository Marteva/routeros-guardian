package routeros

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// connProplist limits /ip/firewall/connection to the fields we use; the full
// object is ~4x larger and the table can have thousands of entries.
const connProplist = ".id,protocol,src-address,dst-address,orig-bytes,repl-bytes,fasttrack,srcnat,dstnat"

type rawLease struct {
	ID            str `json:".id"`
	MAC           str `json:"mac-address"`
	ActiveMAC     str `json:"active-mac-address"`
	Address       str `json:"address"`
	ActiveAddress str `json:"active-address"`
	HostName      str `json:"host-name"`
	ClassID       str `json:"class-id"`
	ClientID      str `json:"client-id"`
	Status        str `json:"status"`
	Dynamic       str `json:"dynamic"`
	Server        str `json:"server"`
	Comment       str `json:"comment"`
}

// DHCPLeases returns /ip/dhcp-server/lease. Leases without a valid MAC are skipped;
// IP is active-address when present, else address (may be invalid for pool/static leases).
func (c *Client) DHCPLeases(ctx context.Context) ([]model.Lease, error) {
	var out []model.Lease
	_, err := getArray(ctx, c, "ip/dhcp-server/lease", nil, func(r *rawLease) {
		mac := NormalizeMAC(string(r.MAC))
		if mac == "" {
			mac = NormalizeMAC(string(r.ActiveMAC))
		}
		if mac == "" {
			return
		}
		ip := parseAddr(r.ActiveAddress)
		if !ip.IsValid() {
			ip = parseAddr(r.Address)
		}
		out = append(out, model.Lease{
			ID:       string(r.ID),
			MAC:      mac,
			IP:       ip,
			Hostname: string(r.HostName),
			ClassID:  string(r.ClassID),
			ClientID: string(r.ClientID),
			Status:   string(r.Status),
			Dynamic:  parseBool(r.Dynamic),
			Server:   string(r.Server),
			Comment:  strings.TrimSpace(string(r.Comment)),
		})
	})
	return out, err
}

type rawARP struct {
	Address   str `json:"address"`
	MAC       str `json:"mac-address"`
	Interface str `json:"interface"`
	Complete  str `json:"complete"`
	Status    str `json:"status"`
}

// ARP returns /ip/arp entries that have a MAC address.
func (c *Client) ARP(ctx context.Context) ([]model.ARPEntry, error) {
	var out []model.ARPEntry
	_, err := getArray(ctx, c, "ip/arp", nil, func(r *rawARP) {
		mac := NormalizeMAC(string(r.MAC))
		if mac == "" {
			return
		}
		out = append(out, model.ARPEntry{
			MAC:       mac,
			IP:        parseAddr(r.Address),
			Interface: string(r.Interface),
			Complete:  arpComplete(r),
		})
	})
	return out, err
}

// arpComplete prefers the explicit "complete" flag, then the neighbour status.
func arpComplete(r *rawARP) bool {
	if r.Complete != "" {
		return parseBool(r.Complete)
	}
	switch strings.ToLower(string(r.Status)) {
	case "failed", "incomplete":
		return false
	}
	return true // has a MAC and no negative status
}

type rawConn struct {
	ID        str `json:".id"`
	Protocol  str `json:"protocol"`
	Src       str `json:"src-address"`
	Dst       str `json:"dst-address"`
	OrigBytes str `json:"orig-bytes"`
	ReplBytes str `json:"repl-bytes"`
	Fasttrack str `json:"fasttrack"`
	SrcNAT    str `json:"srcnat"`
	DstNAT    str `json:"dstnat"`
}

// Connections returns the IPv4 connection-tracking table (/ip/firewall/connection).
func (c *Client) Connections(ctx context.Context) ([]model.Conn, error) {
	conns, _, err := c.ConnectionsWithSize(ctx)
	return conns, err
}

// ConnectionsWithSize is Connections plus the response body size in bytes
// (used by the feasibility probe). Unparsable addresses yield zero AddrPorts
// so that len(conns) still equals the size of the table.
func (c *Client) ConnectionsWithSize(ctx context.Context) ([]model.Conn, int64, error) {
	out := make([]model.Conn, 0, c.connHint.Load()+64)
	n, err := getArray(ctx, c, "ip/firewall/connection", url.Values{".proplist": {connProplist}}, func(r *rawConn) {
		out = append(out, model.Conn{
			ID:        string(r.ID),
			Proto:     string(r.Protocol),
			Src:       parseEndpoint(r.Src),
			Dst:       parseEndpoint(r.Dst),
			OrigBytes: parseUint(r.OrigBytes),
			ReplBytes: parseUint(r.ReplBytes),
			Fasttrack: parseBool(r.Fasttrack),
			SrcNAT:    parseBool(r.SrcNAT),
			DstNAT:    parseBool(r.DstNAT),
		})
	})
	if err != nil {
		return nil, n, err
	}
	c.connHint.Store(int64(len(out)))
	return out, n, nil
}

// DropConnections removes all IPv4 conntrack entries whose source or destination
// is ip and returns how many were removed. Used on quarantine, because
// fasttracked connections bypass the firewall drop rule. Entries that vanish
// concurrently are ignored.
func (c *Client) DropConnections(ctx context.Context, ip netip.Addr) (int, error) {
	var ids []string
	_, err := getArray(ctx, c, "ip/firewall/connection", url.Values{".proplist": {".id,src-address,dst-address"}}, func(r *rawConn) {
		if parseEndpoint(r.Src).Addr() == ip || parseEndpoint(r.Dst).Addr() == ip {
			ids = append(ids, string(r.ID))
		}
	})
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if id == "" {
			continue
		}
		resp, err := c.do(ctx, http.MethodDelete, "ip/firewall/connection/"+id, nil, nil)
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
				continue
			}
			return n, err
		}
		resp.Body.Close()
		n++
	}
	return n, nil
}

type rawResource struct {
	CPULoad     str `json:"cpu-load"`
	CPUCount    str `json:"cpu-count"`
	FreeMemory  str `json:"free-memory"`
	TotalMemory str `json:"total-memory"`
	Uptime      str `json:"uptime"`
	Version     str `json:"version"`
	BoardName   str `json:"board-name"`
	Arch        str `json:"architecture-name"`
}

// Resource returns /system/resource (a single object; an array is tolerated).
func (c *Client) Resource(ctx context.Context) (model.Resource, error) {
	var raw json.RawMessage
	if err := c.Get(ctx, "system/resource", nil, &raw); err != nil {
		return model.Resource{}, err
	}
	var r rawResource
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var arr []rawResource
		if err := json.Unmarshal(raw, &arr); err != nil {
			return model.Resource{}, fmt.Errorf("routeros: decode system/resource: %w", err)
		}
		if len(arr) == 0 {
			return model.Resource{}, errors.New("routeros: empty system/resource")
		}
		r = arr[0]
	} else if err := json.Unmarshal(raw, &r); err != nil {
		return model.Resource{}, fmt.Errorf("routeros: decode system/resource: %w", err)
	}
	return model.Resource{
		CPULoad:     parseInt(r.CPULoad),
		CPUCount:    parseInt(r.CPUCount),
		FreeMemory:  parseUint(r.FreeMemory),
		TotalMemory: parseUint(r.TotalMemory),
		Uptime:      string(r.Uptime),
		Version:     string(r.Version),
		BoardName:   string(r.BoardName),
		Arch:        string(r.Arch),
	}, nil
}

// addressListPath picks the IPv4 or IPv6 address-list menu for address.
// Non-IP values (RouterOS accepts DNS names) go to the IPv4 list.
func addressListPath(address string) string {
	a := address
	if p, err := netip.ParsePrefix(address); err == nil {
		a = p.Addr().String()
	}
	if ip, err := netip.ParseAddr(a); err == nil && ip.Is6() && !ip.Is4In6() {
		return "ipv6/firewall/address-list"
	}
	return "ip/firewall/address-list"
}

// AddressListAdd adds address to a firewall address-list. An existing entry
// ("already have such entry") is treated as success. timeout 0 = permanent.
func (c *Client) AddressListAdd(ctx context.Context, list, address, comment string, timeout time.Duration) error {
	body := map[string]string{"list": list, "address": address}
	if comment != "" {
		body["comment"] = comment
	}
	if t := FormatDuration(timeout); t != "" {
		body["timeout"] = t
	}
	resp, err := c.do(ctx, http.MethodPut, addressListPath(address), nil, body)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusBadRequest &&
			strings.Contains(strings.ToLower(ae.Detail+" "+ae.Message), "already have") {
			return nil
		}
		return err
	}
	resp.Body.Close()
	return nil
}

type rawListEntry struct {
	ID      str `json:".id"`
	List    str `json:"list"`
	Address str `json:"address"`
}

// AddressListRemove deletes all entries of list matching address. RouterOS may
// store "1.2.3.4" for "1.2.3.4/32" (or the reverse for IPv6), so matching is done
// client-side on the normalized form. No matching entry is not an error.
func (c *Client) AddressListRemove(ctx context.Context, list, address string) error {
	path := addressListPath(address)
	want := normalizeListAddress(address)
	var entries []rawListEntry
	q := url.Values{"list": {list}, ".proplist": {".id,list,address"}}
	if err := c.Get(ctx, path, q, &entries); err != nil {
		return err
	}
	for _, e := range entries {
		if string(e.List) != list || normalizeListAddress(string(e.Address)) != want || e.ID == "" {
			continue
		}
		resp, err := c.do(ctx, http.MethodDelete, path+"/"+string(e.ID), nil, nil)
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
				continue // removed concurrently (e.g. timeout expired)
			}
			return err
		}
		resp.Body.Close()
	}
	return nil
}

// normalizeListAddress maps "1.2.3.4/32" and "1.2.3.4" to the same key.
func normalizeListAddress(s string) string {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		p = p.Masked()
		if p.IsSingleIP() {
			return p.Addr().Unmap().String()
		}
		return p.String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String()
	}
	return strings.ToLower(s)
}

// FormatDuration renders d RouterOS-style ("1d2h3m4s"), rounded up to whole
// seconds. Zero or negative durations return "".
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	secs := int64((d + time.Second - 1) / time.Second)
	var b strings.Builder
	for _, u := range []struct {
		n    int64
		unit string
	}{{86400, "d"}, {3600, "h"}, {60, "m"}, {1, "s"}} {
		if v := secs / u.n; v > 0 {
			b.WriteString(strconv.FormatInt(v, 10))
			b.WriteString(u.unit)
			secs -= v * u.n
		}
	}
	return b.String()
}
