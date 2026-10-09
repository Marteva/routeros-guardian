package main

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/Marteva/routeros-guardian/internal/routeros"
)

// fasttrackInfo describes the action=fasttrack-connection filter rule(s).
type fasttrackInfo struct {
	Present   bool
	Enabled   bool // at least one such rule is enabled
	HWOffload bool // an enabled rule has hw-offload=yes
	Rules     []string
}

// checkFasttrack inspects /ip/firewall/filter for fasttrack rules.
func checkFasttrack(ctx context.Context, c *routeros.Client) (fasttrackInfo, error) {
	var rules []map[string]any
	q := url.Values{".proplist": {".id,chain,action,disabled,invalid,hw-offload,comment,bytes"}}
	if err := c.Get(ctx, "ip/firewall/filter", q, &rules); err != nil {
		return fasttrackInfo{}, err
	}
	var fi fasttrackInfo
	for _, r := range rules {
		if field(r, "action") != "fasttrack-connection" {
			continue
		}
		fi.Present = true
		enabled := !isTrue(field(r, "disabled")) && !isTrue(field(r, "invalid"))
		hw := isTrue(field(r, "hw-offload"))
		if enabled {
			fi.Enabled = true
			fi.HWOffload = fi.HWOffload || hw
		}
		desc := field(r, ".id") + " chain=" + field(r, "chain")
		if !enabled {
			desc += " (vypnuto)"
		}
		if hw {
			desc += " hw-offload=yes"
		}
		if cm := field(r, "comment"); cm != "" {
			desc += " \"" + cm + "\""
		}
		fi.Rules = append(fi.Rules, desc)
	}
	return fi, nil
}

// countIPv6Conns returns the size of the IPv6 conntrack table (which Guardian
// does not poll), or -1 when unavailable (IPv6 disabled, no permission...).
func countIPv6Conns(ctx context.Context, c *routeros.Client) int {
	var ids []map[string]any
	if err := c.Get(ctx, "ipv6/firewall/connection", url.Values{".proplist": {".id"}}, &ids); err != nil {
		return -1
	}
	return len(ids)
}

// detectWAN finds the interface of the active IPv4 default route. RouterOS shows
// it as "immediate-gateway":"100.64.0.1%ether1" or a bare interface gateway.
func detectWAN(ctx context.Context, c *routeros.Client) string {
	var routes []map[string]any
	q := url.Values{"dst-address": {"0.0.0.0/0"}, ".proplist": {"dst-address,gateway,immediate-gateway,active,disabled"}}
	if err := c.Get(ctx, "ip/route", q, &routes); err != nil {
		return ""
	}
	for _, r := range routes {
		if field(r, "dst-address") != "0.0.0.0/0" || !isTrue(field(r, "active")) {
			continue
		}
		for _, k := range []string{"immediate-gateway", "gateway"} {
			v := field(r, k)
			if i := strings.LastIndexByte(v, '%'); i >= 0 {
				return v[i+1:]
			}
			if v != "" && !strings.ContainsAny(v, ".:") { // interface name, not an IP
				return v
			}
		}
	}
	return ""
}

type ifCounters struct{ rx, tx uint64 }

// readIfCounters reads rx-byte/tx-byte of one interface.
func readIfCounters(ctx context.Context, c *routeros.Client, name string) (ifCounters, error) {
	var ifs []map[string]any
	q := url.Values{"name": {name}, ".proplist": {"name,rx-byte,tx-byte"}}
	if err := c.Get(ctx, "interface", q, &ifs); err != nil {
		return ifCounters{}, err
	}
	for _, i := range ifs {
		if field(i, "name") == name {
			rx, _ := strconv.ParseUint(field(i, "rx-byte"), 10, 64)
			tx, _ := strconv.ParseUint(field(i, "tx-byte"), 10, 64)
			return ifCounters{rx: rx, tx: tx}, nil
		}
	}
	return ifCounters{}, errNoInterface
}

type probeError string

func (e probeError) Error() string { return string(e) }

const errNoInterface = probeError("interface not found")

// field returns a RouterOS value as string regardless of its JSON type.
func field(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func isTrue(s string) bool { return s == "true" || s == "yes" }
