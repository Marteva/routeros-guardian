// Package model holds the types and interfaces shared by all Guardian packages.
// It is the contract between packages: change it only in coordination.
package model

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrNotFound is returned by Store setters for an unknown MAC or alert ID.
var ErrNotFound = errors.New("not found")

// ---------------------------------------------------------------------------
// Raw RouterOS data (produced by internal/routeros)
// ---------------------------------------------------------------------------

// Lease is one entry of /ip/dhcp-server/lease.
type Lease struct {
	ID       string // RouterOS ".id"
	MAC      string // upper-case, colon separated: "AA:BB:CC:DD:EE:FF"
	IP       netip.Addr
	Hostname string
	ClassID  string // DHCP option 60 (vendor class), may be empty
	ClientID string
	Status   string // "bound", "waiting", ...
	Dynamic  bool
	Server   string
	Comment  string // admin's comment on the (static) lease, used as a friendly name
}

// ARPEntry is one entry of /ip/arp.
type ARPEntry struct {
	MAC       string
	IP        netip.Addr
	Interface string
	Complete  bool
}

// Conn is one entry of /ip/firewall/connection (connection tracking).
type Conn struct {
	ID        string // RouterOS ".id", stable for the lifetime of the connection
	Proto     string // "tcp", "udp", "icmp", ...
	Src       netip.AddrPort
	Dst       netip.AddrPort
	OrigBytes uint64 // bytes in the original direction (LAN -> internet for outbound)
	ReplBytes uint64 // bytes in the reply direction
	Fasttrack bool
	SrcNAT    bool
	DstNAT    bool
}

// Resource is /system/resource.
type Resource struct {
	CPULoad     int // percent
	CPUCount    int
	FreeMemory  uint64
	TotalMemory uint64
	Uptime      string
	Version     string
	BoardName   string
	Arch        string
}

// RouterAPI is the subset of the RouterOS REST API Guardian needs.
type RouterAPI interface {
	DHCPLeases(ctx context.Context) ([]Lease, error)
	ARP(ctx context.Context) ([]ARPEntry, error)
	Connections(ctx context.Context) ([]Conn, error)
	Resource(ctx context.Context) (Resource, error)
	// AddressListAdd adds address to an /ip/firewall/address-list. timeout 0 = permanent.
	// Adding an address that is already in the list must not return an error.
	AddressListAdd(ctx context.Context, list, address, comment string, timeout time.Duration) error
	// AddressListRemove removes address from the list. Missing entry is not an error.
	AddressListRemove(ctx context.Context, list, address string) error
}

// ---------------------------------------------------------------------------
// Domain data
// ---------------------------------------------------------------------------

// Device is a LAN client identified by MAC.
type Device struct {
	MAC         string
	IP          netip.Addr
	Hostname    string
	Vendor      string // from MAC OUI, may be empty
	Kind        string // best-effort guess: "phone", "tv", "camera", "iot", "computer", "unknown", ...
	ClassID     string
	Randomized  bool // locally administered (randomized) MAC
	FirstSeen   time.Time
	LastSeen    time.Time
	Quarantined bool
	Note        string // user note / friendly name (set in UI, wins over everything)
	Comment     string // DHCP lease comment from RouterOS (refreshed on every upsert when non-empty)
	// KindOverride is the kind chosen by the user in the UI ("" = use the guess in Kind).
	// Never overwritten by UpsertDevice.
	KindOverride string
	// GroupID joins devices the user merged manually (same physical device with
	// several MACs). "" = not merged; members share the same non-empty value
	// (the MAC of the group's primary). Never overwritten by UpsertDevice.
	GroupID string
}

// EffectiveKind is the kind detection and UI should use.
func (d Device) EffectiveKind() string {
	if d.KindOverride != "" {
		return d.KindOverride
	}
	return d.Kind
}

// Kinds is the closed set of device kinds (fingerprint guesses and user overrides).
var Kinds = []string{"phone", "tablet", "computer", "tv", "camera", "iot", "speaker",
	"console", "printer", "nas", "network", "unknown"}

// ValidKind reports whether k is one of Kinds.
func ValidKind(k string) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// DisplayName is the friendly name shown to humans:
// Note > Comment > Hostname > Vendor > MAC.
func (d Device) DisplayName() string {
	for _, s := range []string{d.Note, d.Comment, d.Hostname, d.Vendor} {
		if s != "" {
			return s
		}
	}
	return d.MAC
}

// FlowSample is the traffic of one connection between two polls (deltas, not totals).
// Only LAN -> internet connections are emitted.
type FlowSample struct {
	Time      time.Time
	DeviceMAC string
	DeviceIP  netip.Addr
	Dst       netip.AddrPort
	Proto     string
	TxBytes   uint64 // upload delta (orig direction)
	RxBytes   uint64 // download delta (reply direction)
	NewConn   bool   // first time this conntrack ID was seen
	Fasttrack bool
	Country   string // ISO code from GeoIP, "" if unknown
	ASN       uint32
	ASOrg     string
}

// HourStat is the per-device aggregate for one clock hour (UTC, truncated).
type HourStat struct {
	MAC         string
	Hour        time.Time
	TxBytes     uint64
	RxBytes     uint64
	NewConns    int
	DistinctDst int // distinct destination IPs within the hour
}

// DestStat is the per-device aggregate per destination network (country+ASN).
type DestStat struct {
	MAC       string
	Country   string
	ASN       uint32
	ASOrg     string
	FirstSeen time.Time
	LastSeen  time.Time
	Bytes     uint64
}

type Severity int

const (
	SevInfo Severity = iota
	SevWarning
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevWarning:
		return "warning"
	case SevCritical:
		return "critical"
	default:
		return "info"
	}
}

// Alert kinds.
const (
	AlertNewDevice     = "new_device"
	AlertNewCountry    = "new_country"
	AlertNewASN        = "new_asn"
	AlertUploadSpike   = "upload_spike"
	AlertDestFanout    = "dest_fanout" // many distinct destination IPs (scan / botnet)
	AlertBehaviorDrift = "behavior_drift"
)

// Alert is a detected anomaly.
type Alert struct {
	ID        int64
	Time      time.Time
	DeviceMAC string
	Kind      string
	Severity  Severity
	Title     string // short, human readable (Czech UI is fine)
	Detail    string
	Evidence  map[string]any // numbers behind the decision (baseline, observed, ratio...)
	DedupKey  string         // alerts with the same key within the dedup window are suppressed
	Acked     bool
}

// AlertFilter selects alerts for listing.
type AlertFilter struct {
	DeviceMAC string // "" = all
	Since     time.Time
	OnlyOpen  bool // not acked
	Limit     int  // 0 = default (100)
}

// ---------------------------------------------------------------------------
// Service interfaces
// ---------------------------------------------------------------------------

// GeoLookup resolves an internet IP to country and ASN. Implementations must be
// safe for concurrent use and return zero values when unknown.
type GeoLookup interface {
	Lookup(ip netip.Addr) (country string, asn uint32, asOrg string)
}

// Store is the persistence layer (SQLite).
type Store interface {
	// UpsertDevice inserts or updates by MAC. FirstSeen is kept on update,
	// Quarantined and Note are never overwritten by an upsert. isNew reports insertion.
	UpsertDevice(ctx context.Context, d Device) (isNew bool, err error)
	Device(ctx context.Context, mac string) (Device, bool, error)
	Devices(ctx context.Context) ([]Device, error)
	SetQuarantined(ctx context.Context, mac string, q bool) error
	SetNote(ctx context.Context, mac, note string) error
	// SetKindOverride sets the user-chosen kind ("" = back to automatic).
	SetKindOverride(ctx context.Context, mac, kind string) error
	// SetGroup assigns groupID to all macs ("" = remove them from any group).
	SetGroup(ctx context.Context, macs []string, groupID string) error

	// Settings is a small key/value store for runtime settings edited in the UI.
	Settings(ctx context.Context) (map[string]string, error)
	// PutSettings upserts the given keys; an empty value deletes the key.
	PutSettings(ctx context.Context, kv map[string]string) error

	// RecordFlows updates HourStat and DestStat aggregates. Raw samples need not be kept.
	RecordFlows(ctx context.Context, flows []FlowSample) error
	HourStats(ctx context.Context, mac string, from, to time.Time) ([]HourStat, error)
	DestStats(ctx context.Context, mac string) ([]DestStat, error)

	// InsertAlert stores the alert and sets a.ID.
	InsertAlert(ctx context.Context, a *Alert) error
	Alerts(ctx context.Context, f AlertFilter) ([]Alert, error)
	AckAlert(ctx context.Context, id int64) error
	// LastAlertByDedupKey returns the time of the newest alert with this key.
	LastAlertByDedupKey(ctx context.Context, key string) (time.Time, bool, error)

	// Prune deletes aggregates older than the retention window.
	Prune(ctx context.Context, olderThan time.Time) error
	// ResetLearned deletes all traffic aggregates (hour stats, destinations)
	// and alerts; devices and their user edits stay.
	ResetLearned(ctx context.Context) error
	// ResetAll additionally deletes all devices. Settings stay.
	ResetAll(ctx context.Context) error
	Close() error
}

// AlertSink receives alerts from the detection engine (stores, dedups, notifies).
type AlertSink interface {
	Emit(ctx context.Context, a Alert)
}
