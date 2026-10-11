// Package web serves the Guardian for RouterOS UI and its JSON API.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/detect"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

//go:embed static
var staticFS embed.FS

// Status is the runtime state shown in the header bar.
type Status struct {
	Version                                           string
	StartedAt, LastPoll, LearningUntil                time.Time
	LastPollDuration                                  time.Duration
	LastError                                         string
	ConnCount, FasttrackCount, DeviceCount, RouterCPU int
}

// Deps are the handler's collaborators.
type Deps struct {
	Store          model.Store
	API            model.RouterAPI
	QuarantineList string
	Status         func() Status
	Log            *slog.Logger
	// HealthMaxAge is the maximum age of the last successful poll for
	// GET /healthz to report healthy (0 = defaultHealthMaxAge).
	HealthMaxAge time.Duration

	// Settings backs GET/PUT /api/settings (nil = 503).
	Settings *settings.Manager
	// TestNotify sends a test message to all configured notifiers
	// (POST /api/settings/test-notify; nil = 503).
	TestNotify func(ctx context.Context) error
	// Reset wipes learned data (all=false) or everything including devices
	// (all=true) for POST /api/reset (nil = 503).
	Reset func(ctx context.Context, all bool) error
}

const (
	maxBody       = 16 << 10
	maxNoteLen    = 200
	routerTimeout = 10 * time.Second
	detailDays    = 7
	maxDests      = 50
	maxMergeMACs  = 64
	notifyTimeout = 30 * time.Second

	healthPath          = "/healthz"
	defaultHealthMaxAge = 2 * time.Minute
)

// connDropper is optionally implemented by the RouterAPI (routeros.Client).
type connDropper interface {
	DropConnections(ctx context.Context, ip netip.Addr) (int, error)
}

type server struct {
	d   Deps
	now func() time.Time
}

// New returns the HTTP handler: UI at "/", JSON API under "/api/".
// GET /healthz is a plain-text liveness probe for the container healthcheck.
func New(d Deps) http.Handler {
	return newServer(d, time.Now)
}

func newServer(d Deps, now func() time.Time) http.Handler {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Status == nil {
		d.Status = func() Status { return Status{} }
	}
	if d.HealthMaxAge <= 0 {
		d.HealthMaxAge = defaultHealthMaxAge
	}
	s := &server{d: d, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+healthPath, s.healthz)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/devices", s.devices)
	mux.HandleFunc("GET /api/devices/{mac}", s.device)
	mux.HandleFunc("PATCH /api/devices/{mac}", s.patchDevice)
	mux.HandleFunc("POST /api/devices/merge", s.merge)
	mux.HandleFunc("POST /api/devices/{mac}/unmerge", s.unmerge)
	mux.HandleFunc("POST /api/devices/{mac}/quarantine", s.quarantine)
	mux.HandleFunc("DELETE /api/devices/{mac}/quarantine", s.unquarantine)
	mux.HandleFunc("GET /api/alerts", s.alerts)
	mux.HandleFunc("POST /api/alerts/{id}/ack", s.ack)
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)
	mux.HandleFunc("POST /api/settings/test-notify", s.testNotify)
	mux.HandleFunc("POST /api/reset", s.reset)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "unknown endpoint")
	})

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // embedded at build time; cannot fail
	}
	// Serve "/" (index.html) and the top-level files of static/, nothing else.
	assets := map[string]bool{"/": true}
	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		if !e.IsDir() && e.Name() != "index.html" {
			assets["/"+e.Name()] = true
		}
	}
	files := http.FileServerFS(sub)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !assets[r.URL.Path] {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
	return securityHeaders(csrf(mux))
}

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// csrf rejects state-changing requests that do not carry the custom
// X-Guardian header (forces a CORS preflight for cross-site callers) or that
// come from a foreign Origin.
func csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Guardian") != "1" {
			writeErr(w, http.StatusForbidden, "missing X-Guardian header")
			return
		}
		if o := r.Header.Get("Origin"); o != "" && !sameOrigin(o, r.Host) {
			writeErr(w, http.StatusForbidden, "foreign origin")
			return
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeErr(w, http.StatusForbidden, "cross-site request")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOrigin(origin, host string) bool {
	if origin == "null" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// ---------------------------------------------------------------------------
// JSON DTOs
// ---------------------------------------------------------------------------

type statusDTO struct {
	Version        string    `json:"version"`
	Now            time.Time `json:"now"`
	StartedAt      time.Time `json:"startedAt"`
	LastPoll       time.Time `json:"lastPoll"`
	LearningUntil  time.Time `json:"learningUntil"`
	Learning       bool      `json:"learning"`
	LastPollMs     int64     `json:"lastPollMs"`
	LastError      string    `json:"lastError"`
	ConnCount      int       `json:"connCount"`
	FasttrackCount int       `json:"fasttrackCount"`
	DeviceCount    int       `json:"deviceCount"`
	RouterCPU      int       `json:"routerCpu"`
}

type deviceDTO struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	// Kind is the effective kind: the user's choice (KindOverride) if set,
	// else the automatic guess (KindAuto).
	Kind         string    `json:"kind"`
	KindAuto     string    `json:"kindAuto"`
	KindOverride string    `json:"kindOverride"`
	ClassID      string    `json:"classId"`
	Randomized   bool      `json:"randomized"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	Quarantined  bool      `json:"quarantined"`
	Note         string    `json:"note"`
	Comment      string    `json:"comment"`
	Name         string    `json:"name"`
	Tx24h        uint64    `json:"tx24h"`
	Rx24h        uint64    `json:"rx24h"`
	OpenAlerts   int       `json:"openAlerts"`
	// GroupID is the manual merge group ("" = not merged by the user).
	GroupID string `json:"groupId,omitempty"`

	// Set only on grouped rows of GET /api/devices (one physical device,
	// several MACs): Group is "manual" (merged by the user) or "auto"
	// (randomized MACs with the same hostname). Members includes the primary
	// device itself.
	Group                string      `json:"group,omitempty"`
	Members              []memberDTO `json:"members,omitempty"`
	PartiallyQuarantined bool        `json:"partiallyQuarantined,omitempty"`
}

// memberDTO is one MAC of a grouped device.
type memberDTO struct {
	MAC         string    `json:"mac"`
	IP          string    `json:"ip"`
	LastSeen    time.Time `json:"lastSeen"`
	Quarantined bool      `json:"quarantined"`
	Tx24h       uint64    `json:"tx24h"`
	Rx24h       uint64    `json:"rx24h"`
}

type hourDTO struct {
	Hour        time.Time `json:"hour"`
	Tx          uint64    `json:"tx"`
	Rx          uint64    `json:"rx"`
	NewConns    int       `json:"newConns"`
	DistinctDst int       `json:"distinctDst"`
}

type destDTO struct {
	Country   string    `json:"country"`
	ASN       uint32    `json:"asn"`
	ASOrg     string    `json:"asOrg"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Bytes     uint64    `json:"bytes"`
}

type alertDTO struct {
	ID         int64          `json:"id"`
	Time       time.Time      `json:"time"`
	MAC        string         `json:"mac"`
	DeviceName string         `json:"deviceName"`
	Kind       string         `json:"kind"`
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail"`
	Evidence   map[string]any `json:"evidence,omitempty"`
	Acked      bool           `json:"acked"`
}

type deviceDetailDTO struct {
	Device deviceDTO  `json:"device"`
	Hours  []hourDTO  `json:"hours"`
	Dests  []destDTO  `json:"dests"`
	Alerts []alertDTO `json:"alerts"`
}

// mergeDTO is the response of merge / unmerge.
type mergeDTO struct {
	GroupID string   `json:"groupId"` // "" after unmerge
	MACs    []string `json:"macs"`
}

// deviceName is model.Device.DisplayName with whitespace-only fields ignored.
func deviceName(d model.Device) string {
	d.Note = strings.TrimSpace(d.Note)
	d.Comment = strings.TrimSpace(d.Comment)
	d.Hostname = strings.TrimSpace(d.Hostname)
	d.Vendor = strings.TrimSpace(d.Vendor)
	d.MAC = strings.TrimSpace(d.MAC)
	if s := d.DisplayName(); s != "" {
		return s
	}
	return "?"
}

func toDeviceDTO(d model.Device) deviceDTO {
	ip := ""
	if d.IP.IsValid() {
		ip = d.IP.String()
	}
	return deviceDTO{
		MAC: d.MAC, IP: ip, Hostname: d.Hostname, Vendor: d.Vendor,
		Kind: d.EffectiveKind(), KindAuto: d.Kind, KindOverride: d.KindOverride,
		ClassID: d.ClassID, Randomized: d.Randomized, FirstSeen: d.FirstSeen,
		LastSeen: d.LastSeen, Quarantined: d.Quarantined, Note: d.Note, Comment: d.Comment,
		Name: deviceName(d), GroupID: d.GroupID,
	}
}

func toAlertDTO(a model.Alert, names map[string]string) alertDTO {
	return alertDTO{
		ID: a.ID, Time: a.Time, MAC: a.DeviceMAC, DeviceName: names[a.DeviceMAC], Kind: a.Kind,
		Severity: a.Severity.String(), Title: a.Title, Detail: a.Detail, Evidence: a.Evidence, Acked: a.Acked,
	}
}

// alertLang returns the ?lang= of an alert request when it is one of
// settings.Languages, else "" (= keep the stored texts).
func alertLang(r *http.Request) string {
	if l := r.URL.Query().Get("lang"); slices.Contains(settings.Languages, l) {
		return l
	}
	return ""
}

// localize replaces the stored title/detail (written in the notification
// language when the alert was raised) with a rendering in lang from the
// alert's evidence; d is the alert's device (nil = unknown). Alerts whose
// evidence cannot be rendered (older versions) keep the stored texts.
func localize(dto *alertDTO, a model.Alert, d *model.Device, lang string) {
	if lang == "" {
		return
	}
	if title, detail, ok := detect.RenderAlert(a, d, lang); ok {
		dto.Title, dto.Detail = title, detail
	}
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

func (s *server) status(w http.ResponseWriter, r *http.Request) {
	st := s.d.Status()
	now := s.now()
	writeJSON(w, http.StatusOK, statusDTO{
		Version: st.Version, Now: now, StartedAt: st.StartedAt, LastPoll: st.LastPoll,
		LearningUntil: st.LearningUntil, Learning: now.Before(st.LearningUntil),
		LastPollMs: st.LastPollDuration.Milliseconds(), LastError: st.LastError,
		ConnCount: st.ConnCount, FasttrackCount: st.FasttrackCount,
		DeviceCount: st.DeviceCount, RouterCPU: st.RouterCPU,
	})
}

func (s *server) devices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	devs, err := s.d.Store.Devices(ctx)
	if err != nil {
		s.internal(w, "devices", err)
		return
	}
	open, err := s.d.Store.Alerts(ctx, model.AlertFilter{OnlyOpen: true, Limit: 10000})
	if err != nil {
		s.internal(w, "alerts", err)
		return
	}
	openBy := map[string]int{}
	for _, a := range open {
		openBy[a.DeviceMAC]++
	}
	now := s.now()
	from := now.Add(-24 * time.Hour).Truncate(time.Hour)
	out := make([]deviceDTO, 0, len(devs))
	for _, d := range devs {
		dto := toDeviceDTO(d)
		dto.OpenAlerts = openBy[d.MAC]
		hs, err := s.d.Store.HourStats(ctx, d.MAC, from, now)
		if err != nil {
			s.internal(w, "hourstats", err)
			return
		}
		for _, h := range hs {
			dto.Tx24h += h.TxBytes
			dto.Rx24h += h.RxBytes
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, groupDevices(out))
}

// byLastSeen orders newest first, MAC as tie breaker.
func byLastSeen(a, b deviceDTO) bool {
	if !a.LastSeen.Equal(b.LastSeen) {
		return a.LastSeen.After(b.LastSeen)
	}
	return a.MAC < b.MAC
}

// Group key prefixes.
const (
	groupManual = "m:"
	groupAuto   = "h:"
)

// groupKey returns the key under which a device is merged with others, or ""
// when it stands alone. Manual groups (GroupID, merged by the user) win.
// Otherwise: phones use a different randomized MAC per Wi-Fi network but keep
// their hostname, so randomized MACs with the same (case-insensitive)
// hostname are one physical device.
func groupKey(d deviceDTO) string {
	if d.GroupID != "" {
		return groupManual + d.GroupID
	}
	if !d.Randomized {
		return ""
	}
	if h := strings.ToLower(strings.TrimSpace(d.Hostname)); h != "" {
		return groupAuto + h
	}
	return ""
}

// groupDevices merges devices with the same groupKey into one row. The row
// keeps the fields of the most recently seen member, sums traffic and open
// alerts and lists all members. The result is sorted newest first.
func groupDevices(devs []deviceDTO) []deviceDTO {
	sort.SliceStable(devs, func(i, j int) bool { return byLastSeen(devs[i], devs[j]) })
	out := make([]deviceDTO, 0, len(devs))
	keys := make([]string, 0, len(devs)) // parallel to out; "" = single device
	groups := map[string][]deviceDTO{}
	for _, d := range devs {
		k := groupKey(d)
		if k == "" {
			out = append(out, d)
			keys = append(keys, "")
			continue
		}
		if _, seen := groups[k]; !seen {
			out = append(out, deviceDTO{}) // placeholder, keeps the order of the primary
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], d)
	}
	for i, k := range keys {
		if k != "" {
			out[i] = groupRow(groups[k], strings.HasPrefix(k, groupManual))
		}
	}
	return out
}

// groupRow builds the row of one group; ms is sorted newest first.
func groupRow(ms []deviceDTO, manual bool) deviceDTO {
	g := ms[0]
	if len(ms) == 1 {
		return g
	}
	g.Group = "auto"
	if manual {
		g.Group = "manual"
	}
	if strings.TrimSpace(g.Note) == "" && strings.TrimSpace(g.Comment) == "" {
		// a name the user (or DHCP comment) gave another member wins over the hostname
		for _, m := range ms[1:] {
			if strings.TrimSpace(m.Note) != "" || strings.TrimSpace(m.Comment) != "" {
				g.Name = m.Name
				break
			}
		}
	}
	if g.KindOverride == "" {
		// likewise a kind the user chose for another member wins over the guess
		for _, m := range ms[1:] {
			if m.KindOverride != "" {
				g.Kind, g.KindOverride = m.KindOverride, m.KindOverride
				break
			}
		}
	}
	g.Tx24h, g.Rx24h, g.OpenAlerts = 0, 0, 0
	nq := 0
	for _, m := range ms {
		g.Tx24h += m.Tx24h
		g.Rx24h += m.Rx24h
		g.OpenAlerts += m.OpenAlerts
		if m.Quarantined {
			nq++
		}
		if m.FirstSeen.Before(g.FirstSeen) && !m.FirstSeen.IsZero() {
			g.FirstSeen = m.FirstSeen
		}
		g.Members = append(g.Members, memberDTO{MAC: m.MAC, IP: m.IP, LastSeen: m.LastSeen,
			Quarantined: m.Quarantined, Tx24h: m.Tx24h, Rx24h: m.Rx24h})
	}
	g.Quarantined = nq == len(ms)
	g.PartiallyQuarantined = nq > 0 && nq < len(ms)
	return g
}

// healthz reports 200 "ok" when the collector polled the router successfully
// within HealthMaxAge, otherwise 503 with a short reason. It is reachable
// without authentication, so it must not reveal details (e.g. error texts).
func (s *server) healthz(w http.ResponseWriter, r *http.Request) {
	st := s.d.Status()
	code, msg := http.StatusOK, "ok"
	switch {
	case st.LastError != "":
		code, msg = http.StatusServiceUnavailable, "last poll failed"
	case st.LastPoll.IsZero():
		code, msg = http.StatusServiceUnavailable, "no poll yet"
	case s.now().Sub(st.LastPoll) > s.d.HealthMaxAge:
		code, msg = http.StatusServiceUnavailable, "last poll too old ("+s.now().Sub(st.LastPoll).Round(time.Second).String()+")"
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, msg+"\n")
}

// device returns one device with its last 7 days of traffic, destinations
// and alerts (?lang= as for alerts).
func (s *server) device(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, ok := s.lookup(w, r)
	if !ok {
		return
	}
	now := s.now()
	from := now.Add(-detailDays * 24 * time.Hour).Truncate(time.Hour)
	hs, err := s.d.Store.HourStats(ctx, d.MAC, from, now)
	if err != nil {
		s.internal(w, "hourstats", err)
		return
	}
	ds, err := s.d.Store.DestStats(ctx, d.MAC)
	if err != nil {
		s.internal(w, "deststats", err)
		return
	}
	as, err := s.d.Store.Alerts(ctx, model.AlertFilter{DeviceMAC: d.MAC, Limit: 50})
	if err != nil {
		s.internal(w, "alerts", err)
		return
	}
	res := deviceDetailDTO{Device: toDeviceDTO(d), Hours: []hourDTO{}, Dests: []destDTO{}, Alerts: []alertDTO{}}
	from24 := now.Add(-24 * time.Hour).Truncate(time.Hour)
	sort.Slice(hs, func(i, j int) bool { return hs[i].Hour.Before(hs[j].Hour) })
	for _, h := range hs {
		res.Hours = append(res.Hours, hourDTO{Hour: h.Hour, Tx: h.TxBytes, Rx: h.RxBytes, NewConns: h.NewConns, DistinctDst: h.DistinctDst})
		if !h.Hour.Before(from24) {
			res.Device.Tx24h += h.TxBytes
			res.Device.Rx24h += h.RxBytes
		}
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].Bytes > ds[j].Bytes })
	if len(ds) > maxDests {
		ds = ds[:maxDests]
	}
	for _, x := range ds {
		res.Dests = append(res.Dests, destDTO{Country: x.Country, ASN: x.ASN, ASOrg: x.ASOrg, FirstSeen: x.FirstSeen, LastSeen: x.LastSeen, Bytes: x.Bytes})
	}
	names := map[string]string{d.MAC: deviceName(d)}
	lang := alertLang(r)
	for _, a := range as {
		if !a.Acked {
			res.Device.OpenAlerts++
		}
		dto := toAlertDTO(a, names)
		localize(&dto, a, &d, lang)
		res.Alerts = append(res.Alerts, dto)
	}
	writeJSON(w, http.StatusOK, res)
}

// patchDevice edits the user's fields of one device:
// {"note"?: string, "kind"?: string}; kind "" = back to the automatic guess.
func (s *server) patchDevice(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookup(w, r)
	if !ok {
		return
	}
	var body struct {
		Note *string `json:"note"`
		Kind *string `json:"kind"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Note == nil && body.Kind == nil {
		writeErr(w, http.StatusBadRequest, "nothing to change: send note and/or kind")
		return
	}
	// validate everything before changing anything
	var note, kind string
	if body.Note != nil {
		note = strings.TrimSpace(*body.Note)
		if len([]rune(note)) > maxNoteLen {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("note is too long (max %d characters)", maxNoteLen))
			return
		}
	}
	if body.Kind != nil {
		kind = strings.ToLower(strings.TrimSpace(*body.Kind))
		if kind != "" && !model.ValidKind(kind) {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("unknown device kind %q (allowed: %s)", kind, strings.Join(model.Kinds, ", ")))
			return
		}
	}
	if body.Note != nil {
		if err := s.d.Store.SetNote(r.Context(), d.MAC, note); err != nil {
			s.internal(w, "setnote", err)
			return
		}
		d.Note = note
	}
	if body.Kind != nil {
		if err := s.d.Store.SetKindOverride(r.Context(), d.MAC, kind); err != nil {
			s.internal(w, "setkind", err)
			return
		}
		d.KindOverride = kind
	}
	writeJSON(w, http.StatusOK, toDeviceDTO(d))
}

// merge joins devices the user knows to be one physical device:
// {"macs": [...]} with at least two different MACs. Manual groups any of them
// already belongs to are joined as well. The group ID is the MAC of the most
// recently seen member.
func (s *server) merge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		MACs []string `json:"macs"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if len(body.MACs) > maxMergeMACs {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("too many devices (max %d)", maxMergeMACs))
		return
	}
	var macs []string
	for _, m := range body.MACs {
		mac, ok := normalizeMAC(m)
		if !ok {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("invalid MAC address %q", m))
			return
		}
		if !slices.Contains(macs, mac) {
			macs = append(macs, mac)
		}
	}
	if len(macs) < 2 {
		writeErr(w, http.StatusBadRequest, "at least two different devices are required")
		return
	}
	ctx := r.Context()
	devs, err := s.d.Store.Devices(ctx)
	if err != nil {
		s.internal(w, "devices", err)
		return
	}
	byMAC := make(map[string]model.Device, len(devs))
	byGroup := map[string][]model.Device{}
	for _, d := range devs {
		byMAC[d.MAC] = d
		if d.GroupID != "" {
			byGroup[d.GroupID] = append(byGroup[d.GroupID], d)
		}
	}
	members := map[string]model.Device{}
	for _, mac := range macs {
		d, ok := byMAC[mac]
		if !ok {
			writeErr(w, http.StatusNotFound, "device not found: "+mac)
			return
		}
		members[mac] = d
		if d.GroupID != "" {
			for _, x := range byGroup[d.GroupID] { // union with its manual group
				members[x.MAC] = x
			}
		}
	}
	var primary model.Device
	all := make([]string, 0, len(members))
	for mac, d := range members {
		all = append(all, mac)
		if primary.MAC == "" || d.LastSeen.After(primary.LastSeen) ||
			(d.LastSeen.Equal(primary.LastSeen) && d.MAC < primary.MAC) {
			primary = d
		}
	}
	sort.Strings(all)
	if err := s.d.Store.SetGroup(ctx, all, primary.MAC); err != nil {
		s.internal(w, "setgroup", err)
		return
	}
	s.d.Log.Info("devices merged", "group", primary.MAC, "macs", all)
	writeJSON(w, http.StatusOK, mergeDTO{GroupID: primary.MAC, MACs: all})
}

// unmerge dissolves the manual group the device belongs to.
func (s *server) unmerge(w http.ResponseWriter, r *http.Request) {
	d, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if d.GroupID == "" {
		writeErr(w, http.StatusConflict, "device is not in a merged group")
		return
	}
	devs, err := s.d.Store.Devices(r.Context())
	if err != nil {
		s.internal(w, "devices", err)
		return
	}
	macs := []string{d.MAC}
	for _, x := range devs {
		if x.GroupID == d.GroupID && x.MAC != d.MAC {
			macs = append(macs, x.MAC)
		}
	}
	sort.Strings(macs)
	if err := s.d.Store.SetGroup(r.Context(), macs, ""); err != nil {
		s.internal(w, "setgroup", err)
		return
	}
	s.d.Log.Info("devices unmerged", "group", d.GroupID, "macs", macs)
	writeJSON(w, http.StatusOK, mergeDTO{MACs: macs})
}

func (s *server) quarantine(w http.ResponseWriter, r *http.Request) {
	s.setQuarantine(w, r, true)
}

func (s *server) unquarantine(w http.ResponseWriter, r *http.Request) {
	s.setQuarantine(w, r, false)
}

func (s *server) setQuarantine(w http.ResponseWriter, r *http.Request, q bool) {
	d, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.d.API == nil || s.d.QuarantineList == "" {
		writeErr(w, http.StatusServiceUnavailable, "quarantine is not configured")
		return
	}
	if q && !d.IP.IsValid() {
		writeErr(w, http.StatusConflict, "device has no known IP address")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), routerTimeout)
	defer cancel()
	if d.IP.IsValid() {
		var err error
		if q {
			comment := "guardian: " + truncateRunes(sanitizeComment(deviceName(d)), 60)
			err = s.d.API.AddressListAdd(ctx, s.d.QuarantineList, d.IP.String(), comment, 0)
		} else {
			err = s.d.API.AddressListRemove(ctx, s.d.QuarantineList, d.IP.String())
		}
		if err != nil {
			s.d.Log.Error("quarantine router call", "mac", d.MAC, "ip", d.IP, "quarantine", q, "err", err)
			writeErr(w, http.StatusBadGateway, "router rejected the change: "+err.Error())
			return
		}
		// Fasttracked packets bypass the firewall, so the quarantine drop rule
		// would not stop connections that already exist. Best effort.
		if cd, ok := s.d.API.(connDropper); ok && q {
			if n, err := cd.DropConnections(ctx, d.IP); err != nil {
				s.d.Log.Warn("quarantine drop connections", "mac", d.MAC, "ip", d.IP, "err", err)
			} else {
				s.d.Log.Info("quarantine dropped connections", "mac", d.MAC, "count", n)
			}
		}
	}
	if err := s.d.Store.SetQuarantined(r.Context(), d.MAC, q); err != nil {
		s.internal(w, "setquarantined", err)
		return
	}
	s.d.Log.Info("quarantine changed", "mac", d.MAC, "ip", d.IP, "quarantined", q)
	d.Quarantined = q
	writeJSON(w, http.StatusOK, toDeviceDTO(d))
}

// alerts lists alerts, newest first: ?open=1, ?mac=, ?limit= (max 1000),
// ?since= (RFC 3339) and ?lang= (title/detail rendered in that UI language).
func (s *server) alerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.AlertFilter{OnlyOpen: q.Get("open") == "1" || q.Get("open") == "true", Limit: 100}
	if m := q.Get("mac"); m != "" {
		mac, ok := normalizeMAC(m)
		if !ok {
			writeErr(w, http.StatusBadRequest, "invalid MAC address")
			return
		}
		f.DeviceMAC = mac
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "invalid limit")
			return
		}
		f.Limit = min(n, 1000)
	}
	if sv := q.Get("since"); sv != "" {
		t, err := time.Parse(time.RFC3339, sv)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid since parameter (RFC 3339)")
			return
		}
		f.Since = t
	}
	as, err := s.d.Store.Alerts(r.Context(), f)
	if err != nil {
		s.internal(w, "alerts", err)
		return
	}
	names := map[string]string{}
	byMAC := map[string]model.Device{}
	if devs, err := s.d.Store.Devices(r.Context()); err == nil {
		for _, d := range devs {
			names[d.MAC] = deviceName(d)
			byMAC[d.MAC] = d
		}
	}
	lang := alertLang(r)
	out := make([]alertDTO, 0, len(as))
	for _, a := range as {
		dto := toAlertDTO(a, names)
		var dev *model.Device
		if d, ok := byMAC[a.DeviceMAC]; ok {
			dev = &d
		}
		localize(&dto, a, dev, lang)
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) ack(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := s.d.Store.AckAlert(r.Context(), id); err != nil {
		s.internal(w, "ack", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// lookup resolves {mac} and loads the device, writing an error response on failure.
func (s *server) lookup(w http.ResponseWriter, r *http.Request) (model.Device, bool) {
	mac, ok := normalizeMAC(r.PathValue("mac"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid MAC address")
		return model.Device{}, false
	}
	d, found, err := s.d.Store.Device(r.Context(), mac)
	if err != nil {
		s.internal(w, "device", err)
		return model.Device{}, false
	}
	if !found {
		writeErr(w, http.StatusNotFound, "device not found")
		return model.Device{}, false
	}
	return d, true
}

// normalizeMAC accepts "aa:bb:cc:dd:ee:ff", "AA-BB-..." and returns upper-case colon form.
func normalizeMAC(s string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return strings.ToUpper(hw.String()), true
}

func sanitizeComment(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return ' '
		}
		return r
	}, s)
}

func truncateRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
		} else if errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, "empty request body")
		} else {
			writeErr(w, http.StatusBadRequest, "invalid JSON")
		}
		return false
	}
	return true
}

func (s *server) internal(w http.ResponseWriter, op string, err error) {
	if errors.Is(err, model.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	s.d.Log.Error("web api", "op", op, "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error: "+op)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
