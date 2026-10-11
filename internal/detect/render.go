package detect

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/i18n"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// Alert texts are rendered from the alert's Evidence – by the detectors when
// they raise an alert (in settings.Language, the text that is stored and sent
// as a notification) and by the web UI for stored alerts in the viewer's
// language. Every value a text needs is therefore part of Evidence.
//
// Evidence of a stored alert comes back from SQLite as JSON (numbers are
// float64, times strings), so the renderer always decodes it through a JSON
// round trip into typed structs; fresh evidence (native Go types) takes the
// same path, which makes the stored text and a later rendering identical.

// RenderAlert rebuilds the title and detail of an alert raised by this
// package in lang (one of settings.Languages; anything else = English) from
// a.Kind, a.Severity and a.Evidence. d is the current state of the alert's
// device (nil = unknown) and names it (note, DHCP comment or kind label with
// hostname/vendor); without it the device snapshot in the evidence is used.
// Explanations keep the kind stored in the evidence. ok is false when the
// evidence is incomplete (e.g. alerts stored by older versions) or the kind is
// unknown; callers then keep the stored Title/Detail.
func RenderAlert(a model.Alert, d *model.Device, lang string) (title, detail string, ok bool) {
	l := loc(i18n.Fallback)
	if slices.Contains(settings.Languages, lang) {
		l = loc(lang)
	}
	title, detail, err := renderAlert(a, d, l)
	if err != nil {
		return "", "", false
	}
	return title, detail, true
}

// errIncomplete reports evidence that lacks a value a text needs.
var errIncomplete = errors.New("incomplete alert evidence")

// evidence is decoded alert evidence: raw values for presence checks and the
// JSON for decoding into the per-kind structs.
type evidence struct {
	raw map[string]json.RawMessage
	js  []byte
}

func parseEvidence(ev map[string]any) (evidence, error) {
	if len(ev) == 0 {
		return evidence{}, errIncomplete
	}
	js, err := json.Marshal(ev)
	if err != nil {
		return evidence{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(js, &raw); err != nil {
		return evidence{}, err
	}
	return evidence{raw: raw, js: js}, nil
}

// need fails unless every key is present.
func (e evidence) need(keys ...string) error {
	for _, k := range keys {
		if _, ok := e.raw[k]; !ok {
			return fmt.Errorf("%w: no %q", errIncomplete, k)
		}
	}
	return nil
}

func (e evidence) has(key string) bool { _, ok := e.raw[key]; return ok }

func (e evidence) decode(v any) error { return json.Unmarshal(e.js, v) }

// value decodes a single key into v (missing key = error).
func (e evidence) value(key string, v any) error {
	m, ok := e.raw[key]
	if !ok {
		return fmt.Errorf("%w: no %q", errIncomplete, key)
	}
	return json.Unmarshal(m, v)
}

// devSnapshot is the part of a device that names it in alert texts, stored
// as Evidence["device"] for when the device is no longer known.
type devSnapshot struct {
	MAC      string `json:"mac"`
	Note     string `json:"note"`
	Comment  string `json:"comment"`
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
	Kind     string `json:"kind"` // effective kind
}

func snapshotOf(d model.Device) map[string]any {
	return map[string]any{
		"mac": d.MAC, "note": d.Note, "comment": d.Comment,
		"hostname": d.Hostname, "vendor": d.Vendor, "kind": d.EffectiveKind(),
	}
}

func (s devSnapshot) device() model.Device {
	return model.Device{MAC: s.MAC, Note: s.Note, Comment: s.Comment, Hostname: s.Hostname, Vendor: s.Vendor, Kind: s.Kind}
}

// alertDevice is the device that names the alert: the current device when
// known, else the snapshot in the evidence.
func alertDevice(ev evidence, d *model.Device) (model.Device, error) {
	if d != nil {
		return *d, nil
	}
	var s devSnapshot
	if err := ev.value("device", &s); err != nil {
		return model.Device{}, err
	}
	return s.device(), nil
}

// renderAlert dispatches on the alert kind.
func renderAlert(a model.Alert, d *model.Device, l loc) (string, string, error) {
	ev, err := parseEvidence(a.Evidence)
	if err != nil {
		return "", "", err
	}
	switch a.Kind {
	case model.AlertNewDevice:
		if a.DeviceMAC == "" || strings.HasPrefix(a.DedupKey, inventoryDedupKey) {
			return renderInventory(ev, a.Time, l)
		}
		return renderNewDevice(ev, d, a.Severity, l)
	case model.AlertNewCountry:
		return renderCountry(ev, d, l)
	case model.AlertNewASN:
		return renderASN(ev, d, l)
	case model.AlertUploadSpike:
		return renderSpike(ev, d, a.Severity, l)
	case model.AlertDestFanout:
		return renderFanout(ev, d, a.Severity, l)
	}
	return "", "", fmt.Errorf("no texts for alert kind %q", a.Kind)
}

// --- new device ---------------------------------------------------------------

type newDeviceEv struct {
	MAC        string       `json:"mac"`
	IP         string       `json:"ip"`
	Hostname   string       `json:"hostname"`
	Vendor     string       `json:"vendor"`
	Comment    string       `json:"comment"`
	Kind       string       `json:"kind"` // effective kind when the device appeared
	Randomized bool         `json:"randomized"`
	Device     *devSnapshot `json:"device"`
}

func renderNewDevice(ev evidence, d *model.Device, sev model.Severity, l loc) (string, string, error) {
	if err := ev.need("mac", "kind", "randomized"); err != nil {
		return "", "", err
	}
	var x newDeviceEv
	if err := ev.decode(&x); err != nil {
		return "", "", err
	}
	var dev model.Device
	switch {
	case d != nil:
		dev = *d
	case x.Device != nil:
		dev = x.Device.device()
	default: // v0.3.1 evidence: the device as it appeared (no user note yet)
		dev = model.Device{MAC: x.MAC, Hostname: x.Hostname, Vendor: x.Vendor, Comment: x.Comment, Kind: x.Kind}
	}
	name := l.deviceName(dev)
	det := []string{l.t("alert.newdev.first", name)}
	info := []string{"MAC " + x.MAC}
	if x.IP != "" {
		info = append(info, "IP "+x.IP)
	}
	if x.Hostname != "" {
		info = append(info, l.t("alert.newdev.hostname", x.Hostname))
	}
	if x.Comment != "" {
		info = append(info, l.t("alert.newdev.comment", x.Comment))
	}
	if x.Vendor != "" {
		info = append(info, l.t("alert.newdev.vendor", x.Vendor))
	}
	info = append(info, l.t("alert.newdev.kind", l.kind(x.Kind)))
	det = append(det, strings.Join(info, ", ")+".")
	if x.Randomized {
		det = append(det, l.t("alert.newdev.randomized"))
	}
	if sev == model.SevWarning {
		det = append(det, l.t("alert.newdev.advice_warning"))
	} else {
		det = append(det, l.t("alert.newdev.advice_info"))
	}
	return l.t("alert.newdev.title", name), strings.Join(det, " "), nil
}

// --- inventory summary ----------------------------------------------------------

type inventoryEv struct {
	Devices        int       `json:"devices"`
	InventoryUntil time.Time `json:"inventory_until"`
	LearningUntil  time.Time `json:"learning_until"`
	LearningStart  time.Time `json:"learning_start"`
	Hours          *int      `json:"inventory_hours"`
	Learning       *bool     `json:"learning"` // learning still running when the summary was raised
}

// renderInventory renders the inventory summary raised at "at".
func renderInventory(ev evidence, at time.Time, l loc) (string, string, error) {
	if err := ev.need("devices", "learning_until"); err != nil {
		return "", "", err
	}
	var x inventoryEv
	if err := ev.decode(&x); err != nil {
		return "", "", err
	}
	// v0.3.1 did not store inventory_hours and learning; both follow exactly
	// from what it stored (the inventory window starts at the learning start,
	// the summary's time decided between "learning" and "learned").
	var hours int
	switch {
	case x.Hours != nil:
		hours = *x.Hours
	case ev.has("inventory_until") && ev.has("learning_start"):
		hours = int(x.InventoryUntil.Sub(x.LearningStart).Hours())
	default:
		return "", "", fmt.Errorf("%w: no inventory_hours", errIncomplete)
	}
	learning := at.Before(x.LearningUntil)
	if x.Learning != nil {
		learning = *x.Learning
	}
	var parts []string
	for _, k := range inventoryKindOrder {
		if !ev.has("kind_" + k) {
			continue
		}
		var c int
		if err := ev.value("kind_"+k, &c); err != nil {
			return "", "", err
		}
		if c > 0 {
			parts = append(parts, fmt.Sprintf("%s: %d", l.kind(k), c))
		}
	}
	n := x.Devices
	det := []string{
		l.t("alert.inventory.found", hours, l.word("hour", hours), n, l.word("device", n), strings.Join(parts, ", ")),
		l.t("alert.inventory.review"),
	}
	if learning {
		det = append(det, l.t("alert.inventory.learning", l.datetime(x.LearningUntil)))
	} else {
		det = append(det, l.t("alert.inventory.learned"))
	}
	return l.t("alert.inventory.title", n, l.word("device", n)), strings.Join(det, " "), nil
}

// --- new country / new ASN ------------------------------------------------------

// destEv is one new destination (Evidence["new"][i], see destEvidence).
type destEv struct {
	Country  string   `json:"country"`
	ASN      uint32   `json:"asn"`
	ASOrg    string   `json:"as_org"`
	Tx       float64  `json:"tx_bytes"`
	Rx       float64  `json:"rx_bytes"`
	Conns    int      `json:"new_conns"`
	Examples []string `json:"examples"`
}

func destLine(l loc, p destEv, what string) string {
	if al := asLabel(p.ASN, p.ASOrg); al != "" && !strings.HasPrefix(what, al) {
		what += " (" + al + ")"
	}
	ex := ""
	if len(p.Examples) > 0 {
		ex = l.t("alert.dest.examples", strings.Join(p.Examples, ", "))
	}
	return l.t("alert.dest.line", what, l.bytes(p.Tx), l.bytes(p.Rx), p.Conns, l.word("new_conn", p.Conns), ex)
}

type countryEv struct {
	DeviceKind     string   `json:"device_kind"`
	New            []destEv `json:"new"`
	KnownCountries int      `json:"known_countries"`
	KnownList      []string `json:"known_list"`
	CriticalTx     float64  `json:"critical_tx"`
	Immediate      bool     `json:"immediate"`
}

func renderCountry(ev evidence, d *model.Device, l loc) (string, string, error) {
	if err := ev.need("device_kind", "new", "known_countries", "known_list", "critical_tx", "immediate"); err != nil {
		return "", "", err
	}
	var x countryEv
	if err := ev.decode(&x); err != nil {
		return "", "", err
	}
	if len(x.New) == 0 {
		return "", "", fmt.Errorf("%w: no new countries", errIncomplete)
	}
	dev, err := alertDevice(ev, d)
	if err != nil {
		return "", "", err
	}
	name := l.deviceName(dev)
	ccs := make([]string, len(x.New))
	for i, p := range x.New {
		ccs[i] = p.Country
	}
	var title string
	if len(ccs) == 1 {
		title = l.t("alert.country.title.one", name, ccs[0])
	} else {
		title = l.t("alert.country.title.many", name, strings.Join(ccs, ", "))
	}
	var det []string
	for _, p := range x.New {
		det = append(det, l.t("alert.country.first", destLine(l, p, p.Country)))
	}
	if len(x.KnownList) > 0 {
		n := x.KnownCountries
		det = append(det, l.t("alert.country.known", n, l.word("country", n), strings.Join(x.KnownList, ", ")))
	}
	if x.Immediate {
		det = append(det, l.t("alert.country.advice_crit", l.kind(x.DeviceKind), l.bytes(x.CriticalTx)))
	} else {
		det = append(det, l.t("alert.country.advice_warn"))
	}
	return title, strings.Join(det, " "), nil
}

type asnEv struct {
	DeviceKind string   `json:"device_kind"`
	New        []destEv `json:"new"`
	KnownASNs  int      `json:"known_asns"`
}

func renderASN(ev evidence, d *model.Device, l loc) (string, string, error) {
	if err := ev.need("device_kind", "new", "known_asns"); err != nil {
		return "", "", err
	}
	var x asnEv
	if err := ev.decode(&x); err != nil {
		return "", "", err
	}
	if len(x.New) == 0 {
		return "", "", fmt.Errorf("%w: no new networks", errIncomplete)
	}
	dev, err := alertDevice(ev, d)
	if err != nil {
		return "", "", err
	}
	name := l.deviceName(dev)
	var title string
	if len(x.New) == 1 {
		title = l.t("alert.asn.title.one", name, asLabel(x.New[0].ASN, x.New[0].ASOrg))
	} else {
		title = l.t("alert.asn.title.many", name, len(x.New))
	}
	var det []string
	for _, p := range x.New {
		what := asLabel(p.ASN, p.ASOrg)
		if p.Country != "" {
			what += " [" + p.Country + "]"
		}
		det = append(det, l.t("alert.asn.first", destLine(l, p, what)))
	}
	n := x.KnownASNs
	det = append(det, l.t("alert.asn.known", l.kind(x.DeviceKind), n, l.word("network", n)))
	return title, strings.Join(det, " "), nil
}

// --- upload spike -------------------------------------------------------------

// legacyBaselineDays is the baseline window of alerts that did not store it.
const legacyBaselineDays = 28

type spikeEv struct {
	Path       string    `json:"path"`
	Hour       time.Time `json:"hour"`
	DeviceKind string    `json:"device_kind"`
	Observed   float64   `json:"observed_tx"`
	Median     float64   `json:"baseline_median"`
	Max        float64   `json:"baseline_max"`
	Samples    int       `json:"baseline_samples"`
	Method     string    `json:"baseline_method"`
	Ratio      float64   `json:"ratio"`
	Days       *int      `json:"baseline_days"`
	Minutes    int       `json:"minutes"`
}

func renderSpike(ev evidence, d *model.Device, sev model.Severity, l loc) (string, string, error) {
	if err := ev.need("path", "device_kind", "observed_tx", "baseline_median", "baseline_samples", "baseline_method", "ratio"); err != nil {
		return "", "", err
	}
	var x spikeEv
	if err := ev.decode(&x); err != nil {
		return "", "", err
	}
	dev, err := alertDevice(ev, d)
	if err != nil {
		return "", "", err
	}
	name := l.deviceName(dev)
	b := baseline{Median: x.Median, Max: x.Max, Samples: x.Samples, Method: x.Method}
	if x.Path == "fast" {
		if err := ev.need("minutes"); err != nil {
			return "", "", err
		}
		det := []string{
			l.t("alert.spike.fast.detail", x.Minutes, l.bytes(x.Observed),
				l.baseline(b, l.t("unit.per_whole_hour", l.bytes(b.Median))), l.ratio(x.Ratio)),
			spikeAdvice(l, x.DeviceKind, sev),
		}
		return l.t("alert.spike.fast.title", name, l.bytes(x.Observed)), strings.Join(det, " "), nil
	}
	if err := ev.need("hour", "baseline_max"); err != nil {
		return "", "", err
	}
	// v0.3.1 did not store the window; it was always the default one
	// (cmd/guardian uses DefaultConfig, BaselineWindow is not a setting).
	days := legacyBaselineDays
	if x.Days != nil {
		days = *x.Days
	}
	det := []string{
		l.t("alert.spike.detail", hourRange(x.Hour), l.bytes(x.Observed), l.baseline(b, l.perHour(b.Median)), l.ratio(x.Ratio)),
		l.t("alert.spike.max", days, l.word("day", days), l.perHour(b.Max)),
		spikeAdvice(l, x.DeviceKind, sev),
	}
	return l.t("alert.spike.title", name, l.perHour(x.Observed)), strings.Join(det, " "), nil
}

func spikeAdvice(l loc, kind string, sev model.Severity) string {
	if sev == model.SevCritical {
		return l.t("alert.spike.advice_crit", l.kind(kind))
	}
	return l.t("alert.spike.advice_warn")
}

// --- destination fan-out --------------------------------------------------------

type fanoutEv struct {
	Hour     time.Time `json:"hour"`
	Observed int       `json:"observed_dst"`
	NewConns int       `json:"new_conns"`
	Median   float64   `json:"baseline_median"`
	Max      float64   `json:"baseline_max"`
	Samples  int       `json:"baseline_samples"`
	Method   string    `json:"baseline_method"`
	Ratio    float64   `json:"ratio"`
}

func renderFanout(ev evidence, d *model.Device, sev model.Severity, l loc) (string, string, error) {
	if err := ev.need("hour", "observed_dst", "new_conns", "baseline_median", "baseline_max",
		"baseline_samples", "baseline_method", "ratio"); err != nil {
		return "", "", err
	}
	var x fanoutEv
	if err := ev.decode(&x); err != nil {
		return "", "", err
	}
	dev, err := alertDevice(ev, d)
	if err != nil {
		return "", "", err
	}
	b := baseline{Median: x.Median, Max: x.Max, Samples: x.Samples, Method: x.Method}
	det := []string{
		l.t("alert.fanout.detail", hourRange(x.Hour), x.Observed, x.NewConns,
			l.baseline(b, l.t("unit.addr_per_hour", l.num(b.Median))), l.ratio(x.Ratio)),
		l.t("alert.fanout.max", l.t("unit.addr_per_hour", l.num(b.Max))),
		l.t("alert.fanout.explain"),
	}
	if sev == model.SevCritical {
		det = append(det, l.t("alert.fanout.advice_crit"))
	}
	return l.t("alert.fanout.title", l.deviceName(dev), x.Observed), strings.Join(det, " "), nil
}

// --- detector side --------------------------------------------------------------

// setText fills a.Title/a.Detail in the engine's language from a.Evidence –
// the same renderer the web UI uses for stored alerts, so the stored text and
// a later rendering in the same language are identical. d is the device the
// alert is about (nil for the inventory summary).
func (e *Engine) setText(a *model.Alert, d *model.Device) {
	title, detail, err := renderAlert(*a, d, e.lang)
	if err != nil {
		// a bug (a detector stored incomplete evidence): keep the alert
		e.log.Error("render alert text", "kind", a.Kind, "mac", a.DeviceMAC, "err", err)
		title, detail = a.Kind, ""
	}
	a.Title, a.Detail = title, detail
}
