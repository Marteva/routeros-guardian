// Package detect is Guardian's anomaly detection engine.
//
// It is tuned for precision over recall: a home user who gets noise for a
// week switches the watchdog off. Every detector therefore combines a
// relative test (vs. the device's own history) with an absolute minimum,
// respects a global learning period and a per-device warm-up, and explains
// its decision (in the configured language, see internal/i18n) with the
// numbers in Alert.Evidence.
// See DESIGN.md for the rationale behind each detector and threshold.
package detect

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Marteva/routeros-guardian/internal/i18n"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// infoTTL is how long the stored copy of a device (user note, kind override,
// FirstSeen) is trusted before DeviceSeen/Flows reload it with store.Device.
// Tick additionally refreshes all cached devices from one store.Devices call.
const infoTTL = 5 * time.Minute

// Engine consumes device sightings and flow samples and emits alerts.
// All methods are safe for concurrent use.
type Engine struct {
	store model.Store
	sink  model.AlertSink
	base  Config // configuration given to New ("normal" sensitivity)
	log   *slog.Logger

	mu            sync.Mutex
	cfg           Config            // effective configuration (settings applied)
	set           settings.Settings // only DisabledDetectors is kept
	lang          loc               // language of alert texts
	start         time.Time         // fallback learning start
	learnFixed    bool              // learnStart comes from settings / Reset, not from the data
	learnResolved bool
	learnStart    time.Time
	devs          map[string]*devState
	household     map[string]struct{} // countries known for any device
	globalHour    time.Time           // newest clock hour seen in Flows
	lastEval      time.Time           // last hour evaluated by Tick
	summaryFor    time.Time           // learning start whose inventory summary is settled
}

// devState is the bounded in-memory state kept per device.
type devState struct {
	dev          model.Device
	infoLoaded   bool
	infoAt       time.Time // when dev was last refreshed from the store
	lastActivity time.Time

	destLoaded  bool
	destRetryAt time.Time
	countries   map[string]struct{}
	asns        map[uint32]struct{} // nil = not tracked (lenient kind or unstable)
	activeHours int                 // hours with traffic inside the baseline window

	curHour     time.Time
	curTx       uint64
	pendCountry map[string]*pending
	pendASN     map[uint32]*pending

	spikeAlertedHour time.Time // hour for which an upload spike was already raised
	fastBaseHour     time.Time
	fastBase         *baseline
}

// pending accumulates traffic to a not-yet-known destination within one hour.
type pending struct {
	country string
	asn     uint32
	asOrg   string
	tx, rx  uint64
	conns   int
	samples []netip.AddrPort // up to maxSamples example destinations
	alerted bool             // already raised immediately (critical path)
}

const maxSamples = 3

// New creates the engine. start is the process start time; it is only a
// fallback for the learning period when the store has no devices yet.
// Until SetSettings is called the engine uses cfg as given ("normal"
// sensitivity), all detectors are enabled and alert texts are English.
func New(store model.Store, sink model.AlertSink, cfg Config, start time.Time) *Engine {
	def := DefaultConfig()
	if cfg.Profiles == nil {
		cfg.Profiles = def.Profiles
		if cfg.DefaultProfile == (Profile{}) {
			cfg.DefaultProfile = def.DefaultProfile
		}
	}
	if cfg.BaselineWindow <= 0 {
		cfg.BaselineWindow = def.BaselineWindow
	}
	if cfg.EvictAfter <= 0 {
		cfg.EvictAfter = def.EvictAfter
	}
	if cfg.MaxCatchupHours <= 0 {
		cfg.MaxCatchupHours = def.MaxCatchupHours
	}
	if cfg.HistMaxFactor <= 0 {
		cfg.HistMaxFactor = 1
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Engine{
		store:     store,
		sink:      sink,
		base:      cfg,
		cfg:       cfg,
		lang:      loc(i18n.Fallback),
		log:       log.With("component", "detect"),
		start:     start,
		devs:      make(map[string]*devState),
		household: make(map[string]struct{}),
	}
}

// SetSettings applies runtime settings (call it at startup and from
// settings.Manager.OnChange). LearnPeriod and Sensitivity rebuild the
// thresholds from the configuration given to New; a non-zero LearningStart
// is the learning start (zero = derive it from the stored devices);
// DisabledDetectors suppress those alert kinds (the detectors keep learning,
// so re-enabling one does not flood); Language selects the alert texts.
func (e *Engine) SetSettings(s settings.Settings) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cfg := e.base
	if s.LearnPeriod > 0 {
		cfg.LearnPeriod = s.LearnPeriod
	}
	e.cfg = cfg.withSensitivity(s.Sensitivity)
	// Keep only what detection needs (not the notifier secrets).
	e.set = settings.Settings{DisabledDetectors: slices.Clone(s.DisabledDetectors)}
	e.lang = loc(i18n.Fallback)
	if slices.Contains(settings.Languages, s.Language) {
		e.lang = loc(s.Language)
	}
	switch {
	case !s.LearningStart.IsZero():
		if !e.learnResolved || !e.learnStart.Equal(s.LearningStart) {
			e.log.Info("learning period (settings)", "from", s.LearningStart,
				"until", s.LearningStart.Add(e.cfg.LearnPeriod))
		}
		e.learnStart = s.LearningStart
		e.learnFixed, e.learnResolved = true, true
	case e.learnFixed:
		e.learnFixed, e.learnResolved = false, false // derive from the data again
	}
}

// Reset drops all in-memory state – per-device caches, known destinations,
// baselines, hour buckets, the last evaluated hour and the inventory-summary
// mark – after the store was wiped (ResetLearned/ResetAll). Learning
// restarts now (so devices re-appearing after ResetAll fall into a fresh
// inventory window); the caller normally follows up with SetSettings
// carrying the persisted LearningStart.
func (e *Engine) Reset() {
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.devs = make(map[string]*devState)
	e.household = make(map[string]struct{})
	e.globalHour = time.Time{}
	e.lastEval = time.Time{}
	e.summaryFor = time.Time{}
	e.start = now
	e.learnStart = now
	e.learnFixed, e.learnResolved = true, true
	e.log.Info("detection state reset", "learning_until", e.learningUntil())
}

// enabled reports whether alerts of this kind may be raised.
func (e *Engine) enabled(kind string) bool { return e.set.DetectorEnabled(kind) }

// LearningUntil returns the end of the global learning period.
func (e *Engine) LearningUntil() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resolveLearning(context.Background())
	return e.learningUntil()
}

func (e *Engine) learningUntil() time.Time { return e.learnStart.Add(e.cfg.LearnPeriod) }

// inventoryPeriod is the initial inventory window, at most the learning period.
func (e *Engine) inventoryPeriod() time.Duration {
	return min(e.cfg.InventoryPeriod, e.cfg.LearnPeriod)
}

func (e *Engine) inventoryUntil() time.Time { return e.learnStart.Add(e.inventoryPeriod()) }

// resolveLearning derives the learning start from the store: the earliest
// Device.FirstSeen, or the process start if earlier / nothing is stored.
// Store errors fall back to start and are retried on the next call. A start
// set by SetSettings (LearningStart) or Reset is used as is.
func (e *Engine) resolveLearning(ctx context.Context) {
	if e.learnResolved {
		return
	}
	e.learnStart = e.start
	devs, err := e.store.Devices(ctx)
	if err != nil {
		e.log.Warn("learning period: list devices", "err", err)
		return
	}
	for _, d := range devs {
		if !d.FirstSeen.IsZero() && d.FirstSeen.Before(e.learnStart) {
			e.learnStart = d.FirstSeen
		}
	}
	e.learnResolved = true
	e.log.Info("learning period", "from", e.learnStart, "until", e.learningUntil())
}

func (e *Engine) state(mac string) *devState {
	st := e.devs[mac]
	if st == nil {
		st = &devState{dev: model.Device{MAC: mac}}
		e.devs[mac] = st
	}
	return st
}

// ensureInfo loads the stored device (FirstSeen, Note, KindOverride...) and
// reloads it when the copy is older than infoTTL, so a kind override set in
// the UI takes effect within minutes. A failed first load is retried on the
// next call; a failed refresh keeps the old copy until the next TTL.
func (e *Engine) ensureInfo(ctx context.Context, st *devState, now time.Time) {
	if st.infoLoaded && now.Sub(st.infoAt) < infoTTL {
		return
	}
	d, ok, err := e.store.Device(ctx, st.dev.MAC)
	if err != nil {
		e.log.Warn("load device", "mac", st.dev.MAC, "err", err)
		if st.infoLoaded {
			st.infoAt = now
		}
		return
	}
	if ok {
		e.mergeStored(st, d)
	}
	st.infoLoaded = true
	st.infoAt = now
}

// mergeStored refreshes st from the stored copy of the device. When the
// effective kind changes (user override in the UI), the destination cache
// built for the old profile (ASN tracking on/off) is dropped together with
// the current hour's pending destinations and rebuilt lazily from the store –
// conservative: at most one hour of novelty is lost for that device.
func (e *Engine) mergeStored(st *devState, d model.Device) {
	before := st.dev.EffectiveKind()
	mergeDevice(&st.dev, d, true)
	if st.destLoaded && st.dev.EffectiveKind() != before {
		st.destLoaded, st.destRetryAt = false, time.Time{}
		st.countries, st.asns = nil, nil
		st.pendCountry, st.pendASN = nil, nil
	}
}

// mergeDevice copies fresh metadata from src into dst. Stored-only fields
// (FirstSeen, Note, Quarantined, KindOverride, GroupID) are taken only from
// the store copy.
func mergeDevice(dst *model.Device, src model.Device, fromStore bool) {
	if src.IP.IsValid() {
		dst.IP = src.IP
	}
	if src.Hostname != "" {
		dst.Hostname = src.Hostname
	}
	if src.Vendor != "" {
		dst.Vendor = src.Vendor
	}
	if src.Kind != "" {
		dst.Kind = src.Kind
	}
	if src.ClassID != "" {
		dst.ClassID = src.ClassID
	}
	if src.Comment != "" {
		dst.Comment = src.Comment
	}
	dst.Randomized = dst.Randomized || src.Randomized
	if !src.LastSeen.IsZero() {
		dst.LastSeen = src.LastSeen
	}
	if fromStore {
		dst.FirstSeen = src.FirstSeen
		dst.Note = src.Note
		dst.Quarantined = src.Quarantined
		dst.KindOverride = src.KindOverride
		dst.GroupID = src.GroupID
	} else if dst.FirstSeen.IsZero() && !src.FirstSeen.IsZero() {
		dst.FirstSeen = src.FirstSeen
	}
}

// profile is the sensitivity profile of the device's effective kind (the
// user's override wins over the fingerprint guess).
func (e *Engine) profile(st *devState) Profile {
	return e.cfg.profileFor(st.dev.EffectiveKind(), st.dev.Randomized)
}

// behaviourAllowed: past global learning and past the device's own warm-up.
func (e *Engine) behaviourAllowed(st *devState, at time.Time) bool {
	if at.Before(e.learningUntil()) {
		return false
	}
	if st.dev.FirstSeen.IsZero() {
		return false
	}
	return !at.Before(st.dev.FirstSeen.Add(e.cfg.DeviceWarmup))
}

func (e *Engine) emitAll(ctx context.Context, alerts []model.Alert) {
	for _, a := range alerts {
		e.sink.Emit(ctx, a)
	}
}

// DeviceSeen is called for every device in every poll, after store.UpsertDevice.
func (e *Engine) DeviceSeen(ctx context.Context, d model.Device, isNew bool) {
	if d.MAC == "" {
		return
	}
	now := d.LastSeen
	if now.IsZero() {
		now = time.Now()
	}
	e.mu.Lock()
	e.resolveLearning(ctx)
	st := e.state(d.MAC)
	if isNew {
		st.infoLoaded = true // nothing more in the store than what we got
		st.infoAt = now
		if d.FirstSeen.IsZero() {
			d.FirstSeen = now
		}
		st.dev.FirstSeen = d.FirstSeen
	} else {
		e.ensureInfo(ctx, st, now)
	}
	mergeDevice(&st.dev, d, false)
	if now.After(st.lastActivity) {
		st.lastActivity = now
	}
	var alerts []model.Alert
	if isNew {
		if a, ok := e.newDeviceAlert(ctx, st.dev, now); ok {
			alerts = append(alerts, a)
		}
	}
	e.mu.Unlock()
	e.emitAll(ctx, alerts)
}

// Flows is called every poll with the deltas of LAN→internet connections,
// BEFORE they are recorded in the store.
func (e *Engine) Flows(ctx context.Context, flows []model.FlowSample) {
	if len(flows) == 0 {
		return
	}
	e.mu.Lock()
	e.resolveLearning(ctx)
	var alerts []model.Alert
	touched := make(map[*devState]time.Time)
	for i := range flows {
		f := &flows[i]
		if f.DeviceMAC == "" {
			continue
		}
		t := f.Time
		if t.IsZero() {
			t = time.Now()
		}
		hour := t.UTC().Truncate(time.Hour)
		if hour.After(e.globalHour) {
			e.globalHour = hour
			alerts = append(alerts, e.rollover(hour)...)
		}
		st := e.state(f.DeviceMAC)
		e.ensureInfo(ctx, st, t)
		if st.curHour.Before(hour) {
			alerts = append(alerts, e.finishHour(st)...)
			st.curHour = hour
			st.curTx = 0
		}
		if t.After(st.lastActivity) {
			st.lastActivity = t
		}
		// A late sample from an earlier hour still counts for novelty (in the
		// current bucket) but not for the hourly upload accumulator.
		if hour.Equal(st.curHour) {
			st.curTx += f.TxBytes
		}
		touched[st] = t
		e.ensureDest(ctx, st, t)
		if !st.destLoaded {
			continue
		}
		if a, ok := e.trackDest(st, f, t); ok {
			alerts = append(alerts, a)
		}
	}
	for st, t := range touched {
		if a, ok := e.fastSpike(ctx, st, t); ok {
			alerts = append(alerts, a)
		}
	}
	e.mu.Unlock()
	e.emitAll(ctx, alerts)
}

// rollover finishes the hour of every device whose bucket is older than hour.
func (e *Engine) rollover(hour time.Time) []model.Alert {
	var out []model.Alert
	for _, st := range e.devs {
		if !st.curHour.IsZero() && st.curHour.Before(hour) {
			out = append(out, e.finishHour(st)...)
			st.curHour = time.Time{}
			st.curTx = 0
		}
	}
	return out
}

// Tick is called hourly. It refreshes the stored data (notes, kind
// overrides) of all cached devices and evaluates the last completed clock hour(s).
func (e *Engine) Tick(ctx context.Context, now time.Time) {
	e.mu.Lock()
	e.resolveLearning(ctx)
	devs, err := e.store.Devices(ctx)
	if err != nil {
		e.log.Warn("tick: list devices", "err", err)
	}
	for _, d := range devs {
		if st := e.devs[d.MAC]; st != nil {
			e.mergeStored(st, d)
			st.infoLoaded, st.infoAt = true, now
		}
	}
	var alerts []model.Alert
	curHour := now.UTC().Truncate(time.Hour)
	alerts = append(alerts, e.rollover(curHour)...)
	if a, ok := e.inventorySummary(ctx, now); ok {
		alerts = append(alerts, a)
	}
	target := curHour.Add(-time.Hour)
	first := target.Add(-time.Duration(e.cfg.MaxCatchupHours-1) * time.Hour)
	if !e.lastEval.IsZero() && !e.lastEval.Before(first) {
		first = e.lastEval.Add(time.Hour)
	}
	if !first.After(target) {
		if err == nil {
			alerts = append(alerts, e.evalHours(ctx, devs, first, target)...)
		}
		e.lastEval = target
	}
	e.evict(now)
	e.mu.Unlock()
	e.emitAll(ctx, alerts)
}

// evalHours runs the hourly detectors (upload spike, fan-out) for hours
// first..last (inclusive) for every stored device.
func (e *Engine) evalHours(ctx context.Context, devs []model.Device, first, last time.Time) []model.Alert {
	if last.Add(time.Hour).Before(e.learningUntil()) {
		return nil
	}
	spikeOn, fanoutOn := e.enabled(model.AlertUploadSpike), e.enabled(model.AlertDestFanout)
	if !spikeOn && !fanoutOn {
		return nil
	}
	var out []model.Alert
	for _, d := range devs {
		st := e.devs[d.MAC]
		if st == nil {
			// Devices without recent activity in this process: evaluate
			// with a transient state so that nothing is kept in memory.
			st = &devState{dev: model.Device{MAC: d.MAC}}
			mergeDevice(&st.dev, d, true)
		}
		if !e.behaviourAllowed(st, last.Add(time.Hour)) {
			continue
		}
		hs, err := e.store.HourStats(ctx, d.MAC, first.Add(-e.cfg.BaselineWindow), last.Add(time.Hour))
		if err != nil {
			e.log.Warn("tick: hour stats", "mac", d.MAC, "err", err)
			continue
		}
		for h := first; !h.After(last); h = h.Add(time.Hour) {
			if !e.behaviourAllowed(st, h.Add(time.Hour)) {
				continue
			}
			obs, ok := findHour(hs, h)
			if !ok {
				continue
			}
			hist := window(hs, h.Add(-e.cfg.BaselineWindow), h)
			if len(hist) < e.cfg.MinHistoryHours {
				continue
			}
			if spikeOn {
				if a, ok := e.spikeAlert(st, obs, hist, h); ok {
					out = append(out, a)
				}
			}
			if fanoutOn {
				if a, ok := e.fanoutAlert(st, obs, hist, h); ok {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

func findHour(hs []model.HourStat, h time.Time) (model.HourStat, bool) {
	for _, s := range hs {
		if s.Hour.Equal(h) {
			return s, true
		}
	}
	return model.HourStat{}, false
}

// window returns rows with from <= Hour < to.
func window(hs []model.HourStat, from, to time.Time) []model.HourStat {
	var out []model.HourStat
	for _, s := range hs {
		if !s.Hour.Before(from) && s.Hour.Before(to) {
			out = append(out, s)
		}
	}
	return out
}

// evict drops state of devices unseen for EvictAfter.
func (e *Engine) evict(now time.Time) {
	for mac, st := range e.devs {
		if now.Sub(st.lastActivity) > e.cfg.EvictAfter {
			delete(e.devs, mac)
		}
	}
}
