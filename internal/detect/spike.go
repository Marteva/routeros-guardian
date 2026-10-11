package detect

import (
	"context"
	"math"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// spikeVerdict is the outcome of the upload-spike test with its numbers.
type spikeVerdict struct {
	Alert    bool
	Observed float64
	Ref      float64 // baseline median after floor
	Ratio    float64
	Z        float64
	Base     baseline
	Reason   string // why not (for debugging / tests)
}

// spikeTest requires ALL of: absolute minimum, ratio vs. median, robust
// z-score and exceeding the historical maximum by HistMaxFactor.
func spikeTest(p Profile, c *Config, observed float64, b baseline) spikeVerdict {
	v := spikeVerdict{Observed: observed, Base: b}
	v.Ref = math.Max(b.Median, float64(c.BaselineFloorTx))
	if v.Ref <= 0 {
		v.Ref = 1
	}
	v.Ratio = observed / v.Ref
	v.Z = (observed - b.Median) / b.sigma(float64(c.BaselineFloorTx))
	switch {
	case p.SpikeMinTx == 0:
		v.Reason = "disabled"
	case observed < float64(p.SpikeMinTx):
		v.Reason = "below absolute minimum"
	case v.Ratio < p.SpikeRatio:
		v.Reason = "ratio too low"
	case v.Z < p.SpikeMinZ:
		v.Reason = "z-score too low"
	case observed < b.Max*c.HistMaxFactor:
		v.Reason = "seen similar before"
	default:
		v.Alert = true
	}
	return v
}

func spikeSeverity(p Profile) model.Severity {
	if p.SpikeCritical {
		return model.SevCritical
	}
	return model.SevWarning
}

// spikeAlert evaluates a completed hour (Tick path).
func (e *Engine) spikeAlert(st *devState, obs model.HourStat, hist []model.HourStat, h time.Time) (model.Alert, bool) {
	if st.spikeAlertedHour.Equal(h) {
		return model.Alert{}, false // already raised by the fast path
	}
	prof := e.profile(st)
	b := hourBaseline(hist, h, e.cfg.MinSameHourSamples, txVal)
	v := spikeTest(prof, &e.cfg, float64(obs.TxBytes), b)
	if !v.Alert {
		return model.Alert{}, false
	}
	st.spikeAlertedHour = h
	a := model.Alert{
		Time:      h.Add(time.Hour),
		DeviceMAC: st.dev.MAC,
		Kind:      model.AlertUploadSpike,
		Severity:  spikeSeverity(prof),
		Evidence:  spikeEvidence(st, prof, &e.cfg, v, h, "hourly"),
		DedupKey:  "upload_spike:" + st.dev.MAC,
	}
	e.setText(&a, &st.dev)
	return a, true
}

func spikeEvidence(st *devState, p Profile, c *Config, v spikeVerdict, h time.Time, path string) map[string]any {
	return map[string]any{
		"path":             path,
		"hour":             h,
		"device_kind":      st.dev.EffectiveKind(),
		"observed_tx":      uint64(v.Observed),
		"baseline_median":  uint64(v.Base.Median),
		"baseline_mad":     uint64(v.Base.MAD),
		"baseline_max":     uint64(v.Base.Max),
		"baseline_samples": v.Base.Samples,
		"baseline_method":  v.Base.Method,
		"baseline_ref":     uint64(v.Ref),
		"ratio":            round2(v.Ratio),
		"z":                round2(v.Z),
		"min_tx":           p.SpikeMinTx,
		"min_ratio":        p.SpikeRatio,
		"min_z":            p.SpikeMinZ,
		"hist_max_factor":  c.HistMaxFactor,
		"baseline_days":    int(c.BaselineWindow.Hours() / 24),
		"device":           snapshotOf(st.dev),
	}
}

// fastSpike raises an upload spike before the hour ends when the upload
// accumulated in the current hour is already extreme (Flows path).
func (e *Engine) fastSpike(ctx context.Context, st *devState, t time.Time) (model.Alert, bool) {
	c := &e.cfg
	if c.FastSpikeMinTx == 0 || st.curHour.IsZero() || st.curTx < c.FastSpikeMinTx ||
		st.spikeAlertedHour.Equal(st.curHour) || !e.enabled(model.AlertUploadSpike) || !e.behaviourAllowed(st, t) {
		return model.Alert{}, false
	}
	prof := e.profile(st)
	if prof.SpikeMinTx == 0 {
		return model.Alert{}, false
	}
	if !st.fastBaseHour.Equal(st.curHour) {
		st.fastBaseHour = st.curHour
		st.fastBase = nil
		hs, err := e.store.HourStats(ctx, st.dev.MAC, st.curHour.Add(-c.BaselineWindow), st.curHour)
		if err != nil {
			e.log.Warn("fast spike: hour stats", "mac", st.dev.MAC, "err", err)
			return model.Alert{}, false
		}
		hist := window(hs, st.curHour.Add(-c.BaselineWindow), st.curHour)
		if len(hist) >= c.MinHistoryHours {
			b := hourBaseline(hist, st.curHour, c.MinSameHourSamples, txVal)
			st.fastBase = &b
		}
	}
	if st.fastBase == nil {
		return model.Alert{}, false
	}
	b := *st.fastBase
	obs := float64(st.curTx)
	v := spikeVerdict{Observed: obs, Base: b, Ref: math.Max(b.Median, float64(c.BaselineFloorTx))}
	v.Ratio = obs / v.Ref
	v.Z = (obs - b.Median) / b.sigma(float64(c.BaselineFloorTx))
	if v.Ratio < c.FastSpikeRatio || obs < b.Max*c.HistMaxFactor || obs < float64(prof.SpikeMinTx) {
		return model.Alert{}, false
	}
	st.spikeAlertedHour = st.curHour
	mins := int(t.Sub(st.curHour).Minutes())
	if mins < 1 {
		mins = 1
	}
	ev := spikeEvidence(st, prof, c, v, st.curHour, "fast")
	ev["fast_ratio"] = c.FastSpikeRatio
	ev["fast_min_tx"] = c.FastSpikeMinTx
	ev["minutes"] = mins
	a := model.Alert{
		Time:      t,
		DeviceMAC: st.dev.MAC,
		Kind:      model.AlertUploadSpike,
		Severity:  spikeSeverity(prof),
		Evidence:  ev,
		DedupKey:  "upload_spike:" + st.dev.MAC,
	}
	e.setText(&a, &st.dev)
	return a, true
}
