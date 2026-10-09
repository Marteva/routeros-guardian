package detect

import (
	"math"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

type fanoutVerdict struct {
	Alert    bool
	Observed int
	Ref      float64
	Ratio    float64
	Base     baseline
	Reason   string
}

// fanoutTest requires ALL of: absolute minimum of distinct destinations,
// ratio vs. median and exceeding the historical maximum by HistMaxFactor.
func fanoutTest(p Profile, c *Config, observed int, b baseline) fanoutVerdict {
	v := fanoutVerdict{Observed: observed, Base: b}
	v.Ref = math.Max(b.Median, float64(c.BaselineFloorDst))
	if v.Ref <= 0 {
		v.Ref = 1
	}
	v.Ratio = float64(observed) / v.Ref
	switch {
	case p.FanoutMin == 0:
		v.Reason = "disabled"
	case observed < p.FanoutMin:
		v.Reason = "below absolute minimum"
	case v.Ratio < p.FanoutRatio:
		v.Reason = "ratio too low"
	case float64(observed) < b.Max*c.HistMaxFactor:
		v.Reason = "seen similar before"
	default:
		v.Alert = true
	}
	return v
}

func (e *Engine) fanoutAlert(st *devState, obs model.HourStat, hist []model.HourStat, h time.Time) (model.Alert, bool) {
	prof := e.profile(st)
	b := hourBaseline(hist, h, e.cfg.MinSameHourSamples, dstVal)
	v := fanoutTest(prof, &e.cfg, obs.DistinctDst, b)
	if !v.Alert {
		return model.Alert{}, false
	}
	sev := model.SevWarning
	if prof.FanoutCritical {
		sev = model.SevCritical
	}
	l := e.lang
	det := []string{
		l.t("alert.fanout.detail", hourRange(h), obs.DistinctDst, obs.NewConns,
			l.baseline(b, l.t("unit.addr_per_hour", l.num(b.Median))), l.ratio(v.Ratio)),
		l.t("alert.fanout.max", l.t("unit.addr_per_hour", l.num(b.Max))),
		l.t("alert.fanout.explain"),
	}
	if sev == model.SevCritical {
		det = append(det, l.t("alert.fanout.advice_crit"))
	}
	return model.Alert{
		Time:      h.Add(time.Hour),
		DeviceMAC: st.dev.MAC,
		Kind:      model.AlertDestFanout,
		Severity:  sev,
		Title:     l.t("alert.fanout.title", l.deviceName(st.dev), obs.DistinctDst),
		Detail:    strings.Join(det, " "),
		Evidence: map[string]any{
			"hour":             h,
			"device_kind":      st.dev.EffectiveKind(),
			"observed_dst":     obs.DistinctDst,
			"new_conns":        obs.NewConns,
			"baseline_median":  round2(b.Median),
			"baseline_max":     b.Max,
			"baseline_samples": b.Samples,
			"baseline_method":  b.Method,
			"baseline_ref":     v.Ref,
			"ratio":            round2(v.Ratio),
			"min_dst":          prof.FanoutMin,
			"min_ratio":        prof.FanoutRatio,
			"hist_max_factor":  e.cfg.HistMaxFactor,
		},
		DedupKey: "dest_fanout:" + st.dev.MAC,
	}, true
}
