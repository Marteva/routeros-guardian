package detect

import (
	"math"
	"sort"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// baseline is a robust summary of historical hourly values.
type baseline struct {
	Median  float64
	MAD     float64 // median absolute deviation (raw, not scaled)
	Max     float64
	Samples int
	Method  string // "same_hour" or "all_hours"
}

// sigma is the robust standard deviation estimate with a floor so that a
// perfectly flat history does not produce infinite z-scores.
func (b baseline) sigma(floor float64) float64 {
	s := 1.4826 * b.MAD
	if f := 0.1 * b.Median; s < f {
		s = f
	}
	if s < floor {
		s = floor
	}
	return s
}

func median(xs []float64) float64 {
	n := len(xs)
	if n == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func robust(xs []float64) baseline {
	b := baseline{Samples: len(xs)}
	if len(xs) == 0 {
		return b
	}
	b.Median = median(xs)
	dev := make([]float64, len(xs))
	for i, x := range xs {
		dev[i] = math.Abs(x - b.Median)
		if x > b.Max {
			b.Max = x
		}
	}
	b.MAD = median(dev)
	return b
}

// hourBaseline builds a baseline for hour `target` from history rows strictly
// before target. Same hour-of-day samples are preferred when there are at
// least minSame of them; otherwise all hours are used. Hours without a row
// (device offline) are simply missing, which biases the baseline upwards –
// deliberately conservative.
func hourBaseline(hist []model.HourStat, target time.Time, minSame int, val func(model.HourStat) float64) baseline {
	var same, all []float64
	th := target.UTC().Hour()
	for _, h := range hist {
		if !h.Hour.Before(target) {
			continue
		}
		v := val(h)
		all = append(all, v)
		if h.Hour.UTC().Hour() == th {
			same = append(same, v)
		}
	}
	if len(same) >= minSame && minSame > 0 {
		b := robust(same)
		b.Method = "same_hour"
		// The maximum guard must use the whole window: a weekly backup at
		// a different hour still proves the device can do this.
		for _, v := range all {
			if v > b.Max {
				b.Max = v
			}
		}
		return b
	}
	b := robust(all)
	b.Method = "all_hours"
	return b
}

func txVal(h model.HourStat) float64  { return float64(h.TxBytes) }
func dstVal(h model.HourStat) float64 { return float64(h.DistinctDst) }

func round2(x float64) float64 { return math.Round(x*100) / 100 }
