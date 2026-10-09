package detect

import (
	"log/slog"
	"math"
	"time"
)

// Byte size helpers used by the defaults.
const (
	kB = 1 << 10
	mB = 1 << 20
	gB = 1 << 30
)

// Profile holds the per-device-kind sensitivity. A zero numeric threshold
// means "this criterion is disabled" unless stated otherwise.
type Profile struct {
	// --- New country (evaluated per device per clock hour) ---

	// NewCountry enables new-country alerts for this kind.
	NewCountry bool
	// A new country "counts" when ANY of the enabled criteria is met within
	// one clock hour: upload ≥ CountryMinTx, upload+download ≥ CountryMinTotal,
	// new connections ≥ CountryMinConns.
	CountryMinTx    uint64
	CountryMinTotal uint64
	CountryMinConns int
	// CountryHouseholdNew requires the country to be new for the whole
	// household (no other known device talks to it). Used for phones and
	// computers that legitimately hit CDNs all over the world.
	CountryHouseholdNew bool
	// CountryMaxKnown: devices that already talk to this many countries are
	// "globetrotters" and get no new-country alerts (0 = no limit).
	CountryMaxKnown int
	// CountryCriticalTx: upload to a new country at or above this escalates
	// the alert to Critical and emits it immediately (0 = never critical).
	CountryCriticalTx uint64

	// --- New ASN (only for kinds with a small, stable destination set) ---

	NewASN      bool
	ASNMinTx    uint64
	ASNMinTotal uint64
	ASNMinConns int
	// ASNMaxKnown: a device with more known ASNs is "unstable" – ASN alerts
	// are off for it and its ASN set is no longer kept in memory.
	ASNMaxKnown int

	// --- Upload spike (hourly, plus fast path in Flows) ---

	SpikeMinTx    uint64  // absolute minimum upload in the hour
	SpikeRatio    float64 // observed / baseline median
	SpikeMinZ     float64 // robust z-score (median/MAD)
	SpikeCritical bool    // Critical instead of Warning

	// --- Destination fan-out ---

	FanoutMin      int     // absolute minimum distinct destination IPs in the hour
	FanoutRatio    float64 // observed / baseline median
	FanoutCritical bool
}

// Config tunes the Engine. Use DefaultConfig and override fields.
type Config struct {
	// LearnPeriod is the global learning period. It starts at
	// settings.LearningStart when set (Engine.SetSettings), otherwise at the
	// earliest Device.FirstSeen found in the store (so container restarts do
	// not restart learning), falling back to the process start time.
	// Engine.SetSettings overrides it with settings.LearnPeriod.
	LearnPeriod time.Duration
	// InventoryPeriod is the first part of the learning period in which
	// new-device alerts are suppressed (initial inventory; capped at
	// LearnPeriod). One Info summary is emitted once it ends (if InventorySummary).
	InventoryPeriod  time.Duration
	InventorySummary bool
	// DeviceWarmup: no behavioural alerts for a device until FirstSeen+DeviceWarmup.
	DeviceWarmup time.Duration
	// MinHistoryHours: hours with traffic required before baselines are trusted.
	MinHistoryHours int
	// BaselineWindow: how far back hourly baselines look.
	BaselineWindow time.Duration
	// MinSameHourSamples: use same hour-of-day samples for the baseline when at
	// least this many exist, otherwise use all hours in the window.
	MinSameHourSamples int
	// HistMaxFactor: observed value must also exceed the maximum seen in the
	// baseline window by this factor (a device that did it before is not anomalous).
	HistMaxFactor float64
	// BaselineFloorTx / BaselineFloorDst: floors for the baseline median so
	// near-zero baselines do not produce huge ratios.
	BaselineFloorTx  uint64
	BaselineFloorDst int

	// Fast-path upload spike inside Flows (alert before the hour ends).
	FastSpikeMinTx uint64
	FastSpikeRatio float64

	// EvictAfter drops in-memory per-device state for devices unseen this long.
	EvictAfter time.Duration
	// MaxCatchupHours limits how many missed hours one Tick evaluates.
	MaxCatchupHours int

	// Profiles per Device.EffectiveKind(). Kinds not listed use DefaultProfile.
	// Kind "unknown" (or "") with a randomized MAC uses LenientKind's profile.
	Profiles       map[string]Profile
	DefaultProfile Profile
	LenientKind    string

	Logger *slog.Logger // nil = slog.Default()
}

// Strict profile: cameras and IoT – few destinations, little upload expected.
func strictProfile() Profile {
	return Profile{
		NewCountry:        true,
		CountryMinTx:      256 * kB,
		CountryMinTotal:   1 * mB,
		CountryMinConns:   5,
		CountryCriticalTx: 10 * mB,

		NewASN:      true,
		ASNMinTx:    256 * kB,
		ASNMinTotal: 2 * mB,
		ASNMinConns: 5,
		ASNMaxKnown: 25,

		SpikeMinTx:    200 * mB,
		SpikeRatio:    10,
		SpikeMinZ:     6,
		SpikeCritical: true,

		FanoutMin:      100,
		FanoutRatio:    5,
		FanoutCritical: true,
	}
}

// Lenient profile: phones, computers, tablets – browse the whole world.
func lenientProfile() Profile {
	return Profile{
		NewCountry:          true,
		CountryMinTx:        20 * mB,
		CountryHouseholdNew: true,
		CountryMaxKnown:     12,

		SpikeMinTx: 2 * gB,
		SpikeRatio: 20,
		SpikeMinZ:  8,

		FanoutMin:   1500,
		FanoutRatio: 8,
	}
}

// DefaultConfig returns conservative, precision-oriented defaults.
func DefaultConfig() Config {
	strict := strictProfile()

	tv := strictProfile()
	tv.CountryMinTx = 1 * mB
	tv.CountryMinTotal = 20 * mB // streaming CDNs: downloads alone must be big
	tv.CountryMinConns = 0
	tv.CountryCriticalTx = 0
	tv.ASNMinTx = 1 * mB
	tv.ASNMinTotal = 0
	tv.ASNMinConns = 0
	tv.ASNMaxKnown = 15
	tv.SpikeMinTx = 500 * mB
	tv.SpikeCritical = false
	tv.FanoutMin = 200
	tv.FanoutCritical = false

	unknown := strictProfile()
	unknown.CountryMinTx = 2 * mB
	unknown.CountryMinTotal = 0
	unknown.CountryMinConns = 0
	unknown.CountryHouseholdNew = true
	unknown.CountryMaxKnown = 12
	unknown.CountryCriticalTx = 0
	unknown.ASNMinTx = 2 * mB
	unknown.ASNMinTotal = 0
	unknown.ASNMinConns = 0
	unknown.ASNMaxKnown = 15
	unknown.SpikeMinTx = 500 * mB
	unknown.SpikeCritical = false
	unknown.FanoutMin = 300
	unknown.FanoutCritical = false

	lenient := lenientProfile()

	return Config{
		LearnPeriod:        7 * 24 * time.Hour,
		InventoryPeriod:    24 * time.Hour,
		InventorySummary:   true,
		DeviceWarmup:       3 * 24 * time.Hour,
		MinHistoryHours:    48,
		BaselineWindow:     28 * 24 * time.Hour,
		MinSameHourSamples: 7,
		HistMaxFactor:      1.3,
		BaselineFloorTx:    1 * mB,
		BaselineFloorDst:   10,
		FastSpikeMinTx:     1 * gB,
		FastSpikeRatio:     50,
		EvictAfter:         30 * 24 * time.Hour,
		MaxCatchupHours:    3,
		Profiles: map[string]Profile{
			"camera":   strict,
			"iot":      strict,
			"tv":       tv,
			"unknown":  unknown,
			"":         unknown,
			"phone":    lenient,
			"computer": lenient,
			"tablet":   lenient,
		},
		DefaultProfile: lenient,
		LenientKind:    "phone",
	}
}

// profileFor picks the sensitivity profile for a device.
func (c *Config) profileFor(kind string, randomized bool) Profile {
	if (kind == "" || kind == "unknown") && randomized && c.LenientKind != "" {
		kind = c.LenientKind
	}
	if p, ok := c.Profiles[kind]; ok {
		return p
	}
	return c.DefaultProfile
}

// isStrictKind reports kinds where a single anomaly is already alarming.
func isStrictKind(kind string) bool {
	return kind == "camera" || kind == "iot"
}

// Sensitivity scaling (settings.Settings.Sensitivity). "normal" is the
// configuration as given. "low" multiplies every absolute minimum and ratio
// by sensLowFactor and raises the z-score threshold by sensLowZ; "high"
// multiplies by sensHighFactor and lowers z by sensHighZ, but never below the
// safe floors below (a threshold already below its floor is left alone).
// Zero thresholds (= criterion disabled) stay zero. Structural knobs –
// learning, warm-up, history requirements, HistMaxFactor ("a device that did
// it before is not anomalous"), globetrotter/unstable-ASN limits – are not
// affected by sensitivity.
const (
	sensLowFactor  = 2.0
	sensLowZ       = 2.0
	sensHighFactor = 0.5
	sensHighZ      = 1.5

	floorDestBytes  = 64 * kB  // new country / ASN upload and total minimums
	floorDestConns  = 3        // new country / ASN new-connection minimums
	floorCriticalTx = 5 * mB   // immediate-critical upload to a new country
	floorSpikeTx    = 100 * mB // hourly upload minimum
	floorRatio      = 3.0      // spike and fan-out ratio vs. median
	floorZ          = 3.0      // robust z-score
	floorFanout     = 50       // distinct destination IPs per hour
	floorFastTx     = 256 * mB // fast-path upload within the hour
	floorFastRatio  = 10.0     // fast-path ratio vs. hourly median
)

// withSensitivity returns a copy of c with thresholds scaled for s
// ("low", "normal", "high"; anything else = "normal").
func (c Config) withSensitivity(s string) Config {
	var f, dz float64
	switch s {
	case "low":
		f, dz = sensLowFactor, sensLowZ
	case "high":
		f, dz = sensHighFactor, -sensHighZ
	default:
		return c
	}
	profiles := make(map[string]Profile, len(c.Profiles))
	for k, p := range c.Profiles {
		profiles[k] = p.scaled(f, dz)
	}
	c.Profiles = profiles
	c.DefaultProfile = c.DefaultProfile.scaled(f, dz)
	c.FastSpikeMinTx = scaleU(c.FastSpikeMinTx, f, floorFastTx)
	c.FastSpikeRatio = scaleF(c.FastSpikeRatio, f, floorFastRatio)
	return c
}

func (p Profile) scaled(f, dz float64) Profile {
	p.CountryMinTx = scaleU(p.CountryMinTx, f, floorDestBytes)
	p.CountryMinTotal = scaleU(p.CountryMinTotal, f, floorDestBytes)
	p.CountryMinConns = scaleI(p.CountryMinConns, f, floorDestConns)
	p.CountryCriticalTx = scaleU(p.CountryCriticalTx, f, floorCriticalTx)
	p.ASNMinTx = scaleU(p.ASNMinTx, f, floorDestBytes)
	p.ASNMinTotal = scaleU(p.ASNMinTotal, f, floorDestBytes)
	p.ASNMinConns = scaleI(p.ASNMinConns, f, floorDestConns)
	p.SpikeMinTx = scaleU(p.SpikeMinTx, f, floorSpikeTx)
	p.SpikeRatio = scaleF(p.SpikeRatio, f, floorRatio)
	if p.SpikeMinZ != 0 {
		p.SpikeMinZ = floored(p.SpikeMinZ+dz, p.SpikeMinZ, floorZ)
	}
	p.FanoutMin = scaleI(p.FanoutMin, f, floorFanout)
	p.FanoutRatio = scaleF(p.FanoutRatio, f, floorRatio)
	return p
}

// floored returns v, or – when v dropped below floor – floor, but never more
// than the unscaled value orig (a threshold configured below the floor is
// not raised by "high").
func floored(v, orig, floor float64) float64 {
	if v < floor {
		return math.Min(floor, orig)
	}
	return v
}

func scaleF(v, f, floor float64) float64 {
	if v == 0 {
		return 0
	}
	return floored(v*f, v, floor)
}

func scaleU(v uint64, f float64, floor uint64) uint64 {
	if v == 0 {
		return 0
	}
	return uint64(math.Round(floored(float64(v)*f, float64(v), float64(floor))))
}

func scaleI(v int, f float64, floor int) int {
	if v == 0 {
		return 0
	}
	return int(math.Round(floored(float64(v)*f, float64(v), float64(floor))))
}
