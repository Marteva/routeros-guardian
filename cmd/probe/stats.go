package main

import (
	"encoding/csv"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// sample is one poll (one CSV row).
type sample struct {
	Time      time.Time
	PollDur   time.Duration // whole collector poll (leases + ARP + connections)
	ConnDur   time.Duration // connection table request alone
	Entries   int
	RespBytes int64
	CPUBefore int
	CPUAfter  int
	CPUOK     bool
	FreeMem   uint64
	Fasttrack int
	Devices   int
	Flows     int
	VisTx     uint64
	VisRx     uint64
	WanTx     uint64
	WanRx     uint64
	WanOK     bool
	Err       string

	// Conns seen in this and the previous poll with the same tuple, split by
	// fasttrack flag; "moved" = byte counters increased in between.
	FTTracked, FTMoved       int
	NonFTTracked, NonFTMoved int
}

// counterTracker answers "do byte counters of fasttracked connections move?"
// over the whole table (not just LAN->internet).
type counterTracker struct {
	prev map[string]trackedConn
}

type trackedConn struct {
	src, dst netip.AddrPort
	bytes    uint64
	ft       bool
}

func newCounterTracker() *counterTracker { return &counterTracker{prev: map[string]trackedConn{}} }

// update compares conns with the previous poll. Connections whose fasttrack
// flag changed between polls are not counted to avoid bias.
func (t *counterTracker) update(conns []model.Conn) (ftTracked, ftMoved, nonTracked, nonMoved int) {
	cur := make(map[string]trackedConn, len(conns))
	for i := range conns {
		c := &conns[i]
		if c.ID == "" {
			continue
		}
		tc := trackedConn{src: c.Src, dst: c.Dst, bytes: c.OrigBytes + c.ReplBytes, ft: c.Fasttrack}
		cur[c.ID] = tc
		p, ok := t.prev[c.ID]
		if !ok || p.src != tc.src || p.dst != tc.dst || tc.bytes < p.bytes || p.ft != tc.ft {
			continue
		}
		moved := tc.bytes > p.bytes
		if tc.ft {
			ftTracked++
			if moved {
				ftMoved++
			}
		} else {
			nonTracked++
			if moved {
				nonMoved++
			}
		}
	}
	t.prev = cur
	return
}

// sampleWriter appends samples to a CSV file, flushing every row so data
// survives an abrupt stop.
type sampleWriter struct {
	f *os.File
	w *csv.Writer
}

var csvHeader = []string{
	"time", "poll_ms", "conn_ms", "conn_entries", "resp_bytes", "cpu_before", "cpu_after",
	"fasttrack_conns", "ft_tracked", "ft_moved", "nonft_tracked", "nonft_moved",
	"devices", "flows", "visible_tx", "visible_rx", "wan_tx", "wan_rx", "free_mem", "error",
}

func newSampleWriter(path string) (*sampleWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := csv.NewWriter(f)
	if err := w.Write(csvHeader); err != nil {
		f.Close()
		return nil, err
	}
	w.Flush()
	return &sampleWriter{f: f, w: w}, w.Error()
}

func (s *sampleWriter) Write(x sample) error {
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	i := strconv.Itoa
	cpuAfter, wanTx, wanRx := "", "", ""
	if x.CPUOK {
		cpuAfter = i(x.CPUAfter)
	}
	if x.WanOK {
		wanTx, wanRx = u(x.WanTx), u(x.WanRx)
	}
	row := []string{
		x.Time.Format(time.RFC3339), i(int(x.PollDur.Milliseconds())), i(int(x.ConnDur.Milliseconds())),
		i(x.Entries), strconv.FormatInt(x.RespBytes, 10), i(x.CPUBefore), cpuAfter,
		i(x.Fasttrack), i(x.FTTracked), i(x.FTMoved), i(x.NonFTTracked), i(x.NonFTMoved),
		i(x.Devices), i(x.Flows), u(x.VisTx), u(x.VisRx), wanTx, wanRx, u(x.FreeMem), x.Err,
	}
	if err := s.w.Write(row); err != nil {
		return err
	}
	s.w.Flush()
	return s.w.Error()
}

func (s *sampleWriter) Close() error {
	s.w.Flush()
	return s.f.Close()
}

// aggregator keeps all samples (24 h at 15 s is ~6k rows, negligible).
type aggregator struct{ samples []sample }

func newAggregator() *aggregator { return &aggregator{} }

func (a *aggregator) add(s sample) { a.samples = append(a.samples, s) }

// runInfo is the static context of a probe run.
type runInfo struct {
	Start, End   time.Time
	Interval     time.Duration
	URL          string
	Resource     model.Resource
	Fasttrack    fasttrackInfo
	FasttrackErr string
	IPv6Conns    int
	WAN          string
}

// tri is a yes / partial / no / unknown answer.
type tri int

const (
	triUnknown tri = iota
	triYes
	triPartial
	triNo
)

func (t tri) String() string {
	switch t {
	case triYes:
		return "ANO"
	case triPartial:
		return "ČÁSTEČNĚ"
	case triNo:
		return "NE"
	}
	return "NELZE URČIT"
}

// metrics are the computed aggregates behind the verdict.
type metrics struct {
	Polls, Errors             int
	AvgConn, P95Conn, MaxConn time.Duration
	AvgPoll                   time.Duration
	MaxEntries                int
	AvgEntries                float64
	MaxResp                   int64
	FTShare                   float64 // fasttracked / all entries
	CPUBefore, CPUAfter       float64
	CPUDelta                  float64 // avg after-before, percentage points
	CPUAmortized              float64 // estimated average extra load over the interval
	FTTracked, FTMoved        int
	NonFTTracked, NonFTMoved  int
	Counters                  tri
	Coverage                  float64 // visible / WAN bytes, -1 if unknown
	VisibleBytes, WANBytes    uint64
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

func computeMetrics(info runInfo, samples []sample) metrics {
	m := metrics{Polls: len(samples), Coverage: -1}
	var lat []time.Duration
	var sumConn, sumPoll time.Duration
	var sumEntries, sumFT, cpuN int
	var sumBefore, sumAfter float64
	for _, s := range samples {
		if s.Err != "" {
			m.Errors++
			continue
		}
		lat = append(lat, s.ConnDur)
		sumConn += s.ConnDur
		sumPoll += s.PollDur
		sumEntries += s.Entries
		sumFT += s.Fasttrack
		m.MaxEntries = max(m.MaxEntries, s.Entries)
		m.MaxResp = max(m.MaxResp, s.RespBytes)
		if s.CPUOK {
			cpuN++
			sumBefore += float64(s.CPUBefore)
			sumAfter += float64(s.CPUAfter)
		}
		m.FTTracked += s.FTTracked
		m.FTMoved += s.FTMoved
		m.NonFTTracked += s.NonFTTracked
		m.NonFTMoved += s.NonFTMoved
		if s.WanOK {
			m.VisibleBytes += s.VisTx + s.VisRx
			m.WANBytes += s.WanTx + s.WanRx
		}
	}
	ok := len(lat)
	if ok > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		m.AvgConn = sumConn / time.Duration(ok)
		m.AvgPoll = sumPoll / time.Duration(ok)
		m.P95Conn = lat[int(math.Ceil(0.95*float64(ok)))-1]
		m.MaxConn = lat[ok-1]
		m.AvgEntries = float64(sumEntries) / float64(ok)
	}
	if sumEntries > 0 {
		m.FTShare = float64(sumFT) / float64(sumEntries)
	}
	if cpuN > 0 {
		m.CPUBefore = sumBefore / float64(cpuN)
		m.CPUAfter = sumAfter / float64(cpuN)
		m.CPUDelta = m.CPUAfter - m.CPUBefore
		// RouterOS cpu-load is a short (~1 s) moving average, so a spike seen
		// right after the poll lasts roughly max(1 s, poll time) per interval.
		busy := max(time.Second, m.AvgPoll)
		if info.Interval > 0 {
			m.CPUAmortized = math.Max(0, m.CPUDelta) * busy.Seconds() / info.Interval.Seconds()
		}
	}
	if m.WANBytes > 0 {
		m.Coverage = float64(m.VisibleBytes) / float64(m.WANBytes)
	}

	ftR, nonR := ratio(m.FTMoved, m.FTTracked), ratio(m.NonFTMoved, m.NonFTTracked)
	switch {
	case m.FTTracked < 20:
		m.Counters = triUnknown
	case m.FTMoved == 0:
		m.Counters = triNo
	case m.NonFTTracked == 0 || nonR == 0 || ftR >= 0.5*nonR:
		m.Counters = triYes
	default:
		m.Counters = triPartial
	}
	return m
}

// buildSummary renders the Czech report and verdict.
func buildSummary(info runInfo, a *aggregator) string {
	m := computeMetrics(info, a.samples)
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	pct := func(f float64) string { return fmt.Sprintf("%.0f %%", f*100) }
	ms := func(d time.Duration) string { return fmt.Sprintf("%.0f ms", float64(d.Microseconds())/1000) }

	r := info.Resource
	p("=== Guardian probe – výsledek ===")
	p("Router:            %s, RouterOS %s (%s, %d CPU), %s", r.BoardName, r.Version, r.Arch, r.CPUCount, info.URL)
	p("Měření:            %s – %s (%s), interval %s, %d dotazů, %d chyb",
		info.Start.Format("2006-01-02 15:04"), info.End.Format("15:04"), info.End.Sub(info.Start).Round(time.Second),
		info.Interval, m.Polls, m.Errors)

	ftState := "VYPNUT"
	switch {
	case info.FasttrackErr != "":
		ftState = "NEZJIŠTĚN (" + info.FasttrackErr + ")"
	case info.Fasttrack.Enabled:
		ftState = "ZAPNUT"
	case info.Fasttrack.Present:
		ftState = "VYPNUT (pravidlo existuje, je zakázané)"
	}
	p("FastTrack:         %s", ftState)
	for _, rule := range info.Fasttrack.Rules {
		p("                   pravidlo %s", rule)
	}
	if info.Fasttrack.HWOffload {
		p("                   hw-offload=yes – HW offloadovaná spojení nemusí mít aktuální čítače")
	}
	p("Conntrack:         max %d položek, průměr %.0f, podíl fasttrack %s", m.MaxEntries, m.AvgEntries, pct(m.FTShare))
	p("Čítače se hýbou:   fasttrack %d/%d (%s), ostatní %d/%d (%s) spojení mezi dvěma dotazy",
		m.FTMoved, m.FTTracked, pct(ratio(m.FTMoved, m.FTTracked)),
		m.NonFTMoved, m.NonFTTracked, pct(ratio(m.NonFTMoved, m.NonFTTracked)))
	if m.Coverage >= 0 {
		p("Pokrytí provozu:   %s (viditelné LAN→internet %s / WAN %s %s)",
			pct(m.Coverage), human(m.VisibleBytes), info.WAN, human(m.WANBytes))
	} else {
		p("Pokrytí provozu:   nezjištěno (WAN rozhraní %q)", info.WAN)
	}
	p("Latence dotazu:    průměr %s, p95 %s, max %s (celý poll %s), max odpověď %s",
		ms(m.AvgConn), ms(m.P95Conn), ms(m.MaxConn), ms(m.AvgPoll), human(uint64(m.MaxResp)))
	p("CPU routeru:       před dotazem %.1f %%, po dotazu %.1f %% → špička %+.1f %%, odhad průměrné zátěže %+.2f %%",
		m.CPUBefore, m.CPUAfter, m.CPUDelta, m.CPUAmortized)
	switch {
	case info.IPv6Conns > 0:
		p("IPv6:              %d spojení v /ipv6/firewall/connection – Guardian je zatím NEsleduje", info.IPv6Conns)
	case info.IPv6Conns == 0:
		p("IPv6:              žádná IPv6 spojení")
	}

	countersStr := m.Counters.String()
	if !info.Fasttrack.Enabled {
		countersStr = "N/A (fasttrack vypnut)"
	}
	p("")
	p("VERDIKT: FastTrack: %s, čítače fasttrack spojení se aktualizují: %s, průměrná latence dotazu: %s, max položek: %d, odhad zátěže CPU: %+.1f %%",
		strings.SplitN(ftState, " ", 2)[0], countersStr, ms(m.AvgConn), m.MaxEntries, m.CPUDelta)
	for _, rec := range recommendations(info, m) {
		p("DOPORUČENÍ: %s", rec)
	}
	return b.String()
}

// recommendations turns metrics into actionable advice (Czech).
func recommendations(info runInfo, m metrics) []string {
	var out []string
	if m.Polls-m.Errors == 0 {
		return []string{"Žádný úspěšný dotaz – zkontrolujte URL, přihlášení a oprávnění uživatele (read, api, rest-api)."}
	}
	lowCoverage := m.Coverage >= 0 && m.Coverage < 0.6
	switch {
	case info.Fasttrack.Enabled && m.Counters == triNo,
		info.Fasttrack.Enabled && lowCoverage && m.Counters != triYes:
		out = append(out, "Data z fasttrack spojení NEJSOU použitelná. Vyjměte sledovaná zařízení z fasttracku "+
			"(address-list a src-address-list=!<list> / dst-address-list=!<list> ve fasttrack pravidle) "+
			"nebo použijte /ip/traffic-flow (IPFIX) jako zdroj objemů.")
	case info.Fasttrack.Enabled && m.Counters == triPartial:
		out = append(out, "Čítače fasttrack spojení se aktualizují jen částečně – objemová detekce bude podhodnocená; "+
			"zvažte vyjmutí podezřelých zařízení z fasttracku.")
	case info.Fasttrack.Enabled && m.Counters == triUnknown:
		out = append(out, "Málo fasttrack spojení pro jednoznačný závěr – nechte probe běžet déle při běžném provozu.")
	case lowCoverage:
		out = append(out, "Viditelná je jen část WAN provozu (krátká spojení mezi dotazy, provoz samotného routeru) – zvažte kratší interval.")
	default:
		out = append(out, "Data jsou použitelná pro detekci anomálií.")
	}
	if m.Coverage >= 0.6 && m.Coverage < 0.85 {
		out = append(out, fmt.Sprintf("Pokrytí %.0f %%: část bytů se ztrácí u spojení, která skončí mezi dotazy – pro detekci trendů to stačí.", m.Coverage*100))
	}

	iv := info.Interval
	heavy := m.P95Conn > iv/5 || m.CPUAmortized > 3 || m.CPUDelta > 25
	if heavy {
		factor := math.Max(float64(m.P95Conn*5)/float64(iv), m.CPUAmortized/3)
		factor = math.Max(factor, 2)
		sug := time.Duration(math.Ceil(float64(iv)*factor/float64(5*time.Second))) * 5 * time.Second
		out = append(out, fmt.Sprintf("Dotazování je pro router náročné – zvyšte interval na %s (GUARDIAN_POLL_INTERVAL).", sug))
	} else {
		out = append(out, fmt.Sprintf("Interval %s je v pořádku.", iv))
	}
	return out
}

// human formats a byte count.
func human(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
