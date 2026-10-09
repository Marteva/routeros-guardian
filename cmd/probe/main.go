// Command probe is a standalone feasibility tool: it polls the RouterOS REST
// API like Guardian would and records whether usable per-connection traffic
// data is available with FastTrack enabled and what polling costs the router.
//
//	probe -url https://192.168.88.1 -user guardian -pass ... -interval 15s -duration 2h
//
// Output: <out>/samples.csv (one row per poll) and <out>/summary.txt; the
// verdict (in Czech) is also printed to stdout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Marteva/routeros-guardian/internal/collector"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/routeros"
)

type options struct {
	url, user, pass string
	insecure        bool
	interval        time.Duration
	duration        time.Duration
	timeout         time.Duration
	out             string
	lan             []netip.Prefix
	wan             string
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	opts, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, log, opts); err != nil {
		log.Error("probe failed", "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func parseFlags(args []string) (options, error) {
	var o options
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.StringVar(&o.url, "url", envOr("GUARDIAN_ROS_URL", "http://192.168.88.1"), "RouterOS base URL (env GUARDIAN_ROS_URL)")
	fs.StringVar(&o.user, "user", envOr("GUARDIAN_ROS_USER", "guardian"), "REST user (env GUARDIAN_ROS_USER)")
	fs.StringVar(&o.pass, "pass", "", "REST password (env GUARDIAN_ROS_PASS)")
	insecureDef, _ := strconv.ParseBool(envOr("GUARDIAN_ROS_INSECURE_TLS", "true"))
	fs.BoolVar(&o.insecure, "insecure", insecureDef, "skip TLS certificate verification (env GUARDIAN_ROS_INSECURE_TLS)")
	fs.DurationVar(&o.interval, "interval", 15*time.Second, "poll interval")
	fs.DurationVar(&o.duration, "duration", 24*time.Hour, "total run time (Ctrl+C ends early and still writes the summary)")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "per-request timeout")
	fs.StringVar(&o.out, "out", "probe-out", "output directory")
	lanStr := fs.String("lan", envOr("GUARDIAN_LAN", "192.168.88.0/24"), "comma separated LAN prefixes (env GUARDIAN_LAN)")
	fs.StringVar(&o.wan, "wan", "", "WAN interface for traffic coverage check (default: auto-detect from default route)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.pass == "" {
		o.pass = os.Getenv("GUARDIAN_ROS_PASS")
	}
	if o.pass == "" {
		return o, errors.New("password required: -pass or GUARDIAN_ROS_PASS")
	}
	if o.interval < time.Second {
		return o, errors.New("-interval must be >= 1s")
	}
	for _, p := range strings.Split(*lanStr, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			return o, fmt.Errorf("-lan: %w", err)
		}
		o.lan = append(o.lan, pfx.Masked())
	}
	if len(o.lan) == 0 {
		return o, errors.New("-lan: at least one prefix required")
	}
	return o, nil
}

// recorder wraps the client so the collector's Connections call can be timed
// and its raw result inspected without a second (expensive) request.
type recorder struct {
	*routeros.Client
	conns []model.Conn
	dur   time.Duration
	size  int64
}

func (r *recorder) Connections(ctx context.Context) ([]model.Conn, error) {
	t0 := time.Now()
	conns, n, err := r.Client.ConnectionsWithSize(ctx)
	r.dur, r.size, r.conns = time.Since(t0), n, conns
	return conns, err
}

func run(ctx context.Context, log *slog.Logger, o options) error {
	client, err := routeros.New(routeros.Config{
		BaseURL: o.url, User: o.user, Password: o.pass, InsecureTLS: o.insecure, Timeout: o.timeout,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}

	info := runInfo{Start: time.Now(), Interval: o.interval, URL: o.url}
	res, err := client.Resource(ctx)
	if err != nil {
		return fmt.Errorf("cannot reach router (check URL, user, password, /ip/service www/www-ssl): %w", err)
	}
	info.Resource = res
	log.Info("router", "board", res.BoardName, "version", res.Version, "arch", res.Arch, "cpus", res.CPUCount)

	info.Fasttrack, err = checkFasttrack(ctx, client)
	if err != nil {
		log.Warn("firewall filter check failed", "err", err)
		info.FasttrackErr = err.Error()
	} else {
		log.Info("fasttrack rule", "present", info.Fasttrack.Present, "enabled", info.Fasttrack.Enabled, "hw-offload", info.Fasttrack.HWOffload)
	}
	info.IPv6Conns = countIPv6Conns(ctx, client)

	info.WAN = o.wan
	if info.WAN == "" {
		info.WAN = detectWAN(ctx, client)
	}
	if info.WAN != "" {
		log.Info("wan interface", "name", info.WAN)
	} else {
		log.Warn("WAN interface not detected, coverage check disabled (use -wan)")
	}

	csvw, err := newSampleWriter(filepath.Join(o.out, "samples.csv"))
	if err != nil {
		return err
	}
	defer csvw.Close()

	rec := &recorder{Client: client}
	coll := collector.New(rec, nil, o.lan)
	agg := newAggregator()
	ft := newCounterTracker()

	deadline := time.NewTimer(o.duration)
	defer deadline.Stop()
	tick := time.NewTicker(o.interval)
	defer tick.Stop()

	log.Info("probing", "interval", o.interval, "duration", o.duration, "out", o.out)
	var prevWAN *ifCounters
	for {
		s := pollOnce(ctx, client, rec, coll, ft, info.WAN, &prevWAN)
		if ctx.Err() != nil && s.Err != "" {
			break // interrupted mid-poll: don't record a bogus error row
		}
		agg.add(s)
		if err := csvw.Write(s); err != nil {
			log.Warn("csv write", "err", err)
		}
		if s.Err != "" {
			log.Warn("poll", "err", s.Err)
		} else {
			log.Info("poll", "conns", s.Entries, "fasttrack", s.Fasttrack, "conn_ms", s.ConnDur.Milliseconds(),
				"kB", s.RespBytes/1024, "cpu", fmt.Sprintf("%d->%d", s.CPUBefore, s.CPUAfter),
				"ft_moved", fmt.Sprintf("%d/%d", s.FTMoved, s.FTTracked), "flows", s.Flows)
		}
		select {
		case <-ctx.Done():
		case <-deadline.C:
		case <-tick.C:
			continue
		}
		break
	}

	info.End = time.Now()
	summary := buildSummary(info, agg)
	if err := os.WriteFile(filepath.Join(o.out, "summary.txt"), []byte(summary), 0o644); err != nil {
		log.Warn("write summary", "err", err)
	}
	fmt.Println(summary)
	return nil
}

// pollOnce performs one Guardian-like poll wrapped with CPU and WAN sampling.
func pollOnce(ctx context.Context, c *routeros.Client, rec *recorder, coll *collector.Collector,
	ft *counterTracker, wan string, prevWAN **ifCounters) sample {
	now := time.Now()
	s := sample{Time: now}
	before, err := c.Resource(ctx)
	if err != nil {
		s.Err = "resource: " + err.Error()
		return s
	}
	s.CPUBefore = before.CPULoad

	t0 := time.Now()
	snap, err := coll.Poll(ctx, now)
	s.PollDur = time.Since(t0)
	s.ConnDur, s.RespBytes = rec.dur, rec.size
	if err != nil {
		s.Err = err.Error()
		return s
	}

	if after, err := c.Resource(ctx); err == nil {
		s.CPUAfter = after.CPULoad
		s.FreeMem = after.FreeMemory
		s.CPUOK = true
	}

	s.Entries = snap.ConnCount
	s.Fasttrack = snap.FasttrackCount
	s.Devices = len(snap.Devices)
	s.Flows = len(snap.Flows)
	s.VisTx, s.VisRx = snap.VisibleTx, snap.VisibleRx
	s.FTTracked, s.FTMoved, s.NonFTTracked, s.NonFTMoved = ft.update(rec.conns)
	rec.conns = nil // release memory until next poll

	if wan != "" {
		if cur, err := readIfCounters(ctx, c, wan); err == nil {
			if p := *prevWAN; p != nil && cur.rx >= p.rx && cur.tx >= p.tx {
				s.WanRx, s.WanTx, s.WanOK = cur.rx-p.rx, cur.tx-p.tx, true
			}
			*prevWAN = &cur
		}
	}
	return s
}
