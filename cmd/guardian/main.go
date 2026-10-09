// Command guardian is the anomaly watchdog that runs as a RouterOS container.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Marteva/routeros-guardian/internal/collector"
	"github.com/Marteva/routeros-guardian/internal/config"
	"github.com/Marteva/routeros-guardian/internal/detect"
	"github.com/Marteva/routeros-guardian/internal/fingerprint"
	"github.com/Marteva/routeros-guardian/internal/geo"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/notify"
	"github.com/Marteva/routeros-guardian/internal/routeros"
	"github.com/Marteva/routeros-guardian/internal/settings"
	"github.com/Marteva/routeros-guardian/internal/store"
	"github.com/Marteva/routeros-guardian/internal/web"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log) // packages that log via slog.Default() share the format
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	api, err := routeros.New(routeros.Config{
		BaseURL:     cfg.RouterURL,
		User:        cfg.RouterUser,
		Password:    cfg.RouterPassword,
		InsecureTLS: cfg.RouterInsecure,
		Timeout:     10 * time.Second,
	})
	if err != nil {
		return err
	}

	if ok, err := store.RestoreIfMissing(cfg.DBPath, cfg.BackupPath); err != nil {
		log.Warn("restore from backup failed, starting empty", "backup", cfg.BackupPath, "err", err)
	} else if ok {
		log.Info("database restored from backup", "backup", cfg.BackupPath)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer st.Close()
	backup := func(ctx context.Context) {
		if cfg.BackupPath == "" {
			return
		}
		if err := st.Snapshot(ctx, cfg.BackupPath); err != nil {
			log.Warn("backup failed", "backup", cfg.BackupPath, "err", err)
		}
	}

	g, err := geo.Open(cfg.GeoCountryDB, cfg.GeoASNDB)
	if err != nil {
		log.Warn("geoip disabled", "err", err)
		g = geo.Noop{}
	}

	// Env vars are defaults; values saved in the UI (settings table) win.
	mgr, err := settings.NewManager(ctx, st, settings.Defaults(cfg))
	if err != nil {
		return err
	}
	cur := mgr.Get()
	sink := notify.NewSink(st, nil, cur.DedupWindow, log)
	engine := detect.New(st, sink, detect.DefaultConfig(), time.Now())
	applySettings := func(s settings.Settings) {
		sink.Configure(notify.BuildNotifiers(s), s.NotifyMin, s.Language)
		sink.SetDedup(s.DedupWindow)
		engine.SetSettings(s)
	}
	applySettings(cur)
	mgr.OnChange(applySettings)
	coll := collector.New(api, g, cfg.LANPrefixes)
	self := localAddrs()
	coll.IgnoreIPs(self...)
	log.Info("ignoring own addresses", "ips", self)

	// dataMu serialises ingest/Tick/Prune with a data reset from the UI.
	var dataMu sync.Mutex
	reset := func(ctx context.Context, all bool) error {
		dataMu.Lock()
		defer dataMu.Unlock()
		var err error
		if all {
			err = st.ResetAll(ctx)
		} else {
			err = st.ResetLearned(ctx)
		}
		if err != nil {
			return err
		}
		engine.Reset()
		_, err = mgr.Update(ctx, func(s *settings.Settings) error {
			s.LearningStart = time.Now().UTC().Truncate(time.Second)
			return nil
		})
		log.Info("data reset, learning restarted", "all", all)
		return err
	}

	started := time.Now()
	var mu sync.Mutex
	status := web.Status{Version: version, StartedAt: started}
	getStatus := func() web.Status {
		mu.Lock()
		defer mu.Unlock()
		s := status
		s.LearningUntil = engine.LearningUntil()
		return s
	}

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: web.BasicAuth(web.New(web.Deps{
			Store:          st,
			API:            api,
			QuarantineList: cfg.QuarantineList,
			Status:         getStatus,
			Log:            log,
			HealthMaxAge:   3*cfg.PollInterval + 30*time.Second,
			Settings:       mgr,
			TestNotify:     sink.SendTest,
			Reset:          reset,
		}), cfg.WebUser, cfg.WebPass),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Info("web listening", "addr", cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("web server", "err", err)
			stop()
		}
	}()

	poll := func(now time.Time) {
		t0 := time.Now()
		snap, err := coll.Poll(ctx, now)
		var cpu int
		if err == nil {
			if res, rerr := api.Resource(ctx); rerr == nil {
				cpu = res.CPULoad
			}
			dataMu.Lock()
			err = ingest(ctx, st, engine, snap)
			dataMu.Unlock()
		}
		mu.Lock()
		status.LastPoll = now
		status.LastPollDuration = time.Since(t0)
		if err != nil {
			status.LastError = err.Error()
		} else {
			status.LastError = ""
			status.ConnCount = snap.ConnCount
			status.FasttrackCount = snap.FasttrackCount
			status.DeviceCount = len(snap.Devices)
			status.RouterCPU = cpu
		}
		mu.Unlock()
		if err != nil {
			log.Warn("poll failed", "err", err)
		}
	}

	pollT := time.NewTicker(cfg.PollInterval)
	defer pollT.Stop()
	hourT := time.NewTicker(time.Hour)
	defer hourT.Stop()
	var backupC <-chan time.Time
	if cfg.BackupPath != "" {
		backupT := time.NewTicker(cfg.BackupInterval)
		defer backupT.Stop()
		backupC = backupT.C
	}

	poll(time.Now())
	for {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutCtx)
			if err := sink.Close(shutCtx); err != nil { // flush queued notifications
				log.Warn("notify flush", "err", err)
			}
			backup(shutCtx)
			log.Info("shutdown")
			return nil
		case now := <-pollT.C:
			poll(now)
		case <-backupC:
			backup(ctx)
		case now := <-hourT.C:
			dataMu.Lock()
			engine.Tick(ctx, now)
			if err := st.Prune(ctx, now.Add(-mgr.Get().Retention)); err != nil {
				log.Warn("prune", "err", err)
			}
			dataMu.Unlock()
		}
	}
}

// healthcheck is run by the container runtime (image HEALTHCHECK). It asks the
// running instance's /healthz, which is healthy only while polls succeed.
func healthcheck() int {
	listen := os.Getenv("GUARDIAN_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	fmt.Println(strings.TrimSpace(string(body)))
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// localAddrs returns this container's own IPv4/IPv6 unicast addresses, so the
// collector can leave Guardian itself out of the device list.
func localAddrs() []netip.Addr {
	ifAddrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range ifAddrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && !p.Addr().IsLoopback() {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// ingest pushes one snapshot through enrichment, detection and storage.
// Detection sees flows before the store so novelty checks compare against history.
func ingest(ctx context.Context, st model.Store, engine *detect.Engine, snap collector.Snapshot) error {
	for _, d := range snap.Devices {
		fingerprint.Enrich(&d)
		isNew, err := st.UpsertDevice(ctx, d)
		if err != nil {
			return err
		}
		engine.DeviceSeen(ctx, d, isNew)
	}
	engine.Flows(ctx, snap.Flows)
	return st.RecordFlows(ctx, snap.Flows)
}
