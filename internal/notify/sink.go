package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/Marteva/routeros-guardian/internal/i18n"
	"github.com/Marteva/routeros-guardian/internal/model"
)

const (
	defaultQueueSize = 64
	sendTimeout      = 30 * time.Second // per notifier, covers the single retry
	// testAlertKind is the Alert.Kind of the message sent by SendTest.
	testAlertKind = "test"
)

// ErrNoNotifiers is returned by SendTest when no notifier is configured.
var ErrNoNotifiers = errors.New("notify: no notification channel configured")

type job struct {
	a model.Alert
}

// sinkConfig is the hot-swappable part of the Sink. A snapshot is taken per
// Emit / delivered message; the notifiers slice is never mutated in place.
type sinkConfig struct {
	notifiers []Notifier
	minNotify model.Severity // lowest severity that triggers a push
	lang      string         // language of notification texts
	dedup     time.Duration
}

// Sink implements model.AlertSink: it deduplicates, stores and (for alerts
// at or above the configured minimum severity) pushes alerts to the
// notifiers asynchronously. Notifiers, minimum severity, language and the
// dedup window can be changed at runtime (Configure, SetDedup).
type Sink struct {
	store model.Store
	log   *slog.Logger
	now   func() time.Time

	cfgMu sync.RWMutex
	cfg   sinkConfig

	mu     sync.Mutex // serialises dedup check + insert
	queue  chan job
	done   chan struct{}
	closeO sync.Once
	wg     sync.WaitGroup
}

var _ model.AlertSink = (*Sink)(nil)

// NewSink creates the sink and starts its notification worker. Notifications
// default to English and severity Warning and above (see Configure).
func NewSink(store model.Store, notifiers []Notifier, dedup time.Duration, log *slog.Logger) *Sink {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Sink{
		store: store,
		log:   log,
		now:   time.Now,
		cfg: sinkConfig{
			notifiers: slices.Clone(notifiers),
			minNotify: model.SevWarning,
			lang:      i18n.Fallback,
			dedup:     dedup,
		},
		queue: make(chan job, defaultQueueSize),
		done:  make(chan struct{}),
	}
	s.wg.Add(1)
	go s.worker()
	return s
}

// Configure replaces the notifiers, the minimum severity that is pushed and
// the language of notification texts ("" = English). Safe for concurrent use;
// it applies to every message delivered afterwards, including queued ones.
func (s *Sink) Configure(ns []Notifier, minNotify model.Severity, lang string) {
	if lang == "" {
		lang = i18n.Fallback
	}
	s.cfgMu.Lock()
	s.cfg.notifiers = slices.Clone(ns)
	s.cfg.minNotify = minNotify
	s.cfg.lang = lang
	s.cfgMu.Unlock()
}

// SetDedup changes the dedup window (0 disables dedup). Safe for concurrent use.
func (s *Sink) SetDedup(d time.Duration) {
	s.cfgMu.Lock()
	s.cfg.dedup = d
	s.cfgMu.Unlock()
}

func (s *Sink) config() sinkConfig {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// Emit stores the alert (unless suppressed by dedup) and queues it for
// notification. It never blocks on network I/O.
func (s *Sink) Emit(ctx context.Context, a model.Alert) {
	if a.Time.IsZero() {
		a.Time = s.now()
	}
	cfg := s.config()
	s.mu.Lock()
	if a.DedupKey != "" && cfg.dedup > 0 {
		last, ok, err := s.store.LastAlertByDedupKey(ctx, a.DedupKey)
		if err != nil {
			s.log.Warn("alert dedup lookup", "key", a.DedupKey, "err", err)
		} else if ok && a.Time.Sub(last) < cfg.dedup {
			s.mu.Unlock()
			s.log.Debug("alert suppressed (dedup)", "key", a.DedupKey, "last", last)
			return
		}
	}
	err := s.store.InsertAlert(ctx, &a)
	s.mu.Unlock()
	if err != nil {
		s.log.Error("store alert", "kind", a.Kind, "mac", a.DeviceMAC, "err", err)
		// still try to notify: losing the push is worse than losing the row
	} else {
		s.log.Info("alert", "id", a.ID, "kind", a.Kind, "severity", a.Severity.String(),
			"mac", a.DeviceMAC, "title", a.Title)
	}
	if a.Severity < cfg.minNotify || len(cfg.notifiers) == 0 {
		return
	}
	select {
	case <-s.done:
		return
	default:
	}
	select {
	case s.queue <- job{a: a}:
	default:
		s.log.Warn("notification queue full, dropping", "kind", a.Kind, "mac", a.DeviceMAC)
	}
}

// SendTest synchronously sends a test message (in the configured language)
// to every configured notifier. It returns ErrNoNotifiers when there is none,
// otherwise the joined errors of the failed notifiers, each prefixed with the
// notifier's name.
func (s *Sink) SendTest(ctx context.Context) error {
	cfg := s.config()
	if len(cfg.notifiers) == 0 {
		return ErrNoNotifiers
	}
	a := model.Alert{
		Time:     s.now(),
		Kind:     testAlertKind,
		Severity: model.SevInfo,
		Title:    i18n.T(cfg.lang, "notify.test.title"),
		Detail:   i18n.T(cfg.lang, "notify.test.body"),
	}
	ctx = withLang(ctx, cfg.lang)
	errs := make([]error, len(cfg.notifiers))
	var wg sync.WaitGroup
	for i, n := range cfg.notifiers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nctx, cancel := context.WithTimeout(ctx, sendTimeout)
			defer cancel()
			if err := n.Send(nctx, a, model.Device{}); err != nil {
				errs[i] = fmt.Errorf("%s: %w", n.Name(), err)
				s.log.Warn("test notification failed", "notifier", n.Name(), "err", err)
			} else {
				s.log.Info("test notification sent", "notifier", n.Name())
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Close stops the worker after draining queued notifications (bounded by ctx).
func (s *Sink) Close(ctx context.Context) error {
	s.closeO.Do(func() { close(s.done) })
	ch := make(chan struct{})
	go func() { s.wg.Wait(); close(ch) }()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Sink) worker() {
	defer s.wg.Done()
	for {
		select {
		case j := <-s.queue:
			s.deliver(j.a)
		case <-s.done:
			for {
				select {
				case j := <-s.queue:
					s.deliver(j.a)
				default:
					return
				}
			}
		}
	}
}

// deliver pushes one alert using the configuration current at delivery time.
func (s *Sink) deliver(a model.Alert) {
	cfg := s.config()
	if a.Severity < cfg.minNotify || len(cfg.notifiers) == 0 {
		return
	}
	var d model.Device
	if a.DeviceMAC != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		dev, ok, err := s.store.Device(ctx, a.DeviceMAC)
		cancel()
		if err != nil {
			s.log.Warn("device lookup for notification", "mac", a.DeviceMAC, "err", err)
		}
		if ok {
			d = dev
		} else {
			d.MAC = a.DeviceMAC
		}
	}
	base := withLang(context.Background(), cfg.lang)
	for _, n := range cfg.notifiers {
		ctx, cancel := context.WithTimeout(base, sendTimeout)
		err := n.Send(ctx, a, d)
		cancel()
		if err != nil {
			s.log.Warn("notification failed", "notifier", n.Name(), "alert", a.ID, "err", err)
		}
	}
}
