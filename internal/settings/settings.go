// Package settings holds runtime settings that can be edited in the web UI.
//
// Precedence: environment variables (internal/config) provide the defaults;
// once a value is saved in the UI it is stored in the database and wins.
package settings

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Marteva/routeros-guardian/internal/config"
	"github.com/Marteva/routeros-guardian/internal/model"
)

// Languages supported by the UI and by alert/notification texts.
var Languages = []string{"en", "cs", "de", "es", "id", "it", "pl", "pt", "tr", "uk"}

// NormalizeLanguage returns l (trimmed, lower-case) when it is one of
// Languages, else "" (= English). Used for values that were valid once – a
// language stored in the database or set in GUARDIAN_LANGUAGE may have been
// removed since – so that they cannot invalidate the other settings.
func NormalizeLanguage(l string) string {
	l = strings.ToLower(strings.TrimSpace(l))
	if slices.Contains(Languages, l) {
		return l
	}
	return ""
}

// Sensitivities of the detection engine.
var Sensitivities = []string{"low", "normal", "high"}

// Detectors that can be switched off (alert kinds).
var Detectors = []string{model.AlertNewDevice, model.AlertNewCountry, model.AlertNewASN,
	model.AlertUploadSpike, model.AlertDestFanout}

type Settings struct {
	TelegramToken  string
	TelegramChatID string
	NtfyURL        string
	NtfyToken      string
	NotifyMin      model.Severity // alerts at or above are pushed to notifiers

	// Language of alert texts and notifications ("" = en). The UI has its own
	// per-browser choice and falls back to this.
	Language string

	LearnPeriod time.Duration
	// LearningStart is when learning (re)started; zero = derive from the data
	// (earliest device FirstSeen). Set by "reset learned data".
	LearningStart time.Time

	Sensitivity       string   // low | normal | high
	DisabledDetectors []string // alert kinds that are switched off
	DedupWindow       time.Duration
	Retention         time.Duration
}

// DetectorEnabled reports whether alerts of this kind should be raised.
func (s Settings) DetectorEnabled(kind string) bool {
	return !slices.Contains(s.DisabledDetectors, kind)
}

// Defaults builds settings from the environment configuration.
func Defaults(c config.Config) Settings {
	return Settings{
		TelegramToken:  c.TelegramToken,
		TelegramChatID: c.TelegramChatID,
		NtfyURL:        c.NtfyURL,
		NtfyToken:      c.NtfyToken,
		NotifyMin:      model.SevWarning,
		Language:       NormalizeLanguage(c.Language), // unsupported → English
		LearnPeriod:    c.LearnPeriod,
		Sensitivity:    "normal",
		DedupWindow:    c.DedupWindow,
		Retention:      c.Retention,
	}
}

// Validate checks ranges and combinations.
func (s Settings) Validate() error {
	var errs []error
	if s.TelegramToken != "" && s.TelegramChatID == "" {
		errs = append(errs, errors.New("telegram: chat ID is required when a bot token is set"))
	}
	if s.TelegramChatID != "" && s.TelegramToken == "" {
		errs = append(errs, errors.New("telegram: bot token is required when a chat ID is set"))
	}
	if s.NtfyURL != "" {
		u, err := url.Parse(s.NtfyURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.Trim(u.Path, "/") == "" {
			errs = append(errs, errors.New("ntfy: URL must be http(s)://host/topic"))
		}
	}
	if s.NotifyMin < model.SevInfo || s.NotifyMin > model.SevCritical {
		errs = append(errs, errors.New("notify: invalid minimum severity"))
	}
	if s.Language != "" && !slices.Contains(Languages, s.Language) {
		errs = append(errs, fmt.Errorf("language: must be one of %v", Languages))
	}
	if s.LearnPeriod < time.Hour || s.LearnPeriod > 60*24*time.Hour {
		errs = append(errs, errors.New("learning period: must be between 1 hour and 60 days"))
	}
	if !slices.Contains(Sensitivities, s.Sensitivity) {
		errs = append(errs, fmt.Errorf("sensitivity: must be one of %v", Sensitivities))
	}
	for _, d := range s.DisabledDetectors {
		if !slices.Contains(Detectors, d) {
			errs = append(errs, fmt.Errorf("detectors: unknown detector %q", d))
		}
	}
	if s.DedupWindow < time.Minute || s.DedupWindow > 7*24*time.Hour {
		errs = append(errs, errors.New("dedup window: must be between 1 minute and 7 days"))
	}
	if s.Retention < 14*24*time.Hour || s.Retention > 365*24*time.Hour {
		errs = append(errs, errors.New("retention: must be between 14 and 365 days"))
	}
	return errors.Join(errs...)
}

// Database keys.
const (
	kTelegramToken = "telegram.token"
	kTelegramChat  = "telegram.chat"
	kNtfyURL       = "ntfy.url"
	kNtfyToken     = "ntfy.token"
	kNotifyMin     = "notify.min"
	kLanguage      = "language"
	kLearnPeriod   = "learn.period"
	kLearnStart    = "learn.start"
	kSensitivity   = "detect.sensitivity"
	kDisabled      = "detect.disabled"
	kDedup         = "dedup.window"
	kRetention     = "retention"
)

func encode(s Settings) map[string]string {
	kv := map[string]string{
		kTelegramToken: s.TelegramToken,
		kTelegramChat:  s.TelegramChatID,
		kNtfyURL:       s.NtfyURL,
		kNtfyToken:     s.NtfyToken,
		kNotifyMin:     s.NotifyMin.String(),
		kLanguage:      s.Language,
		kLearnPeriod:   s.LearnPeriod.String(),
		kSensitivity:   s.Sensitivity,
		kDisabled:      strings.Join(s.DisabledDetectors, ","),
		kDedup:         s.DedupWindow.String(),
		kRetention:     s.Retention.String(),
		kLearnStart:    "",
	}
	if !s.LearningStart.IsZero() {
		kv[kLearnStart] = s.LearningStart.UTC().Format(time.RFC3339)
	}
	return kv
}

// apply overlays stored values on s. Unparsable values are ignored (the
// default stays) so a bad row can never prevent startup. A stored language
// that is no longer supported becomes "" (English) instead of failing
// validation, which would drop all stored settings in NewManager.
func apply(s *Settings, kv map[string]string) {
	str := func(k string, dst *string) {
		if v, ok := kv[k]; ok {
			*dst = v
		}
	}
	dur := func(k string, dst *time.Duration) {
		if v, ok := kv[k]; ok {
			if d, err := time.ParseDuration(v); err == nil {
				*dst = d
			}
		}
	}
	str(kTelegramToken, &s.TelegramToken)
	str(kTelegramChat, &s.TelegramChatID)
	str(kNtfyURL, &s.NtfyURL)
	str(kNtfyToken, &s.NtfyToken)
	if v, ok := kv[kLanguage]; ok {
		s.Language = NormalizeLanguage(v)
	}
	str(kSensitivity, &s.Sensitivity)
	if v, ok := kv[kNotifyMin]; ok {
		if sev, ok := ParseSeverity(v); ok {
			s.NotifyMin = sev
		}
	}
	if v, ok := kv[kDisabled]; ok {
		s.DisabledDetectors = nil
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				s.DisabledDetectors = append(s.DisabledDetectors, d)
			}
		}
	}
	if v, ok := kv[kLearnStart]; ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			s.LearningStart = t
		}
	}
	dur(kLearnPeriod, &s.LearnPeriod)
	dur(kDedup, &s.DedupWindow)
	dur(kRetention, &s.Retention)
}

// ParseSeverity parses "info", "warning" or "critical".
func ParseSeverity(v string) (model.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "info":
		return model.SevInfo, true
	case "warning":
		return model.SevWarning, true
	case "critical":
		return model.SevCritical, true
	}
	return 0, false
}

// Manager holds the current settings, persists changes and notifies listeners.
type Manager struct {
	mu    sync.RWMutex
	store model.Store
	cur   Settings
	subs  []func(Settings)
}

// NewManager loads stored settings over defaults.
func NewManager(ctx context.Context, store model.Store, defaults Settings) (*Manager, error) {
	kv, err := store.Settings(ctx)
	if err != nil {
		return nil, fmt.Errorf("settings: load: %w", err)
	}
	s := defaults
	apply(&s, kv)
	if err := s.Validate(); err != nil {
		// Stored values became invalid (e.g. limits changed): fall back to defaults.
		s = defaults
	}
	return &Manager{store: store, cur: s}, nil
}

// Get returns a copy of the current settings.
func (m *Manager) Get() Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.cur
	s.DisabledDetectors = slices.Clone(s.DisabledDetectors)
	return s
}

// OnChange registers fn, called (synchronously, after persisting) on every update.
func (m *Manager) OnChange(fn func(Settings)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subs = append(m.subs, fn)
}

// Update applies fn to a copy of the settings, validates, persists and
// notifies listeners. Nothing changes if fn or validation fails.
func (m *Manager) Update(ctx context.Context, fn func(*Settings) error) (Settings, error) {
	m.mu.Lock()
	next := m.cur
	next.DisabledDetectors = slices.Clone(next.DisabledDetectors)
	if err := fn(&next); err != nil {
		m.mu.Unlock()
		return m.Get(), err
	}
	if err := next.Validate(); err != nil {
		m.mu.Unlock()
		return m.Get(), err
	}
	if err := m.store.PutSettings(ctx, encode(next)); err != nil {
		m.mu.Unlock()
		return m.Get(), fmt.Errorf("settings: save: %w", err)
	}
	m.cur = next
	subs := slices.Clone(m.subs)
	m.mu.Unlock()
	for _, fn := range subs {
		fn(next)
	}
	return next, nil
}
