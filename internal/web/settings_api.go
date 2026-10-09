package web

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

// settingsDTO is the body of GET /api/settings and of the PUT response.
// Secrets (bot token, ntfy token) are never returned, only whether they are
// set. Durations are plain numbers with the unit in the field name.
type settingsDTO struct {
	TelegramTokenSet bool   `json:"telegramTokenSet"`
	TelegramChatID   string `json:"telegramChatId"`
	NtfyURL          string `json:"ntfyUrl"`
	NtfyTokenSet     bool   `json:"ntfyTokenSet"`
	NotifyMin        string `json:"notifyMin"` // info | warning | critical
	Language         string `json:"language"`  // alerts/notifications; "" = en

	LearnPeriodDays float64 `json:"learnPeriodDays"`
	// LearningStart is the explicit start of learning (zero = derived from data).
	LearningStart time.Time `json:"learningStart"`
	// LearningUntil / Learning come from the running detection engine.
	LearningUntil time.Time `json:"learningUntil"`
	Learning      bool      `json:"learning"`

	Sensitivity       string   `json:"sensitivity"`
	DisabledDetectors []string `json:"disabledDetectors"`
	DedupWindowHours  float64  `json:"dedupWindowHours"`
	RetentionDays     float64  `json:"retentionDays"`

	Now     time.Time       `json:"now"`
	Options settingsOptions `json:"options"`
}

// settingsOptions lists the allowed values of the choice fields.
type settingsOptions struct {
	Languages     []string `json:"languages"`
	Sensitivities []string `json:"sensitivities"`
	Detectors     []string `json:"detectors"`
	Severities    []string `json:"severities"`
	Kinds         []string `json:"kinds"`
}

// settingsPatch is the body of PUT /api/settings. Absent or null fields stay
// unchanged; for the secrets "" clears the stored value.
type settingsPatch struct {
	TelegramToken     *string   `json:"telegramToken"`
	TelegramChatID    *string   `json:"telegramChatId"`
	NtfyURL           *string   `json:"ntfyUrl"`
	NtfyToken         *string   `json:"ntfyToken"`
	NotifyMin         *string   `json:"notifyMin"`
	Language          *string   `json:"language"`
	LearnPeriodDays   *float64  `json:"learnPeriodDays"`
	Sensitivity       *string   `json:"sensitivity"`
	DisabledDetectors *[]string `json:"disabledDetectors"`
	DedupWindowHours  *float64  `json:"dedupWindowHours"`
	RetentionDays     *float64  `json:"retentionDays"`
}

// badRequest marks errors caused by the client's input (→ 400).
type badRequest struct{ err error }

func (b badRequest) Error() string { return b.err.Error() }
func (b badRequest) Unwrap() error { return b.err }

const (
	day = 24 * time.Hour
	// maxUnits bounds numeric durations so the conversion cannot overflow;
	// Validate enforces the real limits.
	maxUnits = 1e5
)

func (p settingsPatch) apply(s *settings.Settings) error {
	str := func(src *string, dst *string) {
		if src != nil {
			*dst = strings.TrimSpace(*src)
		}
	}
	str(p.TelegramToken, &s.TelegramToken)
	str(p.TelegramChatID, &s.TelegramChatID)
	str(p.NtfyURL, &s.NtfyURL)
	str(p.NtfyToken, &s.NtfyToken)
	str(p.Sensitivity, &s.Sensitivity)
	if p.Language != nil {
		s.Language = strings.ToLower(strings.TrimSpace(*p.Language))
	}
	if p.NotifyMin != nil {
		sev, ok := settings.ParseSeverity(*p.NotifyMin)
		if !ok {
			return errors.New("notify: minimum severity must be info, warning or critical")
		}
		s.NotifyMin = sev
	}
	if p.DisabledDetectors != nil {
		var ds []string
		for _, d := range *p.DisabledDetectors {
			if d = strings.TrimSpace(d); d != "" && !slices.Contains(ds, d) {
				ds = append(ds, d)
			}
		}
		s.DisabledDetectors = ds
	}
	durs := []struct {
		name string
		v    *float64
		unit time.Duration
		dst  *time.Duration
	}{
		{"learnPeriodDays", p.LearnPeriodDays, day, &s.LearnPeriod},
		{"dedupWindowHours", p.DedupWindowHours, time.Hour, &s.DedupWindow},
		{"retentionDays", p.RetentionDays, day, &s.Retention},
	}
	for _, d := range durs {
		if d.v == nil {
			continue
		}
		v := *d.v
		if math.IsNaN(v) || v < 0 || v > maxUnits {
			return fmt.Errorf("%s: out of range", d.name)
		}
		*d.dst = time.Duration(math.Round(v * float64(d.unit)))
	}
	return nil
}

// roundUnits converts d to a number of units with at most 4 decimals.
func roundUnits(d, unit time.Duration) float64 {
	return math.Round(float64(d)/float64(unit)*1e4) / 1e4
}

func (s *server) toSettingsDTO(cur settings.Settings) settingsDTO {
	st := s.d.Status()
	now := s.now()
	disabled := cur.DisabledDetectors
	if disabled == nil {
		disabled = []string{}
	}
	return settingsDTO{
		TelegramTokenSet: cur.TelegramToken != "",
		TelegramChatID:   cur.TelegramChatID,
		NtfyURL:          cur.NtfyURL,
		NtfyTokenSet:     cur.NtfyToken != "",
		NotifyMin:        cur.NotifyMin.String(),
		Language:         cur.Language,

		LearnPeriodDays: roundUnits(cur.LearnPeriod, day),
		LearningStart:   cur.LearningStart,
		LearningUntil:   st.LearningUntil,
		Learning:        now.Before(st.LearningUntil),

		Sensitivity:       cur.Sensitivity,
		DisabledDetectors: disabled,
		DedupWindowHours:  roundUnits(cur.DedupWindow, time.Hour),
		RetentionDays:     roundUnits(cur.Retention, day),

		Now: now,
		Options: settingsOptions{
			Languages:     settings.Languages,
			Sensitivities: settings.Sensitivities,
			Detectors:     settings.Detectors,
			Severities:    []string{model.SevInfo.String(), model.SevWarning.String(), model.SevCritical.String()},
			Kinds:         model.Kinds,
		},
	}
}

func (s *server) getSettings(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	writeJSON(w, http.StatusOK, s.toSettingsDTO(s.d.Settings.Get()))
}

func (s *server) putSettings(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeErr(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	var p settingsPatch
	if !readJSON(w, r, &p) {
		return
	}
	next, err := s.d.Settings.Update(r.Context(), func(cur *settings.Settings) error {
		if err := p.apply(cur); err != nil {
			return badRequest{err}
		}
		if err := cur.Validate(); err != nil {
			return badRequest{err}
		}
		return nil
	})
	var br badRequest
	if errors.As(err, &br) {
		writeErr(w, http.StatusBadRequest, strings.ReplaceAll(br.Error(), "\n", "; "))
		return
	}
	if err != nil {
		s.internal(w, "settings", err)
		return
	}
	s.d.Log.Info("settings changed")
	writeJSON(w, http.StatusOK, s.toSettingsDTO(next))
}

func (s *server) testNotify(w http.ResponseWriter, r *http.Request) {
	if s.d.TestNotify == nil {
		writeErr(w, http.StatusServiceUnavailable, "test notification is not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), notifyTimeout)
	defer cancel()
	if err := s.d.TestNotify(ctx); err != nil {
		msg := s.redactSecrets(err.Error())
		s.d.Log.Warn("test notification failed", "err", msg)
		writeErr(w, http.StatusBadGateway, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// redactSecrets removes the configured tokens from msg: HTTP client errors
// contain the request URL, and Telegram puts the bot token in the path.
func (s *server) redactSecrets(msg string) string {
	if s.d.Settings == nil {
		return msg
	}
	cur := s.d.Settings.Get()
	for _, sec := range []string{cur.TelegramToken, cur.NtfyToken} {
		if len(sec) < 4 {
			continue
		}
		msg = strings.ReplaceAll(msg, sec, "***")
		msg = strings.ReplaceAll(msg, url.PathEscape(sec), "***")
		msg = strings.ReplaceAll(msg, url.QueryEscape(sec), "***")
	}
	return msg
}

func (s *server) reset(w http.ResponseWriter, r *http.Request) {
	if s.d.Reset == nil {
		writeErr(w, http.StatusServiceUnavailable, "reset is not available")
		return
	}
	var body struct {
		Scope string `json:"scope"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	var all bool
	switch body.Scope {
	case "learned":
	case "all":
		all = true
	default:
		writeErr(w, http.StatusBadRequest, `scope must be "learned" or "all"`)
		return
	}
	if err := s.d.Reset(r.Context(), all); err != nil {
		s.internal(w, "reset", err)
		return
	}
	s.d.Log.Warn("data reset from the web UI", "scope", body.Scope)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "scope": body.Scope})
}
