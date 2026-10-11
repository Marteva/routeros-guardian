package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

const (
	tgToken   = "123456789:AAHsecretTelegramToken"
	ntfyToken = "tk_secretNtfyToken42"
)

func withSecrets(t *testing.T, f *fixture) {
	t.Helper()
	_, err := f.set.Update(context.Background(), func(s *settings.Settings) error {
		s.TelegramToken, s.TelegramChatID = tgToken, "-1001234"
		s.NtfyURL, s.NtfyToken = "https://ntfy.sh/guardian-topic", ntfyToken
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func noSecrets(t *testing.T, body string) {
	t.Helper()
	for _, sec := range []string{tgToken, ntfyToken, "secretTelegram", "secretNtfy"} {
		if strings.Contains(body, sec) {
			t.Fatalf("response leaks a secret (%s): %s", sec, body)
		}
	}
}

func TestSettingsGetMasksSecrets(t *testing.T) {
	f := newFixture(t)
	withSecrets(t, f)
	rec := f.do(t, "GET", "/api/settings", "")
	wantCode(t, rec, 200)
	noSecrets(t, rec.Body.String())
	for _, field := range []string{`"telegramToken"`, `"ntfyToken"`} {
		if strings.Contains(rec.Body.String(), field) {
			t.Errorf("response has field %s", field)
		}
	}
	got := decode[settingsDTO](t, rec)
	if !got.TelegramTokenSet || !got.NtfyTokenSet {
		t.Errorf("token flags %v %v", got.TelegramTokenSet, got.NtfyTokenSet)
	}
	if got.TelegramChatID != "-1001234" || got.NtfyURL != "https://ntfy.sh/guardian-topic" {
		t.Errorf("chat %q url %q", got.TelegramChatID, got.NtfyURL)
	}
	if got.NotifyMin != "warning" || got.Language != "en" || got.Sensitivity != "normal" {
		t.Errorf("%+v", got)
	}
	if got.LearnPeriodDays != 7 || got.DedupWindowHours != 6 || got.RetentionDays != 60 {
		t.Errorf("durations %v %v %v", got.LearnPeriodDays, got.DedupWindowHours, got.RetentionDays)
	}
	if got.DisabledDetectors == nil || len(got.DisabledDetectors) != 0 {
		t.Errorf("disabled %#v, want empty list", got.DisabledDetectors)
	}
	if !got.LearningUntil.Equal(f.learnTill) || !got.Learning || !got.Now.Equal(now) {
		t.Errorf("learning until %v learning %v now %v", got.LearningUntil, got.Learning, got.Now)
	}
	o := got.Options
	if !slices.Equal(o.Languages, settings.Languages) || !slices.Equal(o.Sensitivities, settings.Sensitivities) ||
		!slices.Equal(o.Detectors, settings.Detectors) || !slices.Equal(o.Kinds, model.Kinds) ||
		!slices.Equal(o.Severities, []string{"info", "warning", "critical"}) {
		t.Errorf("options %+v", o)
	}

	// Without secrets the flags are false.
	f = newFixture(t)
	got = decode[settingsDTO](t, f.do(t, "GET", "/api/settings", ""))
	if got.TelegramTokenSet || got.NtfyTokenSet {
		t.Errorf("flags set without secrets: %+v", got)
	}
}

func TestSettingsPutPartial(t *testing.T) {
	f := newFixture(t)
	withSecrets(t, f)
	var notified settings.Settings
	f.set.OnChange(func(s settings.Settings) { notified = s })

	rec := f.do(t, "PUT", "/api/settings", `{
		"sensitivity": "high", "learnPeriodDays": 14, "dedupWindowHours": 0.5, "retentionDays": 90,
		"notifyMin": "critical", "language": " CS ", "disabledDetectors": ["new_asn", "new_asn", "dest_fanout"],
		"telegramToken": null, "unknownField": 1}`)
	wantCode(t, rec, 200)
	noSecrets(t, rec.Body.String())
	cur := f.set.Get()
	if cur.Sensitivity != "high" || cur.LearnPeriod != 14*24*time.Hour || cur.DedupWindow != 30*time.Minute ||
		cur.Retention != 90*24*time.Hour || cur.NotifyMin != model.SevCritical || cur.Language != "cs" ||
		!slices.Equal(cur.DisabledDetectors, []string{"new_asn", "dest_fanout"}) {
		t.Errorf("settings %+v", cur)
	}
	if cur.TelegramToken != tgToken || cur.NtfyToken != ntfyToken || cur.TelegramChatID != "-1001234" {
		t.Errorf("absent/null secrets changed: %+v", cur)
	}
	if notified.Sensitivity != "high" {
		t.Error("OnChange listeners not notified")
	}
	got := decode[settingsDTO](t, rec)
	if got.Sensitivity != "high" || got.LearnPeriodDays != 14 || got.DedupWindowHours != 0.5 || got.RetentionDays != 90 ||
		!got.TelegramTokenSet || len(got.DisabledDetectors) != 2 {
		t.Errorf("response %+v", got)
	}
	if f.st.kv["detect.sensitivity"] != "high" {
		t.Errorf("not persisted: %v", f.st.kv)
	}

	// Empty list enables all detectors again.
	wantCode(t, f.do(t, "PUT", "/api/settings", `{"disabledDetectors": []}`), 200)
	if len(f.set.Get().DisabledDetectors) != 0 {
		t.Errorf("disabled %v", f.set.Get().DisabledDetectors)
	}
}

func TestSettingsPutSecrets(t *testing.T) {
	f := newFixture(t)
	withSecrets(t, f)

	// New value replaces, response still masked.
	rec := f.do(t, "PUT", "/api/settings", `{"ntfyToken": " tk_secretNtfyToken43 "}`)
	wantCode(t, rec, 200)
	if f.set.Get().NtfyToken != "tk_secretNtfyToken43" {
		t.Errorf("ntfy token %q", f.set.Get().NtfyToken)
	}
	if strings.Contains(rec.Body.String(), "tk_secretNtfyToken43") {
		t.Fatal("new token echoed back")
	}

	// "" clears.
	wantCode(t, f.do(t, "PUT", "/api/settings", `{"ntfyToken": ""}`), 200)
	if f.set.Get().NtfyToken != "" || f.set.Get().NtfyURL == "" {
		t.Errorf("clear ntfy token: %+v", f.set.Get())
	}
	if got := decode[settingsDTO](t, f.do(t, "GET", "/api/settings", "")); got.NtfyTokenSet {
		t.Error("ntfyTokenSet after clearing")
	}

	// Clearing the bot token alone leaves an orphan chat ID → 400, nothing changed.
	rec = f.do(t, "PUT", "/api/settings", `{"telegramToken": ""}`)
	wantCode(t, rec, 400)
	if !strings.Contains(decode[map[string]string](t, rec)["error"], "telegram") {
		t.Errorf("error %s", rec.Body.String())
	}
	if f.set.Get().TelegramToken != tgToken {
		t.Error("token changed by a rejected update")
	}
	// Clearing both disables Telegram.
	wantCode(t, f.do(t, "PUT", "/api/settings", `{"telegramToken": "", "telegramChatId": ""}`), 200)
	if s := f.set.Get(); s.TelegramToken != "" || s.TelegramChatID != "" {
		t.Errorf("telegram not cleared: %+v", s)
	}
}

func TestSettingsPutValidation(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"learn too short", `{"learnPeriodDays": 0}`, "learning period"},
		{"learn too long", `{"learnPeriodDays": 61}`, "learning period"},
		{"learn negative", `{"learnPeriodDays": -1}`, "learnPeriodDays"},
		{"learn overflow", `{"learnPeriodDays": 1e300}`, "learnPeriodDays"},
		{"retention", `{"retentionDays": 7}`, "retention"},
		{"dedup", `{"dedupWindowHours": 0}`, "dedup"},
		{"sensitivity", `{"sensitivity": "paranoid"}`, "sensitivity"},
		{"severity", `{"notifyMin": "loud"}`, "severity"},
		{"language", `{"language": "xx"}`, "language"},
		{"removed language", `{"language": "ru"}`, "language"},
		{"detector", `{"disabledDetectors": ["coffee"]}`, "coffee"},
		{"ntfy url", `{"ntfyUrl": "ftp://example.com/topic"}`, "ntfy"},
		{"telegram pair", `{"telegramToken": "1:abc"}`, "chat ID"},
		{"wrong type", `{"learnPeriodDays": "7"}`, "invalid JSON"},
		{"bad json", `{`, "invalid JSON"},
		{"empty", ``, "empty"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			before := f.set.Get()
			rec := f.do(t, "PUT", "/api/settings", c.body)
			wantCode(t, rec, 400)
			if msg := decode[map[string]string](t, rec)["error"]; !strings.Contains(msg, c.want) {
				t.Errorf("error %q, want it to mention %q", msg, c.want)
			}
			if after := f.set.Get(); !equalSettings(before, after) {
				t.Errorf("settings changed by a rejected update: %+v", after)
			}
			if len(f.st.kv) != 0 {
				t.Errorf("persisted: %v", f.st.kv)
			}
		})
	}
	// Several errors are joined on one line.
	f := newFixture(t)
	rec := f.do(t, "PUT", "/api/settings", `{"retentionDays": 1, "sensitivity": "x"}`)
	wantCode(t, rec, 400)
	if msg := decode[map[string]string](t, rec)["error"]; strings.Contains(msg, "\n") || !strings.Contains(msg, "; ") {
		t.Errorf("error %q", msg)
	}
}

func equalSettings(a, b settings.Settings) bool {
	return a.Sensitivity == b.Sensitivity && a.LearnPeriod == b.LearnPeriod && a.Retention == b.Retention &&
		a.DedupWindow == b.DedupWindow && a.NotifyMin == b.NotifyMin && a.Language == b.Language &&
		a.TelegramToken == b.TelegramToken && a.TelegramChatID == b.TelegramChatID && a.NtfyURL == b.NtfyURL &&
		a.NtfyToken == b.NtfyToken && slices.Equal(a.DisabledDetectors, b.DisabledDetectors)
}

func TestSettingsPutStoreError(t *testing.T) {
	f := newFixture(t)
	f.st.failPut = true
	wantCode(t, f.do(t, "PUT", "/api/settings", `{"sensitivity": "low"}`), 500)
	if f.set.Get().Sensitivity != "normal" {
		t.Error("in-memory settings changed although saving failed")
	}
}

func TestTestNotify(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "POST", "/api/settings/test-notify", "")
	wantCode(t, rec, 200)
	if f.tests != 1 {
		t.Errorf("TestNotify called %d times", f.tests)
	}

	withSecrets(t, f)
	f.testErr = errors.New(`telegram: Post "https://api.telegram.org/bot` + tgToken + `/sendMessage": dial tcp: i/o timeout`)
	rec = f.do(t, "POST", "/api/settings/test-notify", "")
	wantCode(t, rec, http.StatusBadGateway)
	noSecrets(t, rec.Body.String())
	if msg := decode[map[string]string](t, rec)["error"]; !strings.Contains(msg, "i/o timeout") || !strings.Contains(msg, "bot***") {
		t.Errorf("error %q", msg)
	}
}

func TestReset(t *testing.T) {
	f := newFixture(t)
	wantCode(t, f.do(t, "POST", "/api/reset", `{"scope":"learned"}`), 200)
	wantCode(t, f.do(t, "POST", "/api/reset", `{"scope":"all"}`), 200)
	if !slices.Equal(f.resets, []bool{false, true}) {
		t.Errorf("resets %v", f.resets)
	}
	for _, body := range []string{`{"scope":"everything"}`, `{}`, `{"scope":"ALL"}`, ``} {
		wantCode(t, f.do(t, "POST", "/api/reset", body), 400)
	}
	wantCode(t, f.do(t, "GET", "/api/reset", ""), 404)
	if len(f.resets) != 2 {
		t.Errorf("invalid requests reset data: %v", f.resets)
	}
	f.resetErr = errors.New("database is locked")
	rec := f.do(t, "POST", "/api/reset", `{"scope":"all"}`)
	wantCode(t, rec, 500)
	if strings.Contains(rec.Body.String(), "locked") {
		t.Errorf("internal error detail leaked: %s", rec.Body.String())
	}
}

func TestOptionalDepsUnavailable(t *testing.T) {
	h := New(Deps{Store: &fakeStore{devices: map[string]model.Device{}}})
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/settings", ""},
		{"PUT", "/api/settings", `{"sensitivity":"low"}`},
		{"POST", "/api/settings/test-notify", ""},
		{"POST", "/api/reset", `{"scope":"all"}`},
	} {
		var req *http.Request
		if c.body != "" {
			req = httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		} else {
			req = httptest.NewRequest(c.method, c.path, nil)
		}
		req.Header.Set("X-Guardian", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s: %d, want 503", c.method, c.path, rec.Code)
		}
	}
}
