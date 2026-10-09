package settings

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// kvStore implements only the settings part of model.Store.
type kvStore struct {
	model.Store
	kv      map[string]string
	failPut bool
}

func (s *kvStore) Settings(context.Context) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range s.kv {
		out[k] = v
	}
	return out, nil
}

func (s *kvStore) PutSettings(_ context.Context, kv map[string]string) error {
	if s.failPut {
		return errors.New("disk full")
	}
	for k, v := range kv {
		if v == "" {
			delete(s.kv, k)
		} else {
			s.kv[k] = v
		}
	}
	return nil
}

func defaults() Settings {
	return Settings{
		NotifyMin: model.SevWarning, Language: "en", LearnPeriod: 7 * 24 * time.Hour,
		Sensitivity: "normal", DedupWindow: 6 * time.Hour, Retention: 60 * 24 * time.Hour,
	}
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := &kvStore{kv: map[string]string{}}
	m, err := NewManager(ctx, st, defaults())
	if err != nil {
		t.Fatal(err)
	}
	var notified Settings
	m.OnChange(func(s Settings) { notified = s })
	start := time.Date(2026, 10, 8, 10, 0, 0, 0, time.UTC)
	_, err = m.Update(ctx, func(s *Settings) error {
		s.TelegramToken, s.TelegramChatID = "123:abc", "-42"
		s.Language = "cs"
		s.LearnPeriod = 3 * 24 * time.Hour
		s.LearningStart = start
		s.NotifyMin = model.SevCritical
		s.DisabledDetectors = []string{model.AlertNewASN}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if notified.Language != "cs" {
		t.Fatal("listener not notified")
	}
	// A fresh manager over the same store sees the saved values.
	m2, err := NewManager(ctx, st, defaults())
	if err != nil {
		t.Fatal(err)
	}
	got := m2.Get()
	if got.TelegramToken != "123:abc" || got.TelegramChatID != "-42" || got.Language != "cs" ||
		got.LearnPeriod != 3*24*time.Hour || !got.LearningStart.Equal(start) ||
		got.NotifyMin != model.SevCritical || got.DetectorEnabled(model.AlertNewASN) ||
		!got.DetectorEnabled(model.AlertUploadSpike) {
		t.Fatalf("round trip: %+v", got)
	}
}

func TestValidateRejectsAndKeepsState(t *testing.T) {
	ctx := context.Background()
	st := &kvStore{kv: map[string]string{}}
	m, _ := NewManager(ctx, st, defaults())
	cases := map[string]func(*Settings){
		"telegram without chat": func(s *Settings) { s.TelegramToken = "x" },
		"bad ntfy url":          func(s *Settings) { s.NtfyURL = "ftp://x/y" },
		"ntfy without topic":    func(s *Settings) { s.NtfyURL = "https://ntfy.sh/" },
		"learn too short":       func(s *Settings) { s.LearnPeriod = time.Minute },
		"bad language":          func(s *Settings) { s.Language = "xx" },
		"bad sensitivity":       func(s *Settings) { s.Sensitivity = "paranoid" },
		"unknown detector":      func(s *Settings) { s.DisabledDetectors = []string{"nope"} },
		"retention too short":   func(s *Settings) { s.Retention = 24 * time.Hour },
	}
	for name, fn := range cases {
		if _, err := m.Update(ctx, func(s *Settings) error { fn(s); return nil }); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if len(st.kv) != 0 || m.Get().Language != "en" {
		t.Fatalf("invalid update leaked: %v %+v", st.kv, m.Get())
	}
}

func TestSaveFailureKeepsState(t *testing.T) {
	ctx := context.Background()
	st := &kvStore{kv: map[string]string{}, failPut: true}
	m, _ := NewManager(ctx, st, defaults())
	_, err := m.Update(ctx, func(s *Settings) error { s.Language = "de"; return nil })
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
	if m.Get().Language != "en" {
		t.Fatal("state changed despite failed save")
	}
}

func TestCorruptStoredValuesFallBack(t *testing.T) {
	st := &kvStore{kv: map[string]string{kLearnPeriod: "banana", kSensitivity: "paranoid"}}
	m, err := NewManager(context.Background(), st, defaults())
	if err != nil {
		t.Fatal(err)
	}
	if s := m.Get(); s.LearnPeriod != 7*24*time.Hour || s.Sensitivity != "normal" {
		t.Fatalf("fallback: %+v", s)
	}
}
