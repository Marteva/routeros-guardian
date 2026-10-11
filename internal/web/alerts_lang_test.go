package web

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/Marteva/routeros-guardian/internal/detect"
	"github.com/Marteva/routeros-guardian/internal/model"
	"github.com/Marteva/routeros-guardian/internal/settings"
)

const macCam = "AA:BB:CC:00:00:03"

type captureSink struct{ alerts []model.Alert }

func (c *captureSink) Emit(_ context.Context, a model.Alert) { c.alerts = append(c.alerts, a) }

// addEngineAlert lets the real detection engine (English texts, as with the
// default notification language) raise a new-device alert for a camera and
// stores it as the SQLite store would (evidence through JSON).
func addEngineAlert(t *testing.T, f *fixture) model.Alert {
	t.Helper()
	cam := model.Device{MAC: macCam, IP: netip.MustParseAddr("192.168.88.30"), Vendor: "Hikvision", Kind: "camera",
		FirstSeen: now, LastSeen: now}
	f.st.devices[macCam] = cam
	cfg := detect.DefaultConfig()
	cfg.Logger = slog.New(slog.DiscardHandler)
	sink := &captureSink{}
	e := detect.New(f.st, sink, cfg, now)
	e.SetSettings(settings.Settings{Language: "en"})
	e.DeviceSeen(context.Background(), cam, true) // learning started 48 h ago: past the inventory
	if len(sink.alerts) != 1 {
		t.Fatalf("engine raised %d alerts", len(sink.alerts))
	}
	a := sink.alerts[0]
	js, err := json.Marshal(a.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	a.Evidence = nil
	if err := json.Unmarshal(js, &a.Evidence); err != nil {
		t.Fatal(err)
	}
	a.ID = 10
	f.st.alerts = append([]model.Alert{a}, f.st.alerts...)
	return a
}

func alertByID(t *testing.T, as []alertDTO, id int64) alertDTO {
	t.Helper()
	for _, a := range as {
		if a.ID == id {
			return a
		}
	}
	t.Fatalf("alert %d not in %+v", id, as)
	return alertDTO{}
}

func TestAlertsLang(t *testing.T) {
	f := newFixture(t)
	stored := addEngineAlert(t, f)
	const (
		enTitle = "New device on the network: Camera (Hikvision)"
		csTitle = "Nové zařízení v síti: Kamera (Hikvision)"
	)
	if stored.Title != enTitle {
		t.Fatalf("stored title %q", stored.Title)
	}
	get := func(query string) []alertDTO {
		t.Helper()
		rec := f.do(t, "GET", "/api/alerts"+query, "")
		wantCode(t, rec, 200)
		return decode[[]alertDTO](t, rec)
	}

	cs := alertByID(t, get("?lang=cs"), 10)
	if cs.Title != csTitle || cs.Detail == stored.Detail ||
		cs.Detail != "V síti se poprvé objevilo zařízení Kamera (Hikvision). MAC AA:BB:CC:00:00:03, IP 192.168.88.30, výrobce Hikvision, typ (odhad) Kamera. Pokud zařízení neznáte, můžete ho dát do karantény." {
		t.Errorf("cs: %q / %q", cs.Title, cs.Detail)
	}
	if cs.Kind != model.AlertNewDevice || cs.Severity != "info" || cs.DeviceName != "Hikvision" || cs.Evidence["mac"] != macCam {
		t.Errorf("cs: other fields changed: %+v", cs)
	}
	if en := alertByID(t, get("?lang=en"), 10); en.Title != enTitle || en.Detail != stored.Detail {
		t.Errorf("en: %q / %q", en.Title, en.Detail)
	}
	for _, q := range []string{"", "?lang=", "?lang=xx", "?lang=ru", "?lang=CS", "?open=1&lang=cs%20"} {
		if a := alertByID(t, get(q), 10); a.Title != stored.Title || a.Detail != stored.Detail {
			t.Errorf("%q: stored text expected, got %q", q, a.Title)
		}
	}
	// alerts without renderable evidence (older versions) keep their text
	if a := alertByID(t, get("?lang=cs"), 3); a.Title != "Nové" {
		t.Errorf("legacy alert: %q", a.Title)
	}
	if a := alertByID(t, get("?lang=en&mac="+macA), 1); a.Title != "Nová země" {
		t.Errorf("legacy alert: %q", a.Title)
	}

	// the current device name is used (note set after the alert)
	wantCode(t, f.do(t, "PATCH", "/api/devices/"+macCam, `{"note":"Kamera na zahradě"}`), 200)
	if a := alertByID(t, get("?lang=cs"), 10); a.Title != "Nové zařízení v síti: Kamera na zahradě" {
		t.Errorf("note: %q", a.Title)
	}

	// device detail: same rules for the embedded alerts
	detail := func(query string) alertDTO {
		t.Helper()
		rec := f.do(t, "GET", "/api/devices/"+macCam+query, "")
		wantCode(t, rec, 200)
		return alertByID(t, decode[deviceDetailDTO](t, rec).Alerts, 10)
	}
	if a := detail("?lang=cs"); a.Title != "Nové zařízení v síti: Kamera na zahradě" {
		t.Errorf("detail cs: %q", a.Title)
	}
	if a := detail("?lang=de"); a.Title != "Neues Gerät im Netzwerk: Kamera na zahradě" {
		t.Errorf("detail de: %q", a.Title)
	}
	if a := detail(""); a.Title != enTitle {
		t.Errorf("detail without lang: %q", a.Title)
	}
	if a := detail("?lang=xx"); a.Title != enTitle {
		t.Errorf("detail invalid lang: %q", a.Title)
	}

	// a device no longer known is named from the snapshot in the evidence
	delete(f.st.devices, macCam)
	if a := alertByID(t, get("?lang=cs"), 10); a.Title != csTitle {
		t.Errorf("unknown device: %q", a.Title)
	}
}
