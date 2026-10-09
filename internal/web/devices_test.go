package web

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

func TestPatchDeviceKind(t *testing.T) {
	f := newFixture(t)
	rec := f.do(t, "PATCH", "/api/devices/"+macA, `{"kind":" Camera "}`)
	wantCode(t, rec, 200)
	if got := f.st.devices[macA]; got.KindOverride != "camera" || got.Kind != "tv" {
		t.Errorf("store %+v", got)
	}
	d := decode[deviceDTO](t, rec)
	if d.Kind != "camera" || d.KindAuto != "tv" || d.KindOverride != "camera" {
		t.Errorf("dto kind=%q auto=%q override=%q", d.Kind, d.KindAuto, d.KindOverride)
	}
	// list and detail expose the effective kind too
	for _, x := range decode[[]deviceDTO](t, f.do(t, "GET", "/api/devices", "")) {
		if x.MAC == macA && (x.Kind != "camera" || x.KindAuto != "tv") {
			t.Errorf("list %+v", x)
		}
	}
	if det := decode[deviceDetailDTO](t, f.do(t, "GET", "/api/devices/"+macA, "")); det.Device.Kind != "camera" {
		t.Errorf("detail kind %q", det.Device.Kind)
	}

	// "" = automatic again
	d = decode[deviceDTO](t, f.do(t, "PATCH", "/api/devices/"+macA, `{"kind":""}`))
	if d.Kind != "tv" || d.KindOverride != "" || f.st.devices[macA].KindOverride != "" {
		t.Errorf("reset kind: %+v", d)
	}

	// note and kind together
	wantCode(t, f.do(t, "PATCH", "/api/devices/"+macA, `{"note":"Obývák","kind":"tv"}`), 200)
	if got := f.st.devices[macA]; got.Note != "Obývák" || got.KindOverride != "tv" {
		t.Errorf("store %+v", got)
	}

	// invalid kind: 400 and nothing changes, not even a valid note in the same request
	rec = f.do(t, "PATCH", "/api/devices/"+macA, `{"note":"jiná","kind":"toaster"}`)
	wantCode(t, rec, 400)
	if !strings.Contains(decode[map[string]string](t, rec)["error"], "toaster") {
		t.Errorf("error %s", rec.Body.String())
	}
	if got := f.st.devices[macA]; got.Note != "Obývák" || got.KindOverride != "tv" {
		t.Errorf("rejected request changed the device: %+v", got)
	}
	wantCode(t, f.do(t, "PATCH", "/api/devices/AA:BB:CC:00:00:99", `{"kind":"tv"}`), 404)
}

func TestMergeAndUnmerge(t *testing.T) {
	f := newFixture(t)
	// macB is the most recently seen → primary
	rec := f.do(t, "POST", "/api/devices/merge", `{"macs":["aa:bb:cc:00:00:01","AA-BB-CC-00-00-02"]}`)
	wantCode(t, rec, 200)
	res := decode[mergeDTO](t, rec)
	if res.GroupID != macB || !slices.Equal(res.MACs, []string{macA, macB}) {
		t.Errorf("merge result %+v", res)
	}
	if f.st.devices[macA].GroupID != macB || f.st.devices[macB].GroupID != macB {
		t.Errorf("group ids %q %q", f.st.devices[macA].GroupID, f.st.devices[macB].GroupID)
	}

	ds := decode[[]deviceDTO](t, f.do(t, "GET", "/api/devices", ""))
	if len(ds) != 1 {
		t.Fatalf("rows %d: %+v", len(ds), ds)
	}
	g := ds[0]
	if g.MAC != macB || g.Group != "manual" || g.GroupID != macB || len(g.Members) != 2 {
		t.Errorf("group row %+v", g)
	}
	if g.Name != "Janin iPhone" || g.Tx24h != 150 || g.OpenAlerts != 2 {
		t.Errorf("aggregates name=%q tx=%d alerts=%d", g.Name, g.Tx24h, g.OpenAlerts)
	}

	// Merging with a third device joins the existing group (union).
	const macC = "AA:BB:CC:00:00:03"
	f.st.devices[macC] = model.Device{MAC: macC, Hostname: "nas", LastSeen: now.Add(time.Minute)}
	res = decode[mergeDTO](t, f.do(t, "POST", "/api/devices/merge", `{"macs":["`+macA+`","`+macC+`"]}`))
	if res.GroupID != macC || len(res.MACs) != 3 {
		t.Errorf("union %+v", res)
	}
	for _, m := range []string{macA, macB, macC} {
		if f.st.devices[m].GroupID != macC {
			t.Errorf("%s group %q", m, f.st.devices[m].GroupID)
		}
	}

	// Unmerge through any member dissolves the whole group.
	rec = f.do(t, "POST", "/api/devices/"+macA+"/unmerge", "")
	wantCode(t, rec, 200)
	if res = decode[mergeDTO](t, rec); len(res.MACs) != 3 || res.GroupID != "" {
		t.Errorf("unmerge %+v", res)
	}
	for _, m := range []string{macA, macB, macC} {
		if f.st.devices[m].GroupID != "" {
			t.Errorf("%s still grouped", m)
		}
	}
	if ds = decode[[]deviceDTO](t, f.do(t, "GET", "/api/devices", "")); len(ds) != 3 {
		t.Errorf("rows after unmerge %d", len(ds))
	}
	wantCode(t, f.do(t, "POST", "/api/devices/"+macA+"/unmerge", ""), 409)
	wantCode(t, f.do(t, "POST", "/api/devices/AA:BB:CC:00:00:99/unmerge", ""), 404)
	wantCode(t, f.do(t, "POST", "/api/devices/xyz/unmerge", ""), 400)
}

func TestMergeValidation(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		body string
		code int
	}{
		{`{"macs":["` + macA + `"]}`, 400},
		{`{"macs":["` + macA + `","aa:bb:cc:00:00:01"]}`, 400}, // same device twice
		{`{"macs":[]}`, 400},
		{`{}`, 400},
		{`{"macs":["` + macA + `","nope"]}`, 400},
		{`{"macs":["` + macA + `","AA:BB:CC:00:00:99"]}`, 404},
		{`{"macs":"` + macA + `"}`, 400},
		{`{"macs":[` + strings.Repeat(`"`+macA+`",`, maxMergeMACs) + `"` + macB + `"]}`, 400},
	} {
		if rec := f.do(t, "POST", "/api/devices/merge", c.body); rec.Code != c.code {
			t.Errorf("%s: %d, want %d (%s)", c.body, rec.Code, c.code, rec.Body.String())
		}
	}
	for m, d := range f.st.devices {
		if d.GroupID != "" {
			t.Errorf("%s grouped by a rejected request", m)
		}
	}
}

func TestDevicesManualGroupBeatsAuto(t *testing.T) {
	f := newFixture(t)
	const (
		r1 = "DA:00:00:00:00:01" // randomized "pixel", merged manually with macA
		r2 = "DA:00:00:00:00:02" // randomized "pixel", not merged → stands alone
		r3 = "DA:00:00:00:00:03" // randomized "pixel", not merged → auto group with r2
	)
	f.st.devices[r1] = model.Device{MAC: r1, Hostname: "pixel", Randomized: true, Kind: "phone", LastSeen: now.Add(-time.Minute), GroupID: macA}
	f.st.devices[r2] = model.Device{MAC: r2, Hostname: "Pixel", Randomized: true, Kind: "phone", LastSeen: now.Add(-2 * time.Minute)}
	f.st.devices[r3] = model.Device{MAC: r3, Hostname: "pixel", Randomized: true, Kind: "phone", LastSeen: now.Add(-3 * time.Minute),
		KindOverride: "tablet", IP: netip.MustParseAddr("192.168.88.30")}
	a := f.st.devices[macA]
	a.GroupID = macA
	a.KindOverride = "camera"
	f.st.devices[macA] = a

	ds := decode[[]deviceDTO](t, f.do(t, "GET", "/api/devices", ""))
	// macB, manual {r1, macA}, auto {r2, r3}
	if len(ds) != 3 {
		t.Fatalf("rows %d: %+v", len(ds), ds)
	}
	byMAC := map[string]deviceDTO{}
	for _, d := range ds {
		byMAC[d.MAC] = d
	}
	m, ok := byMAC[r1]
	if !ok || m.Group != "manual" || m.GroupID != macA || len(m.Members) != 2 || m.Members[1].MAC != macA {
		t.Errorf("manual row %+v", m)
	}
	if m.Kind != "camera" || m.KindOverride != "camera" || m.KindAuto != "phone" {
		t.Errorf("manual row kind=%q override=%q auto=%q (member's user choice should win)", m.Kind, m.KindOverride, m.KindAuto)
	}
	au, ok := byMAC[r2]
	if !ok || au.Group != "auto" || au.GroupID != "" || len(au.Members) != 2 || au.Members[1].MAC != r3 {
		t.Errorf("auto row %+v", au)
	}
	if au.Kind != "tablet" {
		t.Errorf("auto row kind %q", au.Kind)
	}
	if b := byMAC[macB]; b.Group != "" || len(b.Members) != 0 {
		t.Errorf("single row %+v", b)
	}
	// rows stay newest first
	if ds[0].MAC != macB || ds[1].MAC != r1 || ds[2].MAC != r2 {
		t.Errorf("order %s %s %s", ds[0].MAC, ds[1].MAC, ds[2].MAC)
	}

	// A manual group with a single remaining member is a normal row but keeps groupId.
	r := f.st.devices[r1]
	r.GroupID = ""
	f.st.devices[r1] = r
	ds = decode[[]deviceDTO](t, f.do(t, "GET", "/api/devices", ""))
	for _, d := range ds {
		if d.MAC == macA && (d.Group != "" || len(d.Members) != 0 || d.GroupID != macA) {
			t.Errorf("lone member %+v", d)
		}
	}
}
