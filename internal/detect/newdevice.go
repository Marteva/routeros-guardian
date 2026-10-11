package detect

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Marteva/routeros-guardian/internal/model"
)

// inventoryDedupKey is the DedupKey (prefix) of the "initial inventory
// finished" alert. The summary is sent once per learning period:
//   - with an explicit learning start (settings.LearningStart / Reset) the key
//     is "inventory_summary:<learning start, unix>", so a reset re-arms it;
//   - with a learning start derived from the data the bare key is used: the
//     derived start shifts slightly across restarts (process start on the very
//     first run, the earliest FirstSeen later), so the stored alert counts
//     when it was raised at or after the learning start.
const inventoryDedupKey = "inventory_summary"

func inventoryKey(learnStart time.Time) string {
	return inventoryDedupKey + ":" + strconv.FormatInt(learnStart.Unix(), 10)
}

// summaryKey is the DedupKey of the summary for the current learning period.
func (e *Engine) summaryKey() string {
	if e.learnFixed {
		return inventoryKey(e.learnStart)
	}
	return inventoryDedupKey
}

// inventoryKindOrder is the order of kinds in the summary.
var inventoryKindOrder = []string{"phone", "computer", "tablet", "tv", "camera", "iot",
	"speaker", "console", "printer", "nas", "network", "unknown"}

// newDeviceSeverity: a new device is normally just information (a guest's
// phone, a new gadget). Only an unidentified device with a real (vendor
// assigned, non-randomized) MAC is a Warning: phones and laptops randomize
// their MAC per network, so a fixed MAC we cannot classify is more likely
// something plugged in that nobody told us about.
func newDeviceSeverity(d model.Device) model.Severity {
	if k := d.EffectiveKind(); (k == "" || k == "unknown") && !d.Randomized {
		return model.SevWarning
	}
	return model.SevInfo
}

// newDeviceAlert decides on a new-device alert. During the initial
// inventory (first InventoryPeriod of the learning period, anchored on the
// effective learning start) nothing is emitted per device – a single summary
// follows when the inventory ends.
func (e *Engine) newDeviceAlert(ctx context.Context, d model.Device, now time.Time) (model.Alert, bool) {
	if !e.enabled(model.AlertNewDevice) || now.Before(e.inventoryUntil()) {
		return model.Alert{}, false
	}
	if other, ok := e.sameHostAs(ctx, d); ok {
		// Phones use a different random MAC per SSID: same hostname, another
		// MAC is the same phone, not a new device.
		e.log.Debug("new randomized MAC with a known hostname, no alert",
			"mac", d.MAC, "hostname", d.Hostname, "known_mac", other.MAC)
		return model.Alert{}, false
	}
	a := model.Alert{
		Time:      now,
		DeviceMAC: d.MAC,
		Kind:      model.AlertNewDevice,
		Severity:  newDeviceSeverity(d),
		Evidence: map[string]any{
			"mac":        d.MAC,
			"ip":         ipString(d),
			"hostname":   d.Hostname,
			"vendor":     d.Vendor,
			"comment":    d.Comment,
			"kind":       d.EffectiveKind(),
			"randomized": d.Randomized,
			"first_seen": d.FirstSeen,
			"device":     snapshotOf(d),
		},
		DedupKey: "new_device:" + d.MAC,
	}
	e.setText(&a, &d)
	return a, true
}

// sameHostAs reports another stored device with the same (case-insensitive)
// hostname as the randomized-MAC device d. Store errors are logged and treated
// as "no match" (alerting is the safe default).
func (e *Engine) sameHostAs(ctx context.Context, d model.Device) (model.Device, bool) {
	host := strings.TrimSpace(d.Hostname)
	if !d.Randomized || host == "" {
		return model.Device{}, false
	}
	devs, err := e.store.Devices(ctx)
	if err != nil {
		e.log.Warn("new device: list devices", "err", err)
		return model.Device{}, false
	}
	for _, o := range devs {
		if o.MAC != d.MAC && strings.EqualFold(strings.TrimSpace(o.Hostname), host) {
			return o, true
		}
	}
	return model.Device{}, false
}

func ipString(d model.Device) string {
	if d.IP.IsValid() {
		return d.IP.String()
	}
	return ""
}

// inventorySettled reports whether the summary for the current learning
// start was already sent (in this or an earlier process – checked in the
// store via LastAlertByDedupKey).
func (e *Engine) inventorySettled(ctx context.Context) (bool, error) {
	if !e.summaryFor.IsZero() && e.summaryFor.Equal(e.learnStart) {
		return true, nil
	}
	if e.learnFixed {
		if _, found, err := e.store.LastAlertByDedupKey(ctx, inventoryKey(e.learnStart)); err != nil || found {
			return found, err
		}
	}
	at, found, err := e.store.LastAlertByDedupKey(ctx, inventoryDedupKey)
	return found && !at.Before(e.learnStart), err
}

// inventorySummary emits one Info alert after the initial inventory window
// listing how many devices were found – once per learning start (restarts
// do not repeat it, a reset re-arms it). It is only emitted until the later
// of the learning end and one more inventory period after the inventory
// window (an engine started long after installation does not announce an
// "inventory").
func (e *Engine) inventorySummary(ctx context.Context, now time.Time) (model.Alert, bool) {
	end := e.inventoryUntil()
	deadline := e.learningUntil()
	if d := end.Add(e.inventoryPeriod()); d.After(deadline) {
		deadline = d
	}
	if !e.cfg.InventorySummary || !e.enabled(model.AlertNewDevice) || now.Before(end) || !now.Before(deadline) {
		return model.Alert{}, false
	}
	done, err := e.inventorySettled(ctx)
	if err != nil {
		e.log.Warn("inventory summary lookup", "err", err)
		return model.Alert{}, false
	}
	if done {
		e.summaryFor = e.learnStart
		return model.Alert{}, false
	}
	devs, err := e.store.Devices(ctx)
	if err != nil {
		e.log.Warn("inventory summary: list devices", "err", err)
		return model.Alert{}, false
	}
	e.summaryFor = e.learnStart
	kinds := map[string]int{}
	n := 0
	for _, d := range devs {
		if d.FirstSeen.IsZero() || d.FirstSeen.Before(end) {
			n++
			k := d.EffectiveKind()
			if !model.ValidKind(k) {
				k = "unknown"
			}
			kinds[k]++
		}
	}
	if n == 0 {
		return model.Alert{}, false
	}
	ev := map[string]any{"devices": n, "inventory_until": end, "learning_until": e.learningUntil(),
		"learning_start": e.learnStart, "inventory_hours": int(e.inventoryPeriod().Hours()),
		"learning": now.Before(e.learningUntil())}
	for k, c := range kinds {
		ev["kind_"+k] = c
	}
	a := model.Alert{
		Time:     now,
		Kind:     model.AlertNewDevice,
		Severity: model.SevInfo,
		Evidence: ev,
		DedupKey: e.summaryKey(),
	}
	e.setText(&a, nil)
	return a, true
}
