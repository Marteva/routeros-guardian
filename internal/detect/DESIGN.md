# internal/detect – design

Guardian is a watchdog for home users, not an enterprise IDS. The main risk
is **alert fatigue**: a week of noise and the user switches it off. Every
detector is therefore built for precision:

* a **relative** test against the device's own history **and** an
  **absolute** minimum must both hold;
* a value the device already produced in the baseline window (×`HistMaxFactor`
  = 1.3) is never anomalous ("it did a 3 GB backup last Sunday");
* alerts are aggregated (one per device per hour per detector) and carry a
  stable `DedupKey` so `notify.Sink` suppresses repeats;
* titles/details explain the decision in the configured language (see
  "Texts and languages"); `Evidence` holds every number used (observed,
  median, MAD, max, ratio, z, thresholds, method).

## Learning

| Gate | Rule | Why |
|---|---|---|
| Global learning | `settings.LearningStart` when set (written by "reset learned data"), otherwise `earliest Device.FirstSeen in store`; + `LearnPeriod` (settings, default 7 d). The derived start falls back to process `start` when the store is empty or errors (retried on next call). | The engine is restarted with every container restart; anchoring on stored data (or the persisted start) means a restart does not restart learning. |
| Initial inventory | first `InventoryPeriod` (24 h, capped at `LearnPeriod`) after the **effective** learning start: **no** per-device new-device alerts. After it ends, one `SevInfo` summary ("Initial inventory complete: N devices", empty `DeviceMAC`) is emitted once per learning start – the store is checked via `LastAlertByDedupKey`, so restarts don't repeat it. It is sent until the later of the learning end and one more inventory period (so a 12 h learning period still gets one). | First start on a network with 30 devices must not produce 30 alerts – and neither must a "reset all", after which every device re-appears as new. |
| Device warm-up | no behavioural alert until `FirstSeen + DeviceWarmup` (3 d) **and** ≥ `MinHistoryHours` (48) hours with traffic in the baseline window. | A newly installed device has no profile yet; a device first seen but mostly offline has too little data. |

New-device alerts are allowed after the inventory window, also during the
rest of the learning period (there is nothing to learn about "a new device
joined").

Inventory summary `DedupKey`: with an explicit learning start (settings /
`Reset`) it is `inventory_summary:<learning start, unix>`, so a reset re-arms
the summary even if old alerts survived. With a derived start the bare
`inventory_summary` is used and a stored alert counts when it was raised at or
after the learning start: the derived start moves slightly across restarts
(process start on the very first run, the earliest FirstSeen afterwards), so a
key embedding it would repeat the summary. The bare key is also what v0.2 used.

### Reset

`Engine.Reset()` (after `store.ResetLearned`/`ResetAll`) drops every
in-memory cache: device states, known countries/ASNs, the household set, hour
buckets, cached baselines, the last evaluated hour and the summary mark. It
restarts learning at `time.Now()` immediately (so polls racing with the reset
already fall into a fresh inventory window); the caller then calls
`SetSettings` with the persisted `LearningStart`.

## Sensitivity profiles (per `Device.EffectiveKind()`)

| Profile | Kinds | Character |
|---|---|---|
| strict | camera, iot | tiny stable destination set, almost no upload; anomalies are Critical |
| tv | tv | stable but streams from many CDNs (downloads) |
| unknown | unknown / "" with fixed MAC | medium |
| lenient | phone, computer, tablet, unlisted kinds, *unknown with randomized MAC* | browse the whole world, upload backups |

All thresholds live in `Config.Profiles` and can be tuned. The profile is
picked by `Device.EffectiveKind()` – a kind chosen by the user in the UI
(`KindOverride`) wins over the fingerprint guess (a "phone" the user marks as
camera gets the strict profile, ASN novelty and Critical severities).

Kind overrides reach the engine without extra store traffic per poll:
`DeviceSeen`/`Flows` reload the stored device (`store.Device`) when the cached
copy is older than 5 min (`infoTTL`), and `Tick` refreshes every cached device
from its hourly `store.Devices` call. When the effective kind changes, the
device's destination cache and the current hour's pending destinations are
dropped and rebuilt lazily for the new profile (at most one hour of novelty is
lost – conservative).

### Global sensitivity (`settings.Sensitivity`)

`SetSettings` rebuilds the thresholds from the configuration given to `New`:

| | low | normal | high |
|---|---|---|---|
| absolute minimums (bytes, conns, distinct IPs, critical upload, fast-path min) | ×2 | ×1 | ×0.5 |
| ratios (spike, fan-out, fast path) | ×2 | ×1 | ×0.5 |
| robust z threshold | +2 | – | −1.5 |

"high" never goes below safe floors (a threshold configured below its floor
is left as is): new country/ASN bytes 64 kB, connections 3, immediate-critical
upload 5 MB, hourly upload 100 MB, ratio 3×, z 3, fan-out 50 IPs, fast path
256 MB / 10×. Zero thresholds (= criterion off) stay off.
Not affected: learning, inventory, warm-up, `MinHistoryHours`,
`HistMaxFactor` ("did it before" guard), globetrotter / unstable-ASN limits,
baseline floors. Examples (camera): upload spike 200 MB/10×/z 6 → high
100 MB/5×/z 4.5, low 400 MB/20×/z 8.

### Disabled detectors (`settings.DisabledDetectors`)

A disabled alert kind (`new_device` incl. the inventory summary,
`new_country`, `new_asn`, `upload_spike`, `dest_fanout`) is never raised. The
novelty detectors keep learning destinations while disabled, so enabling one
again does not report everything seen in the meantime.

## 1. New device (`new_device`)

From `DeviceSeen(isNew=true)`. `SevInfo` normally. `SevWarning` only for an
unclassified device (`unknown`/"") with a **non-randomized** MAC: phones and
laptops randomize per network, so a fixed MAC we cannot classify is more
likely something plugged in that nobody told us about. A new camera/IoT is
Info – usually the user just installed it. `DedupKey new_device:<mac>`.

## 2. New country (`new_country`) / new ASN (`new_asn`)

Evaluated in `Flows` (called before `store.RecordFlows`, so the store holds
only history). Per device the known country set (and, for strict/tv/unknown,
the ASN set) is lazily loaded from `DestStats` and kept in memory; flows to
unknown destinations are accumulated in an hourly bucket. When the clock hour
ends (detected by the next flow of a later hour, or by `Tick`), at most **one
alert per device per detector** lists all destinations that crossed the
threshold. Every pending destination – including sub-threshold one-off CDN
hits – then becomes known (the store has them anyway after a restart).

Thresholds (a destination qualifies if ANY enabled criterion holds within the hour):

| | strict | tv | unknown | lenient |
|---|---|---|---|---|
| country upload | 256 kB | 1 MB | 2 MB | 20 MB |
| country total | 1 MB | 20 MB | – | – |
| country new conns | 5 | – | – | – |
| must be new for whole household | no | no | yes | yes |
| no alerts if device already knows ≥ N countries | – | – | 12 | 12 |
| immediate Critical at upload | 10 MB | – | – | – |
| ASN alerts | yes (≤ 25 known ASNs) | yes (≤ 15) | yes (≤ 15) | **off** |
| ASN upload / total / conns | 256 kB / 2 MB / 5 | 1 MB | 2 MB | – |

False-positive guards:
* phones/computers: only **uploads** count (downloads from a foreign CDN are
  normal), the country must be new for the whole household, and
  "globetrotter" devices (≥ 12 countries) are exempt;
* NTP (port 123), DNS (53) and ICMP are ignored – NTP pool servers are random
  world-wide by design;
* ASN novelty is off for lenient kinds and switches itself off for a device
  whose ASN set grows over `ASNMaxKnown` (unstable profile); a new ASN in a new
  country is reported only once, as the country alert;
* if `DestStats` cannot be loaded, novelty is skipped for that device (retry
  after 5 min) – an empty cache would make everything look new.

Severity: Warning; Critical (immediately, without waiting for the hour end)
when a camera/IoT uploads ≥ 10 MB to a new country. DedupKeys
`new_country:<mac>:<CC,CC>` and `new_asn:<mac>:<asn,asn>`.

## 3. Upload spike (`upload_spike`)

**Hourly path** (`Tick`): the last completed clock hour's `HourStat.TxBytes`
vs. a robust baseline from the previous `BaselineWindow` (28 d):

* baseline = median + MAD of the **same hour of day** when ≥ 7 such samples
  exist, otherwise of all hours with traffic (fallback for short history);
  hours without a row (device offline) are missing, which biases the baseline
  upwards – conservative;
* the median is floored at 1 MB and σ = max(1.4826·MAD, 10 % of median, 1 MB)
  so flat or near-zero histories don't produce absurd ratios;
* ALL must hold: observed ≥ absolute minimum, ratio ≥ R, robust z ≥ Z,
  observed ≥ 1.3 × max in window.

| | strict | tv | unknown | lenient |
|---|---|---|---|---|
| absolute min | 200 MB/h | 500 MB/h | 500 MB/h | 2 GB/h |
| ratio | 10× | 10× | 10× | 20× |
| z | 6 | 6 | 6 | 8 |
| severity | Critical | Warning | Warning | Warning |

**Fast path** (`Flows`): upload accumulated in the current hour ≥ 1 GB **and**
≥ 50× the baseline median (and above the profile minimum and the historical
max) alerts before the hour ends. The baseline is computed once per device per
hour. Both paths share `DedupKey upload_spike:<mac>` and the in-memory
"already alerted this hour" mark, so one spike = one alert.

`Tick` evaluates hours it has not evaluated yet (catch-up up to 3 hours) and
never the same hour twice within one process.

## 4. Destination fan-out (`dest_fanout`)

`HourStat.DistinctDst` of the last hour vs. the same robust baseline (median
floored at 10). ALL must hold: ≥ absolute minimum, ≥ ratio × median,
≥ 1.3 × historical max. Scanning / botnet indicator.

| | strict | tv | unknown | lenient |
|---|---|---|---|---|
| min distinct IPs | 100 | 200 | 300 | 1500 |
| ratio | 5× | 5× | 5× | 8× |
| severity | Critical | Warning | Warning | Warning |

## 5. Behaviour drift (`behavior_drift`)

Not implemented (see `drift.go`). It needs per-week destination aggregates
which `model.Store` does not expose; a `jaccard` helper is ready.

## Texts and languages

All titles and details come from `internal/i18n` (`alerts_<lang>.go`, keys
`alert.*`, `kind.*`, `word.*`, `unit.*`, `fmt.*`), rendered in
`settings.Language` (en, cs, de, pl, ru, es, pt; default and fallback en).
Numbers use the language's decimal separator ("3.1 GB/h" en, "3,1 GB/h"
others), dates the language's layout, counted nouns the plural rules of
cs/pl/ru (`word.<noun>.one|few|many`). Russian/Polish titles avoid past-tense
verbs whose gender would have to agree with the device name. Evidence keys
stay language independent (`kind_camera`, not a translated label).

## Engine mechanics

* One mutex guards all state; alerts are collected under the lock and emitted
  to the sink after unlocking (the sink does store I/O).
* Store errors are logged (`Config.Logger` or `slog.Default()`) and the
  affected check is skipped – never a panic, never a "guess".
* Memory is bounded: per device a few small maps (countries ≤ ~250, ASNs ≤
  `ASNMaxKnown` or none), the hourly pending buckets, and a cached baseline.
  State of devices unseen for 30 days is evicted on `Tick`. `Tick` evaluates
  stored-but-idle devices with a transient state.
* Hours are UTC clock hours, matching `model.HourStat.Hour`; hour-of-day
  seasonality therefore shifts by one hour across DST changes, which the
  conservative thresholds absorb.
