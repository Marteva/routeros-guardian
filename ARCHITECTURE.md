# Guardian for RouterOS – architecture & package contracts

Module path: `github.com/Marteva/routeros-guardian` (project name: **Guardian for RouterOS**). Go 1.26+, **CGO_ENABLED=0** (pure Go, cross-compiled to `linux/arm64`).
Target: MikroTik hAP ax³ (IPQ6000, ARM64, 1 GB RAM), RouterOS 7.20+, container on USB disk.
Budget: < 50 MB RSS, image < 30 MB, polling must not add more than a few % CPU on the router.

Shared types/interfaces live in `internal/model` (read it first, do not change it without the coordinator).
Allowed third-party deps (already in go.mod): `modernc.org/sqlite`, `github.com/oschwald/maxminddb-golang` (v1). Everything else = stdlib.

## Data flow (one poll, every `PollInterval`, default 15 s)

```
routeros.Client ──► collector.Poll ──► Snapshot{Devices, Flows}
                                         │
        fingerprint.Enrich(&dev) ◄───────┤ per device
        store.UpsertDevice ──► isNew ──► detect.Engine.DeviceSeen
                                         │
                       detect.Engine.Flows(flows)   (BEFORE store sees them → novelty works)
                       store.RecordFlows(flows)
hourly ticker ──► detect.Engine.Tick(now) ──► model.AlertSink (notify.Sink) ──► store + ntfy/Telegram
web.New(...) serves UI + JSON API, quarantine via RouterAPI.AddressListAdd
```

## Package APIs (exact signatures – main.go depends on them)

### internal/routeros  (agent: routeros)
```go
type Config struct { BaseURL, User, Password string; InsecureTLS bool; Timeout time.Duration }
func New(cfg Config) (*Client, error)               // *Client implements model.RouterAPI
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error // generic GET /rest/<path>
```
RouterOS REST returns **all values as strings**; flags like "true"/"false". Use `.proplist` to limit fields.

### internal/collector  (agent: routeros)
```go
type Snapshot struct {
    Time time.Time
    Devices []model.Device        // merged DHCP leases + ARP, MAC upper-case, LastSeen=Time
    Flows []model.FlowSample      // only LAN→internet, deltas since previous poll, geo filled
    ConnCount, FasttrackCount int // whole conntrack table / fasttracked entries
    VisibleTx, VisibleRx uint64   // sum of deltas this poll
}
func New(api model.RouterAPI, geo model.GeoLookup, lan []netip.Prefix) *Collector
func (c *Collector) Poll(ctx context.Context, now time.Time) (Snapshot, error)
```

### cmd/probe  (agent: routeros) – feasibility probe, standalone binary
Runs N hours against the router, writes CSV + summary: conntrack size, fasttrack share, whether byte counters move for fasttracked conns, poll latency, router CPU before/while polling.

### internal/store  (agent: store)
```go
func Open(path string) (*SQLite, error)   // *SQLite implements model.Store; WAL mode, migrations
```

### internal/geo  (agent: store)
```go
func Open(countryMMDB, asnMMDB string) (model.GeoLookup, error) // missing file → that part returns zero values, no error
type Noop struct{}                                                // implements model.GeoLookup
```
DB-IP Lite mmdb format (country: `country.iso_code`; asn: `autonomous_system_number`, `autonomous_system_organization`).

### internal/fingerprint  (agent: store)
```go
func Enrich(d *model.Device)   // sets Vendor (OUI), Kind, Randomized; keeps existing non-empty values
```

### internal/detect  (agent: detect)
```go
type Config struct { LearnPeriod time.Duration; /* thresholds… */ }
func DefaultConfig() Config
func New(store model.Store, sink model.AlertSink, cfg Config, start time.Time) *Engine
func (e *Engine) DeviceSeen(ctx context.Context, d model.Device, isNew bool)
func (e *Engine) Flows(ctx context.Context, flows []model.FlowSample)
func (e *Engine) Tick(ctx context.Context, now time.Time)
func (e *Engine) LearningUntil() time.Time
```

### internal/notify  (agent: web)
```go
type Notifier interface { Name() string; Send(ctx context.Context, a model.Alert, d model.Device) error }
func NewNtfy(topicURL, token string) Notifier
func NewTelegram(token, chatID string) Notifier
func NewSink(store model.Store, notifiers []Notifier, dedup time.Duration, log *slog.Logger) *Sink // implements model.AlertSink
```

### internal/web  (agent: web)
```go
type Status struct {
    Version string; StartedAt, LastPoll, LearningUntil time.Time; LastPollDuration time.Duration
    LastError string; ConnCount, FasttrackCount, DeviceCount, RouterCPU int
}
type Deps struct {
    Store model.Store; API model.RouterAPI; QuarantineList string
    Status func() Status; Log *slog.Logger
}
func New(d Deps) http.Handler   // UI at "/", JSON under "/api/", static assets embedded (go:embed), no JS build step
func BasicAuth(h http.Handler, user, pass string) http.Handler // optional UI login (GUARDIAN_WEB_USER/PASS)
```
On quarantine, web also calls `DropConnections(ctx, ip)` if the RouterAPI implements it
(`routeros.Client` does): fasttracked connections bypass the firewall drop rule.
Store setters return `model.ErrNotFound` (aliased as `store.ErrNotFound`) → web maps it to 404.

### deploy/  (agent: deploy)
Dockerfile (multi-stage, distroless/scratch, arm64), build scripts, RouterOS `.rsc` setup, README (English + README.cs.md).

## Conventions
- `log/slog` for logging, context everywhere, no global state.
- Every package has unit tests (`go test ./...` must pass on Windows host too).
- No CGO. No network in tests (use `httptest`).
- UI and alert texts are localized (internal/web/static/i18n.js, internal/i18n); code & comments in English.

## v0.3 contracts (settings, i18n, kind override, manual merge, reset)

### model (coordinator)
- `Device.KindOverride` (user choice, "" = auto), `Device.GroupID` (manual merge; members share
  the primary's MAC; "" = none). Both never overwritten by `UpsertDevice`.
- `Device.EffectiveKind()` – detection and UI use this, never `Kind` directly. `model.Kinds`, `model.ValidKind`.
- Store additions: `SetKindOverride`, `SetGroup(macs, groupID)`, `Settings()`/`PutSettings()` (KV,
  empty value deletes), `ResetLearned()` (hour stats, hour dst, dest stats, alerts), `ResetAll()` (+ devices).

### internal/settings (coordinator, done)
`settings.Settings` (Telegram/ntfy, NotifyMin, Language, LearnPeriod, LearningStart, Sensitivity,
DisabledDetectors, DedupWindow, Retention), `Defaults(config.Config)`, `Validate()`,
`Manager{NewManager, Get, Update(ctx, fn), OnChange(fn)}`. Env = defaults, values saved in UI win.

### internal/i18n (skeleton by coordinator, catalog filled by detect agent)
`i18n.T(lang, key, args...)`, `i18n.Register(lang, entries)` (from init). Languages: en, cs, de, pl, ru, es, pt.

### internal/detect
- `func (e *Engine) SetSettings(s settings.Settings)` – LearnPeriod, LearningStart (if non-zero it
  is the learning start; else earliest device FirstSeen), Sensitivity (low/normal/high scales
  thresholds), DisabledDetectors, Language (alert texts via i18n). Safe for concurrent use.
- `func (e *Engine) Reset()` – drop all in-memory caches/baselines (called after a data wipe).
- Use `Device.EffectiveKind()` for sensitivity profiles and names.
- `func RenderAlert(a model.Alert, d *model.Device, lang string) (title, detail string, ok bool)` –
  rebuilds an alert's texts in any language from its Evidence (the detectors write their texts
  through it); `d` = current device (nil: snapshot in the evidence); ok=false for evidence of
  older versions (keep the stored text). See internal/detect/DESIGN.md "Texts and languages".

### internal/notify
- `func BuildNotifiers(s settings.Settings) []Notifier`
- `func (s *Sink) Configure(ns []Notifier, minNotify model.Severity, lang string)` – hot swap.
- `func (s *Sink) SendTest(ctx) error` – synchronous test message to all notifiers; error if none.

### internal/web
`Deps` additions: `Settings *settings.Manager`, `TestNotify func(ctx) error`,
`Reset func(ctx, all bool) error`. Endpoints: `GET/PUT /api/settings` (secrets never returned,
only `…Set: true`; in PUT absent/null = unchanged, "" = clear), `POST /api/settings/test-notify`,
`POST /api/reset {"scope":"learned"|"all"}`, `PATCH /api/devices/{mac} {note?, kind?}` (kind "" = auto),
`POST /api/devices/merge {"macs":[…]}`, `POST /api/devices/{mac}/unmerge`.
`GET /api/alerts` and `GET /api/devices/{mac}` accept `?lang=xx` (one of `settings.Languages`):
alert title/detail rendered in that language via `detect.RenderAlert`; missing/invalid = stored
text (the notification language at the time the alert was raised).
