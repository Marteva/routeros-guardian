# Configuration

Guardian is configured in two places:

1. **Environment variables** - set on the router with `/container envs`
   (see [routeros-setup.md](routeros-setup.md#8-environment-variables-and-data-mount)).
   They are read once at startup; change them and restart the container.
2. **Settings in the web UI** (**Settings** page) - notifications, language,
   learning period, sensitivity, detectors, retention. They are stored in the
   database and applied immediately, without a restart.

The source of truth is [`internal/config/config.go`](../internal/config/config.go)
(environment) and [`internal/settings/settings.go`](../internal/settings/settings.go)
(UI settings).

## Precedence

For settings that exist in both places:

- The **environment variable is the default.**
- **A value saved in the UI wins** and is stored in the database.
- When you save the Settings page (or reset learned data, which also saves
  the settings), *all* UI-editable values are written to the database. From
  then on, changing the corresponding environment variables has no effect -
  change the value in the UI instead (or start with a fresh database).
- If stored values become invalid (e.g. after an upgrade changes the allowed
  ranges), Guardian falls back to the environment defaults.

## Duration format

Durations accept Go syntax (`15s`, `90m`, `168h`) and a day suffix (`7d`).
Combinations such as `1d12h` are **not** supported - use `36h`.

## Environment variables

### Router connection

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_ROS_URL` | `http://172.17.0.1` | Base URL of the RouterOS REST API (without `/rest`). With the veth in the LAN bridge use the router's LAN IP, e.g. `http://192.168.88.1` or `http://192.168.88.1:81`. `https://` for `www-ssl`. |
| `GUARDIAN_ROS_USER` | `guardian` | API user name. |
| `GUARDIAN_ROS_PASS` | - (**required**) | API user password. Guardian refuses to start without it. |
| `GUARDIAN_ROS_INSECURE_TLS` | `true` | Accept a self-signed `www-ssl` certificate. Irrelevant for `http://`. |
| `GUARDIAN_POLL_INTERVAL` | `15s` | How often the router is polled (minimum `5s`). Increase it on very busy networks (tens of thousands of connections). |

### Network

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_LAN` | `192.168.88.0/24` | LAN prefixes, comma separated (`192.168.88.0/24,10.0.10.0/24`). Only devices and flows from these prefixes are tracked; flows to these prefixes are not counted as internet traffic. |
| `GUARDIAN_QUARANTINE_LIST` | `guardian-quarantine` | Firewall address list used by the Quarantine button. Must match your firewall rules. |

### Storage and backup

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_DB` | `/data/guardian.db` | SQLite database path (WAL mode). Keep `/data` on a mounted disk. |
| `GUARDIAN_BACKUP` | - | Optional path for a database snapshot, e.g. on a network share mounted into the container (`/backup/guardian.db`). Empty = no backup. If the database is missing at startup and the snapshot exists, Guardian restores from it. |
| `GUARDIAN_BACKUP_INTERVAL` | `1h` | Snapshot interval (minimum `1m`). A snapshot is also taken on shutdown. |

### GeoIP

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_GEOIP_COUNTRY` | `/data/geo/country.mmdb` | DB-IP *IP to Country Lite* database (mmdb). Optional. |
| `GUARDIAN_GEOIP_ASN` | `/data/geo/asn.mmdb` | DB-IP *IP to ASN Lite* database (mmdb). Optional. |

Missing files are not an error - the *new country* / *new ASN* detectors are
then simply inactive. Download with `scripts/update-geoip.sh` or
`scripts/update-geoip.ps1`. IP Geolocation by [DB-IP](https://db-ip.com),
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

### Web UI

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_LISTEN` | `:8080` | Listen address of the web UI and JSON API. |
| `GUARDIAN_WEB_USER` | - | UI login name (HTTP Basic auth). Empty = UI without login. |
| `GUARDIAN_WEB_PASS` | - | UI password; required when `GUARDIAN_WEB_USER` is set. |

`GET /healthz` is always reachable without login (it only returns `ok` or a
short reason) so the container healthcheck works.

### Detection and notifications (defaults for UI settings)

These are also editable in the UI; see [precedence](#precedence).

| Variable | Default | UI setting | Description |
|---|---|---|---|
| `GUARDIAN_LEARN_PERIOD` | `7d` | Learning period | Length of the learning phase (UI range 1 hour - 60 days). |
| `GUARDIAN_RETENTION` | `60d` | Retention | How long aggregated statistics are kept (UI range 14 - 365 days). |
| `GUARDIAN_DEDUP_WINDOW` | `6h` | Deduplication window | The same alert is sent only once within this window (UI range 1 minute - 7 days). |
| `GUARDIAN_LANGUAGE` | – (English) | Language | Language of Telegram/ntfy notifications: `en`, `cs`, `de`, `es`, `id`, `it`, `pl`, `pt` (Brazilian Portuguese), `tr`, `uk`; empty or unsupported = English. The web UI shows alerts in its own language, switched with the flag button in the page header. |
| `GUARDIAN_TELEGRAM_TOKEN` | - | Telegram bot token | Bot token from @BotFather. |
| `GUARDIAN_TELEGRAM_CHAT` | - | Telegram chat ID | Chat (or group) ID the bot writes to. Token and chat ID must be set together. |
| `GUARDIAN_NTFY_URL` | - | ntfy topic URL | Full topic URL, e.g. `https://ntfy.sh/your-long-random-topic`. |
| `GUARDIAN_NTFY_TOKEN` | - | ntfy access token | Only for protected topics / your own ntfy server. |

### Other

| Variable | Default | Description |
|---|---|---|
| `TZ` | UTC | Time zone for logs and the UI, e.g. `Europe/Berlin`. Time zone data is built into the binary. |

## UI settings

Open **Settings** in the web UI. Secrets (bot token, ntfy token) are never
sent back to the browser - the UI only shows whether they are set. Leaving a
secret field untouched keeps the stored value; clearing it removes it.

| Setting | Default | Description |
|---|---|---|
| Telegram bot token / chat ID | env | See [notifications](../README.md#notifications). |
| ntfy topic URL / token | env | See [notifications](../README.md#notifications). |
| **Send test notification** | - | Sends a test message to all configured channels and reports errors. |
| Minimum severity to notify | `warning` | `info`, `warning` or `critical`. Alerts below it are only shown in the UI. Most *new device* alerts are `info` - choose `info` to get a push for every new device. |
| Language | env (`en`) | Language of alerts and notifications. The UI language is chosen per browser and falls back to this. |
| Learning period | env (`7d`) | See [how detection works](../README.md#how-detection-works). |
| Sensitivity | `normal` | `low` = fewer alerts (higher thresholds), `high` = more alerts (lower thresholds). Applies on top of the per-device-type profiles. |
| Detectors | all on | Switch off individual detectors: `new_device`, `new_country`, `new_asn`, `upload_spike`, `dest_fanout`. |
| Deduplication window | env (`6h`) | |
| Retention | env (`60d`) | |

### Data reset

- **Reset learned data** - deletes hourly statistics, known destinations and
  alerts, keeps the device list (names, notes, kinds, quarantine). Learning
  starts again from now.
- **Reset everything** - additionally deletes the device list.

Settings are kept in both cases.

## Devices

- **Kind** - Guardian guesses the device type (phone, tablet, computer, tv,
  camera, iot, speaker, console, printer, nas, network, unknown) from the MAC
  vendor, hostname and DHCP data. The kind selects the sensitivity profile
  (cameras and IoT are watched strictly, phones and computers leniently). If
  the guess is wrong, override it in the device detail; *auto* returns to the
  guess.
- **Merge** - phones and laptops often use a random MAC per network or rotate
  it, so one physical device can appear several times. Select the entries and
  merge them; they are then shown together as one device. *Unmerge* splits
  them again.
- **Note** - free text; DHCP lease comments from the router are shown too.

## Example: minimal `/container envs`

```routeros
/container envs add list=guardian key=GUARDIAN_ROS_URL value="http://192.168.88.1"
/container envs add list=guardian key=GUARDIAN_ROS_PASS value="LONG-RANDOM-PASSWORD"
/container envs add list=guardian key=GUARDIAN_LAN value="192.168.88.0/24"
/container envs add list=guardian key=GUARDIAN_WEB_USER value="admin"
/container envs add list=guardian key=GUARDIAN_WEB_PASS value="UI-PASSWORD"
/container envs add list=guardian key=TZ value="Europe/Berlin"
```

Everything else can stay at its default or be set in the UI.
