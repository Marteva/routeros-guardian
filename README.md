# Guardian for RouterOS

[![CI](https://github.com/Marteva/routeros-guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Marteva/routeros-guardian/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Marteva/routeros-guardian?sort=semver)](https://github.com/Marteva/routeros-guardian/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**English** | [Čeština](README.cs.md)

Guardian is a small anomaly-detection watchdog for home networks that runs as
a **container directly on a MikroTik router** (RouterOS 7). It reads DHCP
leases, the ARP table and connection tracking through the RouterOS REST API,
learns what is normal for every device, and tells you when something changes:
a new device on the network, a camera suddenly talking to a new country, a
smart plug uploading hundreds of megabytes, a laptop scanning the internet.

Alerts show up in the built-in web UI and can be pushed to **Telegram** or
**ntfy**. A suspicious device can be put into **quarantine** with one click
(a firewall address list on the router cuts it off from the internet).

No cloud, no agent on the devices, no extra hardware - just the router you
already have.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png">
  <img alt="Guardian web UI: alerts and device list" src="docs/screenshots/overview-light.png">
</picture>

| Device detail | Settings | Phone |
|---|---|---|
| <img src="docs/screenshots/device-detail.png" alt="Device detail with 7-day traffic chart" width="300"> | <img src="docs/screenshots/settings.png" alt="Detection settings" width="300"> | <img src="docs/screenshots/mobile.png" alt="Mobile layout, dark theme" width="200"> |

<sub>Screenshots show the built-in demo with a fictional household (`go run ./tools/demo`) - no real network data.</sub>

> **Status:** early but in daily use. Tested on a hAP ax³ (arm64) with
> RouterOS 7.24.4. Feedback and bug reports are welcome.

## Contents

- [Features](#features)
- [How detection works](#how-detection-works)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Try it without a router](#try-it-without-a-router)
- [Configuration](#configuration)
- [Notifications](#notifications)
- [Quarantine](#quarantine)
- [Security](#security)
- [FAQ and troubleshooting](#faq-and-troubleshooting)
- [Building from source](#building-from-source)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License and attributions](#license-and-attributions)

## Features

- **Runs on the router** - a ~12 MB static Go binary in a ~20 MB image, < 50 MB
  RAM, SQLite storage, no external services required.
- **Device inventory** - every device seen via DHCP/ARP with vendor (MAC OUI),
  guessed type, hostname, DHCP lease comment, first/last seen, traffic in the
  last 24 h. Randomized (private) MAC addresses are recognised.
- **Per-device baselines** - upload volume and number of destinations per
  hour of day, known countries and networks (ASNs) per device.
- **Five detectors** - new device, new country, new ASN, upload spike,
  destination fan-out; tuned for precision to avoid alert fatigue.
- **Notifications** - Telegram and/or ntfy, with a minimum severity,
  deduplication and a test button.
- **One-click quarantine** - adds the device's IP to a firewall address list
  and drops its existing connections.
- **Web UI** - devices (grouping, sorting, notes, type override, manual
  merge of devices with rotating MACs), alerts, settings, light/dark theme;
  7 languages (English, Czech, German, Polish, Russian, Spanish, Portuguese).
- **Settings in the UI** - notifications, language, learning period,
  sensitivity, detectors, retention - no container restart needed.
- **GeoIP** - country and ASN lookups with the free DB-IP Lite databases.
- **Healthcheck** - `/healthz` endpoint and an image `HEALTHCHECK`.
- **Optional backup** - periodic database snapshot to a mounted network share.

## How detection works

Every 15 seconds Guardian reads the router's DHCP leases, ARP table and IPv4
connection-tracking table. For each connection from a LAN device to the
internet it computes the bytes transferred since the previous poll and
aggregates them per device and hour: upload, download, distinct destination
IPs, destination countries and ASNs.

**Learning period.** For the first **7 days** (configurable) Guardian only
learns. The period starts when the first device was seen, so container
restarts do not restart it. The first 24 hours are an initial inventory -
devices found then are not reported one by one (you get a single summary).
After that, new devices are reported immediately; behavioural alerts start
when the learning period ends. A device that joins later gets its own
warm-up (3 days and at least 48 hours with traffic) before behavioural alerts
apply to it. Resetting learned data in the UI starts learning again.

**Per-device baselines.** Hourly values are compared with the same hour of
day over the last 28 days (median and median absolute deviation, falling back
to all hours for short histories). An alert needs **both** a relative
deviation (ratio and robust z-score) **and** an absolute minimum, and the
value must exceed anything the device did in the baseline window by 30 % -
a device that did a 3 GB backup last Sunday is not anomalous for doing it
again.

**Detectors**

| Alert | Fires when | Severity |
|---|---|---|
| `new_device` | a new MAC address appears (after the initial inventory) | info; warning for an unclassified device with a fixed MAC |
| `new_country` | a device exchanges meaningful traffic with a country it never talked to | warning; critical when a camera/IoT device uploads ≥ 10 MB there |
| `new_asn` | a device with a small, stable set of destinations talks to a new network (ASN) | warning |
| `upload_spike` | hourly upload far above the device's baseline (fast path for ≥ 1 GB within an hour) | warning; critical for cameras/IoT |
| `dest_fanout` | unusually many distinct destination IPs in an hour (scanning, botnet) | warning; critical for cameras/IoT |

**Sensitivity.** Thresholds depend on the device type: cameras and IoT
devices are watched strictly (few destinations and little upload are
expected), TVs and unknown devices moderately, phones, tablets and computers
leniently (for them only uploads count towards new countries, the country
must be new for the whole household, and devices that already talk to many
countries are exempt). DNS, NTP and ICMP are ignored. If the type is guessed
wrongly, override it in the UI. On top of that, the global **sensitivity**
(low / normal / high) scales all thresholds, and each detector can be
switched off. Repeated alerts are deduplicated (default 6 hours).

The design rationale and all thresholds are documented in
[`internal/detect/DESIGN.md`](internal/detect/DESIGN.md).

## Requirements

| | |
|---|---|
| RouterOS | **7.20 or newer** with the `container` package and device-mode `container=yes`. Tested on 7.24.4. |
| Architecture | **arm64**, **arm** (32-bit ARMv7) or **x86_64** (e.g. hAP ax³, RB5009, CCR, CHR). |
| Storage | USB/SATA/NVMe disk recommended (image ~20 MB, tarball another ~20 MB, database tens of MB). Keep the container off small internal flash. |
| RAM | ~50 MB free. |
| Optional | Telegram bot or ntfy app for push notifications; DB-IP Lite GeoIP files for country/ASN alerts. |

## Quick start

The full step-by-step guide with explanations, both network layouts and
uninstall instructions is in **[docs/routeros-setup.md](docs/routeros-setup.md)**.
Alternatively, edit the parameters at the top of
[`deploy/routeros-setup.rsc`](deploy/routeros-setup.rsc) and import it.

The commands below assume the RouterOS defaults: router `192.168.88.1`, LAN
`192.168.88.0/24` on bridge `bridge`, a disk `usb1`, and `192.168.88.250` as a
free address for the container.

**1. Enable containers** (once): `/system device-mode update container=yes`,
confirm by pressing the reset button briefly or power-cycling within 5
minutes, install the `container` package for your RouterOS version and
reboot. Details: [docs/routeros-setup.md](docs/routeros-setup.md#2-enable-containers).

**2. API user, REST API, network, quarantine rules**

```routeros
/user group add name=guardian policy="read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon"
/user add name=guardian group=guardian address=192.168.88.250/32 password="LONG-RANDOM-PASSWORD"
/ip service set www disabled=no

/interface veth add name=veth-guardian address=192.168.88.250/24 gateway=192.168.88.1 dhcp=no
/interface bridge port add bridge=bridge interface=veth-guardian
/interface list member add interface=veth-guardian list=LAN

/ip firewall filter add chain=forward action=drop src-address-list=guardian-quarantine comment="guardian: quarantine (src)" place-before=[find where comment="defconf: fasttrack"]
/ip firewall filter add chain=forward action=drop dst-address-list=guardian-quarantine comment="guardian: quarantine (dst)" place-before=[find where comment="defconf: fasttrack"]
```

**3. Environment and data mount**

```routeros
/container envs add list=guardian key=GUARDIAN_ROS_URL value="http://192.168.88.1"
/container envs add list=guardian key=GUARDIAN_ROS_PASS value="LONG-RANDOM-PASSWORD"
/container envs add list=guardian key=GUARDIAN_LAN value="192.168.88.0/24"
/container envs add list=guardian key=GUARDIAN_WEB_USER value="admin"
/container envs add list=guardian key=GUARDIAN_WEB_PASS value="UI-PASSWORD"
/container envs add list=guardian key=TZ value="Europe/Berlin"
/container mounts add list=guardian-data src=/usb1/guardian/data dst=/data
```

**4. Create the container** - choose one:

*A) Pull from GitHub Container Registry* (not yet verified on a router - if it
fails, use B):

```routeros
/container config set registry-url=https://ghcr.io tmpdir=/usb1/guardian/tmp
/container add name=guardian remote-image=marteva/routeros-guardian:latest interface=veth-guardian root-dir=/usb1/guardian/root envlists=guardian mountlists=guardian-data start-on-boot=yes logging=yes workdir=/
```

*B) Upload the release tarball* (verified): download
`routeros-guardian-arm64.tar` (or `-arm` / `-amd64`) from the
[latest release](https://github.com/Marteva/routeros-guardian/releases/latest),
upload it to `usb1` (Winbox → Files, or `scp`), then:

```routeros
/container add name=guardian file=/usb1/routeros-guardian-arm64.tar interface=veth-guardian root-dir=/usb1/guardian/root envlists=guardian mountlists=guardian-data start-on-boot=yes logging=yes workdir=/
```

**5. Start it** once `/container print` shows it stopped (extraction takes a
moment):

```routeros
/container start [find where name=guardian]
/log print where topics~"container"
```

**6. Open the UI** at `http://192.168.88.250:8080`, set up notifications in
**Settings**, and add the [GeoIP databases](docs/routeros-setup.md#10-geoip-databases)
for country/ASN alerts. Then let it learn for a week.

## Try it without a router

Want to see Guardian before installing it? [`tools/demo`](tools/demo) seeds a
database with a **fictional household** (18 devices, a week of traffic and a
few alerts raised by the real detection engine) and serves a fake RouterOS
REST API for it. Guardian then runs on your PC - no router, no Docker:

```sh
go run ./tools/demo -reset     # terminal 1: seeds demo.db, fake router on 127.0.0.1:18728
```

It prints the exact command for a second terminal (PowerShell and bash
variants), essentially:

```sh
GUARDIAN_ROS_URL=http://127.0.0.1:18728 GUARDIAN_ROS_PASS=demo GUARDIAN_DB=demo.db \
GUARDIAN_LAN=192.168.88.0/24 GUARDIAN_LISTEN=127.0.0.1:8080 go run ./cmd/guardian
```

Then open `http://127.0.0.1:8080`. The story: the garden camera started
talking to a new country and uploaded 2.8 GB in the last hour, the robot
vacuum contacted 240 internet addresses last night, an unidentified ESP
device joined two hours ago and a guest tablet yesterday. Live traffic keeps
flowing and quarantine works against the fake router. All names, addresses
and MAC addresses are made up. Without `-reset` an existing demo database is
reused; `-reset` re-seeds it relative to the current time (stop Guardian
first; it refuses to delete a database the tool did not create). With the
[GeoIP files](docs/routeros-setup.md#10-geoip-databases) in `dist/geo` the
printed command includes them, so live traffic gets countries and ASNs too.

## Configuration

Guardian reads environment variables at startup (set with
`/container envs`). The most important ones:

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_ROS_URL` | `http://172.17.0.1` | RouterOS REST API base URL, e.g. `http://192.168.88.1` |
| `GUARDIAN_ROS_USER` | `guardian` | API user |
| `GUARDIAN_ROS_PASS` | - (**required**) | API password |
| `GUARDIAN_ROS_INSECURE_TLS` | `true` | accept a self-signed `www-ssl` certificate |
| `GUARDIAN_POLL_INTERVAL` | `15s` | polling interval (min `5s`) |
| `GUARDIAN_LAN` | `192.168.88.0/24` | LAN prefixes, comma separated |
| `GUARDIAN_DB` | `/data/guardian.db` | SQLite database |
| `GUARDIAN_GEOIP_COUNTRY` / `GUARDIAN_GEOIP_ASN` | `/data/geo/country.mmdb` / `/data/geo/asn.mmdb` | DB-IP Lite databases (optional) |
| `GUARDIAN_LISTEN` | `:8080` | web UI address |
| `GUARDIAN_WEB_USER` / `GUARDIAN_WEB_PASS` | - | UI login (HTTP Basic); empty = no login |
| `GUARDIAN_QUARANTINE_LIST` | `guardian-quarantine` | firewall address list for quarantine |
| `GUARDIAN_BACKUP` / `GUARDIAN_BACKUP_INTERVAL` | - / `1h` | optional database snapshot path and interval |
| `GUARDIAN_LEARN_PERIOD` * | `7d` | learning period |
| `GUARDIAN_RETENTION` * | `60d` | how long statistics are kept |
| `GUARDIAN_DEDUP_WINDOW` * | `6h` | identical alerts are sent once per window |
| `GUARDIAN_LANGUAGE` * | – (English) | notification language: en, cs, de, pl, ru, es, pt (empty = English; the UI, alerts included, has its own language switch) |
| `GUARDIAN_TELEGRAM_TOKEN` / `GUARDIAN_TELEGRAM_CHAT` * | - | Telegram bot token and chat ID |
| `GUARDIAN_NTFY_URL` / `GUARDIAN_NTFY_TOKEN` * | - | ntfy topic URL and optional token |
| `TZ` | UTC | time zone, e.g. `Europe/Berlin` |

\* Also editable in the web UI (**Settings**). The environment variable is the
default; once saved in the UI, the stored value wins (later env changes are
ignored). Notification severity threshold, sensitivity and enabled detectors
are UI-only settings. Durations accept `15s`, `168h` or `7d`.

Full reference: **[docs/configuration.md](docs/configuration.md)**.

## Notifications

Configure them in the UI (**Settings**, then **Send test notification**) or
with environment variables. Setting tokens in the UI keeps them out of
`/container envs`, which every router user with the `read` policy can see.
By default only alerts of severity *warning* and above are pushed; set the
minimum to *info* to be notified about every new device.

### Telegram

1. In Telegram, open **@BotFather**, send `/newbot` and follow the prompts.
   You get a bot token like `123456789:AA...`.
2. Send any message to your new bot (or add it to a group and write there).
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser and find
   `"chat":{"id":...}`. Group chat IDs are negative numbers.
4. Enter the token and chat ID in **Settings** (or set
   `GUARDIAN_TELEGRAM_TOKEN` and `GUARDIAN_TELEGRAM_CHAT`).

### ntfy

1. Install the **ntfy** app (Android/iOS) - <https://ntfy.sh>.
2. Pick a **long random topic name** - anyone who knows it can read your
   alerts, e.g. `guardian-k7f3q9x2m1v8`.
3. Subscribe to the topic in the app.
4. Enter `https://ntfy.sh/guardian-k7f3q9x2m1v8` as the ntfy URL in
   **Settings** (or `GUARDIAN_NTFY_URL`). For a protected topic or your own
   server add an access token (`GUARDIAN_NTFY_TOKEN`).

Critical alerts are sent with high priority.

## Quarantine

The **Quarantine** button on a device:

1. adds the device's current IPv4 address to the address list
   `guardian-quarantine` on the router,
2. removes the device's existing entries from connection tracking (so
   already-established, fasttracked connections cannot continue).

What happens to the traffic is decided by **your firewall rules** (step 2 of
the quick start). The two forward-chain drop rules **must be placed before the
fasttrack rule** - fasttracked packets bypass the firewall, and with loose TCP
tracking even a mid-stream packet of an old connection is picked up again as
*established*.

| Blocked | Still works |
|---|---|
| internet access in both directions | traffic to devices in the same bridge (L2 - printer, casting, ...) |
| access to other routed subnets/VLANs | DHCP and DNS on the router (unless you add the optional input rules) |
| | IPv6 (the quarantine is IPv4 only) |

The entry is by IP address - if the device obtains a different address, the
quarantine no longer matches (a static DHCP lease helps). **Release** removes
the entry again. For complete isolation use a separate VLAN or guest Wi-Fi.
More details: [docs/routeros-setup.md](docs/routeros-setup.md#7-quarantine-firewall-rules).

## Security

- **Least-privilege API user.** The `guardian` group has only `read`,
  `write`, `api` and `rest-api`. `write` is needed for the quarantine address
  list and for removing connections, but it allows configuration changes in
  general - use a long random password and restrict the user's `address=` to
  the container IP.
- **Keep the REST API on the LAN.** Never expose `www`/`www-ssl` to the
  internet. With the container in the LAN bridge its API traffic stays inside
  the router; `www-ssl` (HTTPS) is supported too.
- **Protect the UI.** Set `GUARDIAN_WEB_USER` / `GUARDIAN_WEB_PASS`. Keep the
  UI reachable from the LAN only - no port forwarding; use a VPN (e.g.
  WireGuard on the router) for remote access. State-changing API calls
  require a custom header and same-origin requests (CSRF protection).
  `/healthz` is the only unauthenticated endpoint and reveals only ok/not ok.
- **Secrets.** `/container envs` values are readable by every router user
  with `read`. Prefer entering notification tokens in the UI; they are stored
  in Guardian's database and never sent back to the browser. Protect the
  disk (and backups) accordingly.
- **Container isolation.** The image is a static binary on a distroless base
  without a shell. It runs as root inside the container because RouterOS
  mounts on USB disks are usually owned by root (a non-root build is possible,
  see the [Dockerfile](Dockerfile)).

Found a vulnerability? Please report it privately - see [SECURITY.md](SECURITY.md).

## FAQ and troubleshooting

**Does it work with FastTrack enabled?**
Yes. Fasttracked connections skip the firewall, but connection-tracking byte
counters are still updated (verified on a hAP ax³ with ~95 % of connections
fasttracked), so traffic statistics stay accurate. With hardware offloading
(`hw-offload=yes` on switch chips that support L3 HW offload) counters of
offloaded connections may not be updated - run the probe (below) to check.

**The log shows `401` / `poll failed ... 401 Unauthorized`.**
Wrong password, the user's `address=` does not include the container IP, or
the group lacks the `rest-api` policy. Check `/user print detail` and
`/log print where message~"login failure"`. `connection refused` or a timeout
means the `www`/`www-ssl` service is disabled, uses another port than
`GUARDIAN_ROS_URL`, or its `address=` list excludes the container.

**What does the healthcheck do?**
`/healthz` returns `200 ok` while polling the router succeeds and `503` with a
short reason when the last successful poll is too old. The image runs
`/guardian -healthcheck` as its `HEALTHCHECK`; whether RouterOS acts on image
healthchecks is not verified - you can monitor `http://<container-ip>:8080/healthz`
yourself (e.g. with `/tool netwatch`).

**The container stops right after start.**
See `/log print where topics~"container"`. `GUARDIAN_ROS_PASS is required`
means the env list is not attached (`envlists=`) or the variable is missing.

**`/container add` fails to import the image.**
The tarball must match the router's architecture (`/system resource print`),
be fully uploaded, and the path in `file=` must be correct. Check
`/log print where topics~"container"`.

**`not allowed by device-mode`.**
The device-mode change was not confirmed physically within 5 minutes - repeat it.

**No country/ASN alerts.**
Either the GeoIP files are missing in `/data/geo/` (the log says `geoip disabled`) or the
learning period is still running.

**Notifications fail with `x509: certificate signed by unknown authority`.**
The image was built without a CA bundle (`--no-ca-cert`). Use a release image
or build with the CA bundle.

**Notifications time out.**
The container has no internet access or DNS: check the default gateway of the
veth, the masquerade rule and DNS on the router.

**The router's flash is full.**
`root-dir`, `tmpdir` or the tarball ended up on internal flash instead of the
disk.

**Feasibility probe.** `cmd/probe` connects to the REST API for a few hours
and reports connection-table size, fasttrack share, whether byte counters move
for fasttracked connections, traffic coverage, poll latency and router CPU
load - useful before installing on a busy network:

```sh
go run ./cmd/probe -url http://192.168.88.1 -user guardian -pass PASSWORD -duration 4h
```

(The user's `address=` must temporarily include your PC.) The binary is also
included in the image as `/probe`.

## Building from source

Requirements: Go (version from [`go.mod`](go.mod)), no CGO, no Docker needed.

```sh
go test ./...
scripts/build.sh --arch arm64 --version 0.3.1      # Linux/macOS
.\scripts\build.ps1 -Arch arm64 -Version 0.3.1     # Windows
```

Both scripts cross-compile `guardian` and `probe` and assemble
`dist/routeros-guardian-<arch>.tar` (a `docker save` style tarball with one
uncompressed layer, built by [`tools/mkimage`](tools/mkimage)) that RouterOS
imports with `/container add file=...`. With Docker:

```sh
docker buildx build --platform linux/arm64 -o type=docker,dest=routeros-guardian-arm64.tar -t routeros-guardian:latest .
```

Developer documentation: [ARCHITECTURE.md](ARCHITECTURE.md),
[CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- **DNS integration** with Pi-hole / AdGuard Home - domain names instead of
  bare IPs in alerts.
- **Behaviour drift detector** - slow long-term changes of a device's profile
  (week-over-week comparison).
- **Weekly summary** notification.
- **IPv6** - monitoring and quarantine.

Ideas and pull requests are welcome - please open an issue first for larger
changes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) - development setup, tests, code style
and how to add or improve translations.

## License and attributions

- Guardian for RouterOS is released under the [MIT License](LICENSE).
- IP Geolocation by [DB-IP](https://db-ip.com), licensed under
  [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/).
  The databases are not part of the repository or the image; they are
  downloaded by `scripts/update-geoip.*`.
- MAC vendor prefixes: a curated subset of the IEEE OUI registry.

*Not affiliated with or endorsed by MikroTik. MikroTik and RouterOS are
trademarks of SIA Mikrotīkls.*
