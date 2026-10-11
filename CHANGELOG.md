# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions before 0.3.1 were internal (not publicly released), so they have no
release dates or tags.

## [Unreleased]

## [0.3.3] - 2026-10-11

### Added

- **Indonesian, Italian, Turkish and Ukrainian** translations of the UI,
  alerts and notifications - Guardian now speaks 10 languages. Ukrainian
  counted nouns use their own plural rules (1 / 2-4 / 5+). The new
  translations are machine-assisted; corrections from native speakers are
  welcome (see CONTRIBUTING.md).

### Changed

- **Language picker with flags.** The language drop-down in the header is now
  a compact flag button; it opens a list with the flag and native name of
  every language (keyboard and screen-reader friendly, works on phones).
  Flags are inline SVG, so they also show on Windows.
- **Portuguese is now Brazilian Portuguese** (vocabulary and spelling, "você");
  the language code stays `pt` and it is shown as "Português (Brasil)".
- An unsupported `GUARDIAN_LANGUAGE` value now falls back to English with a
  warning in the log instead of blocking every change in Settings.

### Removed

- **Russian translation.** A saved Russian notification language switches to
  English on upgrade - the other saved settings (Telegram, ntfy, …) are kept -
  and a browser that had Russian selected falls back to the notification
  language, then the browser language, then English.

### Documentation

- Pulling from GHCR (`remote-image=ghcr.io/marteva/routeros-guardian:latest`),
  updating with Repull and the image healthcheck are verified on RouterOS
  7.24.4; the full image name no longer requires changing `registry-url`.

## [0.3.2] - 2026-10-11

### Fixed

- **Alert texts follow the UI language.** The web UI showed alert titles and
  details in the notification language that was set when the alert was raised
  (English by default), and the language switch in the header did not change
  them. Alerts are now rendered in the UI language, including alerts stored
  before the update (as long as their device is still known); Telegram/ntfy
  messages keep using the language from Settings. `GET /api/alerts` and
  `GET /api/devices/{mac}` accept `?lang=xx` for this. A device renamed or
  re-typed later is shown under its current name in old alerts too.
- **Mobile layout.** On phones the device search field stretched past the
  screen edge (horizontal scrolling). The Devices header now wraps: the
  Expand all / Merge buttons on one row and the search field on its own row
  at full width, also with long translations and in merge mode. Alert cards
  put the Acknowledge button below the text (which keeps the full width) and
  wrap long device names, the merge bar stacks its buttons, and the device
  and settings sheets use slightly smaller padding.

## [0.3.1] - 2026-10-09

First public release.

### Added

- **Settings page in the web UI**: Telegram/ntfy, minimum severity to notify,
  language, learning period, sensitivity (low/normal/high), enabling and
  disabling individual detectors, deduplication window and retention.
  Changes apply without a restart; secrets are never sent back to the browser.
- **Test notification** button.
- **Internationalisation**: UI, alerts and notifications in 7 languages -
  English, Czech, German, Polish, Russian, Spanish, Portuguese
  (`GUARDIAN_LANGUAGE` sets the default).
- **Device kind override** - correct a wrongly guessed device type; the kind
  selects the detection profile.
- **Manual merge** of devices that appear under several (randomized) MAC
  addresses, and unmerge.
- **Expand all / Collapse all** button to show every MAC address of grouped
  devices at once (remembered per browser).
- **Light/dark theme toggle.**
- **Data reset** from the UI: learned data only, or everything including the
  device list; learning restarts.
- **Configurable learning period** (environment default, editable in the UI).
- Multi-arch container image `ghcr.io/marteva/routeros-guardian`
  (`linux/arm64`, `linux/arm/v7`, `linux/amd64`).
- Release tarballs for RouterOS (`routeros-guardian-<arch>.tar`) with SHA-256
  checksums; 32-bit ARM (`arm`) and `amd64` builds.
- `scripts/build.sh` and `scripts/update-geoip.sh` for Linux/macOS.
- Generic, parameterised RouterOS setup script `deploy/routeros-setup.rsc`
  and step-by-step docs (`docs/routeros-setup.md`, `docs/configuration.md`).
- CI (gofmt, vet, tests, cross-builds), release workflow, Dependabot.
- **Demo without a router** (`go run ./tools/demo`): seeds a database with a
  fictional household and serves a fake RouterOS REST API for it (also used
  for the README screenshots).

### Changed

- **Renamed to "Guardian for RouterOS"**; Go module
  `github.com/Marteva/routeros-guardian`. Build outputs are now
  `routeros-guardian-<arch>.tar` (previously `guardian-<arch>.tar`).
- Environment variables are now defaults: values saved in the UI take
  precedence.
- Documentation is in English (`README.md`) with a Czech translation
  (`README.cs.md`).
- Released under the MIT License.

## [0.2.0]

### Added

- Container **healthcheck**: `GET /healthz` and `guardian -healthcheck`
  (image `HEALTHCHECK`).
- DHCP **lease comments** from the router shown in the device list.
- Device **grouping** and **sorting** in the UI.
- **GeoIP** with the DB-IP Lite country and ASN databases
  (`scripts/update-geoip.ps1`).
- **Telegram** notifications.
- Existing connections of a device are removed from connection tracking when
  it is quarantined (fasttracked connections bypass the firewall).

## [0.1.0]

### Added

- Initial MVP: Go service running as a RouterOS container, polling the REST
  API (DHCP leases, ARP, connection tracking).
- Device inventory with MAC vendor lookup, device type guess and randomized
  MAC detection.
- Learning period and per-device baselines; detectors `new_device`,
  `new_country`, `new_asn`, `upload_spike`, `dest_fanout`.
- ntfy notifications with deduplication.
- One-click quarantine via a firewall address list.
- Embedded web UI and JSON API with optional HTTP Basic auth and CSRF
  protection; SQLite storage with retention and optional snapshot backup.
- Feasibility probe (`cmd/probe`) and Docker-less image builder
  (`tools/mkimage`, `scripts/build.ps1`).
