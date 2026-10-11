# Contributing to Guardian for RouterOS

Thanks for your interest! Bug reports, RouterOS compatibility notes,
translations and pull requests are all welcome. For larger changes please
open an issue first so we can agree on the approach.

## Development setup

- **Go** - the version in [`go.mod`](go.mod) or newer.
- **No CGO.** Everything is pure Go (`modernc.org/sqlite` is a cgo-free SQLite)
  and is built with `CGO_ENABLED=0`. Do not add dependencies that need cgo.
- No Docker and no router are needed for development and tests.

```sh
git clone https://github.com/Marteva/routeros-guardian.git
cd routeros-guardian
go test ./...
```

On Windows the same works in PowerShell; if `go` is not in `PATH`, use
`& "C:\Program Files\Go\bin\go.exe" test ./...`.

### Running locally against a router

Guardian can run on your PC and talk to a real router over the REST API (the
API user's `address=` must allow your PC):

```sh
export GUARDIAN_ROS_URL=http://192.168.88.1
export GUARDIAN_ROS_PASS='...'
export GUARDIAN_DB=./guardian.db
export GUARDIAN_GEOIP_COUNTRY=./dist/geo/country.mmdb
export GUARDIAN_GEOIP_ASN=./dist/geo/asn.mmdb
go run ./cmd/guardian
# UI: http://localhost:8080
```

(PowerShell: `$env:GUARDIAN_ROS_PASS = '...'` etc.) The database files
(`*.db*`) and GeoIP files (`*.mmdb`) are git-ignored.

No router at hand? `go run ./tools/demo -reset` seeds a database with a
fictional household and serves a fake RouterOS REST API, then prints the
Guardian command to run against it - handy for UI work and screenshots
without personal data (see [README](README.md#try-it-without-a-router)).

The feasibility probe (`go run ./cmd/probe -h`) is handy for checking a
router's connection table and REST performance.

### Building images

- `scripts/build.sh` (Linux/macOS) or `scripts/build.ps1` (Windows) -
  cross-compile and assemble a RouterOS-importable tarball in `dist/`
  without Docker (see [README](README.md#building-from-source)).
- `Dockerfile` - multi-arch image (`linux/arm64`, `linux/arm/v7`,
  `linux/amd64`), used by the release workflow for GHCR.

## Before you open a pull request

```sh
gofmt -l .        # must print nothing
go vet ./...
go test ./...
```

CI runs the same checks and cross-builds all three architectures.
(`-race` is not used: the race detector needs cgo.)

## Code style and conventions

- Standard `gofmt` formatting; idiomatic, simple Go. Stdlib first - the only
  third-party runtime dependencies are `modernc.org/sqlite` and
  `github.com/oschwald/maxminddb-golang`. Discuss before adding new ones.
- `log/slog` for logging, `context.Context` everywhere, no global mutable state.
- Every package has unit tests; tests must not use the network (use
  `net/http/httptest`) and must pass on Windows, Linux and macOS.
- Code and comments in English. User-visible texts go through the
  translation catalogs (below), never hard-coded.
- Keep the router in mind: Guardian runs on small devices (target < 50 MB
  RSS) and must not add noticeable CPU load to the router - avoid extra REST
  calls per poll and use `.proplist` to limit fields.
- Detection changes should favour precision over recall; see
  [`internal/detect/DESIGN.md`](internal/detect/DESIGN.md).
- Shared types and interfaces live in `internal/model`; the package layout is
  described in [ARCHITECTURE.md](ARCHITECTURE.md).
- **No personal data** in code, tests, fixtures or screenshots: use RouterOS
  default addresses (`192.168.88.0/24`), documentation MACs
  (`02:00:00:...`, `AA:BB:CC:...`) and made-up device names.

## Translations

Guardian supports English (`en`), Czech (`cs`), German (`de`), Spanish (`es`),
Indonesian (`id`), Italian (`it`), Polish (`pl`), Brazilian Portuguese (`pt`),
Turkish (`tr`) and Ukrainian (`uk`). There are two catalogs:

| What | Where |
|---|---|
| Web UI texts | [`internal/web/static/i18n.js`](internal/web/static/i18n.js) |
| Alert titles/details and notifications (server side) | [`internal/i18n`](internal/i18n) - `i18n.T(lang, key, args...)`; packages add their texts with `i18n.Register(lang, entries)` from an `init` function |

English is the fallback for missing keys. To improve a translation, edit the
entries for your language in both places. To add a new language, add it to
both catalogs, to `settings.Languages` in
[`internal/settings/settings.go`](internal/settings/settings.go), to `LANGS`,
`LANG_NAMES` and `FLAGS` (inline SVG flag for the language picker) in
[`internal/web/static/app.js`](internal/web/static/app.js), and mention it in
the README. Languages that inflect nouns after numbers also need a rule in
`pluralForm` ([`internal/detect/format.go`](internal/detect/format.go)).
The tests check that every language has every key with the same placeholders.

**Native speakers wanted.** English and Czech are written by the maintainer;
the other translations were machine-assisted and have not been fully reviewed
yet. If you speak German, Spanish, Indonesian, Italian, Polish, Brazilian
Portuguese, Turkish or Ukrainian, corrections are very welcome - a pull
request or an issue listing the wrong texts is enough. Please keep short UI
labels short (the UI must fit on a 320 px wide phone) and keep the
placeholders (`{name}`, `%s`, …) unchanged.

## Documentation

- English is the main language: [`README.md`](README.md) and [`docs/`](docs).
- [`README.cs.md`](README.cs.md) is a Czech translation of the README - please
  keep it in sync when you change the README (or mention it in the PR and
  someone will help).
- RouterOS commands: say which RouterOS version you tested them on. Untested
  commands are marked *unverified* in the docs.
- Add a line to [`CHANGELOG.md`](CHANGELOG.md) under *Unreleased*.

## Reporting bugs

Use the bug report template and include the RouterOS version, router model,
Guardian version and relevant log lines. **Remove passwords, tokens and
personal data** (public IPs, MAC addresses, device names) before posting.
Security issues: see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the
[MIT License](LICENSE).
