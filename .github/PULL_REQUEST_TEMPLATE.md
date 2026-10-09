## What and why

<!-- What does this PR change, and why? Link related issues (e.g. "Fixes #12"). -->

## How was it tested?

<!-- Unit tests, `go test ./...`, tested on a router (model + RouterOS version)? -->

## Checklist

- [ ] `gofmt -l .` prints nothing, `go vet ./...` and `go test ./...` pass
- [ ] Builds with `CGO_ENABLED=0`; no new third-party dependencies (or discussed first)
- [ ] New user-visible texts are added to the translation catalogs
      (`internal/web/static/i18n.js` for the UI, `internal/i18n` for alerts/notifications)
- [ ] Docs updated if behaviour, configuration or RouterOS setup changed
      (`README.md`, `README.cs.md`, `docs/`, `CHANGELOG.md`)
- [ ] No secrets, personal IP/MAC addresses or device names in code, tests or screenshots
