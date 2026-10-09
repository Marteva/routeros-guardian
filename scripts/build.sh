#!/usr/bin/env bash
#
# Builds Guardian for RouterOS (binaries + RouterOS image tarball) WITHOUT Docker.
# Bash equivalent of scripts/build.ps1 for Linux and macOS (also used by CI).
#
#   1) cross-compiles ./cmd/guardian and ./cmd/probe for linux/<arch> into
#      dist/linux-<arch>/ (CGO_ENABLED=0, -trimpath, tag timetzdata)
#   2) assembles dist/routeros-guardian-<arch>.tar in `docker save` format with
#      tools/mkimage; import it on the router with
#      /container add file=usb1/routeros-guardian-<arch>.tar ...
#
# The image needs a CA bundle for HTTPS notifications (ntfy.sh, Telegram).
# Default: tools/mkimage/cacert.pem (downloaded from https://curl.se/ca/cacert.pem
# on request), or the host's bundle with --ca-cert /etc/ssl/certs/ca-certificates.crt.
#
# Examples:
#   scripts/build.sh
#   scripts/build.sh --arch arm --version 0.3.0 --download-ca-cert
#   scripts/build.sh --skip-image
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/build.sh [options]

  --arch ARCH          arm64 (default), arm (armv7) or amd64
  --version VERSION    version string (default: git describe, or dev-<timestamp>)
  --tag REPO:TAG       repo:tag stored in the tarball (default: routeros-guardian:latest)
  --ca-cert FILE       CA bundle to embed (default: tools/mkimage/cacert.pem)
  --download-ca-cert   download https://curl.se/ca/cacert.pem without asking if missing
  --no-ca-cert         build without CA certificates (HTTPS notifications will fail)
  --skip-image         build binaries only, no tarball
  --user UID:GID       run as this user (default: root; e.g. 65532:65532)
  -h, --help           show this help
EOF
}

ARCH=arm64
VERSION=""
TAG="routeros-guardian:latest"
CA_CERT=""
DOWNLOAD_CA=0
NO_CA=0
SKIP_IMAGE=0
RUN_USER=""

while [ $# -gt 0 ]; do
	case "$1" in
	--arch) ARCH="$2"; shift 2 ;;
	--version) VERSION="$2"; shift 2 ;;
	--tag) TAG="$2"; shift 2 ;;
	--ca-cert) CA_CERT="$2"; shift 2 ;;
	--download-ca-cert) DOWNLOAD_CA=1; shift ;;
	--no-ca-cert) NO_CA=1; shift ;;
	--skip-image) SKIP_IMAGE=1; shift ;;
	--user) RUN_USER="$2"; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

case "$ARCH" in
arm64 | arm | amd64) ;;
*) echo "unsupported --arch '$ARCH' (use arm64, arm or amd64)" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

command -v go >/dev/null 2>&1 || { echo "go not found in PATH" >&2; exit 1; }
echo "Go: $(command -v go) ($(go version))"

REVISION=""
if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
	REVISION="$(git rev-parse HEAD 2>/dev/null || true)"
fi
if [ -z "$VERSION" ]; then
	VERSION="$(git describe --tags --always --dirty 2>/dev/null || true)"
	[ -n "$VERSION" ] || VERSION="dev-$(date +%Y%m%d-%H%M)"
fi
echo "Version: $VERSION"

# Paths handed to Go tools are relative to $ROOT so they also work in Git Bash
# on Windows (native go.exe does not understand /c/... paths).
OUT_DIR="dist/linux-$ARCH"
mkdir -p "$OUT_DIR"
LDFLAGS="-s -w -X main.version=$VERSION"

goarm=""
[ "$ARCH" = "arm" ] && goarm=7

echo
echo "[1/3] Compiling linux/$ARCH"
for cmd in guardian probe; do
	echo "  go build ./cmd/$cmd -> $OUT_DIR/$cmd"
	CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" GOARM="$goarm" \
		go build -trimpath -tags timetzdata -ldflags "$LDFLAGS" -o "$OUT_DIR/$cmd" "./cmd/$cmd"
done

if [ "$SKIP_IMAGE" = 1 ]; then
	echo
	echo "Done (no image)."
	exit 0
fi

echo
echo "[2/3] CA certificates"
CA_ARGS=()
if [ "$NO_CA" = 0 ]; then
	[ -n "$CA_CERT" ] || CA_CERT="tools/mkimage/cacert.pem"
	if [ ! -f "$CA_CERT" ]; then
		echo "  $CA_CERT is missing."
		echo "  Guardian needs it for HTTPS notifications (ntfy.sh, Telegram)."
		echo "  Source: https://curl.se/ca/cacert.pem (Mozilla CA bundle, ~230 kB)."
		ok=$DOWNLOAD_CA
		if [ "$ok" = 0 ] && [ -t 0 ]; then
			read -r -p "  Download it now? [y/N] " answer
			case "$answer" in y | Y | yes | YES) ok=1 ;; esac
		fi
		if [ "$ok" = 1 ]; then
			curl -fsSL -o "$CA_CERT" https://curl.se/ca/cacert.pem
			echo "  Downloaded: $CA_CERT"
		fi
	fi
	if [ -f "$CA_CERT" ]; then
		CA_ARGS=(-file "/etc/ssl/certs/ca-certificates.crt=$CA_CERT")
	else
		echo "WARNING: the image will have NO CA certificates - HTTPS notifications will not work." >&2
	fi
fi

echo
echo "[3/3] Building image tarball (docker save format, uncompressed layer)"
TAR_PATH="dist/routeros-guardian-$ARCH.tar"
MK_ARGS=(
	-out "$TAR_PATH"
	-tag "$TAG"
	-arch "$ARCH"
	-exec "/guardian=$OUT_DIR/guardian"
	-exec "/probe=$OUT_DIR/probe"
	-dir /data/geo
	-env "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	-env "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
	-env "GUARDIAN_DB=/data/guardian.db"
	-env "GUARDIAN_LISTEN=:8080"
	-entrypoint /guardian
	-workdir /
	-expose 8080/tcp
	-volume /data
	-healthcheck "/guardian,-healthcheck"
	-label "org.opencontainers.image.title=Guardian for RouterOS"
	-label "org.opencontainers.image.description=Home network anomaly watchdog that runs as a container on MikroTik RouterOS"
	-label "org.opencontainers.image.source=https://github.com/Marteva/routeros-guardian"
	-label "org.opencontainers.image.licenses=MIT"
	-label "org.opencontainers.image.version=$VERSION"
)
[ -n "$REVISION" ] && MK_ARGS+=(-label "org.opencontainers.image.revision=$REVISION")
[ -n "$RUN_USER" ] && MK_ARGS+=(-user "$RUN_USER")
MK_ARGS+=("${CA_ARGS[@]+"${CA_ARGS[@]}"}")

# mkimage runs on the build host, not on the target platform.
# MSYS_NO_PATHCONV stops Git Bash on Windows from rewriting /guardian=... args.
env -u GOOS -u GOARCH -u GOARM MSYS_NO_PATHCONV=1 go run ./tools/mkimage "${MK_ARGS[@]}"

if command -v sha256sum >/dev/null 2>&1; then
	HASH="$(sha256sum "$TAR_PATH" | cut -d' ' -f1)"
else
	HASH="$(shasum -a 256 "$TAR_PATH" | cut -d' ' -f1)"
fi
SIZE="$(du -h "$TAR_PATH" | cut -f1)"
echo
echo "Image: $TAR_PATH ($SIZE)"
echo "SHA256: $HASH"
echo
echo "Next steps:"
echo "  1) Upload the tarball to the router disk (Winbox > Files > drag & drop into usb1,"
echo "     or: scp dist/routeros-guardian-$ARCH.tar admin@192.168.88.1:/usb1/)"
echo "  2) Continue with docs/routeros-setup.md (or deploy/routeros-setup.rsc)."
