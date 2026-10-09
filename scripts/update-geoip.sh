#!/usr/bin/env bash
#
# Downloads the DB-IP Lite GeoIP databases (country + ASN, mmdb format) for
# Guardian. Bash equivalent of scripts/update-geoip.ps1 for Linux and macOS.
#
# DB-IP publishes free "Lite" databases once a month; the current month is
# tried first, then the previous one. Files are stored as country.mmdb and
# asn.mmdb in the output directory (default dist/geo).
#
# License: DB-IP Lite is licensed under CC BY 4.0 - attribution is required:
#   "IP Geolocation by DB-IP" (https://db-ip.com)
#
# Usage:
#   scripts/update-geoip.sh [--month YYYY-MM] [--out DIR] [--upload user@router[:/remote/dir/]]
#
# --upload copies both files with scp (default remote dir /usb1/guardian/data/geo/).
# Restart the container afterwards - Guardian loads the databases at startup.
set -euo pipefail

MONTH="$(date +%Y-%m)"
OUT_DIR=""
UPLOAD=""

while [ $# -gt 0 ]; do
	case "$1" in
	--month) MONTH="$2"; shift 2 ;;
	--out) OUT_DIR="$2"; shift 2 ;;
	--upload) UPLOAD="$2"; shift 2 ;;
	-h | --help) sed -n '2,18p' "$0"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -n "$OUT_DIR" ] || OUT_DIR="$ROOT/dist/geo"
mkdir -p "$OUT_DIR"

prev_month() {
	local y m
	y="${1%-*}"
	m="${1#*-}"
	m=$((10#$m - 1))
	if [ "$m" -eq 0 ]; then
		m=12
		y=$((y - 1))
	fi
	printf '%04d-%02d' "$y" "$m"
}

fetch() { # kind target
	local kind="$1" target="$2" m url
	for m in "$MONTH" "$(prev_month "$MONTH")"; do
		url="https://download.db-ip.com/free/dbip-$kind-lite-$m.mmdb.gz"
		echo "Downloading $url"
		if curl -fsSL "$url" -o "$target.gz.tmp"; then
			gunzip -c "$target.gz.tmp" >"$target.tmp"
			mv -f "$target.tmp" "$target"
			rm -f "$target.gz.tmp"
			echo "  -> $target ($(du -h "$target" | cut -f1), release $m)"
			return 0
		fi
		echo "  not available ($m)" >&2
		rm -f "$target.gz.tmp"
	done
	echo "Could not download DB-IP $kind" >&2
	return 1
}

fetch country "$OUT_DIR/country.mmdb"
fetch asn "$OUT_DIR/asn.mmdb"

echo
echo "GeoIP: IP Geolocation by DB-IP (https://db-ip.com), license CC BY 4.0"

if [ -n "$UPLOAD" ]; then
	dest="$UPLOAD"
	case "$dest" in *:*) ;; *) dest="$dest:/usb1/guardian/data/geo/" ;; esac
	echo "Uploading to $dest"
	scp "$OUT_DIR/country.mmdb" "$OUT_DIR/asn.mmdb" "$dest"
	echo "Done. Restart the container: /container stop [find name=guardian] ; /container start [find name=guardian]"
else
	echo "Upload the files to the router into the container's data mount, sub-directory geo/"
	echo "(e.g. usb1/guardian/data/geo/), then restart the container."
fi
