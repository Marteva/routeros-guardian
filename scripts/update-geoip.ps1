<#
.SYNOPSIS
  Downloads the DB-IP Lite GeoIP databases (country + ASN, mmdb format) for Guardian.

.DESCRIPTION
  DB-IP publishes free "Lite" databases once a month:
    https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz
    https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.mmdb.gz
  The script downloads the current month (falls back to the previous month if
  the current one is not published yet), unpacks the .gz files and stores them
  as country.mmdb and asn.mmdb in -OutDir (default dist\geo).

  License: DB-IP Lite is licensed under CC BY 4.0 - attribution is required:
    "IP Geolocation by DB-IP" (https://db-ip.com)

  Uploading to the router (target = the container's data mount; inside the
  container it is /data/geo/):
    a) Winbox > Files > open usb1/guardian/data/geo and drag & drop both files
    b) scp (OpenSSH ships with Windows 10/11):
         scp dist\geo\country.mmdb dist\geo\asn.mmdb admin@192.168.88.1:/usb1/guardian/data/geo/
    c) -Upload runs scp for you (-RouterHost, -RouterUser, -RemoteDir)
  Then restart the container - Guardian loads the databases at startup.

  Linux/macOS: use scripts/update-geoip.sh.

.EXAMPLE
  .\scripts\update-geoip.ps1
.EXAMPLE
  .\scripts\update-geoip.ps1 -Month 2026-09 -Upload -RouterHost 192.168.88.1 -RouterUser admin
#>
[CmdletBinding()]
param(
    [string]$Month = (Get-Date -Format 'yyyy-MM'),
    [string]$OutDir = '',
    [switch]$Upload,
    [string]$RouterHost = '192.168.88.1',
    [string]$RouterUser = 'admin',
    [string]$RemoteDir = '/usb1/guardian/data/geo/'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $Root 'dist\geo' }
New-Item -ItemType Directory -Force $OutDir | Out-Null

function Expand-Gzip([string]$src, [string]$dst) {
    $in = [System.IO.File]::OpenRead($src)
    try {
        $gz = New-Object System.IO.Compression.GZipStream($in, [System.IO.Compression.CompressionMode]::Decompress)
        $out = [System.IO.File]::Create($dst)
        try { $gz.CopyTo($out) } finally { $out.Dispose(); $gz.Dispose() }
    } finally { $in.Dispose() }
}

function Get-DbIp([string]$kind, [string]$target) {
    # kind: country | asn
    $months = @($Month, ([datetime]::ParseExact($Month, 'yyyy-MM', $null).AddMonths(-1).ToString('yyyy-MM')))
    foreach ($m in $months) {
        $url = "https://download.db-ip.com/free/dbip-$kind-lite-$m.mmdb.gz"
        $gzPath = Join-Path $OutDir "dbip-$kind-lite-$m.mmdb.gz"
        try {
            Write-Host "Downloading $url"
            Invoke-WebRequest -Uri $url -OutFile $gzPath -UseBasicParsing
        } catch {
            Write-Warning "  not available ($m): $($_.Exception.Message)"
            continue
        }
        $tmp = "$target.tmp"
        Expand-Gzip $gzPath $tmp
        Move-Item -Force $tmp $target
        Remove-Item $gzPath
        $mb = [math]::Round((Get-Item $target).Length / 1MB, 1)
        Write-Host "  -> $target ($mb MB, release $m)"
        return
    }
    throw "Could not download DB-IP $kind (tried: $($months -join ', '))"
}

Get-DbIp 'country' (Join-Path $OutDir 'country.mmdb')
Get-DbIp 'asn' (Join-Path $OutDir 'asn.mmdb')

Write-Host ''
Write-Host 'GeoIP: IP Geolocation by DB-IP (https://db-ip.com), license CC BY 4.0'

if ($Upload) {
    if (-not (Get-Command scp -ErrorAction SilentlyContinue)) { throw 'scp not found (Windows: Settings > Optional features > OpenSSH Client)' }
    $dest = "$RouterUser@$RouterHost`:$RemoteDir"
    Write-Host "Uploading to $dest"
    & scp (Join-Path $OutDir 'country.mmdb') (Join-Path $OutDir 'asn.mmdb') $dest
    if ($LASTEXITCODE -ne 0) { throw 'scp failed' }
    Write-Host 'Done. Restart the container: /container stop [find name=guardian] ; /container start [find name=guardian]'
} else {
    Write-Host "Upload the files to the router into $RemoteDir (Winbox > Files, scp, or -Upload)."
}
