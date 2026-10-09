<#
.SYNOPSIS
  Builds Guardian for RouterOS (binaries + RouterOS image tarball) WITHOUT Docker.

.DESCRIPTION
  1) Cross-compiles ./cmd/guardian and ./cmd/probe for linux/<Arch> into
     dist\linux-<Arch>\ (CGO_ENABLED=0, -trimpath, tag timetzdata).
  2) Optionally builds probe.exe for Windows into dist\windows-amd64\ (to run
     the feasibility probe from a PC).
  3) Assembles an image tarball in `docker save` format with tools/mkimage:
     dist\routeros-guardian-<Arch>.tar. Upload it to the router and import it
     with /container add file=usb1/routeros-guardian-<Arch>.tar ...

  CA certificates: Guardian sends notifications over HTTPS (ntfy.sh,
  api.telegram.org), so the image needs /etc/ssl/certs/ca-certificates.crt.
  Windows has no such file; if tools\mkimage\cacert.pem is missing, the script
  offers to download the Mozilla CA bundle from https://curl.se/ca/cacert.pem.
  A custom bundle can be passed with -CaCert.

  Linux/macOS: use scripts/build.sh (same options).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\build.ps1
.EXAMPLE
  .\scripts\build.ps1 -Version 0.3.1 -DownloadCaCert
.EXAMPLE
  .\scripts\build.ps1 -Arch arm -Version 0.3.1      # 32-bit ARM (armv7)
.EXAMPLE
  .\scripts\build.ps1 -SkipImage -WindowsProbe       # binaries + probe.exe only
#>
[CmdletBinding()]
param(
    [ValidateSet('arm64', 'arm', 'amd64')]
    [string]$Arch = 'arm64',
    [string]$Version = '',
    [string]$Tag = 'routeros-guardian:latest',
    [string]$CaCert = '',
    [switch]$DownloadCaCert,   # download cacert.pem without asking
    [switch]$NoCaCert,         # build the image without CA certificates (HTTPS notifications will fail)
    [switch]$SkipImage,        # binaries only, no tarball
    [switch]$WindowsProbe,     # also build dist\windows-amd64\probe.exe
    [string]$User = ''         # empty = root (recommended for writing to USB disks), e.g. '65532:65532'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

# --- find go ----------------------------------------------------------------
$go = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $go) {
    $cand = 'C:\Program Files\Go\bin\go.exe'
    if (Test-Path $cand) { $go = $cand } else { throw 'Go not found (neither in PATH nor in C:\Program Files\Go\bin).' }
}
Write-Host "Go: $go ($(& $go version))"

# --- version ----------------------------------------------------------------
$Revision = ''
if (Get-Command git -ErrorAction SilentlyContinue) {
    $r = (& git rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $r) { $Revision = $r.Trim() }
}
if (-not $Version) {
    $Version = 'dev-' + (Get-Date -Format 'yyyyMMdd-HHmm')
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $d = (& git describe --tags --always --dirty 2>$null)
        if ($LASTEXITCODE -eq 0 -and $d) { $Version = $d.Trim() }
    }
}
Write-Host "Version: $Version"

$ldflags = "-s -w -X main.version=$Version"
$outDir = Join-Path $Root "dist\linux-$Arch"
New-Item -ItemType Directory -Force $outDir | Out-Null

function Invoke-GoBuild([string]$goos, [string]$goarch, [string]$out, [string]$pkg) {
    $saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED; GOARM = $env:GOARM }
    try {
        $env:GOOS = $goos; $env:GOARCH = $goarch; $env:CGO_ENABLED = '0'
        if ($goarch -eq 'arm') { $env:GOARM = '7' }
        Write-Host "  go build $pkg -> $out ($goos/$goarch)"
        & $go build -trimpath -tags timetzdata -ldflags $ldflags -o $out $pkg
        if ($LASTEXITCODE -ne 0) { throw "go build $pkg failed" }
    } finally {
        foreach ($k in $saved.Keys) {
            if ($null -eq $saved[$k]) { Remove-Item "env:$k" -ErrorAction SilentlyContinue }
            else { Set-Item "env:$k" -Value $saved[$k] }
        }
    }
}

Write-Host "`n[1/3] Compiling linux/$Arch"
Invoke-GoBuild 'linux' $Arch (Join-Path $outDir 'guardian') './cmd/guardian'
Invoke-GoBuild 'linux' $Arch (Join-Path $outDir 'probe') './cmd/probe'

if ($WindowsProbe) {
    Write-Host "`n[1b] probe.exe for Windows"
    $winDir = Join-Path $Root 'dist\windows-amd64'
    New-Item -ItemType Directory -Force $winDir | Out-Null
    Invoke-GoBuild 'windows' 'amd64' (Join-Path $winDir 'probe.exe') './cmd/probe'
}

if ($SkipImage) { Write-Host "`nDone (no image)."; exit 0 }

# --- CA bundle --------------------------------------------------------------
Write-Host "`n[2/3] CA certificates"
$caArgs = @()
if (-not $NoCaCert) {
    if (-not $CaCert) { $CaCert = Join-Path $Root 'tools\mkimage\cacert.pem' }
    if (-not (Test-Path $CaCert)) {
        Write-Host "  $CaCert is missing."
        Write-Host '  Guardian needs it for HTTPS notifications (ntfy.sh, Telegram).'
        Write-Host '  Source: https://curl.se/ca/cacert.pem (Mozilla CA bundle, ~230 kB).'
        $ok = $DownloadCaCert
        if (-not $ok) { $ok = (Read-Host '  Download it now? [y/N]') -match '^(y|yes)$' }
        if ($ok) {
            Invoke-WebRequest -Uri 'https://curl.se/ca/cacert.pem' -OutFile $CaCert -UseBasicParsing
            Write-Host "  Downloaded: $CaCert"
        }
    }
    if (Test-Path $CaCert) {
        $caArgs = @('-file', "/etc/ssl/certs/ca-certificates.crt=$CaCert")
    } else {
        Write-Warning 'The image will have NO CA certificates - HTTPS notifications will not work.'
    }
}

# --- image tarball ----------------------------------------------------------
Write-Host "`n[3/3] Building image tarball (docker save format, uncompressed layer)"
$tarPath = Join-Path $Root "dist\routeros-guardian-$Arch.tar"
$mkArgs = @(
    'run', './tools/mkimage',
    '-out', $tarPath,
    '-tag', $Tag,
    '-arch', $Arch,
    '-exec', "/guardian=$(Join-Path $outDir 'guardian')",
    '-exec', "/probe=$(Join-Path $outDir 'probe')",
    '-dir', '/data/geo',
    '-env', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    '-env', 'SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt',
    '-env', 'GUARDIAN_DB=/data/guardian.db',
    '-env', 'GUARDIAN_LISTEN=:8080',
    '-entrypoint', '/guardian',
    '-workdir', '/',
    '-expose', '8080/tcp',
    '-volume', '/data',
    '-healthcheck', '/guardian,-healthcheck',
    '-label', 'org.opencontainers.image.title=Guardian for RouterOS',
    '-label', 'org.opencontainers.image.description=Home network anomaly watchdog that runs as a container on MikroTik RouterOS',
    '-label', 'org.opencontainers.image.source=https://github.com/Marteva/routeros-guardian',
    '-label', 'org.opencontainers.image.licenses=MIT',
    '-label', "org.opencontainers.image.version=$Version"
) + $caArgs
if ($Revision) { $mkArgs += @('-label', "org.opencontainers.image.revision=$Revision") }
if ($User) { $mkArgs += @('-user', $User) }

# mkimage runs on the host (Windows), not on the target platform
$saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH }
Remove-Item env:GOOS, env:GOARCH -ErrorAction SilentlyContinue
try {
    & $go @mkArgs
    if ($LASTEXITCODE -ne 0) { throw 'mkimage failed' }
} finally {
    if ($saved.GOOS) { $env:GOOS = $saved.GOOS }
    if ($saved.GOARCH) { $env:GOARCH = $saved.GOARCH }
}

$size = [math]::Round((Get-Item $tarPath).Length / 1MB, 1)
$hash = (Get-FileHash $tarPath -Algorithm SHA256).Hash.ToLower()
Write-Host ''
Write-Host "Image: $tarPath ($size MB)"
Write-Host "SHA256: $hash"
Write-Host ''
Write-Host 'Next steps:'
Write-Host '  1) Upload the tarball to the router disk (Winbox > Files > drag & drop into usb1,'
Write-Host "     or: scp dist\routeros-guardian-$Arch.tar admin@192.168.88.1:/usb1/)"
Write-Host '  2) Continue with docs/routeros-setup.md (or deploy/routeros-setup.rsc).'
