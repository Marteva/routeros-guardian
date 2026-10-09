# RouterOS setup

Step-by-step installation of Guardian for RouterOS as a container on a MikroTik
router. The same steps are available as a parameterised script in
[`deploy/routeros-setup.rsc`](../deploy/routeros-setup.rsc) (network layout A).

> **What has been tested.** Commands marked **[verified]** were run on
> RouterOS **7.24.4** on a hAP ax³ (arm64). Commands marked **[unverified]**
> follow the MikroTik documentation or earlier RouterOS versions but have not
> been tested by the author on 7.24 - check them with the built-in help
> (type the command and press `?` or `Tab`) before relying on them.
> Corrections are very welcome (open an issue or PR).

All commands use the RouterOS 7 console syntax and can be pasted into
Winbox → New Terminal or an SSH session. Replace the example values
(`192.168.88.x`, `usb1`, passwords) with your own.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Enable containers (device-mode + package)](#2-enable-containers)
3. [Prepare a disk](#3-prepare-a-disk)
4. [API user with least privileges](#4-api-user-with-least-privileges)
5. [REST API service](#5-rest-api-service)
6. [Container network: two layouts](#6-container-network)
7. [Quarantine firewall rules](#7-quarantine-firewall-rules)
8. [Environment variables and data mount](#8-environment-variables-and-data-mount)
9. [Create and start the container](#9-create-and-start-the-container)
10. [GeoIP databases](#10-geoip-databases)
11. [Updating](#11-updating)
12. [Hardening checklist](#12-hardening-checklist)
13. [Uninstall](#13-uninstall)

---

## 1. Prerequisites

| | |
|---|---|
| RouterOS | **7.20 or newer** - the `list=` / `envlists=` / `mountlists=` syntax used here was introduced in 7.20. Tested on 7.24.4. |
| Architecture | `arm64`, `arm` (32-bit ARMv7) or `x86_64`. Check with `/system resource print` (`architecture-name`). MIPS/SMIPS/PowerPC/Tile routers cannot run containers. |
| Storage | ~20 MB for the extracted image (+ ~20 MB for the uploaded tarball) plus a database that grows to tens of MB. Use a USB/SATA/NVMe disk if the internal flash is small (the hAP ax³ has 128 MB flash). |
| RAM | Guardian aims for < 50 MB RSS. |
| Access | Admin access to the router (Winbox, WebFig terminal or SSH). |

Write down: the router's LAN IP (default `192.168.88.1`), the LAN subnet
(`192.168.88.0/24`), the name of the LAN bridge (defconf: `bridge`) and of the
interface list your firewall trusts (defconf: `LAN`).

## 2. Enable containers

### 2a. Device-mode  [unverified - standard MikroTik procedure]

Since RouterOS 7.x the container feature is disabled by *device-mode* and
enabling it needs physical confirmation:

```routeros
/system device-mode print
/system device-mode update container=yes
```

Within **5 minutes** confirm it physically - either briefly press the reset
button (do **not** hold it, holding resets the configuration) or power-cycle
the router (unplug and plug back the power). Without confirmation the change
is discarded. Afterwards `/system device-mode print` must show
`container: yes`. On some models/modes you may need
`/system device-mode update mode=advanced container=yes`.

### 2b. Container package  [unverified]

`container` is a separate package:

1. Download *Extra packages* for **your architecture and exactly your
   RouterOS version** from <https://mikrotik.com/download>.
2. Upload `container-<version>-<arch>.npk` to the router's **Files** root
   (Winbox → Files, drag & drop).
3. `/system reboot`
4. `/system package print` must list `container`.

## 3. Prepare a disk  [unverified]

> Formatting erases the disk.

```routeros
/disk print
/disk format usb1 file-system=ext4 label=guardian
# older 7.x versions: /disk format-drive usb1 file-system=ext4 label=guardian
/disk print
```

The disk appears as `usb1` (see the slot/mount-point column). Directories used
below (`/usb1/guardian/root`, `/usb1/guardian/data`) are created by RouterOS
automatically **[verified]**.

## 4. API user with least privileges

Guardian needs:

| Policy | Why |
|---|---|
| `read` | DHCP leases, ARP, connection tracking, `/system/resource` |
| `write` | add/remove address-list entries (quarantine) and remove a quarantined device's connections |
| `rest-api` | log in over the REST API |
| `api` | kept for compatibility with older 7.x versions; you can try removing it |

Everything else is denied. `write` allows configuration changes in general,
so use a long random password and restrict the user's source address to the
container IP.

**[verified]**

```routeros
/user group add name=guardian policy="read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon"
/user add name=guardian group=guardian address=192.168.88.250/32 password="LONG-RANDOM-PASSWORD"
```

`address=` is the container's IP (layout A; `172.17.0.2/32` for layout B). To
test the API or run the probe from your PC, temporarily use e.g.
`address=192.168.88.0/24` and narrow it again afterwards:

```routeros
/user set [find where name=guardian] address=192.168.88.250/32
```

Avoid `$`, `"`, `\` and `?` in the password - they need escaping in the
RouterOS console.

## 5. REST API service

The REST API is served by the `www` (HTTP) or `www-ssl` (HTTPS) service under
`/rest`.

### Option 1: `www` (HTTP)  [verified]

```routeros
/ip service set www disabled=no port=80
/ip service print where name~"www"
```

Any port works (the author's setup uses a custom port such as 81); set
`GUARDIAN_ROS_URL` accordingly, e.g. `http://192.168.88.1:81`. If the service
has an `address=` list, it must include the container's IP.

With layout A the container sits in the LAN bridge, so its requests to the
router never leave the router - plain HTTP is acceptable there. Do not expose
`www` to the internet.

### Option 2: `www-ssl` (HTTPS)  [unverified on 7.24]

```routeros
/certificate add name=guardian-rest common-name=router.lan subject-alt-name=IP:192.168.88.1 days-valid=3650 key-size=2048 key-usage=digital-signature,key-encipherment,tls-server
/certificate sign guardian-rest
/ip service set www-ssl certificate=guardian-rest disabled=no
```

Then use `GUARDIAN_ROS_URL=https://192.168.88.1` and keep
`GUARDIAN_ROS_INSECURE_TLS=true` (default) for the self-signed certificate.

### Test from a PC

Only works while the user's `address=` includes your PC:

```sh
curl -u guardian:PASSWORD http://192.168.88.1/rest/system/resource
# HTTPS with a self-signed certificate:
curl -k -u guardian:PASSWORD https://192.168.88.1/rest/system/resource
```

It must return JSON (`"cpu-load":"3", "board-name":...`). `401` = wrong
password, user `address=` or group policies; `connection refused` = service
disabled or wrong port.

## 6. Container network

Pick one layout.

| | **A: veth in the LAN bridge** (recommended, [verified]) | **B: separate container bridge + NAT** ([unverified]) |
|---|---|---|
| Container IP | a free LAN address, e.g. `192.168.88.250` | private subnet, e.g. `172.17.0.2` |
| REST API URL | `http://192.168.88.1` (router LAN IP) | `http://172.17.0.1` (router on the container bridge) |
| Web UI | `http://192.168.88.250:8080` directly from the LAN | `http://172.17.0.2:8080` (routed) or a dst-nat on the router IP |
| Internet access | existing LAN masquerade | extra masquerade rule |
| Firewall rules | none (veth joins the `LAN` interface list) | input accept for REST/DNS, forward drop container → LAN |
| Isolation | container is a normal LAN host | container cannot open connections into the LAN |

### Layout A - veth in the LAN bridge  [verified]

Choose an unused LAN address **outside the DHCP pool** and check it is free:

```routeros
/ip arp print where address=192.168.88.250
```

```routeros
/interface veth add name=veth-guardian address=192.168.88.250/24 gateway=192.168.88.1 dhcp=no comment="Guardian for RouterOS"
/interface bridge port add bridge=bridge interface=veth-guardian comment="Guardian for RouterOS"
/interface list member add interface=veth-guardian list=LAN comment="Guardian for RouterOS"
```

- The prefix length of `address=` must match your LAN (e.g. `/22` for a
  `10.0.0.0/22` network).
- `dhcp=no` keeps the static address; remove it if your version rejects the
  parameter.
- The `LAN` list membership lets the container through the defconf input
  rule *"drop all not coming from LAN"*, so it can reach the REST API and DNS.
- Guardian ignores its own address, so the container does not show up as a
  device.

### Layout B - separate container bridge with NAT  [unverified on 7.24]

This is the classic layout from the MikroTik container documentation.

```routeros
/interface bridge add name=containers
/ip address add address=172.17.0.1/24 interface=containers
/interface veth add name=veth-guardian address=172.17.0.2/24 gateway=172.17.0.1
/interface bridge port add bridge=containers interface=veth-guardian

# internet access for the container
/ip firewall nat add chain=srcnat action=masquerade src-address=172.17.0.0/24 out-interface-list=WAN comment="guardian: container egress"

# the "containers" bridge is not in the LAN list -> allow REST + DNS explicitly,
# placed before the defconf input drop
/ip firewall filter add chain=input action=accept protocol=tcp src-address=172.17.0.2 dst-port=80 comment="guardian: container -> REST API" place-before=[find where comment="defconf: drop all not coming from LAN"]
/ip firewall filter add chain=input action=accept protocol=udp src-address=172.17.0.2 dst-port=53 comment="guardian: container -> DNS" place-before=[find where comment="defconf: drop all not coming from LAN"]

# the container must not open connections into the LAN
/ip firewall filter add chain=forward action=drop src-address=172.17.0.0/24 dst-address=192.168.88.0/24 connection-state=new comment="guardian: container -/-> LAN"
```

Optional - publish the UI on the router's LAN IP (`http://192.168.88.1:8080`):

```routeros
/ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-address=192.168.88.1 dst-port=8080 in-interface-list=LAN to-addresses=172.17.0.2 to-ports=8080 comment="guardian: UI on router IP"
```

With layout B use `GUARDIAN_ROS_URL=http://172.17.0.1` (port of your `www`
service), user `address=172.17.0.2/32`, and add `dns=172.17.0.1` to
`/container add` if name resolution does not work.

## 7. Quarantine firewall rules

The **Quarantine** button in the UI adds the device's IPv4 address to the
address list `guardian-quarantine` (configurable with
`GUARDIAN_QUARANTINE_LIST`) and removes the device's existing connections from
connection tracking. Your firewall decides what that means; these two rules
cut the device off from the internet and other routed subnets.

**The rules must be placed before the fasttrack rule** (and before
*accept established,related*). Fasttracked packets bypass the firewall, and
with loose TCP tracking even a mid-stream packet of an old connection is
picked up again as *established* - a drop placed after fasttrack would not
stop it.

**[verified]** (placement by the comment of the defconf fasttrack rule):

```routeros
/ip firewall filter add chain=forward action=drop src-address-list=guardian-quarantine comment="guardian: quarantine (src)" place-before=[find where comment="defconf: fasttrack"]
/ip firewall filter add chain=forward action=drop dst-address-list=guardian-quarantine comment="guardian: quarantine (dst)" place-before=[find where comment="defconf: fasttrack"]
/ip firewall filter print where chain=forward
```

If your fasttrack rule has a different comment, use that comment, or place
the rules at the very top of the forward chain (Winbox → IP → Firewall, drag
them up).

**What a quarantined device can still do**

- Talk to devices in the **same bridge** (L2 traffic is not filtered unless
  the bridge has `use-ip-firewall=yes`) - printers, casting etc. keep working,
  and you can still find and fix the device.
- Talk to the **router itself** (DHCP, DNS, WebFig if allowed from the LAN).
  Optional rules that leave only DHCP and DNS **[unverified]**:

  ```routeros
  /ip firewall filter add chain=input action=accept protocol=udp src-address-list=guardian-quarantine dst-port=53,67 comment="guardian: quarantine dhcp/dns" place-before=[:pick [find where chain=input dynamic=no] 0]
  /ip firewall filter add chain=input action=drop src-address-list=guardian-quarantine comment="guardian: quarantine (router)" place-before=[:pick [find where chain=input dynamic=no comment!="guardian: quarantine dhcp/dns"] 0]
  ```

- Use **IPv6** - the quarantine is IPv4 only. If your ISP provides IPv6, add
  equivalent rules in `/ipv6 firewall filter` or disable IPv6 for that device.
- Get a **different IPv4 address** - the address list contains the IP, not the
  MAC. A static DHCP lease for important devices avoids surprises.

For complete isolation put untrusted devices into a separate VLAN / guest
Wi-Fi.

Manual quarantine and release (Guardian does the same over REST):

```routeros
/ip firewall address-list add list=guardian-quarantine address=192.168.88.50 comment="manual"
/ip firewall address-list remove [find where list=guardian-quarantine address=192.168.88.50]
```

## 8. Environment variables and data mount

RouterOS 7.20+ groups variables and mounts into named lists. **[verified]**

```routeros
/container envs add list=guardian key=GUARDIAN_ROS_URL value="http://192.168.88.1"
/container envs add list=guardian key=GUARDIAN_ROS_USER value="guardian"
/container envs add list=guardian key=GUARDIAN_ROS_PASS value="LONG-RANDOM-PASSWORD"
/container envs add list=guardian key=GUARDIAN_LAN value="192.168.88.0/24"
/container envs add list=guardian key=GUARDIAN_WEB_USER value="admin"
/container envs add list=guardian key=GUARDIAN_WEB_PASS value="UI-PASSWORD"
/container envs add list=guardian key=TZ value="Europe/Berlin"

/container mounts add list=guardian-data src=/usb1/guardian/data dst=/data
```

- All variables: [configuration.md](configuration.md). Notification tokens,
  language, learning period, etc. can also be set later in the web UI
  (**Settings**), which keeps the tokens out of `/container envs` - those are
  readable by every router user with the `read` policy.
- `/data` holds the SQLite database and `geo/` with the GeoIP files.
- Before 7.20 the syntax was different (`name=` instead of `list=`,
  `envlist=`/`mounts=` on the container); those versions are not supported.

## 9. Create and start the container

### Option A: pull from GitHub Container Registry  [unverified]

```routeros
/container config set registry-url=https://ghcr.io tmpdir=/usb1/guardian/tmp
/container add name=guardian remote-image=marteva/routeros-guardian:latest interface=veth-guardian root-dir=/usb1/guardian/root envlists=guardian mountlists=guardian-data start-on-boot=yes logging=yes workdir=/
```

- `registry-url` is a **global** setting - it also applies to pulls of your
  other containers (switch it back to `https://registry-1.docker.io` for
  Docker Hub images).
- `tmpdir` on the disk keeps the download off the small internal flash.
- The image is multi-arch; RouterOS should pick the right architecture.
- The router needs working DNS and internet access.
- If the pull fails, use option B - it does not depend on the registry.

### Option B: release tarball  [verified]

1. Download `routeros-guardian-<arch>.tar` from the
   [latest release](https://github.com/Marteva/routeros-guardian/releases/latest)
   (`arm64`, `arm` for 32-bit ARMv7, `amd64` for x86_64) and verify it against
   `SHA256SUMS.txt` - or build it yourself with `scripts/build.ps1` /
   `scripts/build.sh`.
2. Upload it to the disk root: Winbox → Files → drag & drop into `usb1`, or
   `scp routeros-guardian-arm64.tar admin@192.168.88.1:/usb1/`.
3. Create the container:

```routeros
/container add name=guardian file=/usb1/routeros-guardian-arm64.tar interface=veth-guardian root-dir=/usb1/guardian/root envlists=guardian mountlists=guardian-data start-on-boot=yes logging=yes workdir=/
```

### Start

Extraction takes from a few seconds to a minute. When `/container print`
shows the container as stopped, start it **[verified]**:

```routeros
/container print
/container start [find where name=guardian]
/log print where topics~"container"
```

Open the web UI at `http://192.168.88.250:8080` (layout A). A healthy start
logs `web listening` and no `poll failed` lines. Optional memory cap
**[unverified]**: add `memory-high=128M` to `/container add`.

## 10. GeoIP databases

Without them the *new country* and *new ASN* detectors are inactive (everything
else works). Download the free DB-IP Lite databases on a PC:

```sh
scripts/update-geoip.sh            # Linux/macOS -> dist/geo/
.\scripts\update-geoip.ps1         # Windows    -> dist\geo\
```

Upload `country.mmdb` and `asn.mmdb` to `/usb1/guardian/data/geo/` (Winbox →
Files, or `scp dist/geo/*.mmdb admin@192.168.88.1:/usb1/guardian/data/geo/`)
and restart the container:

```routeros
/container stop [find where name=guardian]
/container start [find where name=guardian]
```

DB-IP publishes new versions monthly; updating once a month is plenty.
IP Geolocation by [DB-IP](https://db-ip.com), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

## 11. Updating

A restart does **not** pick up a new image - the container has to be
re-created **[verified]**. Data in `/usb1/guardian/data` is kept.

```routeros
/container stop [find where name=guardian]
/container remove [find where name=guardian]
# option B: upload the new tarball first; then run the /container add command
# from section 9 again (option A pulls the current :latest image)
/container start [find where name=guardian]
```

To pin a version with option A use a version tag instead of `latest`, e.g.
`remote-image=marteva/routeros-guardian:0.3.0`.

## 12. Hardening checklist

- [ ] API user `address=` is the container's IP only (`/32`).
- [ ] UI login set (`GUARDIAN_WEB_USER` / `GUARDIAN_WEB_PASS`).
- [ ] UI and REST API reachable from the LAN only - no dst-nat from WAN.
- [ ] Notification tokens set in the UI rather than in `/container envs`.
- [ ] Quarantine rules sit above the fasttrack rule.
- [ ] Container root and data on the external disk, not on internal flash.

## 13. Uninstall

```routeros
/container stop [find where name=guardian]
/container remove [find where name=guardian]
/container envs remove [find where list=guardian]
/container mounts remove [find where list=guardian-data]
/ip firewall filter remove [find where comment~"^guardian: "]
/ip firewall nat remove [find where comment~"^guardian: "]
/ip firewall address-list remove [find where list=guardian-quarantine]
/interface list member remove [find where interface=veth-guardian]
/interface bridge port remove [find where interface=veth-guardian]
/interface veth remove [find where name=veth-guardian]
/user remove [find where name=guardian]
/user group remove [find where name=guardian]
```

Then delete `/usb1/guardian` (contains the database) and the tarball in
Winbox → Files. Layout B: also remove the `containers` bridge and its IP
address. The container package can be removed with
`/system package uninstall container` + reboot; switching device-mode back
needs physical confirmation again.
