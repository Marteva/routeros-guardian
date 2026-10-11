# =============================================================================
#  Guardian for RouterOS - router setup script (generic, parameterised)
#  https://github.com/Marteva/routeros-guardian
# =============================================================================
#
#  Network layout used here: the container gets its own IP address in your
#  LAN (veth port in the LAN bridge). It reaches the REST API on the router's
#  LAN IP, the web UI is at http://<container IP>:8080 and internet access
#  goes through your existing masquerade rule. For the alternative (separate
#  container bridge + NAT) see docs/routeros-setup.md.
#
#  What this script does (re-running it skips objects that already exist):
#    1. API group + user with least privileges (read,write,api,rest-api)
#    2. REST API: enables the "www" service on the chosen port
#    3. veth interface in the LAN bridge + member of the LAN interface list
#    4. Quarantine firewall rules, placed BEFORE the fasttrack rule
#    5. Container environment variables and data mount
#    6. The container itself (from a local tarball or from GHCR)
#    7. Removes the parameters (they contain passwords) from memory
#
#  What it does NOT do - do it first (see docs/routeros-setup.md):
#    - /system/device-mode/update container=yes (+ physical confirmation)
#    - install the "container" package matching your RouterOS version
#    - format and mount a USB disk (strongly recommended)
#    - upload the image tarball (only when grdImageSource = "file")
#
#  Requires RouterOS 7.20 or newer (/container envs and mounts use list=,
#  /container add uses envlists= and mountlists=). Every command used in
#  sections 1-6 was tested on RouterOS 7.24.4 (hAP ax3) unless the comment
#  above it says "VERIFY:" - those were not tested by the author.
#
#  HOW TO USE
#    1. Edit the PARAMETERS below in a text editor (at least the passwords
#       and the addresses). Avoid the characters $ " \ ? in passwords.
#    2. Either upload the edited file to the router (Winbox > Files) and run
#           /import file-name=routeros-setup.rsc verbose=yes
#       or paste it into a terminal (Winbox > New Terminal, or SSH) section
#       by section. Each section is one { } block; the parameters are
#       :global variables, so they survive between pastes.
#    3. Start the container (end of section 6) and open the web UI.
#    4. If the import stops early with an error, fix the cause and run it
#       again (existing objects are skipped). Section 7 removes the
#       parameters from memory; if it did not run, do it by hand:
#           /system script environment remove [find where name~"^grd"]
#
#  Comments are plain ASCII on purpose (the RouterOS terminal does not cope
#  well with UTF-8).
# =============================================================================


# =============================================================================
#  PARAMETERS - edit before running
# =============================================================================

# Name used for the container, the API user/group, the env list and as a
# prefix for the veth interface, mount list and directories on the disk.
:global grdName "guardian"

# Router IP in the LAN (container gateway, REST API address).
:global grdRouterIP "192.168.88.1"

# Free LAN address for the container - outside the DHCP pool!
# Check that it is unused:  /ip arp print where address=192.168.88.250
:global grdContainerIP "192.168.88.250"

# Prefix length of the LAN subnet (24 for 192.168.88.0/24).
:global grdPrefixLen "24"

# LAN bridge and the interface list your input chain trusts (defconf: "bridge", "LAN").
:global grdLanBridge "bridge"
:global grdLanList "LAN"

# LAN prefixes Guardian watches (GUARDIAN_LAN), comma separated.
:global grdLan "192.168.88.0/24"

# Port of the www service that serves the REST API (defconf: 80).
:global grdRestPort 80

# Password of the RouterOS API user (long and random!).
:global grdRosPass "CHANGE-ME-long-random-password"

# Web UI login (HTTP Basic auth). Empty user = UI without login (not recommended).
:global grdWebUser "admin"
:global grdWebPass "CHANGE-ME-ui-password"

# Time zone for logs and UI, e.g. Europe/Berlin, America/New_York.
:global grdTZ "UTC"

# Default language of alerts/notifications: en, cs, de, es, id, it, pl, pt, tr, uk.
:global grdLanguage "en"

# Optional notifications. Leave empty and configure them later in the web UI
# (Settings) - then the tokens are not visible in /container envs.
:global grdTelegramToken ""
:global grdTelegramChat ""
:global grdNtfyURL ""

# Disk for the image, container root and data (as in /disk print, e.g. usb1).
:global grdDisk "usb1"

# Image source: "file" = tarball uploaded to the disk root (see grdImageFile),
#               "remote" = pull from GitHub Container Registry (see section 6).
:global grdImageSource "file"
:global grdImageFile "routeros-guardian-arm64.tar"
:global grdRemoteImage "ghcr.io/marteva/routeros-guardian:latest"

# Comment of the fasttrack rule the quarantine rules are placed before.
# If no rule has this comment, they go to the top of the forward chain.
:global grdFasttrackComment "defconf: fasttrack"

# Address list used for quarantine (must match GUARDIAN_QUARANTINE_LIST).
:global grdQList "guardian-quarantine"


# =============================================================================
#  SECTION 1 - API group and user with least privileges
# =============================================================================
#  read     - DHCP leases, ARP, connection tracking, /system/resource
#  write    - add/remove address-list entries (quarantine) and remove
#             connections of a quarantined device
#  rest-api - log in over the REST API;  api - kept for compatibility
#  Everything else (winbox, ssh, web, policy, sensitive, password, ...) is denied.
#  "write" allows configuration changes in general - hence a strong password
#  and address= restricted to the container's IP.
#  To run the probe from a PC, temporarily add your LAN to address=.
{
:global grdName
:global grdRosPass
:global grdContainerIP
:if ([:len [/user group find where name=$grdName]] = 0) do={
    /user group add name=$grdName policy="read,write,api,rest-api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon"
} else={
    :put ("group " . $grdName . " exists - skipped")
}
:if ([:len [/user find where name=$grdName]] = 0) do={
    /user add name=$grdName group=$grdName address=($grdContainerIP . "/32") password=$grdRosPass comment="Guardian for RouterOS"
} else={
    :put ("user " . $grdName . " exists - skipped")
}
}


# =============================================================================
#  SECTION 2 - REST API (www service)
# =============================================================================
#  Guardian talks to http://<router IP>:<port>/rest. The container sits in the
#  LAN bridge, so this traffic never leaves the router. The command below only
#  enables the service and sets its port; it does not touch the service's
#  address= list. Make sure that list (if any) includes the container IP:
#      /ip service print where name~"www"
#  HTTPS instead (www-ssl + certificate) is described in docs/routeros-setup.md.
{
:global grdRestPort
/ip service set www disabled=no port=$grdRestPort
/ip service print where name~"www"
}


# =============================================================================
#  SECTION 3 - container network: veth in the LAN bridge
# =============================================================================
#  The LAN interface-list membership lets the container reach the REST API
#  through the defconf input rule "drop all not coming from LAN".
#  dhcp=no keeps the static address (tested on 7.24.4; remove the parameter
#  if your RouterOS version rejects it).
{
:global grdName
:global grdContainerIP
:global grdPrefixLen
:global grdRouterIP
:global grdLanBridge
:global grdLanList
:local veth ("veth-" . $grdName)
:if ([:len [/interface veth find where name=$veth]] = 0) do={
    /interface veth add name=$veth address=($grdContainerIP . "/" . $grdPrefixLen) gateway=$grdRouterIP dhcp=no comment="Guardian for RouterOS"
} else={
    :put ($veth . " exists - skipped")
}
:if ([:len [/interface bridge port find where interface=$veth]] = 0) do={
    /interface bridge port add bridge=$grdLanBridge interface=$veth comment="Guardian for RouterOS"
}
:if ([:len [/interface list member find where interface=$veth list=$grdLanList]] = 0) do={
    /interface list member add interface=$veth list=$grdLanList comment="Guardian for RouterOS"
}
}


# =============================================================================
#  SECTION 4 - quarantine firewall rules
# =============================================================================
#  Guardian's "Quarantine" button adds the device's IPv4 address to the
#  address list grdQList. These two rules drop its routed traffic (internet,
#  other subnets) in both directions.
#
#  ORDER IS CRITICAL: the drops must come BEFORE the fasttrack rule (and before
#  "accept established,related"). Fasttracked packets skip the filter, and
#  with loose TCP tracking even a mid-stream packet is picked up as
#  "established" - so a drop placed after fasttrack would not stop it.
#  Guardian also removes the device's existing connections on quarantine.
#
#  Not blocked: traffic inside the same bridge (L2, e.g. printer, Chromecast),
#  traffic to the router itself (DHCP, DNS, ...) and IPv6. See the optional
#  input rules below and docs/routeros-setup.md.
{
:global grdQList
:global grdFasttrackComment
:local anchor [/ip firewall filter find where chain=forward comment=$grdFasttrackComment]
:if ([:len $anchor] = 0) do={
    :set anchor [/ip firewall filter find where chain=forward dynamic=no]
}
:if ([:len [/ip firewall filter find where comment="guardian: quarantine (src)"]] = 0) do={
    :if ([:len $anchor] > 0) do={
        /ip firewall filter add chain=forward action=drop src-address-list=$grdQList comment="guardian: quarantine (src)" place-before=[:pick $anchor 0]
    } else={
        /ip firewall filter add chain=forward action=drop src-address-list=$grdQList comment="guardian: quarantine (src)"
    }
}
:if ([:len [/ip firewall filter find where comment="guardian: quarantine (dst)"]] = 0) do={
    :if ([:len $anchor] > 0) do={
        /ip firewall filter add chain=forward action=drop dst-address-list=$grdQList comment="guardian: quarantine (dst)" place-before=[:pick $anchor 0]
    } else={
        /ip firewall filter add chain=forward action=drop dst-address-list=$grdQList comment="guardian: quarantine (dst)"
    }
}
/ip firewall filter print where chain=forward
}

#  OPTIONAL (VERIFY:) - also keep a quarantined device away from the router
#  itself, except DHCP and DNS. Paste manually if you want it:
# /ip firewall filter add chain=input action=accept protocol=udp src-address-list=guardian-quarantine dst-port=53,67 comment="guardian: quarantine dhcp/dns" place-before=[:pick [/ip firewall filter find where chain=input dynamic=no] 0]
# /ip firewall filter add chain=input action=drop src-address-list=guardian-quarantine comment="guardian: quarantine (router)" place-before=[:pick [/ip firewall filter find where chain=input dynamic=no comment!="guardian: quarantine dhcp/dns"] 0]
#
#  Manual quarantine / release (Guardian does the same over REST):
# /ip firewall address-list add list=guardian-quarantine address=192.168.88.50 comment="manual"
# /ip firewall address-list remove [find where list=guardian-quarantine address=192.168.88.50]


# =============================================================================
#  SECTION 5 - environment variables and data mount
# =============================================================================
#  Re-running this section replaces the env list (handy for changing values;
#  restart the container afterwards). All variables: docs/configuration.md.
#  NOTE: values in /container envs are readable by every router user with the
#  "read" policy.
#  The data directory (SQLite database, geo/ for the GeoIP files) lives on the
#  disk: /<disk>/<name>/data -> /data in the container. RouterOS creates the
#  directory if it does not exist.
{
:global grdName
:global grdRouterIP
:global grdRestPort
:global grdRosPass
:global grdLan
:global grdWebUser
:global grdWebPass
:global grdTZ
:global grdLanguage
:global grdTelegramToken
:global grdTelegramChat
:global grdNtfyURL
:global grdQList
:global grdDisk
/container envs remove [find where list=$grdName]
/container envs add list=$grdName key=GUARDIAN_ROS_URL value=("http://" . $grdRouterIP . ":" . $grdRestPort)
/container envs add list=$grdName key=GUARDIAN_ROS_USER value=$grdName
/container envs add list=$grdName key=GUARDIAN_ROS_PASS value=$grdRosPass
/container envs add list=$grdName key=GUARDIAN_LAN value=$grdLan
/container envs add list=$grdName key=GUARDIAN_QUARANTINE_LIST value=$grdQList
/container envs add list=$grdName key=GUARDIAN_LANGUAGE value=$grdLanguage
/container envs add list=$grdName key=TZ value=$grdTZ
:if ([:len $grdWebUser] > 0) do={
    /container envs add list=$grdName key=GUARDIAN_WEB_USER value=$grdWebUser
    /container envs add list=$grdName key=GUARDIAN_WEB_PASS value=$grdWebPass
}
:if ([:len $grdTelegramToken] > 0) do={
    /container envs add list=$grdName key=GUARDIAN_TELEGRAM_TOKEN value=$grdTelegramToken
    /container envs add list=$grdName key=GUARDIAN_TELEGRAM_CHAT value=$grdTelegramChat
}
:if ([:len $grdNtfyURL] > 0) do={
    /container envs add list=$grdName key=GUARDIAN_NTFY_URL value=$grdNtfyURL
}
:local mountList ($grdName . "-data")
:if ([:len [/container mounts find where list=$mountList]] = 0) do={
    /container mounts add list=$mountList src=("/" . $grdDisk . "/" . $grdName . "/data") dst=/data
}
}


# =============================================================================
#  SECTION 6 - the container
# =============================================================================
#  grdImageSource = "file": upload routeros-guardian-<arch>.tar (GitHub
#  release asset or scripts/build.*) to the root of the disk first.
#
#  grdImageSource = "remote": pulls from ghcr.io (verified on 7.24.4). The full
#  image name keeps the global registry-url untouched; only the download tmpdir
#  is moved to the disk. Needs working DNS and internet on the router.
#
#  After the add, wait until /container print shows the container as stopped
#  (extracting takes a few seconds to a minute), then start it.
{
:global grdName
:global grdDisk
:global grdImageSource
:global grdImageFile
:global grdRemoteImage
:local veth ("veth-" . $grdName)
:local base ("/" . $grdDisk . "/" . $grdName)
:if ([:len [/container find where name=$grdName]] > 0) do={
    :put ("container " . $grdName . " exists - skipped (to update: stop, remove, run this section again)")
} else={
    :if ($grdImageSource = "file") do={
        /container add name=$grdName file=("/" . $grdDisk . "/" . $grdImageFile) interface=$veth root-dir=($base . "/root") envlists=$grdName mountlists=($grdName . "-data") start-on-boot=yes logging=yes workdir=/
    } else={
        /container config set tmpdir=($base . "/tmp")
        /container add name=$grdName remote-image=$grdRemoteImage interface=$veth root-dir=($base . "/root") envlists=$grdName mountlists=($grdName . "-data") start-on-boot=yes logging=yes workdir=/
    }
    :put "Container created. When /container print shows it stopped, run:"
    :put ("    /container start [find where name=" . $grdName . "]")
}
}

#  Then check:
#    /container print                       (status running)
#    /log print where topics~"container"    (Guardian's output)
#  Web UI: http://<grdContainerIP>:8080


# =============================================================================
#  SECTION 7 - forget the parameters (they contain passwords)
# =============================================================================
/system script environment remove [find where name~"^grd"]


# =============================================================================
#  MAINTENANCE (paste manually; replace "guardian" if you changed grdName)
# =============================================================================
#  Update to a new image (data in /<disk>/guardian/data is kept). A restart
#  does NOT pick up a new image - the container has to be re-created:
# /container stop [find where name=guardian]
# /container remove [find where name=guardian]
#  ...upload the new tarball (file mode), then run PARAMETERS + SECTION 6 again.
#
#  GeoIP databases: scripts/update-geoip.* -> /<disk>/guardian/data/geo/,
#  then /container stop + /container start.
#
#  Uninstall:
# /container stop [find where name=guardian]
# /container remove [find where name=guardian]
# /container envs remove [find where list=guardian]
# /container mounts remove [find where list=guardian-data]
# /ip firewall filter remove [find where comment~"^guardian: quarantine"]
# /ip firewall address-list remove [find where list=guardian-quarantine]
# /interface list member remove [find where interface=veth-guardian]
# /interface bridge port remove [find where interface=veth-guardian]
# /interface veth remove [find where name=veth-guardian]
# /user remove [find where name=guardian]
# /user group remove [find where name=guardian]
#  Files: Winbox > Files > delete /<disk>/guardian (root, data!) and the tarball.
#  Package / device-mode: /system package uninstall container ; /system reboot
#  (switching device-mode back needs physical confirmation again).
