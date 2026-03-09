# Cisco IOS-XE Compliance Auditor

A policy-driven, role-aware compliance auditing tool for Cisco IOS-XE switches and routers. It connects to devices via SSH (optionally through a jump host), collects configuration and operational data, and checks it against a fully configurable YAML policy. Every single check can be toggled on or off so teams can tailor the audit to their own standards.

Built on **PyATS/Genie** for structured parsing, **Netmiko** for transport, and **Rich** for beautiful console and HTML reports.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Basic Examples](#basic-examples)
  - [CLI Reference](#cli-reference)
- [Configuration Guide](#configuration-guide)
  - [Multiple Config Files](#multiple-config-files)
  - [Audit Settings](#audit-settings-1)
  - [Connection Settings](#connection-settings-2)
  - [Device Inventory](#device-inventory-3)
  - [Compliance Checks](#compliance-checks-5)
- [Hostname Naming Convention](#hostname-naming-convention)
- [How Port Classification Works](#how-port-classification-works)
  - [Uplink vs Downlink Detection](#uplink-vs-downlink-detection)
- [Storm Control — Speed-Aware Thresholds](#storm-control--speed-aware-thresholds)
- [BPDU Guard & Root Guard Logic](#bpdu-guard--root-guard-logic)
- [Compliance Check Reference](#compliance-check-reference)
  - [Management Plane](#management-plane)
  - [Control Plane](#control-plane)
  - [Data Plane](#data-plane)
  - [Role-Specific Checks](#role-specific-checks)
- [Reports & Output](#reports--output)
- [Credentials](#credentials)
- [Project Structure](#project-structure)
- [Extending the Auditor](#extending-the-auditor)
  - [Adding a New Global Check](#adding-a-new-global-check)
  - [Adding a New Per-Interface Check](#adding-a-new-per-interface-check)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Area | Capability |
| ------ | ----------- |
| **90+ compliance checks** | Every check toggleable via `enabled: true/false` in YAML |
| **Concurrent auditing** | Audit multiple devices in parallel — configurable worker count via `max_workers` |
| **Multiple config files** | Run different YAML configs per site or purpose with `-c site_london.yaml` |
| **Role-aware** | Automatically detects device role (Access / Core / SD-WAN / Industrial) from the hostname naming convention |
| **Port classification** | Every interface is classified as ACCESS, TRUNK_UPLINK, TRUNK_DOWNLINK, UNUSED, ROUTED, SVI, etc. |
| **Uplink/downlink detection** | Uses STP root-port election + CDP/LLDP neighbor hostname to reliably determine trunk direction |
| **Speed-aware storm control** | Different threshold tiers for 10G, 1G, and 100M ports |
| **Direction-aware STP guards** | BPDU guard on access ports only; root guard on downlinks only; flags root guard on uplinks as a failure |
| **Jump host support** | SSH through a bastion/jump server using Paramiko direct-tcpip channels |
| **Structured parsing** | Genie parses `show` command output into Python dicts — no fragile regex-on-CLI |
| **Rich console output** | Colour-coded pass/fail tables with score percentages |
| **Interactive HTML reports** | Dashboard with device grid, collapsible sections, status filtering, and search |
| **JSON reports** | Structured JSON output per device for downstream tooling and automation |
| **Credential flexibility** | OS keyring (optional) → environment variables → interactive prompt |
| **Category filtering** | Audit only management plane, or only data plane, etc. |

---

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                 python -m compliance_audit              │
│                      (__main__.py)                      │
└────────────────────────┬────────────────────────────────┘
                         │
                    ┌────▼─────┐
                    │ auditor  │  ← Orchestrator (ThreadPool)
                    └────┬─────┘
                         │
          ┌──────────────┼──────────────────┐
          │              │                  │
   ┌──────▼───────┐ ┌────▼──────┐  ┌────────▼──────────┐
   │ credentials  │ │ collector │  │ compliance_engine │
   │ jump_manager │ │ (Netmiko  │  │ (90+ checks)      │
   │ netmiko_utils│ │  + Genie) │  └────────┬──────────┘
   └──────────────┘ └────┬──────┘           │
                         │           ┌──────▼──────┐
                  ┌──────▼────────   │   report    │
                  │port_classifier│  │ (Rich, HTML,│
                  │(STP + CDP)    │  │  JSON)      │
                  └──────┬────────   └─────────────┘
                         │
                  ┌──────▼────────┐
                  │hostname_parser│
                  │(naming conv)  │
                  └───────────────┘
```

**Data flow:** Connect → Collect show commands (concurrently across devices) → Parse with Genie → Classify every port → Run all enabled checks against policy → Generate reports.

---

## Prerequisites

- **Linux, macOS, or WSL** — PyATS/Genie is not supported on native Windows. If you are on Windows, use [WSL (Windows Subsystem for Linux)](https://learn.microsoft.com/en-us/windows/wsl/install) to run the auditor.
- **Python 3.10+** (uses `match` syntax, `X | Y` union types, dataclasses)
- **Network access** to the target IOS-XE devices (directly or via jump host)
- **SSH enabled** on all devices (`ip ssh version 2`)
- **Privileged EXEC** (enable) access — the tool runs `show running-config`

> **Windows users:** Install WSL with `wsl --install` from an elevated PowerShell, then work inside the Linux environment. All `pip install` and `python -m compliance_audit` commands should be run inside WSL, not native Windows.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/<your-org>/Cisco-Compliance-Audit.git
cd Cisco-Compliance-Audit

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate     # Linux / macOS / WSL

# Install dependencies
pip install -r requirements.txt
```

> **Note:** PyATS does not install on native Windows. If `pip install pyats[library]` fails, you are likely not running inside WSL or a Linux/macOS environment.

### Dependencies

| Package | Purpose |
| --------- | --------- |
| `netmiko` | SSH device connections |
| `paramiko` | Jump host tunnelling |
| `pyats[library]` | Genie structured CLI parsers |
| `genie` | Parse `show` output into Python dicts |
| `rich` | Colour console tables, HTML export |
| `PyYAML` | Configuration file loading |

---

## Quick Start

```bash
# 1. Edit the config with your devices
#    compliance_audit/compliance_config.yaml

# 2. Run the audit against a single device
python -m compliance_audit --device GB-MKD1-005ASW001:10.1.1.1

# 3. Or audit all devices in the config (concurrently)
python -m compliance_audit

# 4. Use a site-specific config file
python -m compliance_audit -c configs/site_london.yaml

# 5. View the reports in ./reports/
```

The tool will prompt for credentials if they are not found in environment variables.

---

## Usage

### Basic Examples

```bash
# Audit a single device (hostname:ip format)
python -m compliance_audit --device GB-MKD1-005ASW001:10.1.1.1

# Audit multiple devices
python -m compliance_audit --device GB-MKD1-005ASW001:10.1.1.1 --device GB-MKD1-005CSW001:10.1.1.2

# Audit by IP only (hostname won't be parsed for role)
python -m compliance_audit --device 10.1.1.1

# Audit all devices listed in compliance_config.yaml
python -m compliance_audit

# Use a different config file (e.g. per-site configs)
python -m compliance_audit -c configs/site_london.yaml
python -m compliance_audit -c configs/site_manchester.yaml

# Skip the jump host (connect directly)
python -m compliance_audit --device 10.1.1.1 --no-jump

# Only run management plane checks
python -m compliance_audit --categories management_plane

# Only run data plane and control plane checks
python -m compliance_audit --categories data_plane control_plane

# Verbose output (INFO level)
python -m compliance_audit -v

# Debug output (DEBUG level)
python -m compliance_audit -vv
```

### CLI Reference

```python
python -m compliance_audit [-h] [-c CONFIG] [-d DEVICES] [--no-jump]
                  [--categories CATEGORIES [CATEGORIES ...]] [-v]

Options:
  -h, --help            Show help and exit
  -c, --config CONFIG   Path to YAML config (default: compliance_config.yaml)
  -d, --device DEVICES  Device to audit — IP or hostname:IP (repeatable)
  --no-jump             Connect directly without jump host
  --categories CAT ...  Only run checks in named categories
  -v, --verbose         Increase verbosity (-v = INFO, -vv = DEBUG)
```

**Exit codes:** `0` = all devices passed, `1` = at least one failure found.

---

## Configuration Guide

All configuration lives in a YAML file (default: `compliance_audit/compliance_config.yaml`). The file is heavily commented and structured into five numbered sections for easy navigation:

| Section | What it controls | How often you edit it |
| --------- | ------------------ | ---------------------- |
| **§1 Audit Settings** | Concurrency, reports, timeouts, reference VLANs | Every run |
| **§2 Connection** | SSH, jump host, credentials | Per environment |
| **§3 Device Inventory** | List of devices to audit | Per run |
| **§4 Classification** | Hostname role codes, endpoint neighbour detection | Set once per org |
| **§5 Compliance Checks** | All 90+ policy checks | When policy changes |

### Multiple Config Files

To manage different sites, environments, or audit scopes, copy the default config and run with `-c`:

```bash
# Copy the default config for a new site
cp compliance_audit/compliance_config.yaml configs/site_london.yaml
cp compliance_audit/compliance_config.yaml configs/site_manchester.yaml

# Run each site independently
python -m compliance_audit -c configs/site_london.yaml
python -m compliance_audit -c configs/site_manchester.yaml
```

Each config file is self-contained — devices, connection settings, and compliance policy are all in one file, so different sites can have different policies.

### Audit Settings (§1)

```yaml
audit_settings:
  max_workers: 5              # Concurrent device audits (1 = sequential)
  collect_timeout: 30         # Per-command timeout (seconds)
  output_dir: "./reports"     # Where reports are saved
  html_report: true           # Generate HTML dashboard report
  json_report: false          # Also dump raw JSON per device
  parking_vlan: 99            # VLAN for unused ports
  native_vlan: 99             # Expected native VLAN on trunks
```

The `max_workers` setting controls how many devices are audited simultaneously. Set to `1` for sequential execution, or increase for faster runs across large inventories. Each worker runs in its own thread with an independent SSH connection.

### Connection Settings (§2)

```yaml
connection:
  device_type: "cisco_xe"     # Netmiko device type
  timeout: 30                 # SSH connection timeout (seconds)
  retries: 3                  # Connection retry attempts
  cred_target: "MyApp/ADM"   # Credential vault target
  jump_host: "192.0.2.60"    # Jump/bastion host IP
  use_jump_host: false        # Set false to connect directly
  credential_store: "none"    # "none" or "keyring" (see Credentials section)
  keyring_service: "cisco-compliance-audit"  # keyring namespace
```

### Device Inventory (§3)

```yaml
devices:
  - hostname: GB-MKD1-005ASW001
    ip: 10.1.1.1
  - hostname: GB-MKD1-005CSW001
    ip: 10.1.1.2
  - hostname: GB-SEV1-001ISW001
    ip: 10.2.3.4
```

Alternatively, pass devices on the command line with `--device` (overrides the YAML list).

### Compliance Checks (§5)

Every check follows the same pattern:

```yaml
check_name:
  enabled: true       # Toggle this check on/off
  # ... check-specific parameters
```

Set `enabled: false` to skip any check your organisation doesn't need.

---

## Hostname Naming Convention

The tool automatically detects device roles by parsing hostnames against a specific naming convention. This drives role-specific compliance checks and per-interface policies.

### Format

```text
GB-MKD1-005ASW001
│   │││  │││││ │││
│   │││  │││││ └── Device number (001 = 1st switch in cabinet)
│   │││  ││└──── Role code (ASW/CSW/SDW/ISW)
│   │││  └────── Comms room / cabinet number (005)
│   ││└───────── Site instance (1 = first branch in city)
│   └─────────── Site code (MKD = government standard code)
└──────────────── Country code (GB)
```

### Role Codes

| Code | Meaning | Description |
| ------ | --------- | ------------- |
| **ASW** | Access Switch | End-user access layer switch |
| **CSW** | Core Switch | Core/distribution layer switch |
| **SDW** | SD-WAN Router | SD-WAN edge router |
| **ISW** | Industrial Switch | Industrial/OT environment switch |

### Site Code

The 2-4 letter site code follows UK government location standards:

| Example | Location |
| --------- | ---------- |
| MKD | Maidenhead |
| SEV | Severnside |
| MNC | Manchester |

The digit after the site code is the branch instance (e.g. `MKD1` = first branch in Maidenhead).

### Examples

| Hostname | Country | Site | Branch | Cabinet | Role | Device # |
| ---------- | --------- | ------ | -------- | --------- | ------ | ---------- |
| `GB-MKD1-005ASW001` | GB | MKD | 1 | 005 | Access Switch | 001 |
| `GB-SEV1-001CSW001` | GB | SEV | 1 | 001 | Core Switch | 001 |
| `GB-MNC2-003SDW001` | GB | MNC | 2 | 003 | SD-WAN Router | 001 |
| `GB-MKD1-005ISW001` | GB | MKD | 1 | 005 | Industrial Switch | 001 |

> **What if the hostname doesn't match?** The audit still runs — it just skips role-specific checks and logs a warning.

---

## How Port Classification Works

Every interface on the device is classified into a role. This determines which compliance checks apply.

| Port Role | Description | Example Checks Applied |
| ----------- | ------------- | ---------------------- |
| `ACCESS` | Switchport mode access | BPDU guard, portfast, storm control, port security, access VLAN |
| `TRUNK_UPLINK` | Trunk toward the core (root bridge) | Storm control, nonegotiate, VLAN pruning, DHCP snooping trust, DAI trust. **No root guard.** |
| `TRUNK_DOWNLINK` | Trunk toward access/industrial switches | Storm control, nonegotiate, VLAN pruning, root guard, DHCP snooping trust, DAI trust |
| `TRUNK_UNKNOWN` | Trunk where direction could not be determined | Same as trunk but root guard findings are flagged as WARN |
| `UNUSED` | Admin-down, no link | Must be shutdown, parking VLAN, no CDP/LLDP, BPDU guard, description "UNUSED" |
| `ROUTED` | Physical L3 interface (`no switchport`) | Not subject to switchport checks |
| `SVI` | Vlan interface | Not subject to switchport checks |
| `LOOPBACK` | Loopback interface | Skipped |
| `PORT_CHANNEL` | Logical port-channel | Classified by membership |
| `MGMT` | AppGigabitEthernet / Management | Skipped |

### Uplink vs Downlink Detection

This is the hardest part of automated switch auditing. The tool uses a **two-signal approach** to reliably determine whether a trunk port is an uplink (toward the core) or a downlink (toward access switches):

#### Signal 1: STP Root Port (Primary)

The tool runs `show spanning-tree` and parses it with Genie. Any interface with STP role **"root"** is the path toward the root bridge — this is the **uplink**.

```cisco
Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- ----
Gi1/0/1             Root FWD 4         128.1    P2p   ← UPLINK
Gi1/0/2             Desg FWD 4         128.2    P2p   ← DOWNLINK candidate
```

#### Signal 2: CDP/LLDP Neighbor Hostname (Secondary)

The tool runs `show cdp neighbors detail` (and falls back to `show lldp neighbors detail`) and parses the neighbor's hostname against the naming convention:

- Neighbor is **CSW** (core switch) → local port is an **uplink**
- Neighbor is **ASW** or **ISW** → local port is a **downlink**

#### Combined Decision

| STP Root Port? | CDP Neighbor Role | Classification |
| ---------------- | ------------------ | ---------------- |
| Yes | Any | **TRUNK_UPLINK** |
| No | CSW | **TRUNK_UPLINK** |
| No | ASW / ISW | **TRUNK_DOWNLINK** |
| No | Unknown / None | **TRUNK_UNKNOWN** (manual review) |

STP is the trusted primary signal. CDP/LLDP acts as a tiebreaker when STP data is unavailable or ambiguous.

---

## Storm Control — Speed-Aware Thresholds

Storm control thresholds should differ based on port speed. A 1% threshold on a 10G port is 100 Mbps of storm traffic, while 1% on a 100M port is only 1 Mbps. The config supports speed-based tiers with both **rising** (upper) and **falling** (lower) thresholds:

```yaml
storm_control:
  enabled: true
  action: "shutdown"
  types:
    - broadcast
    - multicast
  thresholds_by_speed:
    10000:                    # 10 Gbps ports (TenGigabitEthernet/Te)
      broadcast:
        rising: 0.10
        falling: 0.07
      multicast:
        rising: 0.10
        falling: 0.07
    1000:                     # 1 Gbps ports (GigabitEthernet/Gi)
      broadcast:
        rising: 1.00
        falling: 0.70
      multicast:
        rising: 1.00
        falling: 0.70
    100:                      # 100 Mbps ports (FastEthernet/Fa)
      broadcast:
        rising: 10.00
        falling: 7.00
      multicast:
        rising: 10.00
        falling: 7.00
  default_thresholds:         # Fallback when speed is unknown
    broadcast:
      rising: 1.00
      falling: 0.70
    multicast:
      rising: 1.00
      falling: 0.70
```

The tool reads the operational speed from `show interfaces` (via Genie) and selects the matching tier. If the speed doesn't match exactly, it picks the nearest lower tier.

The compliance check validates both the rising and falling thresholds. For example, on a 1G port, the expected configuration would be:

```cisco
storm-control broadcast level 1.00 0.70
storm-control multicast level 1.00 0.70
```

---

## BPDU Guard & Root Guard Logic

These two STP protection mechanisms serve different purposes and must be applied to the **correct port types** — getting this wrong can cause outages.

| Feature | Applied to | Purpose | Misconfiguration Risk |
| --------- | ----------- | --------- | ---------------------- |
| **BPDU guard** | ACCESS ports only | Shuts down the port if a BPDU is received (prevents rogue switches) | If on a trunk → blocks legitimate STP |
| **Root guard** | TRUNK DOWNLINKs only | Prevents a downstream switch from becoming root | If on an UPLINK → can block the real root bridge and break STP |

The auditor enforces this matrix:

```text
BPDU guard on access port     → PASS ✓
BPDU guard missing on access  → FAIL ✗

Root guard on downlink trunk   → PASS ✓
Root guard missing on downlink → FAIL ✗
Root guard on UPLINK trunk     → FAIL ✗ (dangerous!)
Root guard on unknown trunk    → WARN ⚠ (manual review needed)
```

---

## Compliance Check Reference

### Management Plane

| Check | Key | What It Verifies |
| ------- | ----- | ----------------- |
| Password encryption | `service_password_encryption` | `service password-encryption` is present |
| Timestamps (debug) | `service_timestamps_debug` | Full timestamp format including year and timezone |
| Timestamps (log) | `service_timestamps_log` | Full timestamp format including year and timezone |
| TCP keepalives in | `service_tcp_keepalives_in` | Detects dead SSH sessions |
| TCP keepalives out | `service_tcp_keepalives_out` | Detects dead SSH sessions |
| No service pad | `no_service_pad` | X.25 PAD service is disabled |
| No service config | `no_service_config` | Auto-config from network is disabled |
| No IP source route | `no_ip_source_route` | IP source routing is disabled |
| No IP BOOTP server | `no_ip_bootp_server` | BOOTP server is disabled |
| No HTTP server | `no_ip_http_server` | Plain HTTP management is disabled |
| No HTTPS server | `no_ip_http_secure_server` | HTTPS management is disabled (if policy requires) |
| IP CEF | `ip_cef` | Cisco Express Forwarding is enabled |
| No domain lookup | `no_ip_domain_lookup` | Prevents DNS lookup on typos |
| Domain name set | `ip_domain_name` | Corporate domain name is configured |
| No gratuitous ARPs | `no_ip_gratuitous_arps` | Gratuitous ARP is disabled |
| SSH version 2 | `ssh_version` | Only SSHv2 is allowed |
| SSH timeout | `ssh_timeout` | SSH session timeout ≤ configured max |
| SSH auth retries | `ssh_authentication_retries` | Limits brute-force attempts |
| SSH source interface | `ssh_source_interface` | SSH originates from specific interface |
| AAA new-model | `aaa_new_model` | Modern AAA framework is enabled |
| AAA authentication login | `aaa_authentication_login` | Login authentication uses TACACS+ with local fallback |
| AAA authentication enable | `aaa_authentication_enable` | Enable authentication method |
| AAA authorization exec | `aaa_authorization_exec` | EXEC authorization via TACACS+ |
| AAA authorization commands | `aaa_authorization_commands` | Per-level command authorization (1, 15) |
| AAA accounting exec | `aaa_accounting_exec` | EXEC accounting (start-stop) |
| AAA accounting commands | `aaa_accounting_commands` | Per-level command accounting (1, 15) |
| AAA session ID | `aaa_session_id` | Common session ID for correlation |
| TACACS+ server(s) | `tacacs_server` | At least N TACACS+ servers configured |
| NTP server(s) | `ntp_servers` | Expected NTP servers are present |
| NTP authentication | `ntp_authenticate` | NTP authentication is enabled |
| Logging buffered | `logging_buffered` | Local buffer logging is configured |
| Logging console | `logging_console` | Console logging level is appropriate |
| Logging trap | `logging_trap` | Syslog trap level is configured |
| Logging host(s) | `logging_host` | Remote syslog server(s) are configured |
| No SNMP public | `snmp_no_community_public` | Default "public" community is removed |
| No SNMP private | `snmp_no_community_private` | Default "private" community is removed |
| SNMPv3 only | `snmp_v3_only` | Only SNMPv3 with priv is configured |
| Banner login | `banner_login` | Login banner is present (legal warning) |
| Enable secret | `enable_secret` | Uses `enable secret` not `enable password` |
| No enable password | `no_enable_password` | Type-0/7 enable password is removed |
| Username secret | `username_secret` | All local users use `secret` not `password` |
| VTY SSH only | `vty_transport_input_ssh` | Telnet is disabled on VTY lines |
| VTY exec timeout | `vty_exec_timeout` | Idle timeout ≤ configured max |
| VTY access class | `vty_access_class` | ACL restricts VTY access |
| VTY logging sync | `vty_logging_synchronous` | Log messages don't interrupt typing |
| Console exec timeout | `console_exec_timeout` | Console idle timeout |
| Console logging sync | `console_logging_synchronous` | Console logging synchronous |
| Archive logging | `archive_logging` | Configuration change logging is enabled |
| Login block-for | `login_block_for` | Brute-force lockout is configured |
| Login failure log | `login_on_failure_log` | Failed logins are logged |
| Login success log | `login_on_success_log` | Successful logins are logged |
| CDP global state | `cdp_global` | CDP is enabled/disabled per policy |
| LLDP global state | `lldp_global` | LLDP is enabled/disabled per policy |

### Control Plane

| Check | Key | What It Verifies |
| ------- | ----- | ----------------- |
| STP mode | `stp_mode` | Rapid-PVST or MST as required |
| STP extend system-id | `stp_extend_system_id` | Extended system ID for VLAN-based priority |
| STP pathcost method | `stp_pathcost_method` | Long pathcost method (supports 10G+) |
| STP loopguard default | `stp_loopguard_default` | Global loopguard prevents unidirectional link failures |
| STP priority | `stp_priority` | Role-dependent: core = low priority, access = default |
| VTP mode | `vtp_mode` | VTP set to transparent (or off) |
| DHCP snooping global | `dhcp_snooping_global` | `ip dhcp snooping` is enabled |
| DHCP snooping VLANs | `dhcp_snooping_vlans` | Snooping is active for specific VLANs |
| DAI VLANs | `arp_inspection_vlans` | Dynamic ARP Inspection is active for VLANs |
| DAI validation | `arp_inspection_validate` | DAI validates src-mac, dst-mac, IP |
| Errdisable recovery | `errdisable_recovery` | Auto-recovery for bpduguard, storm-control, etc. |
| UDLD | `udld_global` | Unidirectional Link Detection |

### Data Plane

These checks are applied **per interface** based on the port's classified role.

| Check | Key | Applies To | What It Verifies |
| ------- | ----- | ----------- | ----------------- |
| Storm control | `storm_control` | Access + Trunk | Speed-aware broadcast/multicast thresholds |
| BPDU guard | `bpdu_guard` | Access only | `spanning-tree bpduguard enable` |
| Root guard | `root_guard` | Trunk downlinks only | `spanning-tree guard root` (FAIL if on uplink) |
| Portfast | `portfast` | Access only | `spanning-tree portfast` |
| Nonegotiate | `switchport_nonegotiate` | Access + Trunk | DTP disabled (`switchport nonegotiate`) |
| Port security | `port_security` | Access only | MAC limiting and violation action |
| Trunk VLAN pruning | `trunk_allowed_vlans` | Trunk | Trunk does not allow ALL VLANs |
| Explicit mode | `switchport_mode_explicit` | Access + Trunk | No dynamic desirable/auto |
| Access VLAN | `access_vlan_set` | Access | Not using VLAN 1 for data |
| Interface description | `interface_description` | Active ports | Description is present |
| DHCP snooping trust | `dhcp_snooping_trust` | Trunk uplinks/downlinks | Trust on trunk ports |
| DHCP snooping rate limit | `dhcp_snooping_limit_rate` | Access | Rate limit on access ports |
| DAI trust | `arp_inspection_trust` | Trunk uplinks/downlinks | Trust on trunk ports |
| Unused port hardening | `unused_ports` | Unused | Shutdown, parking VLAN, no CDP/LLDP, BPDU guard, description |
| No CDP on access | `no_cdp_on_access_ports` | Access | CDP disabled on user-facing ports |
| Trunk native VLAN | `trunk_native_vlan` | Trunk | Native VLAN is non-default |

### Role-Specific Checks

| Check | Key | Role | What It Verifies |
| ------- | ----- | ------ | ----------------- |
| STP root bridge | `stp_root_check` | Core (CSW) | Core switch IS the STP root |
| STP not root | `stp_not_root` | Access (ASW) | Access switch is NOT the STP root |
| Uplink redundancy | `uplink_redundancy` | Access (ASW) | Uplink uses a port-channel |
| HSRP/VRRP | `hsrp_vrrp` | Core (CSW) | First-hop redundancy on SVIs |
| Routing auth | `routing_protocol_auth` | Core (CSW) | EIGRP/OSPF/BGP authentication |

---

## Reports & Output

The tool generates three types of output:

### Console Report (always)

Rich-formatted tables with colour-coded pass/fail/warn status, grouped by category, with a compliance score percentage. During concurrent runs, a progress bar shows device completion status.

```text
╭──────────────── COMPLIANCE AUDIT REPORT ─────────────────╮
│ Device:  GB-MKD1-005ASW001  (10.1.1.1)                   │
│ Role:    Access Switch                                     │
│ Date:    2026-03-08 14:30 UTC                             │
│ Score:   87.3%  (55 pass / 8 fail / 2 warn / 0 error)    │
╰──────────────────────────────────────────────────────────╯
```

### JSON Report

```json
{
  "hostname": "GB-MKD1-005ASW001",
  "ip": "10.1.1.1",
  "score_pct": 87.3,
  "pass": 55,
  "fail": 8,
  "findings": [
    {
      "check": "bpdu_guard",
      "status": "FAIL",
      "detail": "GigabitEthernet1/0/5: BPDU guard missing (access port)",
      "remediation": "spanning-tree bpduguard enable"
    }
  ]
}
```

### HTML Report

Self-contained HTML reports with a dark-themed dashboard. Two types are generated:

**Per-device report** — Stat cards showing score/pass/fail/warn/error, findings grouped by category, status filter buttons (All / Fail / Warn / Pass), and a search box to find specific checks.

**Consolidated report** (when auditing multiple devices) — An interactive dashboard with:

- Overall score cards and summary statistics
- Clickable device grid with score bars — click a device to jump to its section
- Collapsible per-device sections (expand/collapse all)
- Global status filter buttons (show only failures, warnings, etc.)
- Search box that filters across all devices and hides empty sections
- Back-to-top button for quick navigation

All reports are saved to the `output_dir` (default `./reports/`) with filenames like:

```text
reports/GB-MKD1-005ASW001_20260308_143025.json
reports/GB-MKD1-005ASW001_20260308_143025.html
reports/consolidated_report_20260308_143025.html
```

---

## Credentials

The tool attempts to find credentials in this order:

1. **OS keyring** — if `credential_store: "keyring"` is set in the config (see below)
2. **Environment variables** — `SWITCH_USER` / `SWITCH_PASS` (or `CREDENTIAL_USER` / `CREDENTIAL_PASS`)
3. **Interactive prompt** — asks for username/password

When the keyring backend is enabled, credentials obtained from env-vars or the interactive prompt are **automatically saved** to the OS keyring so subsequent runs are hands-free.

### Using the OS Keyring

Set these two values in the **§2 Connection** section of your config file:

```yaml
connection:
  credential_store: "keyring"                    # enables the keyring backend
  keyring_service: "cisco-compliance-audit"       # namespace — change per site if needed
```

| OS | Backend used |
| -- | ------------ |
| **RHEL / Fedora / Ubuntu** (desktop) | GNOME Keyring via `secretstorage` (D-Bus) |
| **RHEL / Ubuntu** (headless server) | Encrypted file backend (`~/.local/share/python_keyring/`) |
| **Windows** | Windows Credential Manager |
| **macOS** | macOS Keychain |

The `keyring` package is installed automatically with `pip install -r requirements.txt`. If you keep `credential_store: "none"` (the default) the keyring library is **never imported** — no side-effects.

To **delete** stored credentials, use your OS keyring manager or:

```bash
python -c "import keyring; keyring.delete_password('cisco-compliance-audit', '/username'); keyring.delete_password('cisco-compliance-audit', '/password')"
```

For the enable secret (if needed):

- Set `USE_ENABLE=true` and `ENABLE_SECRET=<secret>` as environment variables

---

## Project Structure

```text
Cisco-Compliance-Audit/
├── compliance_audit/
│   ├── __init__.py             # Package exports and version
│   ├── __main__.py             # CLI entry point (python -m compliance_audit)
│   ├── compliance_config.yaml  # ★ Default configuration — all checks here
│   ├── config_loader.py        # YAML config loader
│   ├── credentials.py          # Credential handler (keyring / env / prompt)
│   ├── jump_manager.py         # SSH jump host via Paramiko
│   ├── netmiko_utils.py        # Netmiko connection wrapper
│   ├── hostname_parser.py      # Hostname naming convention parser
│   ├── collector.py            # Data collection + Genie parsing (thread-safe)
│   ├── port_classifier.py      # Interface role classification
│   ├── compliance_engine.py    # All compliance checks (~700 lines)
│   ├── report.py               # Rich console + interactive HTML + JSON reports
│   └── auditor.py              # Orchestrator (concurrent via ThreadPoolExecutor)
├── configs/                    # (optional) Per-site config files
│   ├── site_london.yaml
│   └── site_manchester.yaml
├── requirements.txt            # Python dependencies
├── README.md                   # This file
└── LICENSE
```

---

## Extending the Auditor

### Adding a New Global Check

1. **Add the check to `compliance_config.yaml`:**

    ```yaml
    management_plane:
    my_new_check:
        enabled: true
        expected: "some expected config line"
    ```

2. **Add the check logic in `compliance_engine.py`** inside the relevant `_check_*` method:

    ```python
    if _enabled(mp, "my_new_check"):
        expected = mp.get("my_new_check", {}).get("expected", "")
        f.append(self._present(cfg, re.escape(expected),
                "my_new_check", expected, expected))
    ```

The `_present()` helper checks that a regex matches at least one global config line. The `_absent()` helper checks that a regex does NOT match (for "no X" checks).

### Adding a New Per-Interface Check

1. **Add it to `data_plane` in the YAML** with `enabled: true`
2. **Add the logic in `_check_access_port()`, `_check_trunk_port()`, or `_check_unused_port()`** depending on which port types it applies to
3. Use `pi_has(pi, r"regex pattern")` to check if an interface has a specific config line

### Adding a New Device Role

Role codes are configured in the YAML — no code changes needed:

1. **Add the role** to `hostname_roles` in `compliance_config.yaml`:

    ```yaml
    hostname_roles:
      - code: DSW
        role: distribution_switch
        display: "Distribution Switch"
        trunk_signal: uplink
    ```

2. **Add role-specific checks** under `compliance.role_specific` in the YAML
3. **(Optional)** Add engine logic in `compliance_engine.py` under `_check_role_specific()` if the new role needs custom checks beyond what config toggles provide

---

## Troubleshooting

| Problem | Solution |
| --------- | --------- |
| `Genie not installed — structured parsing unavailable` | Run `pip install pyats[library]`. Without Genie, the tool still works but falls back to regex parsing. |
| `Connection failed` | Check SSH reachability, credentials, and that `ip ssh version 2` is configured on the device. |
| `Hostname did not match naming convention` | Role-specific checks are skipped. Use the `hostname:ip` format on the CLI to provide a parseable hostname. |
| `TRUNK_UNKNOWN` ports in report | Uplink/downlink direction could not be determined. Check that CDP is enabled and the neighbor's hostname follows the naming convention. |
| `Config file not found` | The tool looks for `compliance_config.yaml` in the current directory, then in the `compliance_audit/` directory. Use `--config` for a custom path. |
| Timeout on `show` commands | Increase `collect_timeout` in `audit_settings` or check device responsiveness. |
| Large devices with many interfaces slow to audit | This is expected — every interface is checked individually. Consider using `--categories` to focus on specific check groups. |
| Concurrent audits too slow / too fast | Adjust `max_workers` in `audit_settings`. Use `1` for sequential, or increase for more parallelism. |
| Want different policies per site | Copy `compliance_config.yaml`, edit each copy, and run with `-c configs/site_name.yaml`. |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-check`)
3. Add your check to both the YAML config and the engine
4. Test against a lab device or saved config
5. Submit a pull request

---

## License

See [LICENSE](LICENSE) for details.
