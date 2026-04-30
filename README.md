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
- [Operator Runbook](#operator-runbook)
- [Usage](#usage)
  - [Basic Examples](#basic-examples)
  - [CLI Reference](#cli-reference)
- [Configuration Guide](#configuration-guide)
  - [Multiple Config Directories](#multiple-config-directories)
  - [Audit Settings](#audit-settings-1)
  - [Connection Settings](#connection-settings-2)
  - [Device Inventory](#device-inventory-3)
  - [Compliance Checks](#compliance-checks)
- [Hostname Naming Convention](#hostname-naming-convention)
- [How Port Classification Works](#how-port-classification-works)
  - [Uplink vs Downlink Detection](#uplink-vs-downlink-detection)
  - [Port-Channel / EtherChannel Awareness](#port-channel--etherchannel-awareness)
- [Storm Control — Speed-Aware Thresholds](#storm-control--speed-aware-thresholds)
- [BPDU Guard & Root Guard Logic](#bpdu-guard--root-guard-logic)
- [Compliance Check Reference](#compliance-check-reference)
  - [Management Plane](#management-plane)
  - [Control Plane](#control-plane)
  - [Data Plane](#data-plane)
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
| **Split config directory** | Policy split across `audit_settings.yaml`, `connection.yaml`, `management_plane.yaml` etc. — per-site directories via `-c configs/site_alpha/` |
| **Separate device inventory** | Devices listed in their own `devices/devices.yaml` — swap inventories without touching compliance policy |
| **Role-aware** | Detects device role (Access Switch) from hostname convention; drives trunk direction classification (uplink vs downlink) via CDP/LLDP neighbour matching |
| **Port classification** | Every interface is classified as ACCESS, TRUNK_UPLINK, TRUNK_DOWNLINK, UNUSED, ROUTED, SVI, etc. |
| **Port-channel awareness** | Detects EtherChannel membership via `show etherchannel summary`; runs checks against the Port-channel interface, not individual members |
| **Uplink/downlink detection** | Uses STP root-port election + CDP/LLDP neighbor hostname to reliably determine trunk direction |
| **Speed-aware storm control** | Different threshold tiers for 10G, 1G, and 100M ports |
| **Direction-aware STP guards** | BPDU guard on access ports only; root guard on downlinks only; flags root guard on uplinks as a failure |
| **Jump host support** | SSH through a bastion/jump server using Paramiko direct-tcpip channels |
| **Structured parsing** | Genie parses `show` command output into Python dicts — no fragile regex-on-CLI |
| **Summary CLI output** | Compact summary table per run — detailed findings in HTML/CSV reports, not flooding the terminal |
| **Interactive HTML reports** | Dashboard with device grid, collapsible sections, status filtering, and search |
| **CSV reports** | Exportable CSV summary of all findings across devices |
| **JSON reports** | Structured JSON output per device for downstream tooling and automation |
| **ROI estimation** | Optional estimated minutes saved and value saved in console/JSON/HTML reports |
| **Remediation scripts** | Auto-generated per-device IOS-XE config snippets to fix FAILs — port-channel aware |
| **Bulk approved-pack apply** | Apply all approved remediation packs in one run with `--remediation-apply-all` |
| **Remediation lifecycle workflow** | Enterprise-grade workflow with approval tracking, change tickets, expiry times, and risk controls |
| **Credential flexibility** | `.env` file → OS keyring (optional) → environment variables → interactive prompt |
| **Category filtering** | Audit only management plane, or only data plane, etc. |
| **Severity filtering** | `--min-severity critical/high/medium/low/info` — surface only findings at or above the chosen level |
| **Tag filtering** | `--tags cis pci hardening` — filter findings by compliance framework or custom label |
| **Per-check metadata** | Every check carries `severity`, `tags`, `applies_to_roles`, `exclude_hostnames`, `exclude_interfaces` for fine-grained control |
| **Fail threshold** | Exit with code 1 if any device scores below a configurable percentage |

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

**Data flow:** Connect → Collect show commands (concurrently across devices) → Parse with Genie → Detect EtherChannel membership → Classify every port → Run all enabled checks against policy → Generate reports.

---

## Prerequisites

- **Python 3.10+** — Windows 10/11, Linux, and macOS are all supported. The portable launchers (`setup.bat` / `run.bat` on Windows, `setup.sh` / `run.sh` on Linux) handle the full setup without a system-wide Python install.
- **Network access** to the target IOS-XE devices (directly or via jump host)
- **SSH enabled** on all devices (`ip ssh version 2`)
- **Privileged EXEC** (enable) access — the tool runs `show running-config`

> **Windows users:** Run `setup.bat` once (or double-click it) — it downloads a portable Python 3.12 runtime and installs all dependencies automatically. Then use `run.bat` as your daily launcher. No system-wide Python or WSL required.
> PyATS/Genie are **not** installed on Windows (they do not support it); the auditor automatically falls back to TextFSM (`ntc-templates`) for structured parsing, which is fully supported.

---

## Installation

### Portable Launcher (Recommended)

**Windows** — run once, then use daily:

```bat
setup.bat   ← Downloads portable Python 3.12 and installs all dependencies
run.bat     ← Daily launcher — runs setup.bat automatically on first use
```

**Linux / WSL** — run once, then use daily:

```bash
./setup.sh   # Creates .venv and installs all dependencies
./run.sh     # Daily launcher — activates venv and starts the TUI
```

### Manual Setup

```bash
# Clone the repository
git clone https://github.com/<your-org>/Cisco-Compliance-Audit.git
cd Cisco-Compliance-Audit

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS / WSL
# .venv\Scripts\activate       # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
```

### Dependencies

| Package | Purpose |
| --------- | --------- |
| `netmiko` | SSH device connections |
| `paramiko` | Jump host tunnelling |
| `pyats[library]` | Genie structured CLI parsers |
| `genie` | Parse `show` output into Python dicts |
| `rich` | Colour console tables, HTML export |
| `PyYAML` | Configuration file loading |
| `textual` | Full-screen TUI framework |
| `questionary` | Interactive CLI prompts |
| `keyring` | OS credential store (optional) |

---

## Quick Start

```bash
# 1. Add your devices to the inventory file
#    compliance_audit/devices/devices.yaml

# 2. Customise compliance policy (optional)
#    compliance_audit/compliance_config/management_plane.yaml  (or any section file)

# 3. Run the audit against a single device
python -m compliance_audit --device ZZ-LAB1-001ASW001:192.0.2.61

# 4. Or audit all devices in the inventory (concurrently)
python -m compliance_audit

# 5. Use a site-specific config directory
python -m compliance_audit -c configs/site_alpha

# 6. Use a different device inventory
python -m compliance_audit -i inventories/site_alpha_devices.yaml

# 7. Surface only high-severity findings
python -m compliance_audit --min-severity high

# 8. Surface only CIS or PCI-tagged findings
python -m compliance_audit --tags cis pci

# 9. View the reports in ./reports/
```

The tool will prompt for credentials if they are not found in environment variables.

---

## Operator Runbook

If you just need day-to-day execution steps, use the operator runbook:

- [docs/RUNBOOK.md](docs/RUNBOOK.md)
- [docs/RUNBOOK.html](docs/RUNBOOK.html)

The runbook is command-first and covers audit, approval, apply, apply-all, and troubleshooting flows.

---

## Usage

### Basic Examples

```bash
# Audit a single device (hostname:ip format)
python -m compliance_audit --device ZZ-LAB1-001ASW001:192.0.2.61

# Audit multiple devices
python -m compliance_audit --device ZZ-LAB1-001ASW001:192.0.2.61 --device ZZ-HUB1-001CSW001:192.0.2.62

# Audit by IP only (hostname won't be parsed for role)
python -m compliance_audit --device 192.0.2.61

# Audit all devices listed in devices/devices.yaml
python -m compliance_audit

# Audit only devices in a specific site group
python -m compliance_audit --site site_lab

# Audit devices across multiple site groups
python -m compliance_audit --site site_lab site_brn

# Use a different device inventory file
python -m compliance_audit -i inventories/site_alpha_devices.yaml

# Use a different config directory (e.g. per-site configs)
python -m compliance_audit -c configs/site_alpha
python -m compliance_audit -c configs/site_beta

# Skip the jump host (connect directly)
python -m compliance_audit --device 192.0.2.61 --no-jump

# Only run management plane checks
python -m compliance_audit --categories management_plane

# Only run data plane and control plane checks
python -m compliance_audit --categories data_plane control_plane

# Surface only high-severity and above findings
python -m compliance_audit --min-severity high

# Surface only CIS-tagged findings
python -m compliance_audit --tags cis

# Combine tag and severity filters
python -m compliance_audit --min-severity high --tags cis pci

# Override the report output directory
python -m compliance_audit -o ./my-reports

# Fail if any device scores below 80%
python -m compliance_audit --fail-threshold 80

# Force CSV report generation
python -m compliance_audit --csv

# Verbose output (INFO level)
python -m compliance_audit -v

# Debug output (DEBUG level)
python -m compliance_audit -vv

# Guided interactive wizard (Questionary)
python -m compliance_audit --interactive

# Full-screen premium terminal app (Textual)
python -m compliance_audit --tui

# Show all CLI options in a discoverable table
python -m compliance_audit --list-options

# Remediation lifecycle workflow (with approval tracking)
python -m compliance_audit --remediation-list
python -m compliance_audit --remediation-approve PACK_ID --approver "john.doe" --ticket-id "CHG0012345"
python -m compliance_audit --remediation-approve-all --approver "john.doe" --ticket-id "CHG0012345"
python -m compliance_audit --remediation-apply PACK_ID
python -m compliance_audit --remediation-apply-all
```

### CLI Reference

```text
python -m compliance_audit [-h] [--version] [-c CONFIG] [-d DEVICES] [-i INVENTORY]
                           [--site SITE [SITE ...]] [--no-jump]
                           [--categories CAT [CAT ...]]
                           [--tags TAG [TAG ...]] [--min-severity LEVEL]
                           [-o OUTPUT_DIR] [--fail-threshold PCT]
                           [--csv] [--no-csv] [-v]
                           [--remediation-list [STATUS]]
                           [--remediation-approve PACK_ID]
                           [--remediation-approve-all]
                           [--remediation-reject PACK_ID]
                           [--remediation-apply PACK_ID]
                           [--remediation-apply-all]
                           [--approver NAME] [--ticket-id ID] [--reason TEXT]
                           [--expires-hours HOURS]
                           [--allow-high-risk] [--interactive] [--tui]
                           [--list-options]

Options:
  -h, --help                    Show help and exit
  --version                     Print version information and exit
  -c, --config CONFIG           Path to compliance config directory (default: compliance_config/)
  -d, --device DEVICES          Device to audit — IP or hostname:IP (repeatable)
  -i, --inventory FILE          Path to device inventory YAML (default: devices/devices.yaml)
  --site SITE ...               Only audit devices from these site group(s) (e.g. --site site_lab)
  --no-jump                     Connect directly without jump host
  --categories CAT ...          Only run checks in named categories
  --tags TAG ...                Surface only findings whose tags include at least one of these values
  --min-severity LEVEL          Hide findings below this severity (critical > high > medium > low > info)
  -o, --output-dir DIR          Override the report output directory from config
  --fail-threshold PCT          Exit code 1 if any device scores below this %
  --csv / --no-csv              Force-enable or disable CSV report generation
  -v, --verbose                 Increase verbosity (-v = INFO, -vv = DEBUG)

Remediation Lifecycle Operations:
  --remediation-list [STATUS]   List remediation review packs (optionally filtered by status:
                                all, pending, approved, rejected, applied, failed, expired)
  --remediation-approve PACK_ID Approve a remediation review pack
  --remediation-approve-all     Approve all pending remediation review packs (requires
                                --approver and, by default, --ticket-id). Shows confirmation prompt.
  --remediation-reject PACK_ID  Reject a remediation review pack
  --remediation-apply PACK_ID   Apply an approved remediation review pack
  --remediation-apply-all       Apply all approved remediation review packs in sequence
  --approver NAME               Approver/operator name for approve/reject operations
  --ticket-id ID                Change ticket ID used when approving (required by default;
                                can be disabled in config)
  --reason TEXT                 Reason required when rejecting
  --expires-hours HOURS         Approval expiry in hours (default: from config, fallback 24)
  --allow-high-risk             Allow applying approved packs containing high-risk commands

Premium Interactive Modes:
  --interactive                 Launch guided wizard mode (menu + prompts)
  --tui                         Launch full-screen Textual terminal application
  --list-options                Print all available CLI options in a table and exit
```

**Exit codes:** `0` = all devices passed, `1` = at least one failure (or below `--fail-threshold`).

---

## Configuration Guide

All configuration lives in a **directory of YAML files** (default: `compliance_audit/compliance_config/`). Each section of the policy has its own file — edit only what you need without touching the rest. Device inventory is in a separate file (`compliance_audit/devices/devices.yaml`).

| File | What it controls | How often you edit it |
| ------ | ------------------ | ---------------------- |
| `audit_settings.yaml` | Concurrency, reports, timeouts, ROI, reference VLANs | Every run |
| `connection.yaml` | SSH, jump host, credentials, SSH host key policy | Per environment |
| `classification.yaml` | Inventory path, hostname role codes, endpoint detection | Set once per org |
| `devices/devices.yaml` | List of devices to audit | Per run |
| `management_plane.yaml` | SSH, AAA, NTP, logging, SNMP, VTY, banner checks | When policy changes |
| `control_plane.yaml` | STP, VTP, DHCP snooping, DAI checks | When policy changes |
| `data_plane.yaml` | Per-interface checks (BPDU guard, storm control, port security…) | When policy changes |

### Multiple Config Directories

To manage different sites, environments, or audit scopes, copy the default config directory and run with `-c`:

```bash
# Copy the default config directory for a new site
cp -r compliance_audit/compliance_config configs/site_alpha
cp -r compliance_audit/compliance_config configs/site_beta

# Edit only the files that differ per site
# e.g. update the jump host for site_alpha:
# configs/site_alpha/connection.yaml

# Run each site independently
python -m compliance_audit -c configs/site_alpha
python -m compliance_audit -c configs/site_beta
```

Each config directory is self-contained — connection settings, compliance policy, and classification are in separate files. Edit only the files that differ between sites. The device inventory is referenced via `inventory_file` in `classification.yaml`, so different sites can point to their own inventory:

```yaml
# In configs/site_alpha/classification.yaml
inventory_file: "../inventories/site_alpha_devices.yaml"
```

Or override on the command line:

```bash
python -m compliance_audit -c configs/site_alpha -i inventories/site_alpha_devices.yaml
```

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

  roi:
    enabled: false            # Add estimated minutes/value saved to reports
    manual_minutes_per_device: 20.0
    manual_minutes_per_check: 0.25
    automation_overhead_minutes_per_device: 2.0
    hourly_rate: 0.0          # Set > 0 to show value estimate
    currency: "GBP"
```

The `max_workers` setting controls how many devices are audited simultaneously. Set to `1` for sequential execution, or increase for faster runs across large inventories. Each worker runs in its own thread with an independent SSH connection.

The ROI model is intentionally simple and configurable so teams can align assumptions with their own framework:

- Manual estimate = `manual_minutes_per_device + (manual_minutes_per_check * checks_evaluated)`
- Automated estimate = `actual_runtime_minutes + automation_overhead_minutes_per_device`
- Time saved = `max(0, manual - automated)`
- Value saved = `(time_saved_hours * hourly_rate)`

### Connection Settings (§2)

```yaml
connection:
  device_type: "cisco_xe"     # Netmiko device type
  timeout: 30                 # SSH connection timeout (seconds)
  retries: 3                  # Connection retry attempts
  jump_host: "192.0.2.60"    # Jump/bastion host IP
  use_jump_host: false        # Set false to connect directly
  credential_store: "none"    # "none" or "keyring" (see Credentials section)
  keyring_service: "cisco-compliance-audit"  # keyring namespace
  host_key_checking: false    # true = reject unknown SSH host keys (requires known_hosts)
```

### Device Inventory (§3)

Device inventory lives in its own file (default: `compliance_audit/devices/devices.yaml`), keeping it separate from the compliance policy. The config file references it with:

```yaml
# In compliance_audit/compliance_config/classification.yaml
inventory_file: "devices/devices.yaml"
```

The inventory file format:

```yaml
# devices/devices.yaml

# ── Flat list ────────────────────────────────────────────────────────
devices:
  - ZZ-LAB1-001ASW001                    # bare hostname (DNS)
  - hostname: ZZ-LAB1-001ASW002          # hostname + IP
    ip: 192.0.2.62
  - hostname: legacy-sw-01               # non-standard hostname
    ip: 203.0.113.10
    role: access_switch                  # needed if hostname doesn't match ASW pattern

# ── Groups (organise by site or location) ────────────────────────────
groups:
  site_lab:
    devices:
      - ZZ-LAB1-001ASW001
      - ZZ-LAB1-001ASW002
  site_brn:
    devices:
      - ZZ-BRN1-001ASW001
      - ZZ-BRN1-001ASW002
```

Groups are organisational only — they do not set a role. Use a flat `devices:` list, groups, or both.

**Non-standard hostnames:**

If a device hostname doesn't follow the `ASW` naming convention, add `role: access_switch` so role-specific checks still apply:

```yaml
devices:
  - hostname: legacy-switch-01
    ip: 203.0.113.10
    role: access_switch  # bypasses hostname-based role detection
```

You can also:

- Override the inventory file with `-i` / `--inventory` on the command line
- Skip the inventory entirely and pass devices with `--device` (overrides the file)
- Filter to a specific site group with `--site` without switching files

**Multiple inventory files:**

You can keep separate inventory files per site alongside the default:

```
compliance_audit/devices/
    devices.yaml        ← default (all sites in groups)
    site_brn.yaml       ← branch site only
    site_lab.yaml       ← lab only
```

Point to any of them at runtime:

```bash
# Use a site-specific inventory file
python -m compliance_audit -i devices/site_brn.yaml

# Or filter the default file to one site group
python -m compliance_audit --site site_brn
```

The two approaches are interchangeable — separate files give hard isolation per site; a single grouped file with `--site` is easier to maintain when devices change.

### Compliance Checks

Every check follows the same pattern:

```yaml
check_name:
  enabled: true           # Toggle this check on/off

  # ── Optional metadata fields ──────────────────────────────────────
  severity: high          # critical | high | medium | low | info
                          # Used for --min-severity filtering and report colouring.

  tags: [cis, pci]        # Arbitrary labels — use --tags to filter by framework.
                          # Common values: hardening, encryption, authentication,
                          #   cis, pci, nist, logging, snmp, stp, layer2-security,
                          #   availability, access-control, routing-security

  applies_to_roles:       # Only run this check for these device roles.
    - access_switch       # Omit (or leave empty) to apply to all roles.

  exclude_hostnames:      # Regex patterns — matching device hostnames skip this check.
    - ".*-LEGACY-.*"

  exclude_interfaces:     # Regex patterns (per-interface checks only).
    - "GigabitEthernet0/0"

  # ... check-specific parameters
```

Set `enabled: false` to skip any check your organisation doesn't need. All metadata fields are optional — checks without them default to `severity: medium` and `tags: []`.

---

## Hostname Naming Convention

The tool automatically detects device roles by parsing hostnames against a configurable naming convention. The format below is only a neutral example; the site codes and prefixes can be adapted to whatever standard your environment uses.

### Format

```text
ZZ-LAB1-005ASW001
││  │││  │││││ │││
││  │││  │││││ └── Device number (001 = 1st switch in cabinet)
││  │││  ││└──── Role code (ASW)
││  │││  └────── Comms room / cabinet number (005)
││  ││└───────── Site instance (1 = first branch for that site code)
││  └─────────── Site code (LAB = sample site code)
└──────────────── Prefix / country code (ZZ placeholder)
```

### Role Codes

| Code | Meaning | Description |
| ------ | --------- | ------------- |
| **ASW** | Access Switch | End-user access layer switch |

### Site Code

The 2-4 letter site code is fully configurable. Example placeholders:

| Example | Meaning |
| --------- | ---------- |
| LAB | Example lab or staging site |
| HUB | Example shared services site |
| BRN | Example branch site |
| PLT | Example plant / industrial site |

The digit after the site code is the site instance (e.g. `LAB1` = first instance of the sample site code).

### Examples

| Hostname | Prefix | Site | Branch | Cabinet | Role | Device # |
| ---------- | -------- | ------ | -------- | --------- | ------ | ---------- |
| `ZZ-LAB1-001ASW001` | ZZ | LAB | 1 | 001 | Access Switch | 001 |
| `ZZ-BRN1-001ASW001` | ZZ | BRN | 1 | 001 | Access Switch | 001 |

> **What if the hostname doesn't match?** The audit still runs. However trunk ports may be classified as `TRUNK_UNKNOWN` (direction undetermined) since CDP/LLDP neighbour hostname matching requires a recognisable role code. To restore trunk direction classification for non-standard hostnames, add `role: access_switch` in `devices/devices.yaml` (see [Device Inventory](#device-inventory-3)).

---

## How Port Classification Works

Every interface on the device is classified into a role. This determines which compliance checks apply.

| Port Role | Description | Example Checks Applied |
| ----------- | ------------- | ---------------------- |
| `ACCESS` | Switchport mode access | BPDU guard, portfast, storm control, port security, access VLAN |
| `TRUNK_UPLINK` | Trunk toward the core (root bridge) | Storm control, nonegotiate, VLAN pruning, DHCP snooping trust, DAI trust. **No root guard.** |
| `TRUNK_DOWNLINK` | Trunk toward access/industrial switches | Storm control, nonegotiate, VLAN pruning, root guard, DHCP snooping trust, DAI trust |
| `TRUNK_UNKNOWN` | Trunk where direction could not be determined | Same as trunk but root guard findings are flagged as WARN |
| `TRUNK_ENDPOINT` | Trunk to an endpoint (wireless AP, etc.) | BPDU guard (like access), storm control, nonegotiate |
| `UNUSED` | Admin-down, no link | Must be shutdown, parking VLAN, no CDP/LLDP, BPDU guard, description "UNUSED" |
| `ROUTED` | Physical L3 interface (`no switchport`) | Not subject to switchport checks |
| `SVI` | Vlan interface | Not subject to switchport checks |
| `LOOPBACK` | Loopback interface | Skipped |
| `MGMT` | AppGigabitEthernet / Management | Skipped |

> **Port-channel interfaces** are classified by their actual switchport mode (ACCESS, TRUNK_UPLINK, etc.) and receive the same checks as physical ports. **Member ports** of a port-channel are automatically detected and excluded — checks and remediation target the Port-channel interface, not individual members.

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

### Port-Channel / EtherChannel Awareness

The auditor collects `show etherchannel summary` (Genie-parsed) to detect port-channel membership. This ensures:

- **Member ports** (e.g. Gi1/0/21, Gi1/0/22) are excluded from compliance checks — they inherit configuration from the port-channel
- **Port-channel interfaces** (e.g. Po1) are classified by their actual switchport mode (trunk, access, etc.) and receive the full set of data-plane checks
- **Remediation scripts** target the Port-channel interface, not individual members

If `show etherchannel summary` data is unavailable (e.g. Genie not installed), the auditor falls back to parsing `channel-group` commands from the running-config.

```text
Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
1      Po1(SU)         LACP        Gi1/0/21(P)     Gi1/0/22(P)

→ Gi1/0/21 and Gi1/0/22 are skipped
→ Port-channel1 is checked as a trunk (or access, etc.)
→ Remediation targets "interface Port-channel1"
```

This works with any number of port-channels on a device.

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

> **Note on SSH Version Check:** The SSH version check now parses the output of `show ip ssh` for the "SSH Enabled - version X.X" pattern, as SSH version information doesn't always appear in the running-config on Cisco devices. This provides more reliable detection and accepts both version "2.0" and "1.99" as valid SSHv2. If `show ip ssh` output is unavailable, the check falls back to searching for `ip ssh version 2` in the running-config for backward compatibility.

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
| SSH version 2 | `ssh_version` | Only SSHv2 is allowed (parsed from `show ip ssh` output, fallback to running-config) |
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

---

## Reports & Output

The tool generates several types of output:

### Console Summary (always)

A compact summary table is printed to the terminal showing device scores at a glance. When drilling into per-device findings, each row includes a **Sev** (severity) column colour-coded by level (critical → red, high → yellow, medium → cyan, etc.). Detailed findings are in the HTML and CSV reports.

```text
─────────────────────── AUDIT SUMMARY ────────────────────────
╭────────────────────────┬─────────────┬──────────────┬───────┬──────┬──────┬──────┬───────╮
│ Device                 │ IP          │ Role         │ Score │ Pass │ Fail │ Warn │ Error │
├────────────────────────┼─────────────┼──────────────┼───────┼──────┼──────┼──────┼───────┤
│ ZZ-LAB1-001ASW001      │ 192.0.2.61  │ Access Switch│  87%  │  55  │   8  │   2  │   0   │
│ ZZ-HUB1-001CSW001      │ 192.0.2.62  │ Core Switch  │  94%  │  62  │   4  │   1  │   0   │
╰────────────────────────┴─────────────┴──────────────┴───────┴──────┴──────┴──────┴───────╯
```

When ROI is enabled, the console also shows an ROI estimate line (hours/minutes saved) and optional value saved.

### CSV Report

Tabular summary of all findings across all devices, suitable for spreadsheet analysis or integration with other tools. Includes `severity` and `tags` columns for each finding. Enable with `csv_report: true` in the config or `--csv` on the CLI.

### JSON Report

```json
{
  "hostname": "ZZ-LAB1-001ASW001",
  "ip": "192.0.2.61",
  "score_pct": 87.3,
  "pass": 55,
  "fail": 8,
  "roi": {
    "minutes_saved": 34.6,
    "hours_saved": 0.58,
    "value_saved": 0.0,
    "currency": "GBP"
  },
  "findings": [
    {
      "check": "bpdu_guard",
      "status": "FAIL",
      "detail": "GigabitEthernet1/0/5: BPDU guard missing (access port)",
      "severity": "high",
      "tags": ["layer2-security", "stp", "cis", "pci"],
      "remediation": "spanning-tree bpduguard enable"
    }
  ]
}
```

### HTML Report

Self-contained HTML reports with a dark-themed dashboard. Two types are generated:

**Per-device report** — Stat cards showing score/pass/fail/warn/error, findings grouped by category, status filter buttons (All / Fail / Warn / Pass), and a search box to find specific checks.

When ROI is enabled, additional stat cards show estimated minutes saved and value saved.

**Consolidated report** (when auditing multiple devices) — An interactive dashboard with:

- Overall score cards and summary statistics
- Optional ROI summary cards (minutes/value saved)
- Clickable device grid with score bars — click a device to jump to its section
- Collapsible per-device sections (expand/collapse all)
- Global status filter buttons (show only failures, warnings, etc.)
- Severity badges and tag pills on every finding row
- Search box that filters across all devices and hides empty sections
- Back-to-top button for quick navigation

All reports are saved to the `output_dir` (default `./reports/`) with filenames like:

```text
reports/ZZ-LAB1-001ASW001_20260308_143025.json
reports/ZZ-LAB1-001ASW001_20260308_143025.html
reports/ZZ-LAB1-001ASW001_remediation_20260308_143025.txt
reports/ZZ-LAB1-001ASW002_20260308_143025.html
reports/consolidated_report_20260308_143025.html
reports/compliance_audit_20260308_143025.csv
```

### Remediation Scripts

For each device with FAIL findings, a ready-to-paste IOS-XE config snippet is generated. The script:

- Groups commands into global configuration and per-interface blocks
- Targets Port-channel interfaces for port-channel members (not individual member ports)
- Deduplicates commands and ends with `write memory`

```text
! Remediation script for ZZ-LAB1-001ASW001 (192.0.2.61)
! Generated: 2026-03-08 14:30 UTC
! Findings to fix: 8
!
configure terminal
!
! --- Global Configuration ---
service password-encryption
no ip http server
!
interface Port-channel1
 switchport nonegotiate
 storm-control broadcast level 1.00 0.70
!
end
write memory
```

### Remediation Workflow

Enterprise-grade remediation workflow with approval tracking, change tickets, expiry times, and risk controls. This workflow is designed for production environments where change management and audit trails are required.

##### 1. List Review Packs

After running an audit, remediation review packs are automatically generated for devices with failures. List these packs to see what's available:

```bash
# List all remediation review packs
python -m compliance_audit --remediation-list

# List only pending packs (awaiting approval)
python -m compliance_audit --remediation-list pending

# List by status: pending, approved, rejected, applied, failed, expired
python -m compliance_audit --remediation-list approved
```

**Example output:**

```text
baea5533a7f61a24 | pending  | ZZ-LAB1-001ASW001        | 192.0.2.61      | risk=medium | findings=8   | created=2026-03-23T14:30:25Z
220f8b3b0ce7a91e | approved | ZZ-HUB1-001CSW001        | 192.0.2.62      | risk=low    | findings=4   | created=2026-03-23T14:30:28Z
```

##### 2. Approve a Review Pack

Before applying remediation, a pack must be approved by an authorized operator. Approvals require:

- Approver name (`--approver`)
- Change ticket ID (`--ticket-id`) when `audit_settings.remediation.approval.require_ticket_id: true`
- Optional expiry time (`--expires-hours`, default: 24 hours)

```bash
# Approve a remediation pack
python -m compliance_audit --remediation-approve baea5533a7f61a24 \
  --approver "john.doe" \
  --ticket-id "CHG0012345"

# Approve with custom expiry (72 hours instead of default 24)
python -m compliance_audit --remediation-approve baea5533a7f61a24 \
  --approver "john.doe" \
  --ticket-id "CHG0012345" \
  --expires-hours 72
```

**Approval Metadata:**
The approval is recorded with:

- Approver name
- Change ticket ID
- Approval timestamp
- Expiry timestamp (based on `--expires-hours`)
- Risk level of the pack

If `audit_settings.remediation.approval.require_ticket_id` is set to `false`, `--ticket-id` becomes optional.

Rejected and expired packs are not re-approvable; run a fresh audit to generate a new review pack before approval.

##### 2a. Bulk Approve All Pending Packs

For production environments with many devices, you can approve all pending remediation packs at once:

```bash
# Approve all pending packs (with confirmation prompt)
python -m compliance_audit --remediation-approve-all \
  --approver "john.doe" \
  --ticket-id "CHG0012345"

# Approve all pending packs with custom expiry
python -m compliance_audit --remediation-approve-all \
  --approver "john.doe" \
  --ticket-id "CHG0012345" \
  --expires-hours 72
```

**Bulk Approval Features:**

- Lists all pending packs with hostname, IP, risk level, and findings count
- Shows interactive confirmation prompt before approving
- Approves each pack individually with progress indicators (✓ or ✗)
- Displays summary of successful vs failed approvals
- Safely handles partial failures (continues even if some approvals fail)

**Example interaction:**

```text
Found 15 pending remediation pack(s):
  baea5533... | ZZ-BRN2-022ASW001        | 198.51.100.99   | risk=medium | findings= 72
  220f8b3b... | ZZ-BRN2-023ASW001        | 198.51.100.97   | risk=medium | findings= 32
  ...

Approve all 15 pack(s)? [y/n]: y

✓ Approved: baea5533... (ZZ-BRN2-022ASW001)
✓ Approved: 220f8b3b... (ZZ-BRN2-023ASW001)
...

Bulk approval complete: 15 approved, 0 failed
```

##### 3. Reject a Review Pack

If a remediation pack should not be applied, reject it with a reason:

```bash
# Reject a remediation pack
python -m compliance_audit --remediation-reject baea5533a7f61a24 \
  --approver "john.doe" \
  --reason "Commands conflict with planned maintenance window"
```

**Rejection Metadata:**
The rejection is recorded with:

- Approver/operator name
- Rejection reason
- Rejection timestamp

##### 4. Apply Approved Packs

Once packs are approved and within validity, apply either one pack or all approved packs:

```bash
# Apply an approved remediation pack
python -m compliance_audit --remediation-apply baea5533a7f61a24

# Apply all approved packs in sequence
python -m compliance_audit --remediation-apply-all

# Allow high-risk commands (normally blocked by default)
python -m compliance_audit --remediation-apply baea5533a7f61a24 --allow-high-risk
python -m compliance_audit --remediation-apply-all --allow-high-risk
```

**Safety Controls:**

- **Approval required**: Pack must be in `approved` status
- **Expiry check**: Approval must not be expired
- **Risk assessment**: High-risk commands are blocked by default (override with `--allow-high-risk`)
- **Checksum enforcement**: Script hash must match the approved review pack
- **Preflight drift check**: Only findings still failing are applied
- **Device identity validation**: Device prompt must match approved hostname when enabled

**Application Output:**
The tool provides real-time progress indicators and detailed output including:

- **Live progress bars** for each phase:
  - Connecting to device (with spinner)
  - Running preflight drift check
  - Applying commands
  - Saving configuration
  - Running post-check verification
- Connection status
- Commands applied
- Device responses
- Success/failure status
- Execution time

**Example output:**

```json
{
  "pack_id": "baea5533a7f61a24",
  "hostname": "ZZ-LAB1-001ASW001",
  "ip": "192.0.2.61",
  "status": "success",
  "preflight_still_failing": 8,
  "resolved": 8,
  "commands_applied": 8,
  "device_output_preview": "..."
}
```

##### Configuration

Control remediation workflow behavior in `compliance_config/audit_settings.yaml`:

```yaml
audit_settings:
  remediation:
    enabled: true                           # Enable/disable remediation workflow (generate/list/approve/apply)
    generate_script: true                   # Generate per-device remediation script files
    generate_review_pack: true              # Generate review-pack JSON + SQLite entry

    approval:
      default_expires_hours: 24             # Default approval validity (hours)
      require_ticket_id: true               # Require change ticket for approval

    execution:
      enabled: true                         # Enable/disable remediation execution
      linux_only: true                      # Enforce Linux runtime for apply lifecycle commands
      block_high_risk_by_default: true      # Require --allow-high-risk for high-risk packs
      enforce_checksum: true                # Block apply if script changed since approval
      preflight_drift_check: true           # Confirm approved findings still failing before apply
      require_hostname_match: true          # Ensure device prompt matches expected hostname
      save_config: true                     # Save config after successful apply
      command_verify: false                 # Netmiko command verification during send_config_set
```

##### Workflow Summary

```text
┌─────────────┐
│ Run Audit   │  → Generates remediation review packs for devices with failures
└─────────────┘
      │
      ▼
┌─────────────┐
│ List Packs  │  → Review available packs: --remediation-list
└─────────────┘
      │
      ▼
┌─────────────┐
│ Approve     │  → Approve with ticket ID: --remediation-approve PACK_ID
│  or Reject  │     Or reject with reason: --remediation-reject PACK_ID
└─────────────┘
      │
      ▼
┌─────────────┐
│ Apply       │  → Apply one: --remediation-apply PACK_ID
│             │    Apply all: --remediation-apply-all
└─────────────┘
```

---

## Credentials

The tool attempts to find credentials in this order:

1. **OS keyring** — if `credential_store: "keyring"` is set in the config (see below)
2. **`.env` file** — copy `.env.example` to `.env` at the project root and fill in your values (loaded automatically before env var lookup; never committed to version control)
3. **Environment variables** — `SWITCH_USER` / `SWITCH_PASS` (or `CREDENTIAL_USER` / `CREDENTIAL_PASS`)
4. **Interactive prompt** — asks for username/password

The `.env` file is the simplest option for day-to-day use. The TUI setup screen pre-fills the username and password fields from it automatically. Copy `.env.example` to get started:

```dotenv
SWITCH_USER=your_username
SWITCH_PASS=your_password
USE_ENABLE=false
# ENABLE_SECRET=your_enable_secret
```

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
├── .env.example                    # Credential variables template — copy to .env
├── VERSION.txt                     # Canonical version number
├── compliance_audit/
│   ├── __about__.py                # Package metadata (name, author, licence)
│   ├── __init__.py                 # Package exports and dynamic version
│   ├── __main__.py                 # CLI entry point (python -m compliance_audit)
│   ├── compliance_config/          # ★ Compliance policy (split YAML files)
│   │   ├── audit_settings.yaml     # Concurrency, timeouts, ROI, output paths
│   │   ├── connection.yaml         # SSH, jump host, credentials, host key policy
│   │   ├── classification.yaml     # Inventory path, hostname roles, endpoint detection
│   │   ├── management_plane.yaml   # SSH, AAA, NTP, logging, SNMP, VTY checks
│   │   ├── control_plane.yaml      # STP, VTP, DHCP snooping, DAI checks
│   │   └── data_plane.yaml         # Per-interface checks (BPDU guard, storm control…)
│   ├── devices/
│   │   └── devices.yaml            # ★ Device inventory — hostnames and IPs
│   ├── auditor.py                  # Orchestrator (concurrent via ThreadPoolExecutor)
│   ├── cli_discovery.py            # CLI option table helper
│   ├── collector.py                # Data collection + Genie/TextFSM parsing
│   ├── compliance_engine.py        # All compliance checks
│   ├── credentials.py              # Credential handler (.env / keyring / env / prompt)
│   ├── hostname_parser.py          # Hostname naming convention parser
│   ├── interactive_cli.py          # Guided wizard CLI (questionary)
│   ├── jump_manager.py             # SSH jump host via Paramiko
│   ├── logging_setup.py            # Logging bootstrap (file + console handlers)
│   ├── netmiko_utils.py            # Netmiko connection wrapper
│   ├── port_classifier.py          # Interface role classification + EtherChannel detection
│   ├── remediation.py              # Remediation script generation
│   ├── remediation_cli.py          # Remediation CLI helpers
│   ├── remediation_workflow.py     # Approval lifecycle workflow
│   ├── report.py                   # Rich console + interactive HTML + JSON + CSV reports
│   ├── textual_app.py              # Full-screen 3-screen Textual TUI
│   └── version.py                  # Version reader (reads VERSION.txt)
├── assets/
│   └── config_files/
│       └── logging.conf            # INI logging configuration
├── docs/
│   ├── RUNBOOK.html                # Operator runbook (rendered HTML)
│   └── RUNBOOK.md                  # Operator runbook (Markdown source)
├── logs/                           # Runtime log files (gitignored; .gitkeep tracked)
├── reports/                        # Default report output directory (gitignored; .gitkeep tracked)
├── scripts/
│   └── render_runbook.py           # Renders RUNBOOK.md → RUNBOOK.html
├── tests/
│   ├── test_annotate_findings.py
│   ├── test_hostname_parser.py
│   ├── test_inventory.py
│   └── test_remediation_workflow.py
├── run.bat                         # Windows daily launcher
├── run.sh                          # Linux/WSL daily launcher
├── setup.bat                       # Windows first-time setup (portable Python 3.12)
├── setup.sh                        # Linux/WSL first-time setup (creates .venv)
├── requirements.txt                # Python dependencies (platform markers for pywin32)
├── README.md                       # This file
└── LICENSE
```

---

## Extending the Auditor

### Adding a New Global Check

1. **Add the check to the appropriate file in `compliance_audit/compliance_config/`** (e.g. `management_plane.yaml`):

    ```yaml
    management_plane:
      my_new_check:
        enabled: true
        severity: medium
        tags: [hardening]
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

1. **Add the role** to `hostname_roles` in `compliance_audit/compliance_config/classification.yaml`:

    ```yaml
    hostname_roles:
      - code: DSW
        role: distribution_switch
        display: "Distribution Switch"
        trunk_signal: uplink
    ```

The `trunk_signal` value (`"uplink"`, `"downlink"`, or `"none"`) controls how a CDP/LLDP neighbour with this role code is used to classify trunk port direction on the audited switch.

---

## Troubleshooting

| Problem | Solution |
| --------- | --------- |
| `Genie not installed — falling back to Netmiko/TextFSM parsing` | Install with `pip install pyats[library]` for Genie-based structured parsing. TextFSM (`ntc-templates`) is used automatically when Genie is absent. |
| `Connection failed` | Check SSH reachability, credentials, and that `ip ssh version 2` is configured on the device. |
| `No devices to audit` | Add devices to `devices.yaml` or use `--device` on the CLI. Check that `inventory_file` in the config points to the correct file. |
| `Hostname did not match naming convention` | Role-specific checks are skipped. Use the `hostname:ip` format on the CLI to provide a parseable hostname. |
| `TRUNK_UNKNOWN` ports in report | Uplink/downlink direction could not be determined. Check that CDP is enabled and the neighbor's hostname follows the naming convention. |
| Port-channel members showing as individual findings | Ensure `show etherchannel summary` is collected (requires Genie). Fallback uses `channel-group` from running-config. |
| `Config directory not found` | The tool looks for the `compliance_config` directory in the current directory, then in `compliance_audit/`. Use `--config` for a custom path. |
| Timeout on `show` commands | Increase `collect_timeout` in `audit_settings` or check device responsiveness. |
| Large devices with many interfaces slow to audit | This is expected — every interface is checked individually. Consider using `--categories` to focus on specific check groups. |
| Concurrent audits too slow / too fast | Adjust `max_workers` in `audit_settings`. Use `1` for sequential, or increase for more parallelism. |
| Want different policies per site | Copy the `compliance_config/` directory, edit per-site files, and run with `-c configs/site_name`. Use `-i` for site-specific inventories. |

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
