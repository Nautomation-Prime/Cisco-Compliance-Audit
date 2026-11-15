# Cisco IOS-XE Compliance Auditor

[![Tests](https://github.com/Nautomation-Prime/Cisco-Compliance-Audit/actions/workflows/test.yml/badge.svg)](https://github.com/Nautomation-Prime/Cisco-Compliance-Audit/actions/workflows/test.yml)

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
- [Pre-flight & Health Checks](#pre-flight--health-checks)
- [Configuration Guide](#configuration-guide)
  - [Multiple Config Directories](#multiple-config-directories)
  - [Audit Settings](#audit-settings-1)
  - [Connection Settings](#connection-settings-2)
  - [Device Inventory](#device-inventory-3)
  - [Compliance Checks](#compliance-checks)
- [Policy Exceptions](#policy-exceptions)
  - [Defining an Exception](#defining-an-exception)
  - [How Matching Works](#how-matching-works)
  - [Expiry and Review](#expiry-and-review)
  - [Exception Settings](#exception-settings)
  - [Where Exceptions Show Up](#where-exceptions-show-up)
  - [Exceptions Are Never Remediated](#exceptions-are-never-remediated)
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
  - [Web Integration Helpers](#web-integration-helpers)
  - [Port Trust Placement](#port-trust-placement-dhcp-snooping--dai)
  - [Delta / Drift Reports](#delta--drift-reports)
  - [Remediation Workflow](#remediation-workflow)
- [Scheduled Audits and Email Approval](#scheduled-audits-and-email-approval)
  - [How It Works](#how-it-works)
  - [Setting It Up](#setting-it-up)
  - [Email Settings](#email-settings)
  - [What the Email Contains](#what-the-email-contains)
  - [Approving or Rejecting a Run](#approving-or-rejecting-a-run)
  - [Scheduled Apply](#scheduled-apply)
  - [Unattended Operation](#unattended-operation)
- [Credentials](#credentials)
- [Project Structure](#project-structure)
- [Extending the Auditor](#extending-the-auditor)
  - [Adding a New Global Check](#adding-a-new-global-check)
  - [Adding a New Per-Interface Check](#adding-a-new-per-interface-check)
- [Troubleshooting](#troubleshooting)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Area | Capability |
| ------ | ----------- |
| **90+ compliance checks** | Every check toggleable via `enabled: true/false` in YAML |
| **Concurrent auditing** | Audit multiple devices in parallel — configurable worker count via `max_workers` |
| **Split config directory** | Policy split across `audit_settings.yaml`, `connection.yaml`, `management_plane.yaml` etc. — per-site directories via `-c configs/site_alpha/` |
| **Separate device inventory** | Devices listed in their own `assets/devices/devices.yaml` — swap inventories without touching compliance policy |
| **Role-aware** | Detects device role (Access Switch) from hostname convention; drives trunk direction classification (uplink vs downlink) via CDP/LLDP neighbour matching |
| **Port classification** | Every interface is classified as ACCESS, TRUNK_UPLINK, TRUNK_DOWNLINK, UNUSED, ROUTED, SVI, etc. |
| **Port-channel awareness** | Detects EtherChannel membership via `show etherchannel summary`; runs checks against the Port-channel interface, not individual members |
| **Uplink/downlink detection** | Uses STP root-port election + CDP/LLDP neighbor hostname to reliably determine trunk direction |
| **Speed-aware storm control** | Different threshold tiers for 10G, 1G, and 100M ports |
| **Direction-aware STP guards** | BPDU guard on access ports only; root guard on downlinks only; flags root guard on uplinks as a failure |
| **Trust placement enforcement** | DHCP snooping and DAI trust is checked for presence *and absence* per port kind — a trusted access port is a FAIL, not a silent pass |
| **Jump host support** | SSH through a bastion/jump server using Paramiko direct-tcpip channels |
| **Structured parsing** | Genie parses `show` command output into Python dicts — no fragile regex-on-CLI |
| **Summary CLI output** | Compact summary table per run — detailed findings in HTML/CSV reports, not flooding the terminal |
| **Interactive HTML reports** | Dashboard with device grid, collapsible sections, status filtering, and search |
| **CSV reports** | Exportable CSV summary of all findings across devices |
| **JSON reports** | Structured JSON output per device for downstream tooling and automation |
| **Delta / drift reports** | Each run is diffed against the previous baseline for that device — resolved, new and unchanged failures |
| **ROI estimation** | Optional estimated minutes saved and value saved in console/JSON/HTML reports |
| **Remediation scripts** | Auto-generated per-device IOS-XE config snippets to fix FAILs — port-channel aware |
| **Bulk approved-pack apply** | Apply all approved remediation packs in one run with `--remediation-apply-all` |
| **Scheduled audits with email approval** | Run nightly from a systemd timer or cron; an SMTP email carries every proposed change per switch, risk, new failures, unreachable devices and expired exceptions, plus copy-paste commands to approve the whole run (apply now or at a set time) or reject it. Results of each apply are emailed too |
| **Remediation lifecycle workflow** | Enterprise-grade workflow with approval tracking, change tickets, expiry times, and risk controls |
| **Credential flexibility** | `.env` file → OS keyring (optional) → environment variables → interactive prompt |
| **Category filtering** | Audit only management plane, or only data plane, etc. |
| **Severity filtering** | `--min-severity critical/high/medium/low/info` — surface only findings at or above the chosen level |
| **Tag filtering** | `--tags cis pci hardening` — filter findings by compliance framework or custom label |
| **Per-check metadata** | Every check carries `severity`, `tags`, `applies_to_roles`, `exclude_hostnames`, `exclude_interfaces` for fine-grained control |
| **Policy exceptions** | Approved, time-boxed deviations in `exceptions.yaml` — per device, group, role, IP range, check and interface, with reason, owner, ticket and expiry. Covered findings report as `EXCEPTION`, are **never remediated** (even when expired), and expired ones are flagged for review in every report |
| **Fail threshold** | Exit with code 1 if any device scores below a configurable percentage |
| **Config validation** | Pydantic schema validates every one of the check nodes plus all settings before connecting to devices — clear field-level error messages instead of cryptic runtime failures |
| **Compliance framework mapping** | Every check can carry `framework_controls` IDs (CIS IOS-XE v4, PCI-DSS v4, NIST 800-53r5) — shown as pills in HTML, columns in CSV/JSON |
| **Framework filtering** | `--framework cis pci nist` — surface only findings that map to specific compliance framework control IDs |
| **Pre-flight dry-run** | `--dry-run` validates config, checks credentials, and tests TCP :22 reachability for every device — no SSH connections made |
| **Dependency health check** | `--health` prints a full dependency table (required + optional packages) and config validity status without running an audit |
| **Durable review state** | Approvals, rejections and execution history live in a SQLite store created on every run, with its resolved path printed in the summary |
| **Tested** | 500+ unit tests over the check engine, hostname parsing, inventory loading, policy exceptions and the remediation workflow; CI also lints the YAML and validates the shipped config |

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

For the same download-first experience as the Cisco Config Generator, use the GitHub [Releases](https://github.com/cwmdavies/Cisco-Compliance-Audit/releases) page when you want a packaged snapshot instead of cloning the repository.

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
git clone https://github.com/cwmdavies/Cisco-Compliance-Audit.git
cd Cisco-Compliance-Audit

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate      # Linux / macOS / WSL
# .venv\Scripts\activate       # Windows PowerShell

# Install the package with development extras
pip install -e .[dev]
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

The canonical application version now lives in `pyproject.toml`, which keeps package metadata, CLI `--version`, and the TUI subtitle aligned from one source.

---

## Quick Start

```bash
# 1. Add your devices to the inventory file
#    assets/devices/devices.yaml

# 2. Customise compliance policy (optional)
#    assets/compliance_config/management_plane.yaml  (or any section file)

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

# Audit all devices listed in assets/devices/devices.yaml
python -m compliance_audit

# Audit only devices in a specific site group
python -m compliance_audit --site site_lab

# Audit devices across multiple site groups
python -m compliance_audit --site site_lab site_brn

# Restrict discovery to a CIDR range
python -m compliance_audit --ip-filter 192.168.0.0/24

# Restrict discovery to a hyphen-separated IP range
python -m compliance_audit --ip-filter 192.168.0.1-192.168.0.254

# Combine site and IP filter
python -m compliance_audit --site site_lab --ip-filter 10.10.0.0/22

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
python -m compliance_audit --remediation-list pending --remediation-output json
python -m compliance_audit --remediation-approve PACK_ID --approver "john.doe" --ticket-id "CHG0012345"
python -m compliance_audit --remediation-reject PACK_ID --approver "john.doe" --reason "Change window closed" --remediation-output json
python -m compliance_audit --remediation-approve-all --approver "john.doe" --ticket-id "CHG0012345"
python -m compliance_audit --remediation-apply PACK_ID
python -m compliance_audit --remediation-apply-all --remediation-output json --remediation-no-confirm
```

### CLI Reference

```text
python -m compliance_audit [-h] [--version] [-c CONFIG] [-d DEVICES] [-i INVENTORY]
                           [--site SITE [SITE ...]] [--ip-filter RANGE] [--no-jump]
                           [--categories CAT [CAT ...]]
                           [--tags TAG [TAG ...]] [--min-severity LEVEL]
                           [-o OUTPUT_DIR] [--fail-threshold PCT]
                           [--csv] [--no-csv] [-v]
                           [--framework NAME [NAME ...]]
                           [--remediation-list [STATUS]]
                           [--remediation-output {table,json,csv}]
                           [--remediation-approve PACK_ID]
                           [--remediation-approve-all]
                           [--remediation-reject PACK_ID]
                           [--remediation-apply PACK_ID]
                           [--remediation-apply-all]
                           [--approver NAME] [--ticket-id ID] [--reason TEXT]
                           [--expires-hours HOURS]
                           [--allow-high-risk] [--remediation-no-confirm]
                           [--remediation-apply-due]
                           [--non-interactive] [--notify] [--notify-test]
                           [--run-list] [--run-show RUN_ID] [--run-notify RUN_ID]
                           [--run-approve RUN_ID [--apply-now | --apply-at TIME]]
                           [--run-reject RUN_ID]
                           [--interactive] [--tui]
                           [--list-options] [--health] [--validate-config] [--dry-run]

Options:
  -h, --help                    Show help and exit
  --version                     Print version information and exit
  -c, --config CONFIG           Path to compliance config directory (default: assets/compliance_config/)
  -d, --device DEVICES          Device to audit — IP or hostname:IP (repeatable)
  -i, --inventory FILE          Path to device inventory YAML (default: assets/devices/devices.yaml)
  --site SITE ...               Only audit devices from these site group(s) (e.g. --site site_lab)
  --ip-filter RANGE             Restrict discovery to devices within this IP range.
                                Accepts CIDR notation (e.g. 192.168.0.0/24) or a hyphen-separated
                                range (e.g. 192.168.0.1-192.168.0.254).  Can be combined with --site.
  --no-jump                     Connect directly without jump host
  --categories CAT ...          Only run checks in named categories
  --tags TAG ...                Surface only findings whose tags include at least one of these values
  --min-severity LEVEL          Hide findings below this severity (critical > high > medium > low > info)
  --framework NAME ...          Surface only findings that have a matching framework_controls entry
                                (e.g. --framework cis pci nist — partial match on key names)
  -o, --output-dir DIR          Override the report output directory from config
  --fail-threshold PCT          Exit code 1 if any device scores below this %
  --csv / --no-csv              Force-enable or disable CSV report generation
  -v, --verbose                 Increase verbosity (-v = INFO, -vv = DEBUG)

Remediation Lifecycle Operations:
  --remediation-list [STATUS]   List remediation review packs (optionally filtered by status:
                                all, pending, approved, rejected, applied, failed, expired,
                                superseded)
  --remediation-output FORMAT   Remediation output format: table/json/csv.
                                csv is list-only; json is backend-friendly for all lifecycle ops.
  --remediation-approve PACK_ID Approve a remediation review pack
  --remediation-approve-all     Approve all pending remediation review packs (requires
                                --approver and, by default, --ticket-id). Shows confirmation prompt.
  --remediation-reject PACK_ID  Reject a remediation review pack
  --remediation-apply PACK_ID   Apply an approved remediation review pack
  --remediation-apply-all       Apply all approved remediation review packs in sequence
                                (packs scheduled for later are left alone)
  --remediation-apply-due       Apply approved packs whose scheduled time has arrived
                                (run from a timer every few minutes)
  --approver NAME               Approver/operator name for approve/reject operations
  --ticket-id ID                Change ticket ID used when approving (required by default;
                                can be disabled in config)
  --reason TEXT                 Reason required when rejecting
  --expires-hours HOURS         Approval expiry in hours (default: from config, fallback 24)
  --allow-high-risk             Allow applying approved packs containing high-risk commands
  --remediation-no-confirm      Skip confirmation prompts for bulk remediation operations

Scheduled Audits and Run Approval:
  --non-interactive             Never prompt — fail clearly if credentials are missing or a
                                confirmation would be needed. For cron/systemd jobs.
  --notify                      Email the run summary after the audit (notifications.yaml)
  --notify-test                 Send a test email and exit
  --run-list                    List recent audit runs and their remediation state
  --run-show RUN_ID             Show one run: devices, scores, packs, unreachable devices
  --run-approve RUN_ID          Approve every pending pack from a run (--approver, --ticket-id)
    --apply-now                 ... and apply immediately
    --apply-at TIME             ... and apply at TIME ('YYYY-MM-DD HH:MM' or 'HH:MM' local,
                                or ISO-8601 with an offset)
  --run-reject RUN_ID           Reject every pending or approved pack from a run
                                (--approver, --reason)
  --run-notify RUN_ID           Re-send a run's email

Premium Interactive Modes:
  --interactive                 Launch guided wizard mode (menu + prompts)
  --tui                         Launch full-screen Textual terminal application
  --list-options                Print all available CLI options in a table and exit

Pre-flight & Validation:
  --health                      Check all dependencies and config validity, then exit
  --validate-config             Validate all YAML config files and report Pydantic errors, then exit
  --dry-run                     Validate config, resolve credentials, and test TCP :22 reachability
                                without opening any SSH sessions to devices
```

**Exit codes:** `0` = all devices passed, `1` = at least one failure (or below `--fail-threshold`, or — with `exception_settings.fail_on_expired: true` — a finding under an expired policy exception), `2` = the config or inventory could not be loaded or failed validation, credentials were missing in a non-interactive run, or another audit was already running for the same output directory. Findings covered by an active exception never cause exit code `1`. `--remediation-apply-due` and `--run-approve --apply-now` exit `1` when any pack fails to apply.

---

## Pre-flight & Health Checks

Run these before committing to a full audit — they are fast, read-only, and exit cleanly.

### `--health` — dependency and config check

```bash
python -m compliance_audit --health
python -m compliance_audit --health -c configs/site_alpha
```

Prints:

1. Python version and platform info
2. A dependency table — every required and optional package shown as **OK** or **MISSING**
3. Config validation result — loaded OK, or errors listed

Useful for verifying a fresh install or a new site config before touching devices.

### `--validate-config` — YAML schema validation

```bash
python -m compliance_audit --validate-config
python -m compliance_audit --validate-config -c configs/site_alpha
```

Loads all YAML config files and validates them against the Pydantic schema (`compliance_audit/config_schema.py`): every top-level section, `audit_settings`, `connection`, `hostname_roles`, `endpoint_neighbors`, and every check node with its check-specific settings. Every problem is reported at once, with its full path, and close misspellings get a suggestion:

```text
Config validation failed (5 error(s)):
  audit_settings.max_worker: unknown key — did you mean 'max_workers'?
  connection.device_type: 'cisco_iosxe' is not a Netmiko device_type (did you mean: cisco_ios, cisco_xe, cisco_nxos?)
  compliance.management_plane.ntp_server: unknown check — it would never run — did you mean 'ntp_servers'?
  compliance.management_plane.ntp_servers.expected_servers[1]: '10.0.0.256' is not a valid IP address
  compliance.management_plane.stp_mode: 'stp_mode' is a control_plane check — move it under compliance.control_plane (it is ignored here)
```

**Validation runs on every config load**, not just with this flag: an audit, the TUI, the wizard and the remediation commands all refuse to start on an invalid config (exit code `2`). `--validate-config` is the way to see the errors without running anything else.

What it catches, none of which a YAML linter can see:

- **Unknown keys.** The engine ignores keys it does not read, so `max_worker:`, `expected_server:` or a check key under the wrong plane silently does nothing. Unknown keys are errors in every settings block and every check node; each check accepts exactly the settings the engine reads for it.
- **A missing or mistyped `enabled` key.** A check runs only when its node says `enabled: true`; a node that is absent or has no `enabled` key is off. So `enabld: true` would silently leave a check off — `enabled`, `severity` and `tags` are therefore *required* on every check node.
- **Bad values.** IP addresses (`expected_servers`, `expected_hosts`, `jump_host`) are parsed with Pydantic's `IPvAnyAddress`, so IPv4 and IPv6 work and `10.0.0.256` is rejected; hostnames are allowed where the device accepts them. VLAN IDs and range lists, syslog levels, SSH/STP/storm-control settings and Netmiko `device_type` are range- or choice-checked. Storm-control `falling` may not exceed `rising`.
- **Regexes that do not compile.** `include_hostnames`, `exclude_hostnames`, `exclude_interfaces` and the `endpoint_neighbors` patterns are compiled during validation, because the engine swallows `re.error` at runtime and the filter silently stops applying.
- **Filters that can never match.** An `applies_to_roles` entry that is not a role from `hostname_roles` would skip the check on every device.
- **Policy exceptions that could never match, or are incomplete.** Every exception needs an `id`, `reason`, `expires` date, at least one check and at least one device selector; IDs must be unique; plain check names are checked against the checks the engine can emit (with a "did you mean"); roles, IP networks and regexes are validated. See [Policy Exceptions](#policy-exceptions).

On success, `--validate-config` also summarises the exception register — how many exceptions are active, expiring and expired — and lists each expired one. That is informational: an expired exception is a review item, not a config error, so the exit code stays `0`.

```text
Config valid — no errors found.
Policy exceptions: 4 defined (2 active, 1 expiring, 1 expired)
  EXPIRED EXC-0007 — expired 2026-09-30 (36 day(s) ago); review, renew or remove it
  expiring EXC-0002 — expires 2026-11-20 (in 15 day(s))
```

Exit code: `0` = valid, `2` = validation errors found.

### `--dry-run` — pre-flight reachability check

```bash
python -m compliance_audit --dry-run
python -m compliance_audit --dry-run -c configs/site_alpha -d 10.0.0.1
python -m compliance_audit --dry-run --no-jump
```

Performs all pre-audit checks without opening any SSH sessions to devices:

1. **Config validation** — loads and validates all YAML files against the schema
2. **Device list** — resolves the full device list from inventory or `--device` overrides
3. **Credentials** — checks for credentials in environment variables or keyring (warns if none pre-configured)
4. **Jump host** — tests TCP :22 reachability to the jump host (skipped with `--no-jump`)
5. **Device reachability** — tests TCP :22 to every device in the resolved list

Exit code: `0` = all checks passed, `2` = a validation or reachability issue was found.

---

## Configuration Guide

All configuration lives in a **directory of YAML files** (default: `assets/compliance_config/`). Each section of the policy has its own file — edit only what you need without touching the rest. Device inventory is in a separate file (`assets/devices/devices.yaml`).

| File | What it controls | How often you edit it |
| ------ | ------------------ | ---------------------- |
| `audit_settings.yaml` | Concurrency, reports, timeouts, ROI, reference VLANs | Every run |
| `connection.yaml` | SSH, jump host, credentials, SSH host key policy | Per environment |
| `classification.yaml` | Inventory path, hostname role codes, endpoint detection | Set once per org |
| `assets/devices/devices.yaml` | List of devices to audit | Per run |
| `management_plane.yaml` | SSH, AAA, NTP, logging, SNMP, VTY, banner checks | When policy changes |
| `control_plane.yaml` | STP, VTP, DHCP snooping, DAI checks | When policy changes |
| `data_plane.yaml` | Per-interface checks (BPDU guard, storm control, port security…) | When policy changes |
| `exceptions.yaml` | [Policy exceptions](#policy-exceptions) — approved, time-boxed deviations with expiry dates | When a deviation is approved, renewed or retired |
| `notifications.yaml` | [SMTP email](#email-settings) for scheduled audits — relay, recipients, when to send, attachments | Set once per site |

### Multiple Config Directories

To manage different sites, environments, or audit scopes, copy the default config directory and run with `-c`:

```bash
# Copy the default config directory for a new site
cp -r assets/compliance_config configs/site_alpha
cp -r assets/compliance_config configs/site_beta

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
  json_report: true           # Raw JSON per device — also the delta baseline
  csv_report: false           # CSV summary of every finding
  delta_report: true          # Diff each run against the previous JSON baseline
                              # (needs json_report; the audit warns if it is off)
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

Device inventory lives in its own file (default: `assets/devices/devices.yaml`), keeping it separate from the compliance policy. The config file references it with:

```yaml
# In assets/compliance_config/classification.yaml
inventory_file: "assets/devices/devices.yaml"
```

The inventory file format:

```yaml
# assets/devices/devices.yaml

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

The inventory is validated when it loads (`compliance_audit/inventory_schema.py`). `ip` must be a valid IPv4 or IPv6 address (put DNS names under `hostname`), hostnames must be valid DNS names, and the only keys allowed at the top level and inside a group are `devices:` / `groups:`, so a typo such as `device:` is reported instead of loading an empty inventory. Extra keys on a device entry (`platform`, `notes` …) are kept. The same rules apply to `--device` values, which accept `HOST`, `IP` or `HOST:IP`, including IPv6 (`--device sw1:2001:db8::61`).

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
assets/devices/
    devices.yaml        ← default (all sites in groups)
    site_brn.yaml       ← branch site only
    site_lab.yaml       ← lab only
```

Point to any of them at runtime:

```bash
# Use a site-specific inventory file
python -m compliance_audit -i assets/devices/site_brn.yaml

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

> **`exclude_*` filters or a policy exception?** The `exclude_*` / `include_*` filters change *where a check applies* — the finding becomes `SKIP` and disappears from the reports. Use them for devices or ports the policy genuinely does not cover. For a device that *should* comply but has an approved reason not to, use a [policy exception](#policy-exceptions): it records who approved it and why, stays visible in every report, and expires so it gets reviewed.

---

## Policy Exceptions

Sometimes a switch must deviate from policy for a good reason — a port that faces a customer-managed switch cannot run BPDU guard, an NTP server is unreachable from one region until a WAN upgrade, a legacy poller still needs SNMPv2c. A **policy exception** records that deviation and its approval, and is bounded by an expiry date.

What an exception does:

- The covered finding is reported as **`EXCEPTION`** instead of `FAIL`/`WARN`, with the exception's ID, reason, owner, ticket and expiry beside it.
- It is **never remediated**, whether active or expired: it is left out of the remediation script and review pack, and re-checked at apply time — see [Exceptions Are Never Remediated](#exceptions-are-never-remediated).
- It is left out of the compliance score (configurable for expired ones).
- When it **expires**, it is flagged as `EXPIRED — review required` in the console, HTML, JSON and CSV reports. It is still not remediated. A human decides: renew it, or remove it and let the next audit raise the finding for remediation as normal.

### Defining an Exception

Exceptions live in `assets/compliance_config/exceptions.yaml` (shipped empty, with commented examples):

```yaml
exceptions:
  - id: EXC-0001                    # required — unique, no spaces
    hostname: ZZ-LAB1-001ASW001     # device selector (at least one required)
    check: bpdu_guard               # required — finding name, check key or regex
    interface: Gi1/0/48             # optional — omit for every interface / global finding
    reason: Uplink to customer-managed switch; BPDU guard would err-disable it   # required
    expires: 2027-03-31             # required — YYYY-MM-DD (valid through that day)
    owner: Network Engineering      # optional record-keeping, shown in reports
    approved_by: J. Smith (Security)
    approved_on: 2026-06-01
    ticket: CHG0012345
    notes: Revisit when the customer replaces their switch
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique reference shown in every report (e.g. `EXC-0001` or a change number) |
| `reason` | yes | Why the deviation is accepted |
| `expires` | yes | `YYYY-MM-DD`. Valid through that whole day, `EXPIRED` from the next. `never` only with `allow_permanent: true` |
| `checks` | yes | One or more checks (see matching below) |
| `hostnames` / `ips` / `groups` / `roles` | at least one | Which devices the exception applies to |
| `interfaces` | no | Restrict to specific interfaces |
| `detail` | no | Regex searched for in the finding text, to pick one of several findings a check emits |
| `owner`, `approved_by`, `approved_on`, `ticket`, `notes` | no | Record-keeping, shown in reports |

Every selector takes one value or a list, and the singular spelling (`hostname`, `ip`, `group`, `role`, `check`, `interface`) works too.

**Splitting the register.** Every `*.yaml` file in the config directory is merged, and unlike other lists, every `exceptions:` list is *concatenated* — so you can keep one file per site or team (`exceptions_site_lab.yaml`, `exceptions_site_brn.yaml`, …). To keep the register outside the config directory entirely (for example in a repository owned by the change/risk team), point at it:

```yaml
exceptions_file: ../../change-control/network_exceptions.yaml   # or a list of paths
```

Paths resolve like `inventory_file` (working directory → config directory → project root). An external file may contain only `exceptions:` and `exception_settings:`. Reports show which file each exception came from.

### How Matching Works

Every selector you give must match; a selector you leave out matches everything.

| Selector | Matches | Notes |
| --- | --- | --- |
| `hostnames` | Device hostname — exact or regex, whole-name, case-insensitive | Also tried against the short name (before the first `.`) and the management IP. `[".*"]` covers every device — it must be written explicitly |
| `ips` | Management IP — addresses or CIDR networks (`10.20.0.0/16`) | IPv4 and IPv6 |
| `groups` | Site group from `devices.yaml` | Case-insensitive; ungrouped devices never match |
| `roles` | Device role (e.g. `access_switch`) | Validated against `hostname_roles` |
| `checks` | The check name shown in the report (`ntp_server`), the YAML key of the check that emits it (`ntp_servers`), or a regex (`storm_control.*`) | A YAML key also covers its sub-findings, e.g. `errdisable_recovery` covers `errdisable_recovery_bpduguard`, and `unused_ports` covers `unused_shutdown`, `unused_parking_vlan`, … |
| `interfaces` | Interface name or regex | Abbreviations work both ways and in any case: `Gi1/0/48` = `GigabitEthernet1/0/48`; `"Gi1/0/(4[0-8])"` matches ports 40–48. An exception that lists interfaces never matches a global finding |
| `detail` | Regex searched for in the finding text | e.g. `detail: "192\\.0\\.2\\.70"` to except one missing NTP server but not the others |

More examples:

```yaml
exceptions:
  # A whole site, several related checks, a range of ports
  - id: EXC-0002
    groups: [site_lab]
    checks: [port_security, "storm_control.*"]
    interfaces: ["Gi1/0/(4[0-8])"]
    reason: Lab test bench ports — hosts change daily
    expires: 2026-12-31

  # One NTP server missing on every device in a subnet
  - id: EXC-0003
    ips: 10.20.0.0/16
    check: ntp_servers
    detail: "192\\.0\\.2\\.70"
    reason: Secondary NTP server unreachable from this region until the WAN upgrade
    expires: 2027-01-15
```

Rules:

- Only **FAIL** and **WARN** findings can be covered. **ERROR** (a check that could not run) is never hidden, and PASS/SKIP are left alone.
- A check already turned into `SKIP` by its own `exclude_*`/`include_*`/`applies_to_roles` filter is not touched.
- When several exceptions match one finding, the one with the **latest expiry wins** (`never` beats any date). Renewing an exception is therefore just editing its date — or adding a new entry with a later date.
- An exception scoped to a device that matched **no** failing finding on it is listed as *matched nothing* — usually because the configuration is now compliant and the exception can be retired.

### Expiry and Review

| State | When | How it is shown |
| --- | --- | --- |
| `active` | More than `expiring_soon_days` before expiry | Blue `EXCEPTION` badge |
| `expiring` | Within `expiring_soon_days` of expiry (default 30) | Amber `EXPIRING` badge and banner |
| `expired` | The day after the expiry date onwards | Red `EXPIRED` badge, a "review required" banner, and listed first in every exception table |
| `permanent` | `expires: never` (needs `allow_permanent: true`) | Grey `PERMANENT` badge |

An expired exception still prevents remediation. It is a prompt for a human decision, not a trigger for an automated change.

### Exception Settings

```yaml
exception_settings:
  expiring_soon_days: 30              # flag exceptions expiring within N days (0 = off)
  expired_counts_against_score: false # true = expired exceptions lower the score as failures
  fail_on_expired: false              # true = exit code 1 if any finding is under an expired exception
  allow_permanent: false              # true = allow `expires: never`
```

| Setting | Default | Effect |
| --- | --- | --- |
| `expiring_soon_days` | `30` | Size of the "expiring soon" warning window |
| `expired_counts_against_score` | `false` | Active exceptions never count towards the score. With `true`, findings under an *expired* exception count as not passing, so the score drops until the exception is reviewed |
| `fail_on_expired` | `false` | With `true`, a run exits `1` while any finding sits under an expired exception — useful in CI or scheduled audits |
| `allow_permanent` | `false` | Off by default so every exception has a review date |

### Where Exceptions Show Up

- **Console** — `EXCEPT` (or red `EXPIRED`) status with the exception ID and expiry under the finding; an `Exc` column in the audit summary; and a *Policy Exceptions* panel listing exceptions needing review and exceptions that matched nothing.
- **HTML** — `EXCEPTION` badge plus a state badge on each covered finding, with the reason, owner, ticket and approver beside it, and the suppressed remediation command struck through. Each device has a *Policy exceptions on this device* table. The consolidated report adds **Exception** stat cards, an **Exception register** listing every exception (state, scope, findings covered, devices, and whether it is *in use*, *matched nothing* or *had no device in scope this run*) and **Exceptions** / **Expired exceptions** filter buttons.
- **JSON** — `exception`, `exception_expired`, `exception_expiring` counts; each covered finding carries an `exception` object (`id`, `state`, `expires`, `days_remaining`, `original_status`, `reason`, `owner`, `ticket`, …); an `exceptions.unused` list.
- **CSV** — `exception_id`, `exception_state`, `exception_expires`, `exception_reason`, `exception_owner`, `exception_ticket` columns.
- **Delta** — a FAIL/WARN that is now covered by an exception is reported under `excepted` ("Moved to exception"), not as resolved. If an exception is removed, the finding returns as a new failure with `old_status: EXCEPTION`.
- **TUI** — exception and expired counts on the completion screen.
- **`--validate-config`** — a summary of the register, listing expired and expiring exceptions.

### Exceptions Are Never Remediated

This is enforced at every step, not just at report time:

1. **Script and review pack** — covered findings are left out of `<hostname>_remediation_*.txt` and the review pack. The pack records them, for the reviewer's information only, under `exceptions_excluded`.
2. **Apply time** — `--remediation-apply` / `--remediation-apply-all` reload the exceptions and drop any pack item an exception covers *now*, active or expired. This catches a pack generated or approved **before** the exception was added, and holds whether or not the preflight drift check is enabled. If every item is covered, the apply aborts before connecting to the device.
3. **Drift and post checks** — the preflight and post-apply re-audits apply the same exceptions, so a covered finding is never in the set of findings to fix.

To remediate a deviation that was excepted, remove the exception (or let a human decide not to renew it and delete it), re-run the audit, and approve the new pack as normal.

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

> **What if the hostname doesn't match?** The audit still runs. However trunk ports may be classified as `TRUNK_UNKNOWN` (direction undetermined) since CDP/LLDP neighbour hostname matching requires a recognisable role code. To restore trunk direction classification for non-standard hostnames, add `role: access_switch` in `assets/devices/devices.yaml` (see [Device Inventory](#device-inventory-3)).

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
| No finger service | `no_service_finger` | `service finger` is not enabled |
| No TCP/UDP small servers | `no_service_tcp_small_servers`, `no_service_udp_small_servers` | Echo/discard/chargen/daytime services are off |
| No IP finger | `no_ip_finger` | `ip finger` is not enabled |
| No IP source route | `no_ip_source_route` | IP source routing is disabled |
| No IP BOOTP server | `no_ip_bootp_server` | BOOTP server is disabled |
| No HTTP server | `no_ip_http_server` | Plain HTTP management is disabled |
| No HTTPS server | `no_ip_http_secure_server` | HTTPS management is disabled (if policy requires) |
| IP CEF | `ip_cef` | Cisco Express Forwarding is enabled |
| No domain lookup | `no_ip_domain_lookup` | Prevents DNS lookup on typos |
| Domain name set | `ip_domain_name` | Corporate domain name is configured (exact match) |
| No gratuitous ARPs | `no_ip_gratuitous_arps` | Gratuitous ARP is disabled |
| SSH version 2 | `ssh_version` | Only SSHv2 is allowed (parsed from `show ip ssh` output, fallback to running-config) |
| SSH timeout | `ssh_timeout` | SSH session timeout ≤ configured max |
| SSH auth retries | `ssh_authentication_retries` | Limits brute-force attempts |
| SSH source interface | `ssh_source_interface` | SSH originates from the named interface (abbreviations such as `Lo0` accepted) |
| AAA new-model | `aaa_new_model` | Modern AAA framework is enabled |
| AAA authentication login | `aaa_authentication_login` | Login authentication uses TACACS+ with local fallback |
| AAA authentication enable | `aaa_authentication_enable` | Enable authentication method |
| AAA authorization exec | `aaa_authorization_exec` | EXEC authorization via TACACS+ |
| AAA authorization commands | `aaa_authorization_commands` | One line per level in `levels`; `{level}` in `expected_prefix` is substituted |
| AAA accounting exec | `aaa_accounting_exec` | EXEC accounting (start-stop) |
| AAA accounting commands | `aaa_accounting_commands` | One line per level in `levels`; `{level}` in `expected_prefix` is substituted |
| AAA session ID | `aaa_session_id` | Common session ID for correlation |
| TACACS+ server(s) | `tacacs_server` | At least N TACACS+ servers configured |
| TACACS+ source interface | `tacacs_source_interface` | `ip tacacs source-interface`, global or in an `aaa group server` |
| NTP server(s) | `ntp_servers` | Expected NTP servers are present (whole-address match, IPv6 aware) |
| NTP source interface | `ntp_source_interface` | `ntp source` names the expected interface |
| NTP authentication | `ntp_authenticate` | NTP authentication is enabled |
| Logging buffered | `logging_buffered` | Buffer ≥ `min_size` and level at least as verbose as `level` |
| Logging console | `logging_console` | Console level no more verbose than `level` (or console logging off) |
| Logging monitor | `logging_monitor` | Terminal-monitor level no more verbose than `level` |
| Logging trap | `logging_trap` | Syslog level at least as verbose as `level` |
| Logging host(s) | `logging_host` | Remote syslog server(s) are configured (whole-address match) |
| Logging source / origin-id | `logging_source_interface`, `logging_origin_id` | Source interface and origin-id type (and string) match |
| No SNMP public | `snmp_no_community_public` | Default "public" community is removed |
| No SNMP private | `snmp_no_community_private` | Default "private" community is removed |
| SNMPv3 only | `snmp_v3_only` | Only SNMPv3 with priv is configured |
| Banner login | `banner_login` | Login banner is present (legal warning) |
| Enable secret | `enable_secret` | Uses `enable secret` not `enable password` |
| No enable password | `no_enable_password` | Type-0/7 enable password is removed |
| Username secret | `username_secret` | All local users use `secret` not `password` |
| VTY SSH only | `vty_transport_input_ssh` | Telnet is disabled on VTY lines |
| VTY exec timeout | `vty_exec_timeout` | Idle timeout ≤ configured max |
| VTY access class | `vty_access_class` | The named ACL is applied inbound (`access-class <acl> in`) |
| VTY / console login authentication | `vty_login_authentication`, `console_login_authentication` | The line uses `method_list` (`default` also passes when the default list applies implicitly) |
| VTY logging sync | `vty_logging_synchronous` | Log messages don't interrupt typing |
| Console exec timeout | `console_exec_timeout` | Console idle timeout |
| Console logging sync | `console_logging_synchronous` | Console logging synchronous |
| Login block-for | `login_block_for` | Lockout at least as strict as `seconds`/`attempts`/`within` |
| Login delay | `login_delay` | Delay between attempts ≥ `seconds` |
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
| STP priority | `stp_priority` | Access switches never below `access_priority` (can't win root); `core_roles` at or below `core_priority` |
| STP BackboneFast / UplinkFast | `stp_backbonefast`, `stp_uplinkfast` | Present under PVST+; SKIP under rapid-pvst/MST, where they have no effect |
| VTP mode | `vtp_mode` | VTP set to transparent (or off) |
| VTP domain | `vtp_domain` | Domain from `show vtp status` matches `expected` (any domain if blank) |
| DHCP snooping global | `dhcp_snooping_global` | `ip dhcp snooping` is enabled |
| DHCP snooping VLANs | `dhcp_snooping_vlans` | Snooping is active for specific VLANs |
| DAI VLANs | `arp_inspection_vlans` | Dynamic ARP Inspection is active for VLANs |
| DAI validation | `arp_inspection_validate` | Every validation listed in `checks` is enabled |
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
| Port security | `port_security` | Access only | Enabled, plus max MAC, violation mode and aging (IOS defaults when a line is absent) |
| Trunk VLAN pruning | `trunk_allowed_vlans` | Trunk | Trunk does not allow ALL VLANs |
| Explicit mode | `switchport_mode_explicit` | Access + Trunk | No dynamic desirable/auto |
| Access VLAN | `access_vlan_set` | Access | Not using VLAN 1 for data |
| Interface description | `interface_description` | Active ports | Description is present |
| DHCP snooping trust | `dhcp_snooping_trust` | All switchports | Trust present where required, and **absent** on access/endpoint/unused ports |
| DHCP snooping rate limit | `dhcp_snooping_limit_rate` | Access | Rate limit present and no looser than `rate` |
| DAI trust | `arp_inspection_trust` | All switchports | Trust present where required, and **absent** on access/endpoint/unused ports |
| Unused port hardening | `unused_ports` | Unused | Shutdown, parking VLAN, no CDP/LLDP, BPDU guard, description |
| No CDP on access | `no_cdp_on_access_ports` | Access | CDP disabled on user-facing ports |
| Trunk native VLAN | `trunk_native_vlan` | Trunk | Native VLAN is non-default |

### Compliance Framework Mapping

Every check that maps to a published compliance standard carries a `framework_controls` block in YAML. Use this to generate framework-scoped reports and to filter audits to only the checks relevant to a specific standard.

**Supported frameworks:**

| Framework | Key | Example control ID |
| ---------- | ---- | ------------------- |
| CIS Cisco IOS XE Benchmark v4 | `cis_ios_xe_v4` | `"2.2.1"` |
| PCI DSS v4.0 | `pci_dss_v4` | `"2.3.1"` |
| NIST SP 800-53 Rev 5 | `nist_800_53r5` | `"SC-8"` |

**YAML example (in any check definition):**

```yaml
ssh_version:
  enabled: true
  severity: critical
  tags: [hardening, cis, pci, nist]
  framework_controls:
    cis_ios_xe_v4: "3.3.1"
    pci_dss_v4: "2.3.1"
    nist_800_53r5: "SC-8"
```

**Filtering to a specific framework:**

```bash
# Show only CIS-mapped findings
python -m compliance_audit --framework cis

# Show findings from both CIS and PCI
python -m compliance_audit --framework cis pci

# Combine with severity filter
python -m compliance_audit --framework pci --min-severity high
```

The filter does a **partial key match** — `--framework cis` matches `cis_ios_xe_v4`, `--framework pci` matches `pci_dss_v4`, etc. Findings with no `framework_controls` entries are reported as `SKIP` when `--framework` is active.

**Reports:** Framework control IDs appear as coloured pills in HTML reports (tooltip shows the full key name) and as a `framework_controls` column in CSV and JSON output.

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

When policy exceptions are configured, the summary gains an **Exc** column (with an `(N expired)` marker) and a *Policy Exceptions* panel lists expired and soon-to-expire exceptions, plus any that matched nothing — see [Where Exceptions Show Up](#where-exceptions-show-up).

### CSV Report

Tabular summary of all findings across all devices, suitable for spreadsheet analysis or integration with other tools. Includes `severity`, `tags`, and `framework_controls` columns for each finding (framework controls formatted as `cis_ios_xe_v4:5.1.1|pci_dss_v4:1.2.5`), plus `exception_id`, `exception_state`, `exception_expires`, `exception_reason`, `exception_owner` and `exception_ticket` for findings covered by a policy exception. Enable with `csv_report: true` in the config or `--csv` on the CLI.

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
      "framework_controls": {
        "cis_ios_xe_v4": "5.1.1",
        "pci_dss_v4": "1.2.5"
      },
      "remediation": "spanning-tree bpduguard enable"
    },
    {
      "check": "bpdu_guard",
      "status": "EXCEPTION",
      "detail": "GigabitEthernet1/0/48: BPDU guard missing (access port)",
      "interface": "GigabitEthernet1/0/48",
      "remediation": "spanning-tree bpduguard enable",
      "exception": {
        "id": "EXC-0001",
        "state": "expired",
        "expires": "2026-09-30",
        "days_remaining": -36,
        "original_status": "FAIL",
        "reason": "Uplink to customer-managed switch",
        "owner": "Network Engineering",
        "ticket": "CHG0012345",
        "source": "exceptions.yaml"
      }
    }
  ]
}
```

Findings with `"status": "EXCEPTION"` keep their `remediation` text for reference only — nothing in the tool ever applies it. The top-level `exception`, `exception_expired` and `exception_expiring` fields count covered findings, and `exceptions.unused` lists exceptions scoped to the device that matched nothing.

### HTML Report

Self-contained HTML reports with a dark-themed dashboard. Two types are generated:

**Per-device report** — Stat cards showing score/pass/fail/warn/error, findings grouped by category, status filter buttons (All / Fail / Warn / Pass), and a search box to find specific checks. When policy exceptions apply, it also shows Exceptions / Expired exceptions stat cards and filter buttons, and a *Policy exceptions on this device* table with expired exceptions highlighted at the top.

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
- An **Exception register** (when exceptions are configured) — every exception with its state, scope, owner/ticket, findings covered and devices; expired and expiring ones first, behind a review banner

All reports are saved to the `output_dir` (default `./reports/`) with filenames like:

```text
reports/ZZ-LAB1-001ASW001_20260308_143025.json
reports/ZZ-LAB1-001ASW001_20260308_143025.html
reports/ZZ-LAB1-001ASW001_remediation_20260308_143025.txt
reports/ZZ-LAB1-001ASW002_20260308_143025.html
reports/consolidated_report_20260308_143025.html
reports/compliance_audit_20260308_143025.csv
reports/ZZ-LAB1-001ASW001_review_16c8a31c5d0b.json
reports/report_artifacts_index.json
reports/runs/audit-20260308T143025123456Z.json
reports/db/remediation_reviews.db
```

`output_dir` is resolved to an absolute path at the start of a run and printed
in the audit summary, along with the remediation review database. The database
lives at `<output_dir>/db/remediation_reviews.db` and is created on every run
where `audit_settings.remediation.generate_review_pack` is true — even when
there is nothing to remediate. `--remediation-list` reports the same path when
it finds no packs, so you can always confirm which database is in use.

The `report_artifacts_index.json` file is maintained as reports are generated and includes report type, run identifier, MIME type, and report path metadata (including HTML artifacts for portal embedding).

### Web Integration Helpers

For backend integrations, the package now exposes Python wrappers and safe report-serving helpers:

```python
from compliance_audit import (
    list_review_packs_api,
    approve_review_pack_api,
    reject_review_pack_api,
    apply_all_approved_packs_api,
    load_report_artifact_index,
    read_report_content,
)

# Remediation lifecycle operations as dict payloads
packs = list_review_packs_api("./reports", status="pending")
approved = approve_review_pack_api("./reports", "PACK_ID", "web.user", "CHG0012345")
rejected = reject_review_pack_api("./reports", "PACK_ID", "web.user", "Rejected reason")

# Bulk apply (respects server-side policy gates in config)
apply_results = apply_all_approved_packs_api("assets/compliance_config", "./reports")

# Report metadata + safe HTML content load for portal embedding
index = load_report_artifact_index("./reports")
html_payload = read_report_content("./reports", "consolidated_report_20260308_143025.html")
mime = html_payload["mime_type"]       # text/html
html = html_payload["content_text"]    # decoded HTML for embedding
```

### Port trust placement (DHCP snooping / DAI)

Cisco's guidance is to trust only the interfaces that lead to the DHCP server
and to leave every host-facing port untrusted — a trusted access port is exempt
from snooping and DAI validation, which is exactly where a rogue DHCP server or
ARP spoofer would sit. `dhcp_snooping_trust` and `arp_inspection_trust` enforce
both halves, and both are driven from `data_plane.yaml`:

```yaml
dhcp_snooping_trust:
  enabled: true
  on_uplinks: true             # "ip dhcp snooping trust" must be PRESENT
  on_downlinks: false
  on_endpoint_trunks: false
  on_unknown_trunks: false
  on_access_ports: false
  on_unused_ports: false
  untrusted:                   # "ip dhcp snooping trust" must be ABSENT
    access_ports: true
    endpoint_trunks: true
    unused_ports: true
    unknown_trunks: false
    downlinks: false
    uplinks: false
```

Port kinds are `access_ports`, `uplinks`, `downlinks`, `unknown_trunks`,
`endpoint_trunks` and `unused_ports`. A kind listed under both `on_<kind>` and
`untrusted` is treated as required. Kinds left out of both produce no finding,
which is why `unknown_trunks` defaults to silent — the tool will not guess the
direction of a trunk it could not classify. Violations remediate to
`no ip dhcp snooping trust` / `no ip arp inspection trust`.

### Delta / Drift Reports

With `delta_report: true`, every run is compared against the previous JSON report
for the same device and a `<hostname>_delta_<timestamp>.json` file is written:

| Section | Meaning |
| --- | --- |
| `resolved` | Was FAIL or WARN, now PASS |
| `new_failures` | Was PASS or absent, now FAIL or WARN |
| `unchanged_fails` | Still failing |
| `excepted` | Was FAIL or WARN, now covered by a [policy exception](#policy-exceptions) (`EXCEPTION`) — not counted as resolved |

A short delta summary also prints in the console after the audit table.

Delta needs `json_report: true` — the per-device JSON report *is* the baseline.
If `delta_report` is on while `json_report` is off, the run warns that no drift
can ever be detected rather than silently producing nothing:

```text
Warning: delta reporting is enabled but json_report is off — per-device JSON
reports are the baseline, so no drift will ever be detected.
```

This is the closure evidence for a change: audit, remediate, re-audit, and the
delta shows exactly what the change achieved.

### Remediation Scripts

For each device with FAIL findings, a ready-to-paste IOS-XE config snippet is generated. The script:

- Groups commands into global configuration and per-interface blocks
- Targets Port-channel interfaces for port-channel members (not individual member ports)
- Deduplicates commands and ends with `write memory`
- Never includes a finding covered by a [policy exception](#policy-exceptions), active or expired

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

Each audit run tags its review packs with the run ID, so a whole run can be approved, scheduled or rejected in one command — see [Approving or Rejecting a Run](#approving-or-rejecting-a-run). When a device is audited again, any of its packs still `pending` from an earlier run become `superseded`: they were written against an older configuration and can no longer be approved. Approved packs are left alone (the preflight drift check guards them).

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
- **Schedule**: A pack approved with `--apply-at` is refused until its time, and `--remediation-apply-all` skips it; `--remediation-apply-due` applies it when due
- **Policy exceptions**: Items covered by an exception in force *now* — active or expired — are dropped before connecting, even from packs approved before the exception existed; if every item is covered the apply aborts. The result reports `skipped_for_exceptions`

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
  "skipped_for_exceptions": 0,
  "device_output_preview": "..."
}
```

##### Configuration

Control remediation workflow behavior in `assets/compliance_config/audit_settings.yaml`:

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

## Scheduled Audits and Email Approval

Run the audit unattended on a Linux host, email the result to whoever approves changes, and let them approve the whole run — to apply now or at a time they choose — or reject it, with one command on the host.

### How It Works

```text
01:30  timer ─► audit ─► run manifest + review packs (tagged with the run ID)
                      └─► email: proposed changes per switch, risk, new failures,
                          unreachable devices, expired exceptions, and the commands:

     --run-approve RUN_ID --approver NAME --ticket-id ID --apply-now
     --run-approve RUN_ID --approver NAME --ticket-id ID --apply-at "2026-11-07 02:00"
     --run-reject  RUN_ID --approver NAME --reason TEXT

every 5 min  timer ─► --remediation-apply-due ─► applies packs whose time has come
                                              └─► email: what was applied, what failed
```

Every audit run writes a **run manifest** to `<output_dir>/runs/<run_id>.json`: devices and scores, devices that could not be audited (and why), the review pack for each device, expired exceptions and report paths. `--run-list` and `--run-show RUN_ID` read it together with the live pack states.

### Setting It Up

`deploy/README.md` has the step-by-step install: a service account, the virtual environment, credentials in `.env` (mode 600), systemd units for the nightly audit and the 5-minute apply check (`deploy/systemd/`), and the cron equivalent. In short:

```bash
# 1. notifications.yaml: enabled: true, smtp_host, from_address, to (see below)
python -m compliance_audit --notify-test                   # check mail delivery
python -m compliance_audit --dry-run --non-interactive     # check credentials and reachability
# 2. enable the timers
sudo cp deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cisco-compliance-audit.timer cisco-compliance-audit-apply.timer
```

Remediation execution must be enabled (`audit_settings.remediation.execution.enabled: true`) for approved runs to be applied. Execution is Linux-only by default.

### Email Settings

`assets/compliance_config/notifications.yaml` (shipped disabled):

```yaml
notifications:
  email:
    enabled: true
    smtp_host: smtp-relay.corp.example.com
    smtp_port: 25                   # 25/587 STARTTLS, 465 ssl
    security: starttls              # starttls | ssl | none
    username: ""                    # SMTP AUTH user if needed; password from SMTP_PASSWORD
    from_address: compliance-audit@corp.example.com
    to: [netops@corp.example.com]
    cc: []
    send_when: always               # always | issues | action_required
    notify_on_apply: true
    notify_on_failure: true
    attach_report: true             # the consolidated HTML report
    attach_scripts: true            # each pending pack's remediation script
    max_attachment_mb: 10
    max_findings_per_device: 100    # rows per device in the email body (0 = all)
    command: "sudo -u netaudit /opt/cisco-compliance-audit/.venv/bin/python -m compliance_audit"
```

| Setting | Meaning |
| --- | --- |
| `security` | `starttls` (default) upgrades the connection; `ssl` uses TLS from the start; `none` only on a trusted network |
| `username` | Only if the relay needs a login; the password is read from `SMTP_PASSWORD` (environment or `.env`), never from YAML |
| `send_when` | `always`; `issues` — anything not fully compliant, unreachable devices or expired exceptions; `action_required` — packs awaiting approval, unreachable devices, ERROR findings or expired exceptions |
| `command` | How approvers run the tool on the host. It is shown in the email's commands, together with the run's exact `-c` config and `-o` output directory so they act on the same review database. Blank = the Python that ran the audit |
| `max_attachment_mb` | Total attachment budget. Scripts are attached first (small, and exactly what would be pushed), then the report; anything that does not fit is listed in the email with its path on the host |

Validation (`--validate-config`) checks the block like the rest of the config: an enabled email with no relay, sender or recipients, malformed addresses and unknown keys are errors.

### What the Email Contains

The body is email-safe HTML (inline styles, no scripts, renders in Outlook and webmail) with a plain-text alternative, and holds everything needed to decide:

- **Totals** — devices audited and unreachable, score, FAIL/WARN/ERROR, exceptions (expired), packs.
- **Decision required** — how many packs await approval and how many are high risk, the approval window, and the approve-now / approve-at-time / reject / leave-one-device-out commands ready to paste. If execution is disabled in config, it says so.
- **Proposed changes** — per switch: risk, score, every finding with its exact command and risk, and the configuration block that would be sent. Findings covered by policy exceptions are noted as excluded. If a change for the switch from an earlier run is already approved or scheduled, it says so.
- **New since the previous run** (from the delta report), **devices not audited** with the reason, **policy exceptions needing review** (expired or expiring), and **devices with no remediation proposed**.
- **Attachments** — the remediation script for each pending pack and the interactive consolidated report.

The interactive HTML report cannot be the body itself — mail clients strip its JavaScript and styles — so it travels as an attachment.

### Approving or Rejecting a Run

On the audit host (the email shows the exact commands):

```bash
python -m compliance_audit --run-list                      # recent runs and their state
python -m compliance_audit --run-show RUN_ID               # devices, scores, packs

# Approve every pending pack in the run and apply immediately
python -m compliance_audit --run-approve RUN_ID --approver "Jo Bloggs" --ticket-id CHG0012345 --apply-now

# ... or apply at a set time (host local time; 'HH:MM' = next occurrence)
python -m compliance_audit --run-approve RUN_ID --approver "Jo Bloggs" --ticket-id CHG0012345 --apply-at "2026-11-07 02:00"

# Reject the run
python -m compliance_audit --run-reject RUN_ID --approver "Jo Bloggs" --reason "Out of change window"

# Leave one switch out: reject its pack, then approve the run
python -m compliance_audit --remediation-reject PACK_ID --approver "Jo Bloggs" --reason "Site freeze"
```

- Approving without `--apply-now` / `--apply-at` approves only; apply later with `--remediation-apply`.
- **High-risk packs** (AAA, TACACS/RADIUS, SNMP, routing, ACL, control plane) are skipped unless the approval includes `--allow-high-risk`. The allowance is recorded on the pack, so a scheduled apply — which runs with nobody to pass the flag — honours it.
- `--run-approve` shows the run and asks for confirmation; add `--remediation-no-confirm` to skip it. In a non-interactive run the confirmation is refused rather than skipped.
- Re-running `--run-approve` on an approved run changes its schedule (or switches it to `--apply-now`).
- A run whose packs were **superseded** by a newer audit cannot be approved — approve the newer run.
- `--remediation-output json` gives machine-readable results for every run command.

### Scheduled Apply

`--remediation-apply-due` applies every approved pack whose scheduled time has passed, then emails the result (`notify_on_apply`). Run it every few minutes; with the shipped timer a change scheduled for 02:00 is applied at the first check at or after 02:00.

- The approval window (`approval.default_expires_hours`) starts at the scheduled time, so a change scheduled for next week does not expire before it is due. A check that runs late (host down) still applies it within the window.
- Before the scheduled time, `--remediation-apply PACK_ID` refuses the pack and `--remediation-apply-all` skips it.
- Every other apply gate still applies at the scheduled time: checksum, device identity, preflight drift check, policy exceptions, and the high-risk block (unless allowed on approval).

### Unattended Operation

- `--non-interactive` never prompts. Missing credentials (no `SWITCH_USER`/`SWITCH_PASS` in the environment or `.env`, nothing in the keyring) fail immediately with exit code `2` instead of waiting for input. Without a terminal attached the prompt is skipped anyway.
- If a scheduled audit with `--notify` cannot run — invalid config, empty inventory, missing credentials — a **failure email** is sent (`notify_on_failure`).
- An audit holds `<output_dir>/.locks/audit.lock` and applies hold `.locks/apply.lock`, so a run that is still going makes the next one stop at once (exit `2`) instead of interleaving.
- Exit code `1` from the audit means "devices have findings"; the shipped systemd unit treats it as success (`SuccessExitStatus=1`). `2` means it could not run.

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
├── pyproject.toml                  # Canonical package metadata and version
├── compliance_audit/
│   ├── __about__.py                # Package metadata (name, author, licence)
│   ├── __init__.py                 # Package exports and dynamic version
│   ├── __main__.py                 # CLI entry point (python -m compliance_audit)
│   ├── ...
├── assets/
│   ├── compliance_config/          # ★ Compliance policy (split YAML files)
│   │   ├── audit_settings.yaml     # Concurrency, timeouts, ROI, output paths
│   │   ├── connection.yaml         # SSH, jump host, credentials, host key policy
│   │   ├── classification.yaml     # Inventory path, hostname roles, endpoint detection
│   │   ├── management_plane.yaml   # SSH, AAA, NTP, logging, SNMP, VTY checks
│   │   ├── control_plane.yaml      # STP, VTP, DHCP snooping, DAI checks
│   │   ├── data_plane.yaml         # Per-interface checks (BPDU guard, storm control…)
│   │   ├── exceptions.yaml         # Policy exceptions — approved deviations with expiry
│   │   └── notifications.yaml      # SMTP email for scheduled audits
│   ├── devices/
│   │   └── devices.yaml            # ★ Device inventory — hostnames and IPs
│   ├── auditor.py                  # Orchestrator (concurrent via ThreadPoolExecutor)
│   ├── cli_discovery.py            # CLI option table helper
│   ├── collector.py                # Data collection + Genie/TextFSM parsing
│   ├── checks/                     # Compliance checks, one module per policy section
│   │   ├── base.py                 # Result models, policy helpers, shared predicates
│   │   ├── control.py              # STP, VTP, DHCP snooping, DAI, errdisable, UDLD, CoPP
│   │   ├── data.py                 # Per-interface checks by port role
│   │   ├── management.py           # Services, SSH, AAA, NTP, logging, SNMP, VTY, console
│   │   └── role.py                 # Role-specific checks (access switches, …)
│   ├── compliance_engine.py        # Assembles the check mixins and drives a run
│   ├── config_schema.py            # Pydantic validation for the YAML config + check registry
│   ├── credentials.py              # Credential handler (.env / keyring / env / prompt)
│   ├── hostname_parser.py          # Hostname naming convention parser
│   ├── interactive_cli.py          # Guided wizard CLI (questionary)
│   ├── inventory_schema.py         # Pydantic models for devices.yaml and --device values
│   ├── jump_manager.py             # SSH jump host via Paramiko
│   ├── logging_setup.py            # Logging bootstrap (file + console handlers)
│   ├── netmiko_utils.py            # Netmiko connection wrapper
│   ├── notifications.py            # SMTP email: run summary, apply result, failure, test
│   ├── policy_exceptions.py        # Policy exception register: matching, expiry, run summaries
│   ├── port_classifier.py          # Interface role classification + EtherChannel detection
│   ├── remediation.py              # Remediation script generation
│   ├── remediation_cli.py          # Remediation CLI helpers
│   ├── remediation_workflow.py     # Approval lifecycle workflow
│   ├── report.py                   # Rich console + interactive HTML + JSON + CSV reports
│   ├── run_cli.py                  # --run-list / --run-show rendering
│   ├── runs.py                     # Run manifests, run approve/reject, schedule parsing, locks
│   ├── schema_types.py             # Shared Pydantic field types (IP/hostname, VLANs, regex)
│   ├── textual_app.py              # Full-screen 3-screen Textual TUI
│   └── version.py                  # Version reader (pyproject.toml)
├── assets/
│   └── config_files/
│       └── logging.conf            # INI logging configuration
├── deploy/
│   ├── README.md                   # Scheduled audits on a Linux host: install, timers, cron
│   └── systemd/                    # Nightly audit + 5-minute scheduled-apply service/timer units
├── docs/
│   ├── RUNBOOK.html                # Operator runbook (rendered HTML)
│   └── RUNBOOK.md                  # Operator runbook (Markdown source)
├── logs/                           # Runtime log files (gitignored; .gitkeep tracked)
├── reports/                        # Default report output directory (gitignored; .gitkeep tracked)
├── scripts/
│   └── render_runbook.py           # Renders RUNBOOK.md → RUNBOOK.html
├── tests/
│   ├── test_annotate_findings.py
│   ├── test_config_paths.py
│   ├── test_dhcp_snooping_vlans.py
│   ├── test_hostname_parser.py
│   ├── test_inventory.py
│   ├── test_management_plane_checks.py  # SNMP / AAA / SSH / VTY / console
│   ├── test_policy_exceptions.py        # Exception matching, expiry, reports, never-remediate
│   ├── test_scheduled_runs.py           # Run manifests, run approval, scheduled apply, email
│   ├── test_port_trust.py               # DHCP snooping + DAI trust placement
│   ├── test_remediation_workflow.py
│   └── test_version.py
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

1. **Add the check to the appropriate file in `assets/compliance_config/`** (e.g. `management_plane.yaml`):

    ```yaml
    management_plane:
      my_new_check:
        enabled: true
        severity: medium
        tags: [hardening]
        expected: "some expected config line"
    ```

2. **Add the check logic** inside the relevant `_check_*` method. Checks live in
   `compliance_audit/checks/`, one module per policy section — `management.py`,
   `control.py`, `data.py`, `role.py` — each a mixin that `ComplianceEngine`
   inherits. A management-plane check goes in `checks/management.py`:

    ```python
    if _enabled(mp, "my_new_check"):
        expected = mp.get("my_new_check", {}).get("expected", "")
        f.append(self._present(cfg, re.escape(expected),
                "my_new_check", expected, expected))
    ```

The `_present()` helper checks that a regex matches at least one global config line. The `_absent()` helper checks that a regex does NOT match (for "no X" checks).

### Adding a New Per-Interface Check

1. **Add it to `data_plane` in the YAML** with `enabled: true`
2. **Add the logic in `checks/data.py`** — `_check_access_port()`, `_check_trunk_port()`, or `_check_unused_port()` depending on which port types it applies to
3. Use `pi_has(pi, r"regex pattern")` to check if an interface has a specific config line, or `pi_has_command(pi, "exact command")` when the negated (`no …`) form must not count as present
4. Use `pi_int_arg(pi, r"command\s+(\d+)")` when the check needs the configured *value*, not just the command's presence

### Adding a New Device Role

Role codes are configured in the YAML — no code changes needed:

1. **Add the role** to `hostname_roles` in `assets/compliance_config/classification.yaml`:

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
| `Config directory not found` | The tool looks for the `assets/compliance_config` directory in the current directory, then at the project root. Use `--config` for a custom path. |
| Timeout on `show` commands | Increase `collect_timeout` in `audit_settings` or check device responsiveness. |
| Large devices with many interfaces slow to audit | This is expected — every interface is checked individually. Consider using `--categories` to focus on specific check groups. |
| Concurrent audits too slow / too fast | Adjust `max_workers` in `audit_settings`. Use `1` for sequential, or increase for more parallelism. |
| Want different policies per site | Copy the `assets/compliance_config/` directory, edit per-site files, and run with `-c configs/site_name`. Use `-i` for site-specific inventories. |
| Audit reports very few findings | Most checks ship `enabled: false`. Enable the ones your policy requires in the plane YAML files. |
| Reports are not where you expect | `output_dir` is relative to the working directory. Read the `Output directory:` line printed in the summary, or pass `--output-dir` explicitly. |
| `--remediation-list` finds nothing | Confirm the database path in the message matches the `Review database:` line from the audit. If you used `--output-dir` for the audit, use it for the remediation commands too. |
| Delta reports never appear | `json_report` is off — it is the delta baseline. Enable it, or set `delta_report: false` to silence the warning. |
| A check you enabled produces no findings | Check the spelling of the `enabled` key — a check runs only with `enabled: true`. Validation reports a missing or misspelt key. |
| `Config validation failed` before anything runs | Every config load is validated. Fix the listed keys — each line gives the full path, and near-misses get a "did you mean". Re-check with `--validate-config`. |
| `Inventory validation failed` | An inventory entry has a bad IP, an invalid hostname, or an unknown top-level/group key. The message names the entry, e.g. `groups.site_lab.devices[2]`. |
| Remediation apply refuses to run | Execution is Linux-only by default. Apply from Linux/WSL, or set `execution.linux_only: false` if your policy allows. |
| `engine_error` finding for a whole device | A check crashed. Run with `-vv` and check `logs/debug.log` for the traceback. |

---

## Testing

```bash
# Install the dev extras (pytest, yamllint)
pip install -e .[dev]

# Run the suite
pytest tests/ -q

# Lint the shipped YAML and validate it against the schema
yamllint assets/
python -m compliance_audit --validate-config
```

CI runs all three on every push and pull request, across Python 3.10, 3.11 and
3.12.

The check methods are pure functions of `(policy, ParsedConfig | PortInfo)`, so
they can be tested against a running-config snippet without a device. The
existing tests are the template:

| File | Covers |
| --- | --- |
| `tests/test_management_plane_checks.py` | SNMP, AAA, SSH, VTY, console — the highest-severity checks |
| `tests/test_port_trust.py` | DHCP snooping and DAI trust placement across every port kind |
| `tests/test_dhcp_snooping_vlans.py` | VLAN-aware snooping and DAI checks, VLAN range helpers |
| `tests/test_annotate_findings.py` | Severity, tags and the YAML-level role/hostname/group filters |
| `tests/test_policy_exceptions.py` | Exception schema, matching, expiry states, scoring, reports, and that excepted findings are never remediated (script, pack and apply time) |
| `tests/test_scheduled_runs.py` | Review-store migration, superseding, scheduling, run approve/reject, locks, email content and transport, and the full audit → email → approve → scheduled apply flow through the CLI |
| `tests/test_hostname_parser.py` | Hostname convention parsing and role detection |
| `tests/test_inventory.py` | Inventory loading, flat lists and site groups |
| `tests/test_remediation_workflow.py` | Remediation settings resolution |
| `tests/test_config_paths.py` | Config directory resolution |

A worked example — one check, one config snippet, one assertion:

```python
def test_ssh_plus_telnet_fails(self):
    # "transport input ssh telnet" still permits telnet
    findings = run_check(
        "_check_vty_lines",
        "line vty 0 4\n transport input ssh telnet\n",
        vty_transport_input_ssh={},
    )
    assert one(findings, "vty_transport_ssh").status == Status.FAIL
```

When adding a check, test the case where a **non-compliant device could be
reported as PASS**. That is the failure mode that matters: a crash is obvious,
a false PASS is not.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-check`)
3. Add your check to both the YAML config and the relevant module in `compliance_audit/checks/`
4. Add tests — at minimum, the compliant case, the non-compliant case, and the case where the check could wrongly pass
5. Run `pytest tests/ -q`, `yamllint assets/` and `python -m compliance_audit --validate-config`
6. Test against a lab device or saved config
7. Submit a pull request

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Free to use, modify and redistribute. If you'd like it tailored, deployed or extended for your estate, see [Work With Me](https://www.nautomationprime.io/work-with-me/).
