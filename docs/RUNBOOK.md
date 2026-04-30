# Cisco Compliance Audit Runbook

This runbook is for operators who need to run audits and remediation safely.

For deep technical detail, see [README.md](../README.md).

Other formats:
- [RUNBOOK.html](RUNBOOK.html) for browser viewing

To regenerate the HTML copy after editing this file:

```bash
python scripts/render_runbook.py
```

## Scope

Use this guide to:
- Run compliance audits
- Review remediation packs
- Approve or reject packs
- Apply one approved pack
- Apply all approved packs
- Run guided interactive workflows without memorizing flags

This guide assumes you have network reachability to devices and can run commands
from a shell (for example Linux, WSL, or Windows PowerShell).

## Pre-Checks (Start Here)

**Starting the tool:**

- **Windows:** Run `run.bat` (or double-click it) — handles the Python runtime and launches the TUI automatically.
- **Linux / WSL:** Run `./run.sh` — activates the virtual environment and launches the TUI.
- **Manual:** `python -m compliance_audit --tui` or `python -m compliance_audit` from an activated environment.

1. Confirm config and inventory files are correct. Config directory: `compliance_audit/compliance_config/`
2. Confirm credentials are available — options in order of precedence: `.env` file → OS keyring → environment variables (`SWITCH_USER` / `SWITCH_PASS`) → interactive prompt. Copy `.env.example` to `.env` for a convenient credential file.
3. Confirm remediation execution policy in `audit_settings.yaml` if you plan to apply changes.
4. If you track automation value, enable ROI settings in `audit_settings.roi`.

## Optional ROI Setup

If you want reports to show estimated time saved/value saved, enable ROI in config:

```yaml
audit_settings:
  roi:
    enabled: true
    manual_minutes_per_device: 20.0
    manual_minutes_per_check: 0.25
    automation_overhead_minutes_per_device: 2.0
    hourly_rate: 85.0
    currency: "GBP"
```

Interpretation:
- Minutes saved = estimated manual effort minus automated effort
- Value saved = hours saved multiplied by hourly_rate

ROI appears in:
- Console summary (run-level estimate)
- Per-device JSON report under roi
- Per-device HTML stat cards
- Consolidated HTML stat cards and summary line

## Common Command Templates

```bash
# Run full audit from default config
python -m compliance_audit

# Run audit with specific config directory
python -m compliance_audit -c configs/site_alpha

# Run audit for a single device
python -m compliance_audit --device ZZ-LAB1-001ASW001:192.0.2.61

# Audit only devices in a specific site group (from the grouped inventory)
python -m compliance_audit --site site_lab

# Audit devices across multiple site groups
python -m compliance_audit --site site_lab site_brn

# Use a separate per-site inventory file instead
python -m compliance_audit -i devices/site_brn.yaml

# Surface only high-severity findings
python -m compliance_audit --min-severity high

# Surface only CIS or PCI-tagged findings
python -m compliance_audit --tags cis pci

# Combine severity and tag filters
python -m compliance_audit --min-severity high --tags cis pci

# Launch guided interactive wizard
python -m compliance_audit --interactive

# Launch full-screen premium TUI
python -m compliance_audit --tui

# Show all available CLI options in a table
python -m compliance_audit --list-options

# List remediation packs
python -m compliance_audit --remediation-list

# List only pending remediation packs
python -m compliance_audit --remediation-list pending

# List remediation packs as JSON (for automation)
python -m compliance_audit --remediation-list all --remediation-output json

# List remediation packs as CSV, sorted by risk, with a limit
python -m compliance_audit --remediation-list all --remediation-output csv --remediation-sort risk --remediation-limit 50

# Approve one pack
python -m compliance_audit --remediation-approve <PACK_ID> --approver "john.doe" --ticket-id "CHG0012345"

# Reject one pack
python -m compliance_audit --remediation-reject <PACK_ID> --approver "john.doe" --reason "Reason text"

# Apply one approved pack
python -m compliance_audit --remediation-apply <PACK_ID>

# Apply all approved packs
python -m compliance_audit --remediation-apply-all
```

## Standard Operating Procedure

### 0) Choose Operator Experience

Guided wizard mode (recommended for discoverability):

```bash
python -m compliance_audit --interactive
```

Full-screen 3-screen terminal UI:

```bash
python -m compliance_audit --tui
```

Command discovery table (all argparse options):

```bash
python -m compliance_audit --list-options
```

Notes:
- Use `--interactive` when you want prompts and command previews.
- Use `--tui` when you want a full-screen dashboard and keyboard-driven navigation.
- Use standard flags for CI/automation and scripted operations.

#### Textual Keyboard Cheat Sheet

When running `python -m compliance_audit --tui`:

The TUI is a 3-screen application:

1. **Setup screen** — fill in config directory, inventory path, device overrides, categories, output directory, and credentials, then click **Start Audit**
2. **Audit screen** — live statistics panel (devices, completed, compliant, failures, warnings, errors) with a scrollable real-time log stream
3. **Complete screen** — summary of totals across all devices with **Back to Log** and **Quit** buttons

Key bindings (all screens):

- `Ctrl+Q` — quit the application at any point

### 1) Run Audit

```bash
# Full audit using default config directory
python -m compliance_audit

# Audit with optional filters
python -m compliance_audit --min-severity high
python -m compliance_audit --tags cis pci
python -m compliance_audit --categories management_plane
```

Expected outcome:
- Reports are generated in output_dir
- Remediation scripts and review packs are generated for failing findings

### 2) Review Pack Queue

```bash
python -m compliance_audit --remediation-list pending
```

Decide per pack:
- Approve if safe and in scope
- Reject if risky, out of policy, or outside change window

### 3) Approve Packs

Approve one:

```bash
python -m compliance_audit --remediation-approve <PACK_ID> \
  --approver "john.doe" \
  --ticket-id "CHG0012345"
```

Approve all pending with confirmation:

```bash
python -m compliance_audit --remediation-approve-all \
  --approver "john.doe" \
  --ticket-id "CHG0012345"
```

Notes:
- Ticket ID is required by default and controlled by config:
  audit_settings.remediation.approval.require_ticket_id
- Use --expires-hours to override default expiry.

### 4) Apply Changes

Apply one approved pack:

```bash
python -m compliance_audit --remediation-apply <PACK_ID>
```

Apply all approved packs:

```bash
python -m compliance_audit --remediation-apply-all
```

If high-risk packs are blocked and change authority allows it:

```bash
python -m compliance_audit --remediation-apply <PACK_ID> --allow-high-risk
python -m compliance_audit --remediation-apply-all --allow-high-risk
```

### 5) Post-Apply Verification

```bash
python -m compliance_audit --remediation-list applied
python -m compliance_audit --remediation-list failed
```

Optional: rerun audit for confirmation.

```bash
python -m compliance_audit
```

## Safety Rules

1. Do not use remediation apply during unauthorized change windows.
2. Do not approve packs without reviewing risk and ticket alignment.
3. Treat --allow-high-risk as exception-only with explicit approval.
4. Prefer --remediation-apply-all only after queue review.

## Troubleshooting Quick Table

| Symptom | Likely Cause | Action |
| --- | --- | --- |
| Remediation workflow disabled error | remediation.enabled false | Enable audit_settings.remediation.enabled |
| Execution disabled error | execution.enabled false | Enable audit_settings.remediation.execution.enabled |
| Approval expired | TTL passed | Re-run audit, generate new pack, approve again |
| Checksum mismatch | Script changed after approval | Re-run audit and approve fresh pack |
| High-risk blocked | Policy enforcement active | Use --allow-high-risk only with approval |
| Hostname mismatch | Prompt does not match approved host | Verify target device identity and inventory |

## Escalation and Rollback

If apply fails or behavior is unexpected:
1. Stop additional apply actions.
2. Capture pack ID, device, and error output.
3. Check remediation execution log in output_dir.
4. Escalate to network engineering/change manager.
5. Use your standard network rollback procedure for the affected device/site.

## Daily Checklist

1. Run audit.
2. Review pending queue.
3. Approve/reject with ticket mapping.
4. Apply (single or all).
5. Verify applied/failed status.
6. Rerun audit for closure evidence.
