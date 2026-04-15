# Cisco Compliance Audit Runbook

This runbook is for operators who need to run audits and remediation safely.

For deep technical detail, see [README.md](../README.md).

Other formats:
- [RUNBOOK.html](RUNBOOK.html) for browser viewing
- [RUNBOOK.txt](RUNBOOK.txt) for basic text editors

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

1. Confirm config and inventory files are correct.
2. Confirm credentials are available (keyring, env vars, or prompt).
3. Confirm remediation execution policy in config if you plan to apply changes.
4. If you track automation value, enable ROI settings in audit_settings.roi.

Example config path:
- compliance_audit/compliance_config.yaml

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

# Run audit with specific config
python -m compliance_audit -c configs/site_london.yaml

# Run audit for a single device
python -m compliance_audit --device GB-SITE1-001ASW001:10.1.1.1

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

Full-screen premium terminal UI:

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

- `1` launch guided wizard mode
- `2` run quick audit using default settings
- `3` focus the CLI options table
- `q` quit the full-screen TUI

Tip:
- From the options table, use your terminal arrow keys to scroll rows.

### 1) Run Audit

```bash
python -m compliance_audit -c compliance_audit/compliance_config.yaml
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

### 4) Dry-Run Before Apply (Recommended)

Single pack preflight:

```bash
python -m compliance_audit --remediation-apply <PACK_ID> --apply-dry-run
```

Apply-all preflight:

```bash
python -m compliance_audit --remediation-apply-all --apply-dry-run
```

### 5) Apply Changes

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

### 6) Post-Apply Verification

```bash
python -m compliance_audit --remediation-list applied
python -m compliance_audit --remediation-list failed
```

Optional: rerun audit for confirmation.

```bash
python -m compliance_audit -c compliance_audit/compliance_config.yaml
```

## Safety Rules

1. Do not use remediation apply during unauthorized change windows.
2. Always use --apply-dry-run before production apply.
3. Do not approve packs without reviewing risk and ticket alignment.
4. Treat --allow-high-risk as exception-only with explicit approval.
5. Prefer --remediation-apply-all only after queue review.

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
4. Preflight dry-run.
5. Apply (single or all).
6. Verify applied/failed status.
7. Rerun audit for closure evidence.
