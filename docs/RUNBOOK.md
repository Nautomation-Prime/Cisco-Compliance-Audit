# Cisco Compliance Audit Runbook

Operator guide for running compliance audits and applying remediation safely on
Cisco IOS-XE access switches.

For architecture, the full check catalogue and configuration reference, see
[README.md](../README.md). This runbook covers *how to run it*; the README
covers *how it works*.

Other formats:
- [RUNBOOK.html](RUNBOOK.html) for browser viewing

To regenerate the HTML copy after editing this file:

```bash
python scripts/render_runbook.py
```

## Contents

- Scope and assumptions
- Quick reference card
- Before your first run
- Pre-flight checks
- Credentials
- Running an audit
- Where the output goes
- Reading the results
- Port trust placement (DHCP snooping / DAI)
- Drift and delta reporting
- Policy exceptions
- Remediation lifecycle
- Scheduled audits and email approval
- ROI reporting
- Web backend integration
- Configuration quick reference
- Safety rules
- Troubleshooting
- Escalation and rollback
- Checklists
- Appendix A: exit codes
- Appendix B: output file naming
- Appendix C: glossary

## Scope and Assumptions

Use this guide to:
- Run compliance audits against IOS-XE access switches
- Interpret findings, scores and reports
- Review, approve and reject remediation packs
- Apply approved packs, singly or in bulk
- Verify the result and produce closure evidence

This guide assumes you have network reachability to the devices (directly or via
the configured jump host) and can run commands from a shell.

**This release targets Cisco IOS-XE access switches.** Checks, port
classification and remediation commands are written for that platform and role.

**Remediation *execution* is Linux-only by default.** Auditing, reviewing and
approving work on any platform, but `--remediation-apply` refuses to run
anywhere other than Linux unless `execution.linux_only` is set to `false`. On
Windows, expect to audit and approve locally and apply from Linux or WSL.

## Quick Reference Card

```bash
# Health and config checks — do these first, they touch no devices
python -m compliance_audit --health
python -m compliance_audit --validate-config            # also lists expired/expiring exceptions
python -m compliance_audit --dry-run

# Audit
python -m compliance_audit                              # whole inventory
python -m compliance_audit --device SW1:192.0.2.61      # one device
python -m compliance_audit --site site_lab              # one site group
python -m compliance_audit --ip-filter 192.0.2.0/24      # one IP range
python -m compliance_audit --min-severity high          # high and above only
python -m compliance_audit --tags cis pci               # CIS or PCI findings
python -m compliance_audit --framework cis              # only CIS-mapped checks
python -m compliance_audit --categories management_plane

# Guided and full-screen modes
python -m compliance_audit --interactive                # prompted wizard
python -m compliance_audit --tui                        # full-screen dashboard
python -m compliance_audit --list-options               # every flag, in a table

# Remediation lifecycle
python -m compliance_audit --remediation-list pending
python -m compliance_audit --remediation-approve <PACK_ID> --approver "you" --ticket-id "CHG0012345"
python -m compliance_audit --remediation-reject  <PACK_ID> --approver "you" --reason "Out of window"
python -m compliance_audit --remediation-apply   <PACK_ID>
python -m compliance_audit --remediation-apply-all

# Scheduled audits: approve or reject a whole run (commands are in the email)
python -m compliance_audit --run-list
python -m compliance_audit --run-show <RUN_ID>
python -m compliance_audit --run-approve <RUN_ID> --approver "you" --ticket-id "CHG0012345" --apply-now
python -m compliance_audit --run-approve <RUN_ID> --approver "you" --ticket-id "CHG0012345" --apply-at "2026-11-07 02:00"
python -m compliance_audit --run-reject  <RUN_ID> --approver "you" --reason "Out of window"
python -m compliance_audit --notify-test                # check email delivery

# Non-interactive, machine-readable lifecycle (for a backend or CI)
python -m compliance_audit --remediation-list all --remediation-output json
python -m compliance_audit --remediation-apply-all --remediation-output json --remediation-no-confirm
```

## Before Your First Run

**Starting the tool:**

- **Windows:** run `run.bat` (or double-click it). It bootstraps the portable Python runtime on first use and launches the TUI.
- **Linux / WSL:** run `./run.sh`. It creates the virtual environment on first use and launches the TUI.
- **Manual:** `python -m compliance_audit --tui`, or plain `python -m compliance_audit`, from an activated environment.

Confirm each of the following before auditing anything:

1. **Config directory** — `assets/compliance_config/`. Eight YAML files, deep-merged at load time (including `exceptions.yaml`, the policy-exception register, and `notifications.yaml`, email for scheduled runs). You can point elsewhere with `-c`.
2. **Device inventory** — `assets/devices/devices.yaml`. Flat list or site groups. Override with `-i`.
3. **Credentials** — see the next section.
4. **Which checks are enabled.** The shipped config ships most checks `enabled: false` so a first run is quiet. Nothing is wrong if your first audit reports few findings — turn on what your policy requires.
5. **Remediation policy** — `audit_settings.remediation` in `audit_settings.yaml`, if you intend to apply changes.

## Pre-Flight Checks

Three commands validate the setup without touching a single device. Run them in
this order after any config change.

### `--health`

Checks that dependencies are importable and the config directory loads.

```bash
python -m compliance_audit --health
```

Reports each dependency as OK / MISSING / not installed, then the config status
and the number of checks defined. `genie` and `pyats` show as *not installed* on
Windows by design — they are Linux/WSL only, and the tool falls back to
regex parsing without them.

### `--validate-config`

Validates every YAML file against the schema, lists every problem, and exits.

```bash
python -m compliance_audit --validate-config
```

The same validation runs on **every** config load. An audit, the TUI, the
wizard and the remediation commands all refuse to start on an invalid config,
so this flag is how you see the errors without running anything else.

This catches the mistakes YAML lint cannot see:

- **Unknown keys.** The engine ignores keys it does not read, so `max_worker:`,
  `expected_server:`, or a check placed under the wrong plane silently does
  nothing. These are errors, with a "did you mean" where one is close.
- **A mistyped `enabled` key.** A check runs only with `enabled: true`, so
  `enabld: true` would quietly leave it off. `enabled`, `severity` and `tags`
  are required on every check node.
- **Bad values.** IP addresses (`expected_servers`, `expected_hosts`,
  `jump_host`) must be valid IPv4/IPv6 or a hostname; VLAN lists, syslog
  levels, storm-control thresholds and the Netmiko `device_type` are checked.
- **Regexes that do not compile**, in the hostname/interface filters and the
  `endpoint_neighbors` patterns. The engine swallows `re.error`, so the filter
  would silently stop applying.
- **Policy exceptions that are incomplete or could never match** — a missing
  `id`, `reason`, `expires` or device selector, a duplicate ID, a misspelt
  check name (with a "did you mean"), an unknown role or a bad IP network.

When the config is valid, the command also prints the state of the exception
register and names every **expired** and **expiring** exception. That is a
review prompt, not an error — the exit code stays 0.

The device inventory is validated when it loads: `ip` must be a real IPv4/IPv6
address and only `devices:` / `groups:` are allowed at the top level, so a
`device:` typo is reported instead of auditing nothing.

Exit code 2 means validation failed.

### `--dry-run`

Validates config, resolves credentials and tests TCP reachability — without
auditing.

```bash
python -m compliance_audit --dry-run
python -m compliance_audit --dry-run --site site_lab
```

Use this before a change window to confirm the inventory is reachable and the
credentials resolve, so the audit itself does not fail halfway through.

## Credentials

Resolved in this order, first match wins:

1. `.env` file in the project root — copy `.env.example` to `.env` to start
2. OS keyring, when `connection.credential_store: keyring`
3. Environment variables `SWITCH_USER` / `SWITCH_PASS` (and `ENABLE_SECRET`)
4. Interactive prompt

Notes:
- The `.env` file is gitignored. Keep it out of shared drives and backups.
- With the keyring store, credentials are saved on first successful prompt and reused afterwards.
- Jump-host credentials follow the same chain; configure the host in `connection.yaml`.

## Running an Audit

### Choose your interface

| Mode | Command | When to use |
| --- | --- | --- |
| Standard CLI | `python -m compliance_audit` | Automation, CI, scripted runs |
| Guided wizard | `--interactive` | You want prompts and a command preview before it runs |
| Full-screen TUI | `--tui` | You want a live dashboard and keyboard navigation |
| Option discovery | `--list-options` | You cannot remember a flag |

### TUI notes

The TUI is a three-screen application:

1. **Setup** — config directory, inventory path, device overrides, categories, output directory and credentials, then **Start Audit**
2. **Audit** — live statistics (devices, completed, compliant, failures, warnings, errors) with a scrolling real-time log
3. **Complete** — totals across all devices, with **Back to Log** and **Quit**

`Ctrl+Q` quits from any screen.

### Scoping a run

```bash
# One device (hostname:ip lets the tool parse the role from the hostname)
python -m compliance_audit --device ZZ-LAB1-001ASW001:192.0.2.61

# Several devices
python -m compliance_audit -d SW1:192.0.2.61 -d SW2:192.0.2.62

# One or more site groups from the inventory
python -m compliance_audit --site site_lab
python -m compliance_audit --site site_lab site_brn

# Restrict discovery to an IP range — CIDR or a hyphenated range
python -m compliance_audit --ip-filter 192.0.2.0/24
python -m compliance_audit --ip-filter 192.0.2.10-192.0.2.60

# A different inventory file entirely
python -m compliance_audit -i devices/site_brn.yaml

# A different config directory (per-site policy)
python -m compliance_audit -c configs/site_alpha

# Only some check categories
python -m compliance_audit --categories management_plane control_plane

# Connect directly, bypassing the jump host
python -m compliance_audit --no-jump
```

### Filtering findings

`--min-severity`, `--tags` and `--framework` do not skip checks — every check
still runs, and non-matching findings are reported as SKIP.

```bash
python -m compliance_audit --min-severity high
python -m compliance_audit --tags cis pci
python -m compliance_audit --framework cis
python -m compliance_audit --min-severity high --tags cis
```

**Filters apply to the console summary, the consolidated report and the exit
code only.** Per-device reports and remediation scripts are written by the
worker threads before the filters are known, and deliberately keep the full,
unfiltered result set. A filtered run therefore still produces a full-scope
remediation script. The run prints a reminder when filters are active.

### Failing a build on the score

```bash
# Exit 1 if any device scores below 80%
python -m compliance_audit --fail-threshold 80
```

Without `--fail-threshold`, the run exits 1 if any device has at least one FAIL.

## Where the Output Goes

`output_dir` (default `./reports`) is resolved to an absolute path at the start
of every run and printed in the summary, together with the remediation review
database. If you are ever unsure where results landed, read those two lines —
they are authoritative for that run.

```
  CSV report: /path/to/reports/compliance_audit_20260905_143025.csv
  HTML report: /path/to/reports/consolidated_report_20260905_143025.html
  Output directory: /path/to/reports
  Review database: /path/to/reports/db/remediation_reviews.db
```

The review database is created on **every** run where
`remediation.generate_review_pack` is true, even a run with nothing to
remediate. An empty database is normal and expected; it is not a sign of
failure.

Override the location per run:

```bash
python -m compliance_audit --output-dir /var/audit/2026-09
```

If you override it for the audit, use the same `--output-dir` for the
remediation commands — otherwise they will look in a different database.

## Reading the Results

### Statuses

| Status | Meaning |
| --- | --- |
| PASS | The device satisfies the check |
| FAIL | The device does not satisfy the check; remediation may be available |
| WARN | Something needs a human decision — the tool will not guess |
| SKIP | The check did not apply, or was filtered out by tags/severity/framework/role/hostname/group rules |
| ERROR | The check could not run (parse failure, engine error) |
| EXCEPTION | A FAIL or WARN covered by an approved policy exception. Never remediated. Shown with a state: *active*, *expiring*, *expired* (needs review) or *permanent* |

### Score

Score is `PASS / (all findings except SKIP and EXCEPTION) x 100`, rounded to
one decimal place. A device with no applicable findings scores 100%. Because
SKIP is excluded, filtering a run changes the reported score — compare like with
like. With `exception_settings.expired_counts_against_score: true`, findings
under an *expired* exception count as not passing.

### Severity

`critical` > `high` > `medium` > `low` > `info`, set per check in YAML.
`--min-severity high` surfaces critical and high only.

### Tags and frameworks

Checks carry free-form `tags` (for example `cis`, `pci`, `layer2-security`) and
an optional `framework_controls` map naming the specific control they satisfy.
`--tags` matches the former; `--framework` matches the latter. Use
`--framework cis` when you need evidence mapped to numbered CIS controls rather
than everything loosely tagged for it.

## Port Trust Placement (DHCP Snooping / DAI)

Worth calling out because it is the check most often misread.

Cisco's guidance is to trust only the interfaces that lead to the DHCP server —
uplinks and inter-switch links — and to leave every host-facing port untrusted.
A trusted access port is exempt from DHCP snooping and DAI validation, which is
exactly where a rogue DHCP server or ARP spoofer would sit.

`dhcp_snooping_trust` and `arp_inspection_trust` enforce **both** halves:

- `on_<kind>: true` — the trust command must be **present** on that kind of port
- `untrusted: {<kind>: true}` — the trust command must be **absent** there

Port kinds are `access_ports`, `uplinks`, `downlinks`, `unknown_trunks`,
`endpoint_trunks` and `unused_ports`. A kind listed under both is treated as
required. A kind in neither produces no finding at all.

`unknown_trunks` defaults to silent in both directions. When a trunk has no
CDP/LLDP neighbour data the classifier cannot tell an uplink from a downlink, and
the tool will not guess. If your environment has a firm answer, set it
explicitly.

A trusted access port reports as:

```
[FAIL] dhcp_snooping_trust  Gi1/0/1: DHCP snooping trust must NOT be set on
                            this port (access port) - it bypasses validation here
                            -> no ip dhcp snooping trust
```

Both checks ship `enabled: false`. Turn them on in `data_plane.yaml`.

## Drift and Delta Reporting

When `delta_report` is enabled, each run is compared against the previous JSON
report for the same device and a delta file is written showing what changed:

- **Resolved** — was FAIL/WARN, now PASS
- **New failures** — was PASS or absent, now FAIL/WARN
- **Unchanged failures** — still failing

A short delta summary prints in the console after the audit table.

Delta needs `json_report: true`, because the per-device JSON report *is* the
baseline. If `delta_report` is on and `json_report` is off, the run warns that
no drift can ever be detected rather than failing silently.

- **Moved to exception** — was FAIL/WARN, now covered by a policy exception
  (not counted as resolved)

Delta is your closure evidence: run the audit, remediate, run it again, and the
delta shows exactly what the change achieved.

## Policy Exceptions

An exception records an **approved, time-boxed deviation** from policy for a
specific device, group, role or IP range — and optionally specific checks,
interfaces or finding text. Exceptions live in
`assets/compliance_config/exceptions.yaml` (or any `exceptions*.yaml` in the
config directory, or the file(s) named by `exceptions_file:`). The README has
the full field and matching reference; this section is the operating procedure.

**What an exception does — and does not do:**

- The covered finding reports as `EXCEPTION`, with its ID, reason, owner,
  ticket and expiry, in the console, HTML, JSON and CSV output.
- It is **never remediated** — active *or* expired. It is not in the script,
  not in the review pack, and is dropped again at apply time even from a pack
  approved before the exception was added.
- It does not hide errors: only FAIL and WARN can be covered, never ERROR.
- It does not change *what* is audited. The check still runs every time, so
  the moment the device becomes compliant the exception shows as *matched
  nothing* and can be retired.

### Adding an exception

1. Get the deviation approved through your normal risk/change process.
2. Find the check name in the report (e.g. `bpdu_guard`, `ntp_server`) and, for
   per-port findings, the interface.
3. Add an entry. Keep the scope as narrow as the approval:

   ```yaml
   exceptions:
     - id: EXC-0001
       hostname: ZZ-LAB1-001ASW001
       check: bpdu_guard
       interface: Gi1/0/48
       reason: Uplink to customer-managed switch; BPDU guard would err-disable it
       owner: Network Engineering
       approved_by: J. Smith (Security)
       ticket: CHG0012345
       expires: 2027-03-31
   ```

4. `python -m compliance_audit --validate-config` — catches typos in check
   names, roles and dates.
5. Re-audit the device. Confirm the finding now shows `EXCEPTION` and is gone
   from the remediation script.
6. If a review pack containing that finding is already pending or approved,
   reject it and approve the regenerated one. (Applying the old pack is safe —
   the excepted item is skipped at apply time — but the queue should reflect
   reality.)

### When an exception expires

Expired exceptions appear in red, first in every exceptions table, under a
"review required" banner, and in the `--validate-config` output. They are
**still not remediated**. Someone has to decide:

- **Renew** — get the deviation re-approved and move `expires` to a later date
  (or add a new entry with a later date; the latest expiry wins).
- **Retire** — remove the entry. The next audit reports the finding as FAIL and
  generates a review pack, which goes through approval like any other change.

`expiring_soon_days` (default 30) gives advance warning. To make expiry
impossible to ignore in automation, set `fail_on_expired: true` (the run exits
1 while any finding sits under an expired exception) and/or
`expired_counts_against_score: true` (the score drops).

### Retiring unused exceptions

The console summary and the HTML exception register list exceptions that
*matched nothing* on the devices in scope. Usually the device has been fixed and
the exception can be deleted. If you expected it to match, check the device
selectors and check name against the report — a register entry for a device
that was not in this run shows as *no device in scope*.

## Remediation Lifecycle

### The model

Every device with remediable FAIL findings produces two artefacts: a plain-text
IOS-XE **remediation script**, and a JSON **review pack** recording the device,
the findings, the commands, a risk rating and a SHA-256 of the script. Packs are
tracked in a SQLite database and move through this lifecycle:

```
pending -> approved -> applied
   |          |   \
   |          |    +-> (scheduled: waits for --remediation-apply-due)
   |          +-> expired   (approval TTL passed)
   +-> rejected            failed  (apply errored)
   +-> superseded          (the device was audited again before approval)
```

Every pack also records the **run** that produced it, so a whole run can be
approved, scheduled or rejected at once — see *Scheduled Audits and Email
Approval* below.

Risk is derived from the commands themselves: AAA, TACACS/RADIUS, SNMP
community/host, routing, ACL and control-plane commands rate **high**; spanning
tree, trunking, DHCP snooping, DAI, VLAN, VTP and storm-control rate **medium**;
everything else **low**. A pack's rating is its highest single command.

### 1. Review the queue

```bash
python -m compliance_audit --remediation-list            # everything
python -m compliance_audit --remediation-list pending    # awaiting approval
python -m compliance_audit --remediation-list approved
python -m compliance_audit --remediation-list applied
python -m compliance_audit --remediation-list failed
python -m compliance_audit --remediation-list rejected
python -m compliance_audit --remediation-list expired
```

Sort, limit and reformat for automation or evidence:

```bash
python -m compliance_audit --remediation-list all --remediation-sort risk
python -m compliance_audit --remediation-list all --remediation-output json
python -m compliance_audit --remediation-list all --remediation-output csv \
  --remediation-sort risk --remediation-limit 50
```

If the list comes back empty it names the database it consulted. Check that path
matches the one the audit printed.

**Read the script before approving.** The pack names its script path; open it.
The pack is a summary, the script is what will actually run.

### 2. Approve

```bash
python -m compliance_audit --remediation-approve <PACK_ID> \
  --approver "john.doe" \
  --ticket-id "CHG0012345"
```

Approve everything pending, with a confirmation prompt and a summary table
first:

```bash
python -m compliance_audit --remediation-approve-all \
  --approver "john.doe" \
  --ticket-id "CHG0012345"
```

Return a JSON payload instead of console output — for a backend, or to record
the decision in a change ticket:

```bash
python -m compliance_audit --remediation-approve <PACK_ID> \
  --approver "john.doe" --ticket-id "CHG0012345" --remediation-output json
```

Notes:
- `--approver` is always required.
- `--ticket-id` is required when `remediation.approval.require_ticket_id` is true.
- `--expires-hours` overrides the default TTL (`approval.default_expires_hours`, 24 hours as shipped). Approval expires; an expired pack must be re-approved.

### 3. Reject

```bash
python -m compliance_audit --remediation-reject <PACK_ID> \
  --approver "john.doe" \
  --reason "Outside change window"
```

`--reason` is mandatory and is recorded in the pack for audit purposes.
`--remediation-output json` works here too.

### 4. Apply

```bash
python -m compliance_audit --remediation-apply <PACK_ID>
python -m compliance_audit --remediation-apply-all
```

Every apply passes through these gates, in order. Any one of them aborts the
apply:

| Gate | Setting | What it prevents |
| --- | --- | --- |
| Status is `approved` | — | Applying an unreviewed or rejected pack |
| Approval not expired | `approval.default_expires_hours` | Applying a stale decision |
| Script file still exists | — | Applying a pack whose script was deleted |
| Workflow enabled | `remediation.enabled` | Accidental use where policy forbids it |
| Execution enabled | `execution.enabled` | Audit-only deployments applying changes |
| Linux only | `execution.linux_only` | Applying from an unsupported platform |
| Script checksum matches | `execution.enforce_checksum` | Applying a script edited after approval |
| High risk blocked | `execution.block_high_risk_by_default` | Applying AAA/SNMP/routing changes without an explicit override |
| Device identity matches | `execution.require_hostname_match` | Applying to the wrong switch — the live prompt must contain the approved hostname |
| Preflight drift check | `execution.preflight_drift_check` | Applying changes that are no longer needed |
| Scheduled time | `--apply-at` on approval | Applying before the agreed time — the pack is refused until then, and `--remediation-apply-all` skips it |
| Policy exceptions | `exceptions.yaml` (always on) | Pushing a change that an exception — active or expired — covers now, including from packs approved before the exception was added. Covered items are dropped before connecting; if all items are covered the apply aborts |

The **preflight drift check** re-audits the device immediately before applying
and intersects the result with the approved findings. Anything already fixed is
dropped from the command list. If *none* of the approved findings are still
failing, the apply aborts entirely — the device has changed since approval and
the pack should be regenerated.

After the commands run, the tool saves the configuration
(`execution.save_config`), re-audits, and reports how many findings were
resolved. Anything still failing is listed explicitly. A post-remediation report
is written when `execution.generate_post_report` is enabled.

`--remediation-apply-all` prompts for confirmation. In a pipeline, where there
is nobody to answer it, suppress the prompt and take JSON back:

```bash
python -m compliance_audit --remediation-apply-all \
  --remediation-output json --remediation-no-confirm
```

Use `--remediation-no-confirm` only where the queue has already been reviewed by
a human — it removes the last stop before changes reach devices.

Overriding the high-risk block requires explicit change authority:

```bash
python -m compliance_audit --remediation-apply <PACK_ID> --allow-high-risk
python -m compliance_audit --remediation-apply-all --allow-high-risk
```

### 5. Verify and close

```bash
python -m compliance_audit --remediation-list applied
python -m compliance_audit --remediation-list failed
python -m compliance_audit                              # re-audit for closure evidence
```

Every apply attempt, successful or not, appends a JSON line to
`<output_dir>/remediation_execution.log`. That file is your execution audit
trail — keep it with the change record.

## Scheduled Audits and Email Approval

The audit can run unattended every night on a Linux host and email its result
to the approvers. The email holds everything needed to decide — the proposed
changes per switch with their exact commands and risk, what is new since the
previous run, unreachable devices and expired exceptions — plus the commands
to approve or reject. Setting up the host and timers is covered step by step
in `deploy/README.md`.

### Setting up (once)

1. Fill in `assets/compliance_config/notifications.yaml`: `enabled: true`,
   `smtp_host`, `smtp_port`, `security`, `from_address`, `to`. Set `command`
   to how approvers run the tool (e.g. through `sudo -u netaudit ...`), so
   the commands in the email work as pasted.
2. Put switch credentials in `.env` (mode 600) for the service account.
3. Check it:

   ```bash
   python -m compliance_audit --validate-config
   python -m compliance_audit --notify-test
   python -m compliance_audit --dry-run --non-interactive
   ```

4. Install and enable the timers from `deploy/systemd/`: the nightly audit
   (`--non-interactive --notify`) and the 5-minute scheduled-apply check
   (`--remediation-apply-due --non-interactive`).

### Each morning: deciding on a run

1. Read the email. Its subject says whether action is needed:
   `ACTION REQUIRED: N remediation pack(s) to approve`.
2. Review the proposed changes in the body (and the attached scripts if
   needed). Check the **Devices not audited** and **Policy exceptions needing
   review** sections too — they need attention whatever you decide.
3. To leave one switch out, reject its pack first:
   `--remediation-reject PACK_ID --approver "you" --reason "..."`.
4. Decide, on the audit host:

   ```bash
   # apply now
   python -m compliance_audit --run-approve RUN_ID --approver "you" --ticket-id CHG... --apply-now
   # apply in tonight's window (host local time)
   python -m compliance_audit --run-approve RUN_ID --approver "you" --ticket-id CHG... --apply-at "2026-11-07 02:00"
   # reject
   python -m compliance_audit --run-reject RUN_ID --approver "you" --reason "..."
   ```

   If the email says some packs are **high risk**, they are skipped unless you
   add `--allow-high-risk` to the approval. That allowance is recorded, so the
   scheduled apply honours it.
5. Confirm with `--run-show RUN_ID`: packs show as `scheduled <time>`,
   `approved` or `applied`.

### What happens at the scheduled time

The apply timer runs `--remediation-apply-due` every 5 minutes. At the first
check after the scheduled time it applies the run's packs through every normal
gate — checksum, device identity, preflight drift check, policy exceptions —
then emails the result: devices changed, findings resolved, anything that
failed. Re-audit (or wait for the next nightly run) for closure evidence.

### Things to know

- **Approve the latest run.** When a device is audited again, its packs still
  `pending` from earlier runs become `superseded` and can no longer be
  approved. Approved or scheduled packs are left alone; the next email notes
  that a change for that switch is already scheduled.
- **The approval window** starts at the scheduled time, so a change scheduled
  for next week does not expire before then.
- **To reschedule**, run `--run-approve` again with a new `--apply-at` (or
  `--apply-now`). **To cancel**, `--run-reject` the run.
- **Failure emails.** If a scheduled audit cannot run (invalid config, no
  devices, missing credentials), recipients get a failure email instead of
  silence.
- **Overlaps.** A run still going when the next one starts makes the new one
  stop at once (exit 2); nothing interleaves.
- **Re-send an email** with `--run-notify RUN_ID`.

## ROI Reporting

If you track automation value, enable ROI in `audit_settings.yaml`:

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
- Value saved = hours saved multiplied by `hourly_rate` (leave at 0 to hide the money figure)

ROI appears in the console summary, the per-device JSON under `roi`, the
per-device HTML stat cards, and the consolidated HTML.

Separate profiles exist for `audit` and `post_remediation` runs, so
post-remediation verification is not credited at full manual-audit rates.

## Web Backend Integration

The lifecycle commands can drive a web front end or a pipeline rather than a
terminal.

- `--remediation-output json` returns a machine-readable payload from list, approve, reject, apply and apply-all.
- `--remediation-output csv` is **list-only**; asking for it on any other operation is an error.
- `--remediation-no-confirm` suppresses the interactive prompt on bulk operations.
- `<output_dir>/report_artifacts_index.json` indexes every generated report with its metadata, HTML path and run ID.

To embed generated HTML in a web view, resolve the path through the helper
rather than opening it directly:

```python
from compliance_audit import read_report_content

content = read_report_content(allowed_root="reports", requested_path=user_supplied)
```

It resolves the request against an allowed root and rejects traversal attempts,
so a path arriving from a browser cannot escape the reports directory.

The same operations are available in-process, without shelling out:
`list_review_packs_api`, `approve_review_pack_api`, `reject_review_pack_api`,
`apply_approved_pack_api` and `apply_all_approved_packs_api`.

## Configuration Quick Reference

All files live in `assets/compliance_config/` and are deep-merged at load time,
so each can be edited independently.

| File | Contains |
| --- | --- |
| `audit_settings.yaml` | Concurrency, timeouts, output, report formats, ROI, the whole remediation policy |
| `connection.yaml` | Device type, timeouts, retries, jump host, credential store |
| `classification.yaml` | Hostname role codes, trunk direction signals, endpoint neighbour patterns |
| `management_plane.yaml` | Services, SSH, AAA, NTP, logging, SNMP, banners, users, VTY, console |
| `control_plane.yaml` | STP, VTP, DHCP snooping, DAI, errdisable, UDLD, CoPP |
| `data_plane.yaml` | Per-interface checks by port role |
| `exceptions.yaml` | Policy exceptions and `exception_settings` (expiry warning window, scoring, exit code) |
| `notifications.yaml` | SMTP email for scheduled audits: relay, recipients, `send_when`, attachments, the command shown to approvers |

Settings you will reach for most:

```yaml
audit_settings:
  max_workers: 5              # concurrent device audits; 1 = sequential
  collect_timeout: 30         # per-command timeout, seconds
  output_dir: "./reports"
  html_report: true
  json_report: true           # also the delta baseline
  csv_report: false
  delta_report: true          # needs json_report
  parking_vlan: 99            # expected VLAN for unused ports
  native_vlan: 99             # expected native VLAN on trunks
```

Every check node supports the same common fields:

```yaml
my_check:
  enabled: true
  severity: high              # critical | high | medium | low | info
  tags: [cis, pci]
  framework_controls:
    cis_ios_xe_v4: "5.3.1"
  applies_to_roles: [access]  # skip on other roles
  include_hostnames: []       # regex; only these devices run the check
  exclude_hostnames: []       # regex; these devices skip it
  include_groups: []          # site groups from the inventory
  exclude_groups: []
  exclude_interfaces: []      # regex; exempt ports without disabling the check
```

**A check runs only when its node says `enabled: true`.** Set
`enabled: false` to turn one off rather than deleting the node, so the policy
stays self-documenting. `--validate-config` requires the key on every node.

Every check setting has a documented default in `compliance_audit/config_schema.py`,
and the engine uses exactly that default when a key is omitted. Level and
threshold settings are bounds, not exact values:

- `logging_console.level`, `logging_monitor.level` — the most verbose level allowed (`no logging console` also passes).
- `logging_trap.level`, `logging_buffered.level` — the least verbose level allowed; `logging_buffered.min_size` is a minimum.
- `stp_priority` — access switches must not go *below* `access_priority`; roles in `core_roles` must be at or below `core_priority`. Priorities are base values (multiples of 4096).
- `login_block_for` — `seconds` and `within` are minimums, `attempts` a maximum; `login_delay.seconds` is a minimum.
- `port_security` — IOS defaults are used when a line is absent (maximum 1, violation shutdown, no aging).

## Safety Rules

1. Never apply remediation outside an authorised change window.
2. Read the remediation script, not just the pack summary, before approving.
3. Treat `--allow-high-risk` as an exception requiring named approval. High risk means AAA, TACACS/RADIUS, SNMP, routing, ACL or control-plane changes — the commands that can lock you out of the device.
4. Use `--remediation-apply-all` only after reviewing the whole queue.
5. Never disable `require_hostname_match` or `enforce_checksum` to get past an error. Both exist to stop you changing the wrong device, or running a script that is not the one that was approved.
6. Re-audit after applying. An apply that reports success is not the same as a device that is compliant.
7. Keep `remediation_execution.log` with the change record.
8. Never use a policy exception to defer a fix you intend to make. An exception blocks remediation of that finding until someone removes it — expiry flags it but does not lift the block.
9. Keep exception scope as narrow as the approval: one device and interface rather than a regex over the estate, and a real expiry date rather than `never`.
10. Approve a run from what the email shows, not from its subject line. `--run-approve` approves every pending pack in the run; reject individual packs first to leave a switch out.
11. Add `--allow-high-risk` to a run approval only with the named approval it needs: on a scheduled run it takes effect later, with nobody watching.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| No remediation packs found | Nothing failed, or remediation is disabled | Check the database path in the message matches the audit's `Review database:` line; confirm checks are enabled |
| Audit reports very few findings | Most checks ship `enabled: false` | Enable the checks your policy requires in the plane YAML files |
| Remediation workflow disabled | `remediation.enabled: false` | Enable it in `audit_settings.yaml` |
| Execution disabled | `execution.enabled: false` | Enable it, or apply from a host where policy allows |
| Linux-only error | Applying from Windows or macOS | Apply from Linux/WSL, or set `execution.linux_only: false` if your policy allows |
| Approval expired | TTL passed since approval | Re-run the audit, generate a fresh pack, approve again |
| Checksum mismatch | Script edited or regenerated after approval | Re-run the audit and approve the new pack — do not disable the check |
| High-risk blocked | Pack contains AAA/SNMP/routing commands | Obtain explicit approval, then `--allow-high-risk` |
| Device identity mismatch | Live prompt does not contain the approved hostname | Verify the inventory entry and the target device before doing anything else |
| Drift check aborts the apply | None of the approved findings still fail | The device already changed; re-audit and regenerate the pack |
| Config validation fails on `enabled` | A check node has a mistyped or missing `enabled` key | Fix the key — without `enabled: true` the check does not run |
| Audit stops with `Config validation failed` | Every config load is validated | Fix each listed path; re-check with `--validate-config` |
| `Inventory validation failed` | Bad IP, invalid hostname, or unknown key in `devices.yaml` | Fix the entry named in the message, e.g. `groups.site_lab.devices[2]` |
| Delta reports never appear | `json_report` is off | Enable `json_report`; the JSON report is the baseline |
| `engine_error` finding for a device | A check crashed | Check `logs/debug.log` for the traceback |
| Reports are not where you expect | `output_dir` is relative to the working directory | Read the `Output directory:` line in the summary; pass `--output-dir` to be explicit |
| Genie / pyATS not installed | Windows | Expected — the tool falls back to regex parsing. Use WSL for structured parsing |
| A failing finding is missing from the remediation script | It is covered by a policy exception | Check the `EXCEPTION` row in the report; remove or narrow the exception if the fix is wanted |
| Apply prints `Skipping N item(s) now covered by a policy exception` | An exception was added after the pack was generated | Expected — those items are not pushed. Reject the pack and approve a regenerated one to keep the queue tidy |
| Apply aborts: `Every finding in this pack is covered by a policy exception` | The whole pack is now excepted | Nothing to do unless the exception is wrong; reject the pack |
| An exception never matches (listed as *matched nothing*) | Device selector or check name does not match the report | Compare `hostnames`/`groups`/`checks`/`interfaces` with the report; the device may already be compliant |
| `exceptions_file not found` | Path in `exceptions_file` does not resolve | Paths are tried against the working directory, the config directory, then the project root |
| No email after a scheduled audit | Email disabled, `send_when` filtered it, or the relay refused it | Check `--run-list` (Email column) and the run manifest's `notification` field; run `--notify-test` |
| `--notify-test` fails | Relay host/port/security wrong, or SMTP AUTH without `SMTP_PASSWORD` | Match `security` to the relay (`starttls` on 25/587, `ssl` on 465); set `SMTP_PASSWORD` in `.env` if `username` is set |
| `No device credentials found and this run is non-interactive` | No `SWITCH_USER`/`SWITCH_PASS` for the service account | Put them in `.env` (mode 600) next to `run.sh`, or use the keyring |
| `Nothing in run ... could be approved` | Packs are high risk, superseded, or already decided | Add `--allow-high-risk` if approved to; otherwise approve the newer run (`--run-list`) |
| `Pack is scheduled to be applied at ...` | Applying a scheduled pack early | Wait for the apply timer, or re-approve the run with `--apply-now` |
| A scheduled change did not happen | Apply timer not running, execution disabled, or the apply failed | `systemctl list-timers 'cisco-compliance-audit*'`; check the apply email and `remediation_execution.log` |
| `Another audit is already running for this output directory` | The previous run is still going, or a stale process | Wait; the lock is released when that process exits |
| Exception validation: `'never' needs exception_settings.allow_permanent` | `expires: never` without opting in | Give it a date, or set `allow_permanent: true` if your policy allows permanent exceptions |

For anything else, run with `-vv` for DEBUG output and check `logs/debug.log`.

## Escalation and Rollback

If an apply fails or the device behaves unexpectedly:

1. Stop. Do not run further apply commands, and do not retry with `--allow-high-risk`.
2. Capture the pack ID, hostname, IP and the full error output.
3. Read the tail of `<output_dir>/remediation_execution.log` for the recorded attempt.
4. Check whether the configuration was saved — if `execution.save_config` was enabled and the commands applied, the change is in startup-config.
5. Escalate to network engineering and the change manager with the above.
6. Roll back using your standard network procedure for the affected device or site. This tool does not perform rollback.

## Checklists

### Per-run checklist

1. Run `--dry-run` to confirm config, credentials and reachability.
2. Run the audit.
3. Note the `Output directory:` and `Review database:` lines.
4. Review the pending queue and read the scripts.
5. Approve or reject each pack against its ticket.
6. Apply during the change window.
7. Confirm applied/failed status.
8. Re-audit and keep the delta report as closure evidence.

### After changing the config

1. `python -m compliance_audit --validate-config`
2. `python -m compliance_audit --dry-run`
3. Audit one representative device before the whole estate.
4. Confirm the findings changed in the direction you intended.

### Periodic

1. Review packs left in `pending` — they expire and become noise.
2. Archive old reports; `output_dir` grows without limit.
3. Re-check that enabled checks still match current policy.
4. Review the exception register: renew or retire every **expired** exception, plan for the **expiring** ones, and delete exceptions that *matched nothing*.
5. Scheduled runs: check `--run-list` for runs left *awaiting approval* and for failed emails, and `systemctl list-timers` that both timers are active.

## Appendix A: Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Success — no failing devices, or the run was informational |
| 1 | At least one device has a FAIL finding, or scored below `--fail-threshold`, or — with `exception_settings.fail_on_expired: true` — a finding sits under an expired policy exception |
| 2 | Config could not be loaded or failed validation, or a remediation command was rejected (bad arguments, disabled workflow, failed gate), credentials were missing in a non-interactive run, or another audit/apply already holds the lock |

`--remediation-apply-due` and `--run-approve ... --apply-now` exit 1 when any
pack fails to apply. The shipped systemd audit unit treats the audit's exit 1
(findings) as success.

Exit codes respect active filters: a finding converted to SKIP does not count
towards exit code 1. Nor does a finding covered by an active policy exception.

## Appendix B: Output File Naming

All paths are relative to `output_dir`.

| Pattern | Contents |
| --- | --- |
| `<hostname>_<timestamp>.json` | Per-device findings; also the delta baseline |
| `<hostname>_<timestamp>.html` | Per-device interactive report |
| `<hostname>_delta_<timestamp>.json` | Change since the previous baseline |
| `<hostname>_remediation_<timestamp>.txt` | Ready-to-paste IOS-XE config snippet |
| `<hostname>_review_<pack_id>.json` | Review pack — findings, commands, risk, checksum |
| `consolidated_report_<timestamp>.html` | All devices in one report |
| `compliance_audit_<timestamp>.csv` | Every finding, one row each |
| `db/remediation_reviews.db` | SQLite review and approval state |
| `remediation_execution.log` | Append-only JSON lines, one per apply attempt |
| `report_artifacts_index.json` | Index of generated reports — metadata, HTML paths, run IDs |
| `runs/<run_id>.json` | Run manifest — devices, scores, unreachable devices, packs, exceptions, email outcome |
| `.locks/audit.lock`, `.locks/apply.lock` | Held while an audit or apply runs |

Timestamps are local time, `YYYYMMDD_HHMMSS`. Hostnames are sanitised for use in
filenames.

## Appendix C: Glossary

| Term | Meaning |
| --- | --- |
| **Review pack** | JSON record of one device's remediable findings, the commands, a risk rating and the script checksum |
| **Pack ID** | 16-character identifier derived from hostname, IP, audit timestamp and script name |
| **Drift check** | Re-audit run immediately before applying, to confirm the approved findings still fail |
| **Post-check** | Re-audit run immediately after applying, to confirm the findings are resolved |
| **Endpoint trunk** | A trunk port terminating on a non-switch device, typically a wireless AP |
| **Unknown trunk** | A trunk whose direction could not be determined from STP or CDP/LLDP |
| **Parking VLAN** | VLAN unused ports are expected to sit in |
| **Baseline** | The previous per-device JSON report, used for delta comparison |
| **Policy exception** | An approved, time-boxed deviation from policy in `exceptions.yaml`. Covered findings report as `EXCEPTION` and are never remediated |
| **Expired exception** | An exception past its `expires` date. Flagged for review in every report; still never remediated |
| **Exception register** | All configured exceptions, shown in the consolidated HTML report with state, scope and usage |
| **Run** | One execution of the audit, identified by its run ID (`audit-YYYYMMDDTHHMMSSffffffZ`); the unit a scheduled email reports on and an approver approves or rejects |
| **Run manifest** | `runs/<run_id>.json` — the summary of a run used by `--run-show` and the email |
| **Superseded** | A pending pack replaced because its device was audited again before anyone approved it |
| **Scheduled apply** | An approved pack with an `--apply-at` time, applied by `--remediation-apply-due` once that time arrives |
