# Scheduled audits on a Linux host

Run the audit every night, email the result to the people who approve
changes, and let them approve (to apply now or at a set time) or reject the
whole run with one command on the host.

```text
01:30  timer ─► audit ─► run summary + review packs ─► email: changes, risk, commands
                                                            │
   approver on the host:  --run-approve RUN_ID ... --apply-now
                          --run-approve RUN_ID ... --apply-at "2026-11-07 02:00"
                          --run-reject  RUN_ID ... --reason "..."
                                                            │
every 5 min  timer ─► --remediation-apply-due ─► applies due packs ─► email: result
```

## 1. Install

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin netaudit
sudo mkdir -p /opt/cisco-compliance-audit
sudo chown netaudit: /opt/cisco-compliance-audit
# Copy or clone the release into /opt/cisco-compliance-audit, then:
cd /opt/cisco-compliance-audit
sudo -u netaudit bash setup.sh          # creates .venv and installs dependencies
```

Credentials for the switches go in `/opt/cisco-compliance-audit/.env`
(copy `.env.example`), readable only by the service account:

```bash
sudo -u netaudit cp .env.example .env
sudo -u netaudit chmod 600 .env
sudo -u netaudit ${EDITOR:-vi} .env      # SWITCH_USER, SWITCH_PASS (+ SMTP_PASSWORD if needed)
```

## 2. Configure

1. **Email** — in `assets/compliance_config/notifications.yaml` set
   `enabled: true`, `smtp_host`, `smtp_port`, `security`, `from_address`
   and `to`. Set `command` to how approvers will run the tool, e.g.

   ```yaml
   command: "sudo -u netaudit /opt/cisco-compliance-audit/.venv/bin/python -m compliance_audit"
   ```

   The email's approve/reject commands then work as pasted.
2. **Remediation** — in `audit_settings.yaml`, `remediation.execution.enabled`
   must be `true` for approved runs to be applied. Leave
   `block_high_risk_by_default: true`: high-risk packs then need
   `--allow-high-risk` on the approval itself.
3. **Check it** (as the service account):

   ```bash
   cd /opt/cisco-compliance-audit
   sudo -u netaudit .venv/bin/python -m compliance_audit --validate-config
   sudo -u netaudit .venv/bin/python -m compliance_audit --notify-test
   sudo -u netaudit .venv/bin/python -m compliance_audit --dry-run --non-interactive
   ```

## 3. Enable the timers

```bash
sudo cp deploy/systemd/*.service deploy/systemd/*.timer /etc/systemd/system/
# Edit User=, paths and OnCalendar= in the copies if yours differ.
sudo systemctl daemon-reload
sudo systemctl enable --now cisco-compliance-audit.timer cisco-compliance-audit-apply.timer
systemctl list-timers 'cisco-compliance-audit*'
```

Run one audit now to see the whole flow:

```bash
sudo systemctl start cisco-compliance-audit.service
journalctl -u cisco-compliance-audit.service -n 100
```

| Unit | When | Exit codes |
| --- | --- | --- |
| `cisco-compliance-audit.service` | 01:30 nightly (`OnCalendar`) | 0 compliant, 1 findings (treated as success via `SuccessExitStatus=1`), 2 could not run (a failure email is sent) |
| `cisco-compliance-audit-apply.service` | every 5 minutes | 0 nothing due or all applied, 1 a scheduled apply failed (unit shows as failed; the apply email says why) |

Both jobs take a lock in the output directory, so a run that is still going
when the next one starts makes the new one stop immediately.

## Cron instead of systemd

```cron
# m  h  dom mon dow  command
30   1  *   *   *    cd /opt/cisco-compliance-audit && .venv/bin/python -m compliance_audit --non-interactive --notify >> logs/scheduled-audit.log 2>&1
*/5  *  *   *   *    cd /opt/cisco-compliance-audit && .venv/bin/python -m compliance_audit --remediation-apply-due --non-interactive >> logs/scheduled-apply.log 2>&1
```

Install it in the service account's crontab: `sudo crontab -u netaudit -e`.

## Approving a run

The email lists every proposed change per switch. On the host:

```bash
CA="sudo -u netaudit /opt/cisco-compliance-audit/.venv/bin/python -m compliance_audit"
$CA --run-show audit-20261106T013000123456Z
$CA --run-approve audit-20261106T013000123456Z --approver "Jo Bloggs" --ticket-id CHG0012345 --apply-now
$CA --run-approve audit-20261106T013000123456Z --approver "Jo Bloggs" --ticket-id CHG0012345 --apply-at "2026-11-07 02:00"
$CA --run-reject  audit-20261106T013000123456Z --approver "Jo Bloggs" --reason "Not in this change window"
```

See the README section *Scheduled Audits and Email Approval* and the RUNBOOK
for the full behaviour.
