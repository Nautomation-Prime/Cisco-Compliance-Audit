"""
Email notifications for scheduled audits and remediation.

Three kinds of email, all sent through the SMTP relay in
``notifications.yaml``:

* **Run email** (``--notify``) — everything an approver needs to decide on a
  run: what would change on each switch (findings, exact commands, risk),
  what is new since the last run, expired exceptions, unreachable devices,
  and the copy-paste commands to approve (now or at a set time) or reject.
  The body is self-contained, email-safe HTML (inline styles, no scripts)
  with a plain-text alternative.  The interactive consolidated report and
  the per-device remediation scripts are attached for drill-down, within
  ``max_attachment_mb``.
* **Apply email** — the outcome of an immediate or scheduled apply.
* **Failure email** — a scheduled audit that could not run.

Nothing here raises into the audit: a notification that fails is logged and
recorded in the run manifest, and the audit result stands.
"""

from __future__ import annotations

import html
import json
import logging
import os
import shlex
import smtplib
import socket
import ssl
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Optional

from pydantic import ValidationError

from .config_schema import EmailNotificationSchema
from .credentials import load_dotenv
from .remediation_workflow import (
    _flatten_apply_commands,
    format_schedule,
    get_remediation_settings,
    list_review_packs,
)
from .runs import manifest_path

log = logging.getLogger(__name__)

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}
_RISK_COLOURS = {"high": ("#991b1b", "#fee2e2"), "medium": ("#92400e", "#fef3c7"),
                 "low": ("#1e40af", "#dbeafe")}
_STATE_COLOURS = {"expired": ("#991b1b", "#fee2e2"), "expiring": ("#92400e", "#fef3c7")}


class NotificationError(RuntimeError):
    """Email could not be built or sent."""


# ─────────────────────────────────────────────────────────────────────────────
#  Settings and transport
# ─────────────────────────────────────────────────────────────────────────────

def email_settings(cfg: dict) -> EmailNotificationSchema:
    """The validated ``notifications.email`` block (defaults when absent)."""
    raw = (cfg.get("notifications") or {}).get("email") or {}
    try:
        return EmailNotificationSchema.model_validate(raw)
    except ValidationError as exc:
        raise NotificationError(f"notifications.email is invalid: {exc}") from exc


def _smtp_password() -> str:
    load_dotenv()
    return os.environ.get("SMTP_PASSWORD", "")


def send_email(msg: EmailMessage, settings: EmailNotificationSchema) -> None:
    """Deliver *msg* through the configured relay.  Raises ``NotificationError``."""
    context = ssl.create_default_context()
    try:
        if settings.security == "ssl":
            smtp = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port,
                timeout=settings.timeout, context=context,
            )
        else:
            smtp = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.timeout)
        with smtp:
            smtp.ehlo()
            if settings.security == "starttls":
                smtp.starttls(context=context)
                smtp.ehlo()
            if settings.username:
                password = _smtp_password()
                if not password:
                    raise NotificationError(
                        "notifications.email.username is set but SMTP_PASSWORD is not "
                        "(set it in the environment or .env)"
                    )
                smtp.login(settings.username, password)
            smtp.send_message(msg)
    except NotificationError:
        raise
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        raise NotificationError(
            f"could not send via {settings.smtp_host}:{settings.smtp_port} "
            f"({settings.security}): {exc}"
        ) from exc


def _new_message(settings: EmailNotificationSchema, subject: str) -> EmailMessage:
    msg = EmailMessage()
    prefix = settings.subject_prefix.strip()
    msg["Subject"] = f"{prefix} {subject}".strip()
    msg["From"] = settings.from_address or ""
    msg["To"] = ", ".join(settings.to)
    if settings.cc:
        msg["Cc"] = ", ".join(settings.cc)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=(settings.from_address or "localhost").split("@")[-1])
    msg["X-Mailer"] = "cisco-compliance-audit"
    return msg


def _outcome(settings: EmailNotificationSchema, **fields) -> dict:
    return {
        "sent": False,
        "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "to": list(settings.to) + list(settings.cc),
        "error": "",
        "skipped": "",
        **fields,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Formatting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _e(value) -> str:
    """HTML-escape anything — device text (descriptions, banners) included."""
    return html.escape("" if value is None else str(value), quote=True)


def _local(ts: str) -> str:
    """``2026-11-06T01:30:00Z`` → ``2026-11-06 01:30 GMT``."""
    try:
        when = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return ts or ""
    return format_schedule(when)


def _badge(text: str, colours: tuple[str, str]) -> str:
    fg, bg = colours
    return (
        f'<span style="display:inline-block;padding:1px 6px;border-radius:3px;'
        f'font-size:11px;font-weight:bold;color:{fg};background:{bg};">{_e(text)}</span>'
    )


_TABLE = 'style="border-collapse:collapse;width:100%;font-size:13px;margin:6px 0 14px;"'
_TH = ('style="text-align:left;padding:5px 8px;border-bottom:2px solid #d1d5db;'
       'background:#f3f4f6;font-size:12px;"')
_TD = 'style="padding:5px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top;"'
_PRE = ('style="background:#f3f4f6;border:1px solid #d1d5db;border-radius:4px;padding:8px 10px;'
        'font-family:Consolas,Menlo,monospace;font-size:12px;white-space:pre-wrap;margin:6px 0;"')
_H3 = 'style="margin:22px 0 6px;font-size:16px;color:#111827;"'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    """Rows are already-escaped HTML cells."""
    head = "".join(f"<th {_TH}>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td {_TD}>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table {_TABLE}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def command_base(settings: EmailNotificationSchema, manifest: dict) -> str:
    """The command an approver runs on the audit host, pinned to this run's
    config and output directory so it acts on the same review database."""
    cmd = settings.command.strip() or f"{shlex.quote(sys.executable)} -m compliance_audit"
    return (
        f"{cmd} -c {shlex.quote(manifest.get('config_path', ''))} "
        f"-o {shlex.quote(manifest.get('output_dir', ''))}"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Run email
# ─────────────────────────────────────────────────────────────────────────────

def should_send(manifest: dict, send_when: str) -> tuple[bool, str]:
    """Apply ``send_when``; returns ``(send, reason_if_not)``."""
    totals = manifest.get("totals", {})
    expired = bool(manifest.get("exceptions", {}).get("expired"))
    unreachable = bool(manifest.get("unreachable"))
    if send_when == "always":
        return True, ""
    if send_when == "issues":
        issues = (
            totals.get("fail", 0) or totals.get("warn", 0) or totals.get("error", 0)
            or unreachable or expired or totals.get("packs", 0)
        )
        return bool(issues), "every device is compliant (send_when: issues)"
    action = totals.get("packs", 0) or unreachable or totals.get("error", 0) or expired
    return bool(action), "nothing needs a decision (send_when: action_required)"


def _load_pack(path: str) -> Optional[dict]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def _run_packs(manifest: dict) -> list[dict]:
    """Packs the run produced, with their current lifecycle status."""
    statuses = {
        e.pack_id: e for e in list_review_packs(manifest["output_dir"], run_id=manifest["run_id"])
    }
    packs: list[dict] = []
    for device in manifest.get("devices", []):
        if not device.get("pack_id"):
            continue
        pack = _load_pack(device.get("pack_path", ""))
        if pack is None:
            continue
        entry = statuses.get(device["pack_id"])
        # A change for this device approved from an earlier run and not yet
        # applied (typically scheduled for tonight) makes this one redundant.
        earlier = [
            e for e in list_review_packs(
                manifest["output_dir"], status="approved", hostname=device["hostname"]
            )
            if e.run_id != manifest["run_id"]
        ]
        packs.append({
            "device": device,
            "pack": pack,
            "status": entry.status if entry else pack["lifecycle"]["status"],
            "scheduled_for": entry.scheduled_for if entry else "",
            "earlier_approved": earlier,
        })
    packs.sort(key=lambda p: (RISK_ORDER.get(p["pack"]["risk"]["highest"], 9),
                              p["device"]["hostname"].lower()))
    return packs


def _subject(manifest: dict, pending: int, high: int) -> str:
    t = manifest["totals"]
    parts: list[str] = []
    if pending:
        parts.append(
            f"ACTION REQUIRED: {pending} remediation pack(s) to approve"
            + (f" ({high} high risk)" if high else "")
        )
    elif t["fail"] == 0 and t["warn"] == 0 and not t["unreachable"]:
        parts.append(f"All {t['audited']} device(s) compliant")
    else:
        parts.append("Audit complete, no remediation proposed")
    parts.append(f"{t['audited']} device(s), {t['score_pct']}%")
    if t["unreachable"]:
        parts.append(f"{t['unreachable']} unreachable")
    expired = len(manifest.get("exceptions", {}).get("expired", []))
    if expired:
        parts.append(f"{expired} expired exception(s)")
    return " — ".join(parts) + f" — {manifest['run_id']}"


def _attachments(manifest: dict, packs: list[dict], settings: EmailNotificationSchema):
    """Pick files to attach within the size cap; returns (attached, omitted)."""
    budget = int(settings.max_attachment_mb * 1024 * 1024)
    candidates: list[tuple[str, Path]] = []
    if settings.attach_scripts:  # small and exactly what would be pushed: first
        for p in packs:
            if p["status"] == "pending" and p["device"].get("script_path"):
                candidates.append(("script", Path(p["device"]["script_path"])))
    if settings.attach_report and manifest.get("reports", {}).get("consolidated_html"):
        candidates.append(("report", Path(manifest["reports"]["consolidated_html"])))

    attached: list[tuple[str, Path, bytes]] = []
    omitted: list[tuple[Path, str]] = []
    used = 0
    for kind, path in candidates:
        try:
            data = path.read_bytes()
        except OSError as exc:
            omitted.append((path, f"unreadable: {exc}"))
            continue
        if used + len(data) > budget:
            omitted.append((path, f"{len(data) / 1048576:.1f} MB exceeds the "
                                  f"{settings.max_attachment_mb:g} MB attachment limit"))
            continue
        used += len(data)
        attached.append((kind, path, data))
    return attached, omitted


def build_run_email(
    manifest: dict,
    settings: EmailNotificationSchema,
    *,
    remediation: Optional[dict] = None,
) -> EmailMessage:
    """The run email: decision summary in the body, detail as attachments."""
    rem = remediation or {}
    packs = _run_packs(manifest)
    pending = [p for p in packs if p["status"] == "pending"]
    high = sum(1 for p in pending if p["pack"]["risk"]["highest"] == "high")
    attached, omitted = _attachments(manifest, packs, settings)
    cmd = command_base(settings, manifest)
    run_id = manifest["run_id"]
    t = manifest["totals"]
    cap = settings.max_findings_per_device

    html_parts: list[str] = []
    text: list[str] = []

    # ── Header and totals ──────────────────────────────────
    html_parts.append(
        f'<h2 style="margin:0 0 4px;font-size:20px;">Compliance audit {_e(run_id)}</h2>'
        f'<div style="color:#6b7280;font-size:12px;margin-bottom:12px;">'
        f"Finished {_e(_local(manifest.get('finished_at', '')))} on {_e(manifest.get('host'))}"
        f" &middot; tool v{_e(manifest.get('tool_version'))}</div>"
    )
    totals_rows = [[
        _e(t["audited"]), _e(t["unreachable"]), f"<b>{_e(t['score_pct'])}%</b>",
        _e(t["fail"]), _e(t["warn"]), _e(t["error"]),
        _e(t["exception"]) + (f" ({_e(t['expired_exceptions'])} expired)" if t["expired_exceptions"] else ""),
        _e(t["packs"]),
    ]]
    html_parts.append(_table(
        ["Audited", "Unreachable", "Score", "Fail", "Warn", "Error", "Exceptions", "Packs"],
        totals_rows,
    ))
    text += [
        f"Compliance audit {run_id}",
        f"Finished {_local(manifest.get('finished_at', ''))} on {manifest.get('host')}",
        "",
        f"Audited: {t['audited']}  Unreachable: {t['unreachable']}  Score: {t['score_pct']}%",
        f"Fail: {t['fail']}  Warn: {t['warn']}  Error: {t['error']}  "
        f"Exceptions: {t['exception']} ({t['expired_exceptions']} expired)  Packs: {t['packs']}",
        "",
    ]

    # ── Decision box ───────────────────────────────────────
    if pending:
        approver = '--approver "Your Name"'
        ticket = ' --ticket-id "CHG0000000"'
        high_flag = " --allow-high-risk" if high else ""
        tz = datetime.now().astimezone().strftime("%Z")
        commands = [
            "# Approve every pack below and apply now",
            f"{cmd} --run-approve {run_id} {approver}{ticket}{high_flag} --apply-now",
            "",
            f"# Approve and apply at a set time (local time on {manifest.get('host')}, {tz})",
            f'{cmd} --run-approve {run_id} {approver}{ticket}{high_flag} --apply-at "YYYY-MM-DD HH:MM"',
            "",
            "# Reject the whole run",
            f'{cmd} --run-reject {run_id} {approver} --reason "Why"',
            "",
            "# Leave one device out: reject its pack first, then approve the run",
            f'{cmd} --remediation-reject PACK_ID {approver} --reason "Why"',
        ]
        notes = [
            f"Approving applies the changes below to {len(pending)} device(s). "
            "The preflight drift check re-audits each device first and skips anything "
            "already fixed.",
            "These packs are superseded if a device is audited again before you approve — "
            "approve the newer run instead.",
            f"An approval is valid for {rem.get('approval_default_expires_hours', 24)} hour(s) "
            "from approval, or from the scheduled time.",
        ]
        if high:
            notes.append(
                f"{high} pack(s) contain high-risk commands (AAA, SNMP, routing, ACL…). The "
                "commands above include --allow-high-risk; remove it to approve only the "
                "lower-risk packs."
            )
        if not rem.get("execution_enabled", False):
            notes.insert(0, "Remediation execution is DISABLED in this config "
                            "(audit_settings.remediation.execution.enabled) — approved packs "
                            "cannot be applied until it is enabled.")
        html_parts.append(
            '<div style="border:2px solid #f59e0b;background:#fffbeb;border-radius:6px;'
            'padding:12px 14px;margin:10px 0 16px;">'
            f'<div style="font-size:15px;font-weight:bold;margin-bottom:6px;">Decision required: '
            f"{len(pending)} remediation pack(s) awaiting approval"
            + (f" &middot; {high} high risk" if high else "") + "</div>"
            + "<ul style=\"margin:4px 0 8px 18px;padding:0;font-size:13px;\">"
            + "".join(f"<li>{_e(n)}</li>" for n in notes) + "</ul>"
            f"<pre {_PRE}>{_e(chr(10).join(commands))}</pre>"
            '<div style="font-size:12px;color:#6b7280;">Run these on the audit host. '
            f"To review on the host first: {_e(cmd)} --run-show {_e(run_id)}</div></div>"
        )
        text += ["DECISION REQUIRED", "-" * 17, *[f"* {n}" for n in notes], "", *commands, ""]
    elif packs:
        states = ", ".join(sorted({p["status"] for p in packs}))
        html_parts.append(f"<p>All packs from this run are already decided ({_e(states)}).</p>")
        text += [f"All packs from this run are already decided ({states}).", ""]

    # ── Unreachable devices ────────────────────────────────
    if manifest.get("unreachable"):
        html_parts.append(f"<h3 {_H3}>Devices not audited</h3>")
        html_parts.append(_table(
            ["Device", "IP", "Reason"],
            [[_e(u["hostname"]), _e(u["ip"]), _e(u["error"])] for u in manifest["unreachable"]],
        ))
        text += ["DEVICES NOT AUDITED", *[f"- {u['hostname']} ({u['ip']}): {u['error']}"
                                          for u in manifest["unreachable"]], ""]

    # ── Proposed changes per device ────────────────────────
    if packs:
        html_parts.append(f"<h3 {_H3}>Proposed changes</h3>")
        text += ["PROPOSED CHANGES", ""]
    for item in packs:
        dev, pack = item["device"], item["pack"]
        risk = pack["risk"]["highest"]
        findings = pack.get("findings", [])
        shown = findings if not cap else findings[:cap]
        status = item["status"]
        sched = (f" — scheduled {format_schedule(_parse(item['scheduled_for']))}"
                 if item.get("scheduled_for") else "")
        html_parts.append(
            '<div style="border:1px solid #d1d5db;border-radius:6px;padding:10px 12px;margin:8px 0;">'
            f'<div style="font-size:14px;"><b>{_e(dev["hostname"])}</b> ({_e(dev["ip"])}) '
            f"{_badge(risk.upper() + ' RISK', _RISK_COLOURS.get(risk, ('#374151', '#e5e7eb')))} "
            f'<span style="color:#6b7280;font-size:12px;">{_e(dev.get("role_display") or dev.get("role"))}'
            + (f" &middot; group {_e(dev['group'])}" if dev.get("group") else "")
            + f" &middot; score {_e(dev['score_pct'])}% &middot; {len(findings)} change(s)"
            f" &middot; pack {_e(pack['pack_id'])} &middot; {_e(status)}{_e(sched)}</span></div>"
        )
        html_parts.append(_table(
            ["Check", "Interface", "Finding", "Command", "Risk"],
            [[_e(f.get("check_name")), _e(f.get("interface") or "—"), _e(f.get("detail")),
              f'<code style="font-size:12px;">{_e(f.get("command"))}</code>',
              _badge(f.get("risk", ""), _RISK_COLOURS.get(f.get("risk", ""), ("#374151", "#e5e7eb")))]
             for f in shown],
        ))
        if len(shown) < len(findings):
            html_parts.append(
                f'<div style="font-size:12px;color:#92400e;">{len(findings) - len(shown)} more '
                "change(s) not listed here — see the attached remediation script.</div>"
            )
        config_lines = _flatten_apply_commands(pack.get("command_groups", {}))
        if config_lines and len(shown) == len(findings):
            html_parts.append(
                '<div style="font-size:12px;color:#6b7280;margin-top:4px;">'
                "Configuration that will be sent:</div>"
                f"<pre {_PRE}>{_e(chr(10).join(config_lines))}</pre>"
            )
        earlier_notes: list[str] = []
        for e in item.get("earlier_approved", []):
            when = (f"scheduled for {format_schedule(_parse(e.scheduled_for))}"
                    if e.scheduled_for else "approved, waiting to be applied")
            note = (f"A change for this device from run {e.run_id} is already {when} "
                    f"(pack {e.pack_id}). Approving this run as well is usually unnecessary — "
                    "the preflight drift check skips anything that change has fixed.")
            earlier_notes.append(note)
            html_parts.append(
                f'<div style="font-size:12px;color:#92400e;margin:4px 0;">&#9888; {_e(note)}</div>'
            )
        excluded = pack.get("exceptions_excluded") or []
        if excluded:
            html_parts.append(
                f'<div style="font-size:12px;color:#1e40af;">{len(excluded)} finding(s) on this '
                "device are covered by policy exceptions and are not part of this change.</div>"
            )
        html_parts.append("</div>")

        text += [
            f"{dev['hostname']} ({dev['ip']}) — {risk.upper()} risk — {len(findings)} change(s) "
            f"— pack {pack['pack_id']} — {status}{sched}",
            *[f"  - {f.get('check_name')}"
              + (f" [{f.get('interface')}]" if f.get("interface") else "")
              + f": {f.get('detail')}\n      -> {f.get('command')} ({f.get('risk')})"
              for f in shown],
        ]
        if len(shown) < len(findings):
            text.append(f"  ... {len(findings) - len(shown)} more — see the attached script")
        if excluded:
            text.append(f"  ({len(excluded)} finding(s) covered by policy exceptions)")
        text += [f"  ! {note}" for note in earlier_notes]
        text.append("")

    # ── New since the last run ─────────────────────────────
    new_rows: list[list[str]] = []
    for dev in manifest.get("devices", []):
        delta = dev.get("delta") or {}
        for nf in delta.get("new_failure_items", []):
            new_rows.append([_e(dev["hostname"]), _e(nf.get("check")),
                             _e(nf.get("interface") or "—"), _e(nf.get("status")),
                             _e(nf.get("detail"))])
    if new_rows:
        html_parts.append(f"<h3 {_H3}>New since the previous run</h3>")
        html_parts.append(_table(["Device", "Check", "Interface", "Status", "Detail"], new_rows))
        text += ["NEW SINCE THE PREVIOUS RUN",
                 *[f"- {html.unescape(r[0])}: {html.unescape(r[1])} {html.unescape(r[2])} "
                   f"{html.unescape(r[3])}" for r in new_rows], ""]

    # ── Exceptions needing review ──────────────────────────
    review = (manifest.get("exceptions", {}).get("expired", [])
              + manifest.get("exceptions", {}).get("expiring", []))
    if review:
        html_parts.append(f"<h3 {_H3}>Policy exceptions needing review</h3>")
        html_parts.append(_table(
            ["ID", "State", "Owner / ticket", "Devices", "Reason"],
            [[_e(r["id"]),
              _badge(r["state"].upper(), _STATE_COLOURS.get(r["state"], ("#374151", "#e5e7eb")))
              + f'<div style="font-size:11px;color:#6b7280;">{_e(r.get("status_text"))}</div>',
              _e(" / ".join(x for x in (r.get("owner"), r.get("ticket")) if x) or "—"),
              _e(", ".join(r.get("covered_devices") or []) or "—"),
              _e(r.get("reason"))] for r in review],
        ))
        html_parts.append(
            '<div style="font-size:12px;color:#6b7280;">Expired exceptions are still never '
            "remediated — renew or remove them in exceptions.yaml.</div>"
        )
        text += ["POLICY EXCEPTIONS NEEDING REVIEW",
                 *[f"- {r['id']}: {r.get('status_text')}" for r in review], ""]

    # ── Devices with nothing to approve ────────────────────
    quiet = [d for d in manifest.get("devices", []) if not d.get("pack_id")]
    if quiet:
        html_parts.append(f"<h3 {_H3}>No remediation proposed</h3>")
        html_parts.append(_table(
            ["Device", "IP", "Score", "Fail", "Warn", "Exceptions"],
            [[_e(d["hostname"]), _e(d["ip"]), _e(f"{d['score_pct']}%"), _e(d["fail"]),
              _e(d["warn"]), _e(d["exception"])] for d in quiet],
        ))
        text += ["NO REMEDIATION PROPOSED",
                 *[f"- {d['hostname']} ({d['ip']}): {d['score_pct']}%" for d in quiet], ""]

    # ── Files ──────────────────────────────────────────────
    files = [f"Run summary: {manifest_path(manifest['output_dir'], run_id)}"]
    for label, key in (("Consolidated report", "consolidated_html"), ("CSV", "csv")):
        if manifest.get("reports", {}).get(key):
            files.append(f"{label}: {manifest['reports'][key]}")
    footer = "".join(f"<li>{_e(f)}</li>" for f in files)
    if attached:
        footer += "<li>Attached: " + _e(", ".join(p.name for _k, p, _d in attached)) + "</li>"
    for path, why in omitted:
        footer += f"<li>Not attached: {_e(path.name)} — {_e(why)}</li>"
    html_parts.append(
        f'<h3 {_H3}>Files on {_e(manifest.get("host"))}</h3>'
        f'<ul style="font-size:12px;color:#374151;margin:4px 0 0 18px;padding:0;">{footer}</ul>'
    )
    text += ["FILES", *[f"- {f}" for f in files]]
    text += [f"- Attached: {p.name}" for _k, p, _d in attached]
    text += [f"- Not attached: {p.name} ({why})" for p, why in omitted]

    msg = _new_message(settings, _subject(manifest, len(pending), high))
    msg.set_content("\n".join(text))
    msg.add_alternative(
        '<!DOCTYPE html><html><body style="margin:0;padding:16px;background:#ffffff;">'
        '<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#1f2937;'
        f'max-width:1000px;">{"".join(html_parts)}</div></body></html>',
        subtype="html",
    )
    for kind, path, data in attached:
        subtype = "html" if path.suffix.lower() == ".html" else "plain"
        msg.add_attachment(data, maintype="text", subtype=subtype, filename=path.name)
    return msg


def _parse(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def notify_run(cfg: dict, manifest: dict, *, force: bool = False) -> dict:
    """Build and send the run email.  Never raises; returns an outcome dict.

    *force* ignores ``send_when`` (used when an operator re-sends a run).
    """
    try:
        settings = email_settings(cfg)
    except NotificationError as exc:
        return {"sent": False, "error": str(exc), "skipped": "", "to": []}
    if not settings.enabled:
        return _outcome(settings, skipped="notifications.email.enabled is false")
    if not force:
        send, why = should_send(manifest, settings.send_when)
        if not send:
            return _outcome(settings, skipped=why)
    try:
        rem = get_remediation_settings(cfg.get("audit_settings", {}))
        msg = build_run_email(manifest, settings, remediation=rem)
        send_email(msg, settings)
    except (NotificationError, OSError, KeyError, ValueError) as exc:
        log.error("Run email for %s failed: %s", manifest.get("run_id"), exc)
        return _outcome(settings, error=str(exc))
    log.info("Run email for %s sent to %s", manifest.get("run_id"), ", ".join(settings.to))
    return _outcome(settings, sent=True, subject=msg["Subject"],
                    attachments=[part.get_filename() for part in msg.iter_attachments()])


# ─────────────────────────────────────────────────────────────────────────────
#  Apply, failure and test emails
# ─────────────────────────────────────────────────────────────────────────────

def build_apply_email(
    summaries: list[dict],
    settings: EmailNotificationSchema,
    *,
    trigger: str,
    output_dir: str = "",
) -> EmailMessage:
    ok = sum(1 for s in summaries if s.get("status") in {"success", "dry-run"})
    failed = len(summaries) - ok
    runs = sorted({s.get("run_id", "") for s in summaries if s.get("run_id")})
    subject = (f"Remediation {'FAILED' if failed and not ok else 'applied'}: "
               f"{ok} succeeded, {failed} failed"
               + (f" — {', '.join(runs)}" if runs else ""))
    rows, text = [], [f"Remediation apply ({trigger}) on {socket.gethostname()}", ""]
    for s in summaries:
        good = s.get("status") in {"success", "dry-run"}
        result = (f"{s.get('resolved', 0)}/{s.get('preflight_still_failing', 0)} resolved, "
                  f"{s.get('commands_applied', 0)} command(s)") if good else s.get("error", "")
        if s.get("skipped_for_exceptions"):
            result += f"; {s['skipped_for_exceptions']} skipped (policy exceptions)"
        rows.append([
            _e(s.get("hostname")), _e(s.get("ip")), _e(s.get("pack_id")), _e(s.get("run_id", "")),
            _badge(s.get("status", "").upper(),
                   ("#166534", "#dcfce7") if good else ("#991b1b", "#fee2e2")),
            _e(result),
        ])
        text.append(f"- {s.get('hostname')} ({s.get('ip')}) pack {s.get('pack_id')}: "
                    f"{s.get('status')} — {result}")
    post = (Path(output_dir) / "post_remediation") if output_dir else None
    html_body = (
        f'<h2 style="margin:0 0 8px;font-size:18px;">Remediation apply — {_e(trigger)}</h2>'
        + _table(["Device", "IP", "Pack", "Run", "Status", "Result"], rows)
        + (f'<p style="font-size:12px;color:#6b7280;">Post-remediation reports: {_e(post)}</p>'
           if post else "")
        + '<p style="font-size:12px;color:#6b7280;">Re-run the audit for closure evidence; '
          "the delta report shows what changed.</p>"
    )
    msg = _new_message(settings, subject)
    msg.set_content("\n".join(text + ([f"", f"Post-remediation reports: {post}"] if post else [])))
    msg.add_alternative(
        '<!DOCTYPE html><html><body style="margin:0;padding:16px;">'
        f'<div style="font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#1f2937;">{html_body}'
        "</div></body></html>",
        subtype="html",
    )
    return msg


def notify_apply(cfg: dict, summaries: list[dict], *, trigger: str, output_dir: str = "") -> dict:
    """Email the outcome of an apply.  Never raises."""
    try:
        settings = email_settings(cfg)
    except NotificationError as exc:
        return {"sent": False, "error": str(exc), "skipped": "", "to": []}
    if not settings.enabled or not settings.notify_on_apply:
        return _outcome(settings, skipped="apply emails are off")
    if not summaries:
        return _outcome(settings, skipped="nothing was applied")
    try:
        send_email(build_apply_email(summaries, settings, trigger=trigger,
                                     output_dir=output_dir), settings)
    except NotificationError as exc:
        log.error("Apply email failed: %s", exc)
        return _outcome(settings, error=str(exc))
    return _outcome(settings, sent=True)


def notify_failure(cfg: Optional[dict], message: str) -> dict:
    """Tell recipients a scheduled audit could not run.  Never raises."""
    try:
        settings = email_settings(cfg or {})
    except NotificationError as exc:
        return {"sent": False, "error": str(exc), "skipped": "", "to": []}
    if not settings.enabled or not settings.notify_on_failure:
        return _outcome(settings, skipped="failure emails are off")
    host = socket.gethostname()
    msg = _new_message(settings, f"Scheduled audit FAILED on {host}")
    msg.set_content(
        f"The scheduled compliance audit on {host} could not complete.\n\n{message}\n\n"
        "Check logs/debug.log on the host, fix the cause, and run "
        "python -m compliance_audit --dry-run to confirm before the next run."
    )
    msg.add_alternative(
        '<!DOCTYPE html><html><body style="font-family:Segoe UI,Helvetica,Arial,sans-serif;">'
        f'<h2 style="color:#991b1b;font-size:18px;">Scheduled audit failed on {_e(host)}</h2>'
        f"<pre {_PRE}>{_e(message)}</pre>"
        '<p style="font-size:13px;">Check <code>logs/debug.log</code> on the host, fix the cause, '
        "and run <code>python -m compliance_audit --dry-run</code> before the next run.</p>"
        "</body></html>",
        subtype="html",
    )
    try:
        send_email(msg, settings)
    except NotificationError as exc:
        log.error("Failure email failed: %s", exc)
        return _outcome(settings, error=str(exc))
    return _outcome(settings, sent=True)


def send_test_email(cfg: dict) -> EmailNotificationSchema:
    """Send a test message; raises ``NotificationError`` with the reason on failure."""
    settings = email_settings(cfg)
    if not settings.enabled:
        raise NotificationError("notifications.email.enabled is false in notifications.yaml")
    host = socket.gethostname()
    msg = _new_message(settings, f"Test email from {host}")
    msg.set_content(
        f"This is a test from the compliance audit tool on {host}.\n"
        f"Relay: {settings.smtp_host}:{settings.smtp_port} ({settings.security})\n"
        "If you can read this, scheduled audit emails will reach you."
    )
    send_email(msg, settings)
    return settings
