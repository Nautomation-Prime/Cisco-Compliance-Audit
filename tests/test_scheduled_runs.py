"""
Tests for scheduled audits: run manifests, run-level approval, scheduled
apply, email notifications and unattended (non-interactive) operation.

The end-to-end tests drive the real CLI and engine against a fake SSH layer
and a fake SMTP relay, so the whole flow — audit, email, approve, schedule,
apply when due, apply email — is exercised without a device or a mail server.
"""

from __future__ import annotations

import json
import shutil
import smtplib
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from compliance_audit import __main__ as cli
from compliance_audit import auditor, credentials, notifications
from compliance_audit import remediation_workflow as rw
from compliance_audit.checks.base import AuditResult, Finding, Status
from compliance_audit.collector import DeviceData, parse_running_config
from compliance_audit.config_schema import (
    EmailNotificationSchema,
    validate_compliance_config,
)
from compliance_audit.report import save_remediation_script
from compliance_audit.report_artifacts import (
    load_report_artifact_index,
    update_report_artifact_index,
)
from compliance_audit.runs import (
    LockHeld,
    approve_run,
    build_manifest,
    exclusive_lock,
    list_manifests,
    load_manifest,
    parse_schedule_time,
    reject_run,
    run_status,
    write_manifest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "assets" / "compliance_config"
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _interactive_reset():
    credentials.set_interactive(True)
    yield
    credentials.set_interactive(True)


# ---------------------------------------------------------------------------
# Helpers: packs in a review store
# ---------------------------------------------------------------------------

def _result(hostname="SW1", ip="192.0.2.1", run_id="run-A", *findings) -> AuditResult:
    res = AuditResult(hostname, ip, "access_switch", "Access Switch", list(findings))
    res.audit_ts = f"2026-11-06 {run_id}"
    setattr(res, "run_id", run_id)
    return res


def _make_pack(out: Path, hostname="SW1", run_id="run-A", command="service password-encryption",
               check="service_password_encryption") -> str:
    res = _result(hostname, "192.0.2.1", run_id,
                  Finding(check, Status.FAIL, "Missing", "management_plane", "", command))
    script = save_remediation_script(res, str(out))
    pack = json.loads(rw.generate_review_pack(res, script, str(out)).read_text())
    return pack["pack_id"]


def _status(out: Path, pack_id: str) -> str:
    return rw.get_review_pack(str(out), pack_id)["lifecycle"]["status"]


def _manifest(out: Path, run_id: str, devices=()) -> dict:
    manifest = {
        "schema_version": 1, "run_id": run_id, "finished_at": "2026-11-06T01:30:00Z",
        "host": "audit-host", "tool_version": "1.0.0", "config_path": str(CONFIG_DIR),
        "output_dir": str(out), "totals": {"audited": len(devices), "unreachable": 0,
                                            "score_pct": 50.0, "fail": 1, "warn": 0, "error": 0,
                                            "exception": 0, "expired_exceptions": 0,
                                            "packs": sum(1 for d in devices if d.get("pack_id"))},
        "devices": list(devices), "unreachable": [], "exceptions": {}, "reports": {},
        "notification": {},
    }
    write_manifest(out, manifest)
    return manifest


# ---------------------------------------------------------------------------
# Review store: run IDs, migration, superseding
# ---------------------------------------------------------------------------

class TestReviewStore:
    def test_pack_records_run_and_lists_by_run(self, tmp_path):
        a = _make_pack(tmp_path, "SW1", "run-A")
        b = _make_pack(tmp_path, "SW2", "run-B")
        assert rw.get_review_pack(str(tmp_path), a)["run_id"] == "run-A"
        assert [e.pack_id for e in rw.list_review_packs(str(tmp_path), run_id="run-B")] == [b]

    def test_existing_database_is_migrated(self, tmp_path):
        db = rw.get_review_db_path(str(tmp_path))
        db.parent.mkdir(parents=True)
        with sqlite3.connect(db) as conn:  # the original schema, without run columns
            conn.execute(
                "CREATE TABLE remediation_reviews (pack_id TEXT PRIMARY KEY, hostname TEXT NOT NULL,"
                " ip TEXT NOT NULL, status TEXT NOT NULL, highest_risk TEXT NOT NULL,"
                " findings_count INTEGER NOT NULL, created_ts TEXT NOT NULL, approved_by TEXT,"
                " approved_at TEXT, ticket_id TEXT, expires_at TEXT, rejected_by TEXT,"
                " rejected_at TEXT, reject_reason TEXT, script_path TEXT NOT NULL,"
                " script_sha256 TEXT NOT NULL, pack_path TEXT NOT NULL, applied_at TEXT,"
                " apply_status TEXT, apply_summary TEXT)"
            )
            conn.execute(
                "INSERT INTO remediation_reviews VALUES ('old1','SW9','192.0.2.9','pending','low',1,"
                "'2026-01-01T00:00:00Z','','','','','','','','s','x','p','','','')"
            )
        entries = rw.list_review_packs(str(tmp_path))
        assert entries[0].pack_id == "old1" and entries[0].run_id == ""
        _make_pack(tmp_path, "SW1", "run-A")  # new rows insert fine after migration
        assert len(rw.list_review_packs(str(tmp_path))) == 2

    def test_supersede_only_older_pending_packs(self, tmp_path):
        old_pending = _make_pack(tmp_path, "SW1", "run-A")
        old_approved = _make_pack(tmp_path, "SW1", "run-B", command="no ip http server",
                                  check="no_ip_http_server")
        rw.approve_review_pack(str(tmp_path), old_approved, "jo", "CHG1")
        other_device = _make_pack(tmp_path, "SW2", "run-A")
        current = _make_pack(tmp_path, "SW1", "run-C")

        assert rw.supersede_pending_packs(str(tmp_path), "SW1", "run-C") == [old_pending]
        assert _status(tmp_path, old_pending) == "superseded"
        assert _status(tmp_path, old_approved) == "approved"   # a decision already made
        assert _status(tmp_path, other_device) == "pending"
        assert _status(tmp_path, current) == "pending"

    def test_superseded_pack_cannot_be_approved(self, tmp_path):
        pid = _make_pack(tmp_path, "SW1", "run-A")
        rw.supersede_pending_packs(str(tmp_path), "SW1", "run-B")
        with pytest.raises(RuntimeError, match="superseded"):
            rw.approve_review_pack(str(tmp_path), pid, "jo", "CHG1")


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------

class TestScheduling:
    @pytest.mark.parametrize("text, expected", [
        ("2026-11-07T02:00:00Z", datetime(2026, 11, 7, 2, 0, tzinfo=timezone.utc)),
        ("2026-11-07T03:00:00+01:00", datetime(2026, 11, 7, 2, 0, tzinfo=timezone.utc)),
    ])
    def test_explicit_times(self, text, expected):
        assert parse_schedule_time(text, now=NOW) == expected

    def test_local_time_forms(self):
        local = datetime(2026, 11, 7, 2, 0).astimezone()
        assert parse_schedule_time("2026-11-07 02:00", now=NOW) == local.astimezone(timezone.utc)

    def test_time_of_day_is_next_occurrence(self):
        when = parse_schedule_time("02:00", now=NOW)
        assert NOW < when <= NOW + timedelta(days=1)
        assert when.astimezone().strftime("%H:%M") == "02:00"

    @pytest.mark.parametrize("text", ["2020-01-01 02:00", "yesterday", "", "25:00"])
    def test_rejects_past_and_garbage(self, text):
        with pytest.raises(RuntimeError):
            parse_schedule_time(text, now=NOW)

    def test_approval_window_runs_from_schedule(self, tmp_path):
        pid = _make_pack(tmp_path)
        when = datetime.now(timezone.utc) + timedelta(days=3)
        rw.approve_review_pack(str(tmp_path), pid, "jo", "CHG1", expires_hours=4,
                               scheduled_for=when)
        approval = rw.get_review_pack(str(tmp_path), pid)["approval"]
        expires = datetime.strptime(approval["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
        assert expires.replace(tzinfo=timezone.utc) - when < timedelta(hours=4, minutes=1)
        assert approval["scheduled_for"]

    def test_schedule_must_be_future(self, tmp_path):
        pid = _make_pack(tmp_path)
        with pytest.raises(RuntimeError, match="future"):
            rw.approve_review_pack(str(tmp_path), pid, "jo", "CHG1",
                                   scheduled_for=datetime.now(timezone.utc) - timedelta(minutes=1))

    def test_due_packs(self, tmp_path, monkeypatch):
        later = _make_pack(tmp_path, "SW1", "run-A")
        unscheduled = _make_pack(tmp_path, "SW2", "run-A")
        rw.approve_review_pack(str(tmp_path), later, "jo", "CHG1",
                               scheduled_for=datetime.now(timezone.utc) + timedelta(hours=1))
        rw.approve_review_pack(str(tmp_path), unscheduled, "jo", "CHG1")
        assert rw.due_packs(str(tmp_path)) == []
        future = datetime.now(timezone.utc) + timedelta(hours=2)
        assert [e.pack_id for e in rw.due_packs(str(tmp_path), now=future)] == [later]

    def test_apply_refuses_before_schedule_without_connecting(self, tmp_path, monkeypatch):
        pid = _make_pack(tmp_path)
        rw.approve_review_pack(str(tmp_path), pid, "jo", "CHG1",
                               scheduled_for=datetime.now(timezone.utc) + timedelta(hours=1))
        monkeypatch.setattr(rw, "_open_device_connection_with_creds",
                            lambda *a, **k: pytest.fail("must not connect"))
        with pytest.raises(RuntimeError, match="scheduled"):
            rw.apply_approved_pack(str(CONFIG_DIR), str(tmp_path), pid)


# ---------------------------------------------------------------------------
# Run-level approve / reject
# ---------------------------------------------------------------------------

class TestRunDecisions:
    def _run(self, out: Path) -> tuple[str, str, str]:
        low = _make_pack(out, "SW1", "run-A")
        high = _make_pack(out, "SW2", "run-A", command="no snmp-server community public",
                          check="snmp_no_community_public")
        _manifest(out, "run-A", [
            {"hostname": "SW1", "pack_id": low}, {"hostname": "SW2", "pack_id": high},
        ])
        return "run-A", low, high

    def test_high_risk_needs_explicit_allowance(self, tmp_path):
        run_id, low, high = self._run(tmp_path)
        decision = approve_run(str(tmp_path), run_id, approver="jo", ticket_id="CHG1",
                               expires_hours=24, require_ticket_id=True)
        assert [a["pack_id"] for a in decision.acted] == [low]
        assert decision.skipped[0]["pack_id"] == high
        assert _status(tmp_path, high) == "pending"

    def test_allowance_is_recorded_for_scheduled_apply(self, tmp_path):
        run_id, low, high = self._run(tmp_path)
        when = datetime.now(timezone.utc) + timedelta(hours=1)
        approve_run(str(tmp_path), run_id, approver="jo", ticket_id="CHG1", expires_hours=24,
                    require_ticket_id=True, scheduled_for=when, allow_high_risk=True)
        pack = rw.get_review_pack(str(tmp_path), high)
        assert pack["lifecycle"]["status"] == "approved"
        assert pack["approval"]["allow_high_risk"] is True
        assert pack["approval"]["scheduled_for"]

    def test_reapproving_reschedules(self, tmp_path):
        run_id, low, _high = self._run(tmp_path)
        first = datetime.now(timezone.utc) + timedelta(hours=1)
        second = datetime.now(timezone.utc) + timedelta(hours=5)
        for when in (first, second):
            approve_run(str(tmp_path), run_id, approver="jo", ticket_id="CHG1", expires_hours=24,
                        require_ticket_id=True, scheduled_for=when)
        assert rw.get_review_pack(str(tmp_path), low)["approval"]["scheduled_for"] == \
            second.strftime("%Y-%m-%dT%H:%M:%SZ")

    def test_superseded_run_cannot_be_approved(self, tmp_path):
        run_id, _low, _high = self._run(tmp_path)
        rw.supersede_pending_packs(str(tmp_path), "SW1", "run-B")
        rw.supersede_pending_packs(str(tmp_path), "SW2", "run-B")
        with pytest.raises(RuntimeError, match="approve the newer run"):
            approve_run(str(tmp_path), run_id, approver="jo", ticket_id="CHG1",
                        expires_hours=24, require_ticket_id=True)

    def test_reject_run(self, tmp_path):
        run_id, low, high = self._run(tmp_path)
        decision = reject_run(str(tmp_path), run_id, approver="jo", reason="not now")
        assert len(decision.acted) == 2
        assert _status(tmp_path, low) == _status(tmp_path, high) == "rejected"

    def test_unknown_and_malicious_run_ids(self, tmp_path):
        with pytest.raises(RuntimeError, match="Run not found"):
            run_status(str(tmp_path), "audit-nope")
        with pytest.raises(RuntimeError, match="Invalid run ID"):
            load_manifest(str(tmp_path), "../../etc/passwd")


# ---------------------------------------------------------------------------
# Manifests and locks
# ---------------------------------------------------------------------------

class TestManifestAndLock:
    def test_build_manifest(self, tmp_path):
        res = _result("SW1", "192.0.2.1", "run-A",
                      Finding("a", Status.PASS, "ok"), Finding("b", Status.FAIL, "bad"))
        setattr(res, "_pack", {"pack_id": "p1", "highest_risk": "low", "findings_count": 1})
        m = build_manifest(
            run_id="run-A", started_at=NOW, results=[res],
            unreachable=[{"hostname": "SW2", "ip": "192.0.2.2", "error": "timeout"}],
            config_path="cfg", output_dir=str(tmp_path), tool_version="1.0.0",
        )
        assert m["totals"] == {**m["totals"], "devices": 2, "audited": 1, "unreachable": 1,
                               "score_pct": 50.0, "packs": 1}
        assert m["devices"][0]["pack_id"] == "p1"

    def test_list_manifests_newest_first(self, tmp_path):
        for run_id, ts in (("run-A", "2026-11-05T01:30:00Z"), ("run-B", "2026-11-06T01:30:00Z")):
            write_manifest(tmp_path, {"run_id": run_id, "finished_at": ts})
        assert [m["run_id"] for m in list_manifests(tmp_path)] == ["run-B", "run-A"]

    def test_lock_is_exclusive_and_released(self, tmp_path):
        with exclusive_lock(tmp_path, "audit"):
            with pytest.raises(LockHeld, match="already running"):
                with exclusive_lock(tmp_path, "audit"):
                    pass
            with exclusive_lock(tmp_path, "apply"):  # different lock: fine
                pass
        with exclusive_lock(tmp_path, "audit"):
            pass

    def test_artifact_index_survives_concurrent_updates(self, tmp_path):
        files = []
        for i in range(40):
            f = tmp_path / f"r{i}.json"
            f.write_text("{}")
            files.append(f)
        errors: list[Exception] = []

        def worker(f):
            try:
                update_report_artifact_index(str(tmp_path), f, report_type="json")
            except Exception as exc:  # pragma: no cover - the bug this guards
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f,)) for f in files]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(load_report_artifact_index(str(tmp_path))["artifacts"]) == 40


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

EMAIL = {"enabled": True, "smtp_host": "relay.test", "from_address": "audit@corp.example.com",
         "to": ["netops@corp.example.com"]}


class FakeSMTP:
    """Records what would have been sent."""

    instances: list["FakeSMTP"] = []

    def __init__(self, host, port, timeout=30, context=None):
        self.host, self.port, self.calls, self.messages = host, port, [], []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, context=None):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, msg):
        self.messages.append(msg)


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    return FakeSMTP


def _sent(smtp_cls) -> list:
    return [m for inst in smtp_cls.instances for m in inst.messages]


class TestNotificationSettings:
    def test_shipped_config_valid_and_disabled(self):
        cfg = auditor.read_compliance_config(str(CONFIG_DIR))
        assert notifications.email_settings(cfg).enabled is False

    def test_enabled_needs_relay_and_addresses(self):
        cfg = {"notifications": {"email": {"enabled": True}}}
        assert "smtp_host, from_address, to" in "\n".join(validate_compliance_config(cfg))

    def test_bad_address(self):
        cfg = {"notifications": {"email": {**EMAIL, "to": ["not-an-address"]}}}
        assert "is not an email address" in "\n".join(validate_compliance_config(cfg))

    def test_unknown_key(self):
        cfg = {"notifications": {"email": {**EMAIL, "smtp_server": "x"}}}
        assert "unknown key" in "\n".join(validate_compliance_config(cfg))

    @pytest.mark.parametrize("send_when, totals, expect", [
        ("always", {}, True),
        ("issues", {"fail": 0, "warn": 0}, False),
        ("issues", {"warn": 2}, True),
        ("action_required", {"warn": 2}, False),
        ("action_required", {"packs": 1}, True),
    ])
    def test_should_send(self, send_when, totals, expect):
        assert notifications.should_send({"totals": totals}, send_when)[0] is expect


class TestTransport:
    def test_starttls_and_login(self, smtp, monkeypatch):
        monkeypatch.setenv("SMTP_PASSWORD", "s3cret")
        settings = EmailNotificationSchema(**{**EMAIL, "username": "relayuser"})
        notifications.send_email(notifications._new_message(settings, "x"), settings)
        calls = smtp.instances[0].calls
        assert "starttls" in calls and ("login", "relayuser", "s3cret") in calls

    def test_username_without_password(self, smtp, monkeypatch):
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)
        settings = EmailNotificationSchema(**{**EMAIL, "username": "relayuser"})
        with pytest.raises(notifications.NotificationError, match="SMTP_PASSWORD"):
            notifications.send_email(notifications._new_message(settings, "x"), settings)

    def test_relay_failure_never_raises_from_notify(self, monkeypatch, tmp_path):
        def boom(*a, **k):
            raise OSError("connection refused")
        monkeypatch.setattr(smtplib, "SMTP", boom)
        out = notifications.notify_failure({"notifications": {"email": EMAIL}}, "it broke")
        assert out["sent"] is False and "connection refused" in out["error"]

    def test_disabled_is_skipped(self):
        out = notifications.notify_failure({}, "x")
        assert out["skipped"] and not out["sent"]


# ---------------------------------------------------------------------------
# End to end: audit → email → approve → schedule → apply when due → email
# ---------------------------------------------------------------------------

CONFIGS = {
    "192.0.2.61": "hostname ZZ-LAB1-001ASW001\nip http server\nntp server 192.0.2.70\n"
                  "snmp-server community public RO\n"
                  "interface GigabitEthernet1/0/1\n description <script>alert(1)</script>\n",
    "192.0.2.62": "hostname ZZ-LAB1-001ASW002\nservice password-encryption\nip http server\n"
                  "ntp server 192.0.2.70\nntp server 192.0.2.71\n",
}


class _Conn:
    sent: list[str] = []

    def find_prompt(self):
        return "ZZ-LAB1-001ASW001#"

    def send_config_set(self, commands, cmd_verify=False, exit_config_mode=True):
        _Conn.sent.extend(commands)
        return "ok"

    def save_config(self):
        return "ok"

    def disconnect(self):
        pass


class _Connector:
    def __init__(self, **kw):
        self.kw = kw

    def connect(self):
        if self.kw["ip"] not in CONFIGS:
            raise OSError("timed out")
        return _Conn()


class _Collector:
    def __init__(self, timeout=30):
        pass

    def collect(self, conn, ip=""):
        text = CONFIGS[ip]
        return DeviceData(hostname=text.split()[1], ip=ip, running_config=text,
                          parsed_config=parse_running_config(text))


@pytest.fixture
def site(tmp_path, monkeypatch, smtp):
    cfg_dir = tmp_path / "cfg"
    shutil.copytree(CONFIG_DIR, cfg_dir)
    mp_file = cfg_dir / "management_plane.yaml"
    mp = yaml.safe_load(mp_file.read_text())
    checks = mp["compliance"]["management_plane"]
    for key in ("service_password_encryption", "no_ip_http_server", "ntp_servers",
                "snmp_no_community_public"):
        checks[key]["enabled"] = True
    checks["ntp_servers"]["expected_servers"] = ["192.0.2.70", "192.0.2.71"]
    mp_file.write_text(yaml.safe_dump(mp))
    (cfg_dir / "notifications.yaml").write_text(
        yaml.safe_dump({"notifications": {"email": {**EMAIL, "command": "ca"}}})
    )
    (cfg_dir / "exceptions.yaml").write_text(yaml.safe_dump({"exceptions": [{
        "id": "EXC-1", "hostname": "ZZ-LAB1-001ASW002", "check": "no_ip_http_server",
        "reason": "vendor UI", "expires": "2026-10-01",
    }]}))
    monkeypatch.setenv("SWITCH_USER", "u")
    monkeypatch.setenv("SWITCH_PASS", "p")
    monkeypatch.setattr(auditor, "DeviceConnector", _Connector)
    monkeypatch.setattr(auditor, "DataCollector", _Collector)
    monkeypatch.setattr(cli, "configure_logging", lambda: None)
    monkeypatch.setattr(rw, "_open_device_connection_with_creds", lambda *a, **k: (_Conn(), None))
    monkeypatch.setattr(rw, "_validate_linux_only", lambda: None)
    monkeypatch.setattr(rw, "_collect_fail_set", lambda *a, **k: {
        (c, "") for c in ("service_password_encryption", "no_ip_http_server", "ntp_server",
                          "snmp_no_community_public")})
    _Conn.sent = []
    out = tmp_path / "reports"

    def run(*argv) -> int:
        monkeypatch.setattr(sys, "argv", ["ca", "-c", str(cfg_dir), "-o", str(out), *argv])
        try:
            cli.main()
        except SystemExit as exc:
            return int(exc.code or 0)
        return 0

    devices = ["-d", "ZZ-LAB1-001ASW001:192.0.2.61", "-d", "ZZ-LAB1-001ASW002:192.0.2.62",
               "-d", "ZZ-LAB1-001ASW003:192.0.2.63"]
    return run, out, devices


class TestEndToEnd:
    def _audit(self, site, smtp):
        run, out, devices = site
        assert run(*devices, "--no-jump", "--non-interactive", "--notify") == 1  # findings
        manifest = list_manifests(out)[0]
        return manifest, _sent(smtp)

    def test_audit_writes_manifest_and_emails_decision(self, site, smtp):
        manifest, sent = self._audit(site, smtp)
        assert manifest["totals"]["audited"] == 2
        assert manifest["unreachable"][0]["hostname"] == "ZZ-LAB1-001ASW003"
        assert manifest["notification"]["sent"] is True
        assert [d["hostname"] for d in manifest["devices"] if d["pack_id"]] == ["ZZ-LAB1-001ASW001"]

        msg = sent[0]
        assert "ACTION REQUIRED" in msg["Subject"] and manifest["run_id"] in msg["Subject"]
        html = msg.get_body(("html",)).get_content()
        text = msg.get_body(("plain",)).get_content()
        for body in (html, text):
            assert f"--run-approve {manifest['run_id']}" in body
            assert "--apply-now" in body and "--apply-at" in body and "--run-reject" in body
            assert "no snmp-server community public" in body
            assert "ZZ-LAB1-001ASW003" in body and "EXC-1" in body
        assert "--allow-high-risk" in html  # the pack contains a high-risk command
        assert "<script>" not in html       # device text is escaped
        names = [p.get_filename() for p in msg.iter_attachments()]
        assert any(n.endswith(".txt") for n in names) and any(n.endswith(".html") for n in names)

    def test_attachments_respect_size_cap(self, site, smtp, tmp_path):
        manifest, _ = self._audit(site, smtp)
        # Scripts go first (small, and exactly what would be pushed); the
        # report is left out once the cap is reached and listed instead.
        settings = EmailNotificationSchema(**{**EMAIL, "max_attachment_mb": 0.001})
        msg = notifications.build_run_email(manifest, settings)
        names = [p.get_filename() for p in msg.iter_attachments()]
        assert len(names) == 1 and names[0].endswith(".txt")
        assert "attachment limit" in msg.get_body(("plain",)).get_content()
        settings = EmailNotificationSchema(**{**EMAIL, "max_attachment_mb": 0})
        assert list(notifications.build_run_email(manifest, settings).iter_attachments()) == []

    def test_schedule_then_apply_when_due(self, site, smtp, monkeypatch, capsys):
        run, out, _devices = site
        manifest, _ = self._audit(site, smtp)
        run_id = manifest["run_id"]
        when = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M")

        # Without --ticket-id: refused (ticket required by the shipped config).
        assert run("--run-approve", run_id, "--approver", "Jo", "--apply-at", when,
                   "--remediation-no-confirm") == 2
        # Confirmation can't be asked non-interactively.
        assert run("--non-interactive", "--run-approve", run_id, "--approver", "Jo",
                   "--ticket-id", "CHG1", "--apply-at", when, "--allow-high-risk") == 2
        assert run("--run-approve", run_id, "--approver", "Jo", "--ticket-id", "CHG1",
                   "--apply-at", when, "--allow-high-risk", "--remediation-no-confirm") == 0
        assert run_status(out, run_id).state == "scheduled"

        assert run("--remediation-apply-all") == 0          # leaves the scheduled pack alone
        assert run("--remediation-apply-due") == 0          # not due yet
        assert _Conn.sent == []

        real_now = rw._utc_now
        monkeypatch.setattr(rw, "_utc_now", lambda: real_now() + timedelta(hours=1))
        assert run("--remediation-apply-due", "--non-interactive") == 0
        assert "no snmp-server community public" in _Conn.sent
        assert run_status(out, run_id).state == "applied"
        assert "Remediation applied: 1 succeeded" in _sent(smtp)[-1]["Subject"]

        capsys.readouterr()
        assert run("--run-show", run_id, "--remediation-output", "json") == 0
        shown = json.loads(capsys.readouterr().out)
        assert shown["state"] == "applied" and shown["packs"][0]["status"] == "applied"

    def test_apply_now(self, site, smtp):
        run, out, _devices = site
        manifest, _ = self._audit(site, smtp)
        assert run("--run-approve", manifest["run_id"], "--approver", "Jo", "--ticket-id",
                   "CHG1", "--allow-high-risk", "--apply-now", "--remediation-no-confirm") == 0
        assert "no snmp-server community public" in _Conn.sent
        assert run_status(out, manifest["run_id"]).state == "applied"

    def test_reject_and_next_run_supersedes(self, site, smtp):
        run, out, devices = site
        first, _ = self._audit(site, smtp)
        assert run("--run-reject", first["run_id"], "--approver", "Jo", "--reason", "no") == 0
        assert run_status(out, first["run_id"]).state == "rejected"

        # A pending pack is superseded by the next audit of the same device.
        second, _ = self._audit(site, smtp)
        third, _ = self._audit(site, smtp)
        assert run_status(out, second["run_id"]).state == "superseded"
        assert run_status(out, third["run_id"]).state == "awaiting approval"

    def test_apply_flags_need_run_approve(self, site):
        run, _out, _devices = site
        assert run("--apply-now") == 2

    def test_notify_requires_enabled_email(self, site, tmp_path):
        run, _out, devices = site
        (tmp_path / "cfg" / "notifications.yaml").write_text(
            yaml.safe_dump({"notifications": {"email": {"enabled": False}}})
        )
        assert run(*devices, "--notify") == 2

    def test_missing_credentials_non_interactive(self, site, smtp, monkeypatch):
        run, _out, devices = site
        monkeypatch.delenv("SWITCH_USER")
        monkeypatch.delenv("SWITCH_PASS")
        monkeypatch.setattr(credentials, "load_dotenv", lambda: None)
        assert run(*devices, "--no-jump", "--non-interactive", "--notify") == 2
        assert "FAILED" in _sent(smtp)[-1]["Subject"]

    def test_overlapping_audit_is_skipped(self, site):
        run, out, devices = site
        with exclusive_lock(out, "audit"):
            assert run(*devices, "--no-jump", "--non-interactive") == 2

    def test_earlier_approved_change_is_flagged(self, site, smtp):
        run, out, _devices = site
        first, _ = self._audit(site, smtp)
        when = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M")
        run("--run-approve", first["run_id"], "--approver", "Jo", "--ticket-id", "CHG1",
            "--apply-at", when, "--allow-high-risk", "--remediation-no-confirm")
        second, sent = self._audit(site, smtp)
        assert f"from run {first['run_id']} is already scheduled" in \
            sent[-1].get_body(("plain",)).get_content()


class TestNonInteractiveCredentials:
    def test_prompt_is_refused(self, monkeypatch):
        monkeypatch.delenv("SWITCH_USER", raising=False)
        monkeypatch.delenv("SWITCH_PASS", raising=False)
        monkeypatch.delenv("CREDENTIAL_USER", raising=False)
        monkeypatch.delenv("CREDENTIAL_PASS", raising=False)
        monkeypatch.setattr(credentials, "load_dotenv", lambda: None)
        credentials.set_interactive(False)
        with pytest.raises(RuntimeError, match="non-interactive"):
            credentials.CredentialHandler().get_secret_with_fallback()
