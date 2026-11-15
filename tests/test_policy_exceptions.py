"""
Tests for policy exceptions (compliance_audit.policy_exceptions).

The property everything else hangs off: a finding covered by an exception is
never remediated — whether the exception is active or expired, whether the
pack was generated before or after the exception was added, and whether or
not the preflight drift check runs.  Expired exceptions are only flagged.
"""

from __future__ import annotations

import ast
import copy
import csv
import json
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml
from rich.console import Console

from compliance_audit import remediation_workflow as rw
from compliance_audit.auditor import read_compliance_config
from compliance_audit.checks.base import (
    FINDING_NAME_ALIASES,
    UNOWNED_FINDING_NAMES,
    AuditResult,
    Finding,
    Status,
    _build_check_map,
    _find_check_key,
)
from compliance_audit.collector import DeviceData, parse_running_config
from compliance_audit.compliance_engine import ComplianceEngine
from compliance_audit.config_schema import (
    CHECK_SCHEMAS,
    ROLE_CHECK_SCHEMAS,
    validate_compliance_config,
)
from compliance_audit.hostname_parser import parse_hostname
from compliance_audit.policy_exceptions import (
    ExceptionRegister,
    ExceptionRule,
    register_rows,
)
from compliance_audit.report import (
    compute_delta,
    print_exception_summary,
    print_report,
    save_consolidated_html,
    save_csv,
    save_html,
    save_json,
    save_remediation_script,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "assets" / "compliance_config"
CHECKS_DIR = REPO_ROOT / "compliance_audit" / "checks"
TODAY = date(2026, 11, 5)
HOST = "ZZ-LAB1-001ASW001"
IP = "192.0.2.61"

_SHIPPED = read_compliance_config(str(CONFIG_DIR), validate=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def exc(**kw) -> dict:
    """A valid exception entry; keyword arguments override fields."""
    entry = {
        "id": "EXC-1",
        "hostnames": [HOST],
        "checks": ["bpdu_guard"],
        "reason": "Uplink to a customer-managed switch",
        "expires": "2027-03-31",
    }
    entry.update(kw)
    return {k: v for k, v in entry.items() if v is not None}


def register(*entries, today=TODAY, **settings) -> ExceptionRegister:
    return ExceptionRegister.from_config(
        {"exceptions": list(entries), "exception_settings": settings}, today=today
    )


def finding(check="bpdu_guard", status=Status.FAIL, interface="", detail="detail",
            remediation="spanning-tree bpduguard enable", category="data_plane"):
    return Finding(check, status, detail, category, interface, remediation)


def result_with(*findings, group="", role="access_switch") -> AuditResult:
    return AuditResult(HOST, IP, role, "Access Switch", list(findings), group=group)


def apply(reg: ExceptionRegister, *findings, group="", role="access_switch",
          check_map=None) -> AuditResult:
    res = result_with(*findings, group=group, role=role)
    reg.apply_to_result(res, check_map or _build_check_map(_SHIPPED["compliance"]))
    return res


def errors_for(cfg) -> str:
    return "\n".join(validate_compliance_config(cfg))


@pytest.fixture
def cfg():
    return copy.deepcopy(_SHIPPED)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestSchema:
    def test_shipped_config_with_exceptions_file_is_valid(self):
        assert "exceptions" in _SHIPPED
        assert validate_compliance_config(_SHIPPED) == []

    def test_valid_entry(self, cfg):
        cfg["exceptions"] = [exc()]
        assert errors_for(cfg) == ""

    @pytest.mark.parametrize("missing", ["id", "reason", "expires", "checks"])
    def test_required_fields(self, cfg, missing):
        cfg["exceptions"] = [exc(**{missing: None})]
        assert f"exceptions[0:" in errors_for(cfg) or "exceptions[0]" in errors_for(cfg)
        assert missing in errors_for(cfg)

    def test_needs_a_device_selector(self, cfg):
        cfg["exceptions"] = [exc(hostnames=None)]
        assert "needs at least one device selector" in errors_for(cfg)

    def test_every_device_on_purpose(self, cfg):
        cfg["exceptions"] = [exc(hostnames=[".*"])]
        assert errors_for(cfg) == ""

    def test_bad_date(self, cfg):
        cfg["exceptions"] = [exc(expires="31/03/2027")]
        assert "exceptions[0:EXC-1].expires" in errors_for(cfg)

    def test_never_needs_allow_permanent(self, cfg):
        cfg["exceptions"] = [exc(expires="never")]
        assert "allow_permanent" in errors_for(cfg)
        cfg["exception_settings"] = {"allow_permanent": True}
        assert errors_for(cfg) == ""

    def test_duplicate_ids(self, cfg):
        cfg["exceptions"] = [exc(), exc(checks=["portfast"])]
        assert "duplicate exception id 'EXC-1'" in errors_for(cfg)

    def test_unknown_check_name_with_suggestion(self, cfg):
        cfg["exceptions"] = [exc(checks=["bpdu_gaurd"])]
        out = errors_for(cfg)
        assert "unknown check 'bpdu_gaurd'" in out
        assert "did you mean 'bpdu_guard'" in out

    @pytest.mark.parametrize(
        "name", ["ntp_server", "ntp_servers", "errdisable_recovery_bpduguard",
                 "unused_shutdown", "vty_lines", "stp_not_root", "storm_control.*"]
    )
    def test_known_names_aliases_prefixes_and_regexes(self, cfg, name):
        cfg["exceptions"] = [exc(checks=[name])]
        assert errors_for(cfg) == ""

    def test_invalid_regex(self, cfg):
        cfg["exceptions"] = [exc(interfaces=["Gi1/0/(1"])]
        assert "invalid regex" in errors_for(cfg)

    def test_invalid_ip(self, cfg):
        cfg["exceptions"] = [exc(hostnames=None, ips=["10.0.0.300"])]
        assert "not an IP address or CIDR network" in errors_for(cfg)

    def test_unknown_role(self, cfg):
        cfg["exceptions"] = [exc(roles=["core_switch"])]
        assert "unknown role 'core_switch'" in errors_for(cfg)

    def test_singular_keys_and_scalars(self, cfg):
        entry = exc(hostnames=None, checks=None)
        entry.update(hostname=HOST, check="bpdu_guard", interface="Gi1/0/1")
        cfg["exceptions"] = [entry]
        assert errors_for(cfg) == ""

    def test_singular_and_plural_together(self, cfg):
        cfg["exceptions"] = [exc(check="portfast")]
        assert "use either 'check' or 'checks'" in errors_for(cfg)

    def test_unknown_key_suggests(self, cfg):
        cfg["exceptions"] = [exc(expiry="2027-01-01")]
        assert "unknown key" in errors_for(cfg)

    def test_approved_after_expiry(self, cfg):
        cfg["exceptions"] = [exc(approved_on="2027-04-01")]
        assert "approved_on" in errors_for(cfg)

    def test_whitespace_in_id(self, cfg):
        cfg["exceptions"] = [exc(id="EXC 1")]
        assert "must not contain whitespace" in errors_for(cfg)

    def test_numeric_id_and_ticket_accepted(self, cfg):
        cfg["exceptions"] = [exc(id=42, ticket=12345)]
        assert errors_for(cfg) == ""

    def test_exceptions_must_be_a_list(self, cfg):
        cfg["exceptions"] = {"EXC-1": exc()}
        assert "exceptions: must be a list" in errors_for(cfg)

    def test_settings_typo(self, cfg):
        cfg["exception_settings"] = {"expiring_soon_day": 10}
        assert "exception_settings.expiring_soon_day: unknown key" in errors_for(cfg)

    def test_error_names_the_source_file(self, cfg):
        cfg["exceptions"] = [{**exc(checks=["nope"]), "_source": "exceptions_brn.yaml"}]
        assert "(in exceptions_brn.yaml)" in errors_for(cfg)


class TestFindingNameRegistry:
    """Every finding name the engine emits must resolve, or exceptions on it are typos."""

    def emitted_names(self) -> set[str]:
        names: set[str] = set()
        for path in CHECKS_DIR.glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                fname = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                arg = None
                if fname == "Finding" and node.args:
                    arg = node.args[0]
                elif fname in ("_present", "_absent") and len(node.args) >= 3:
                    arg = node.args[2]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    names.add(arg.value)
        return names

    def test_every_emitted_name_resolves(self):
        keys = {k for s in CHECK_SCHEMAS.values() for k in s}
        keys |= {k for s in ROLE_CHECK_SCHEMAS.values() for k in s}
        check_map = {k: {} for k in keys}
        unresolved = {
            n for n in self.emitted_names()
            if not _find_check_key(n, check_map) and n not in UNOWNED_FINDING_NAMES
        }
        assert unresolved == set()

    def test_aliases_point_at_real_checks(self):
        keys = {k for s in CHECK_SCHEMAS.values() for k in s}
        keys |= {k for s in ROLE_CHECK_SCHEMAS.values() for k in s}
        assert set(FINDING_NAME_ALIASES.values()) <= keys

    def test_alias_now_carries_check_severity(self):
        # ntp_server findings used to miss the ntp_servers node entirely.
        check_map = {"ntp_servers": {"severity": "critical", "tags": ["time"]}}
        assert _find_check_key("ntp_server", check_map) == "ntp_servers"


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestLoading:
    def _copy_config(self, tmp_path: Path) -> Path:
        dst = tmp_path / "cfg"
        shutil.copytree(CONFIG_DIR, dst)
        return dst

    def test_exceptions_concatenate_across_files(self, tmp_path):
        d = self._copy_config(tmp_path)
        (d / "exceptions.yaml").write_text(yaml.safe_dump({"exceptions": [exc()]}))
        (d / "exceptions_site_b.yaml").write_text(
            yaml.safe_dump({"exceptions": [exc(id="EXC-2", checks=["portfast"])]})
        )
        cfg = read_compliance_config(str(d))
        assert [e["id"] for e in cfg["exceptions"]] == ["EXC-1", "EXC-2"]
        assert cfg["exceptions"][1]["_source"] == "exceptions_site_b.yaml"

    def test_external_exceptions_file(self, tmp_path):
        d = self._copy_config(tmp_path)
        ext = tmp_path / "risk" / "net_exceptions.yaml"
        ext.parent.mkdir()
        ext.write_text(yaml.safe_dump({
            "exceptions": [exc(id="EXT-1")],
            "exception_settings": {"fail_on_expired": True},
        }))
        (d / "exceptions.yaml").write_text(yaml.safe_dump({
            "exceptions": [exc()],
            "exceptions_file": str(ext),
        }))
        cfg = read_compliance_config(str(d))
        assert [e["id"] for e in cfg["exceptions"]] == ["EXC-1", "EXT-1"]
        assert cfg["exception_settings"]["fail_on_expired"] is True
        assert ExceptionRegister.from_config(cfg).settings.fail_on_expired is True

    def test_external_file_may_only_hold_exceptions(self, tmp_path):
        d = self._copy_config(tmp_path)
        ext = tmp_path / "x.yaml"
        ext.write_text(yaml.safe_dump({"exceptions": [], "compliance": {}}))
        (d / "exceptions.yaml").write_text(yaml.safe_dump({"exceptions_file": str(ext)}))
        with pytest.raises(ValueError, match="may only contain"):
            read_compliance_config(str(d))

    def test_missing_external_file(self, tmp_path):
        d = self._copy_config(tmp_path)
        (d / "exceptions.yaml").write_text(yaml.safe_dump({"exceptions_file": "nope.yaml"}))
        with pytest.raises(FileNotFoundError, match="exceptions_file not found"):
            read_compliance_config(str(d))

    def test_validate_config_reports_register_state(self, tmp_path):
        d = self._copy_config(tmp_path)
        (d / "exceptions.yaml").write_text(yaml.safe_dump({"exceptions": [
            exc(id="OLD-1", expires="2020-01-01"),
            exc(id="NEW-1", checks=["portfast"], expires="2099-01-01"),
        ]}))
        proc = subprocess.run(
            [sys.executable, "-m", "compliance_audit", "--config", str(d), "--validate-config"],
            capture_output=True, text=True, cwd=REPO_ROOT,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "Config valid" in proc.stdout
        assert "EXPIRED" in proc.stdout and "OLD-1" in proc.stdout


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

class TestDeviceMatching:
    @pytest.mark.parametrize("pattern, hostname, ip, expected", [
        (HOST, HOST, IP, True),
        (HOST.lower(), HOST, IP, True),                      # case-insensitive
        (HOST, HOST + "0", IP, False),                       # whole-name, not prefix
        ("ZZ-LAB1-.*", HOST, IP, True),                      # regex
        (HOST, HOST + ".corp.example", IP, True),            # short name
        (IP, "unknown-name", IP, True),                      # management IP
    ])
    def test_hostnames(self, pattern, hostname, ip, expected):
        rule = ExceptionRule.from_entry(exc(hostnames=[pattern]))
        assert rule.matches_device(hostname, ip) is expected

    def test_ips_cidr(self):
        rule = ExceptionRule.from_entry(exc(hostnames=None, ips=["192.0.2.0/25"]))
        assert rule.matches_device(HOST, "192.0.2.61")
        assert not rule.matches_device(HOST, "192.0.2.200")
        assert not rule.matches_device(HOST, "not-an-ip")

    def test_groups_case_insensitive_and_unknown_group(self):
        rule = ExceptionRule.from_entry(exc(hostnames=None, groups=["Site_Lab"]))
        assert rule.matches_device(HOST, IP, group="site_lab")
        assert not rule.matches_device(HOST, IP, group="site_brn")
        assert not rule.matches_device(HOST, IP, group="")
        # None = unknown (legacy review pack): err towards "covered".
        assert rule.matches_device(HOST, IP, group=None)

    def test_roles(self):
        rule = ExceptionRule.from_entry(exc(hostnames=None, roles=["access_switch"]))
        assert rule.matches_device(HOST, IP, role="access_switch")
        assert not rule.matches_device(HOST, IP, role="unknown")

    def test_all_selectors_must_match(self):
        rule = ExceptionRule.from_entry(exc(groups=["site_lab"]))
        assert rule.matches_device(HOST, IP, group="site_lab")
        assert not rule.matches_device("OTHER", IP, group="site_lab")
        assert not rule.matches_device(HOST, IP, group="site_brn")


class TestFindingMatching:
    def test_by_finding_name(self):
        res = apply(register(exc()), finding())
        assert res.findings[0].status == Status.EXCEPTION

    def test_by_yaml_key_through_alias(self):
        reg = register(exc(checks=["ntp_servers"]))
        res = apply(reg, finding("ntp_server", remediation="ntp server 192.0.2.70"))
        assert res.findings[0].status == Status.EXCEPTION

    def test_by_yaml_key_for_dynamic_names(self):
        reg = register(exc(checks=["errdisable_recovery"]))
        res = apply(reg, finding("errdisable_recovery_bpduguard"))
        assert res.findings[0].status == Status.EXCEPTION

    def test_regex(self):
        reg = register(exc(checks=["storm_control.*"]))
        res = apply(reg, finding("storm_control_action"), finding("storm_control"),
                    finding("portfast"))
        assert [f.status for f in res.findings] == [
            Status.EXCEPTION, Status.EXCEPTION, Status.FAIL]

    @pytest.mark.parametrize("pattern, interface, expected", [
        ("Gi1/0/48", "GigabitEthernet1/0/48", True),
        ("GigabitEthernet1/0/48", "Gi1/0/48", True),
        ("gi1/0/48", "GigabitEthernet1/0/48", True),
        ("Gi1/0/4", "GigabitEthernet1/0/48", False),
        ("Gi1/0/(4[0-8])", "GigabitEthernet1/0/45", True),
        ("Gi1/0/(4[0-8])", "GigabitEthernet1/0/49", False),
        ("GigabitEthernet1/0/.*", "GigabitEthernet1/0/7", True),
    ])
    def test_interfaces(self, pattern, interface, expected):
        res = apply(register(exc(interfaces=[pattern])), finding(interface=interface))
        assert (res.findings[0].status == Status.EXCEPTION) is expected

    def test_interface_scoped_exception_skips_global_findings(self):
        res = apply(register(exc(interfaces=["Gi1/0/1"])), finding(interface=""))
        assert res.findings[0].status == Status.FAIL

    def test_detail_selects_one_of_several_findings(self):
        reg = register(exc(checks=["ntp_servers"], detail=r"192\.0\.2\.71"))
        res = apply(
            reg,
            finding("ntp_server", detail="NTP server 192.0.2.70 missing"),
            finding("ntp_server", detail="NTP server 192.0.2.71 missing"),
        )
        assert [f.status for f in res.findings] == [Status.FAIL, Status.EXCEPTION]

    @pytest.mark.parametrize("status, covered", [
        (Status.FAIL, True), (Status.WARN, True),
        (Status.ERROR, False), (Status.PASS, False), (Status.SKIP, False),
    ])
    def test_only_fail_and_warn_are_covered(self, status, covered):
        res = apply(register(exc()), finding(status=status))
        assert (res.findings[0].status == Status.EXCEPTION) is covered
        if covered:
            assert res.findings[0].exception.original_status == status.value

    def test_other_device_untouched(self):
        res = apply(register(exc(hostnames=["OTHER-SWITCH"])), finding())
        assert res.findings[0].status == Status.FAIL
        assert res.unused_exceptions == []

    def test_latest_expiry_wins(self):
        reg = register(exc(id="OLD", expires="2026-01-01"),
                       exc(id="RENEWED", expires="2027-06-30"))
        res = apply(reg, finding())
        assert res.findings[0].exception.id == "RENEWED"
        assert res.findings[0].exception_state == "active"

    def test_unused_exceptions_reported_per_device(self):
        reg = register(exc(), exc(id="EXC-2", checks=["portfast"]))
        res = apply(reg, finding(), finding("portfast", status=Status.PASS))
        assert [u["id"] for u in res.unused_exceptions] == ["EXC-2"]


class TestLifecycle:
    @pytest.mark.parametrize("expires, state, days", [
        ("2027-03-31", "active", 146),
        ("2026-11-20", "expiring", 15),
        ("2026-11-05", "expiring", 0),     # valid through its expiry date
        ("2026-11-04", "expired", -1),     # expired the day after
        ("2020-01-01", "expired", -2500),
    ])
    def test_states(self, expires, state, days):
        rule = ExceptionRule.from_entry(exc(expires=expires))
        assert rule.state_on(TODAY, 30) == (state, days)

    def test_permanent(self):
        reg = register(exc(expires="never"), allow_permanent=True)
        res = apply(reg, finding())
        assert res.findings[0].exception_state == "permanent"
        assert res.findings[0].exception.days_remaining is None

    def test_expiring_window_can_be_disabled(self):
        rule = ExceptionRule.from_entry(exc(expires="2026-11-06"))
        assert rule.state_on(TODAY, 0)[0] == "active"

    def test_state_counts(self):
        reg = register(exc(), exc(id="B", expires="2020-01-01"),
                       exc(id="C", expires="2026-11-10"))
        assert reg.state_counts() == {
            "active": 1, "expiring": 1, "expired": 1, "permanent": 0}


# ---------------------------------------------------------------------------
# Scoring and exit codes
# ---------------------------------------------------------------------------

class TestScoring:
    def _result(self, **settings):
        reg = register(exc(id="ACTIVE", checks=["portfast"]),
                       exc(id="EXPIRED", expires="2020-01-01"), **settings)
        return apply(
            reg,
            finding("bpdu_guard"),                  # → expired exception
            finding("portfast"),                    # → active exception
            finding("root_guard", status=Status.PASS),
            finding("trunk_native_vlan"),           # plain FAIL
        )

    def test_exceptions_leave_the_score_by_default(self):
        res = self._result()
        assert (res.exception_count, res.expired_exception_count) == (2, 1)
        assert res.total == 2 and res.score_pct == 50.0
        assert res.fail_count == 1

    def test_expired_can_count_against_the_score(self):
        res = self._result(expired_counts_against_score=True)
        assert res.total == 3 and res.score_pct == 33.3

    def test_has_failures(self):
        reg = register(exc(expires="2020-01-01"))
        assert not apply(reg, finding()).has_failures
        reg = register(exc(expires="2020-01-01"), fail_on_expired=True)
        assert apply(reg, finding()).has_failures
        reg = register(exc(), fail_on_expired=True)  # active → never fails the run
        assert not apply(reg, finding()).has_failures


# ---------------------------------------------------------------------------
# Engine integration
# ---------------------------------------------------------------------------

class TestEngine:
    POLICY = {"management_plane": {
        "service_password_encryption": {"enabled": True, "severity": "high", "tags": []},
        "no_ip_http_server": {
            "enabled": True, "severity": "high", "tags": [],
            "exclude_hostnames": ["ZZ-LAB1-.*"],
        },
    }}

    def _audit(self, reg, group="site_lab"):
        text = f"hostname {HOST}\nip http server\n"
        data = DeviceData(hostname=HOST, ip=IP, running_config=text,
                          parsed_config=parse_running_config(text))
        engine = ComplianceEngine(self.POLICY, exceptions=reg)
        return engine.audit(data, parse_hostname(HOST), {}, group=group)

    def _one(self, res, name):
        return next(f for f in res.findings if f.check_name == name)

    def test_engine_applies_exceptions_and_records_group(self):
        reg = register(exc(hostnames=None, groups=["site_lab"],
                           checks=["service_password_encryption"]))
        res = self._audit(reg)
        assert res.group == "site_lab"
        assert self._one(res, "service_password_encryption").status == Status.EXCEPTION

    def test_yaml_skip_wins_over_exception(self):
        reg = register(exc(checks=["no_ip_http_server"]))
        res = self._audit(reg)
        assert self._one(res, "no_ip_http_server").status == Status.SKIP
        assert [u["id"] for u in res.unused_exceptions] == ["EXC-1"]

    def test_no_register_means_no_change(self):
        res = self._audit(None)
        assert self._one(res, "service_password_encryption").status == Status.FAIL


# ---------------------------------------------------------------------------
# Never remediated
# ---------------------------------------------------------------------------

def _mixed_result(*, expired=False) -> AuditResult:
    reg = register(exc(interfaces=["Gi1/0/48"],
                       expires="2020-01-01" if expired else "2027-03-31"))
    return apply(
        reg,
        finding(interface="GigabitEthernet1/0/48", remediation="spanning-tree bpduguard enable"),
        finding(interface="GigabitEthernet1/0/1", remediation="spanning-tree bpduguard enable"),
        group="site_lab",
    )


class TestNeverRemediated:
    @pytest.mark.parametrize("expired", [False, True])
    def test_script_leaves_out_excepted_findings(self, tmp_path, expired):
        script = save_remediation_script(_mixed_result(expired=expired), str(tmp_path))
        text = script.read_text()
        assert "interface GigabitEthernet1/0/1\n" in text
        assert "GigabitEthernet1/0/48" not in text
        assert "Findings to fix: 1" in text

    def test_no_script_when_everything_is_excepted(self, tmp_path):
        res = apply(register(exc(expires="2020-01-01")), finding())
        assert save_remediation_script(res, str(tmp_path)) is None

    @pytest.mark.parametrize("expired", [False, True])
    def test_review_pack_leaves_out_excepted_findings(self, tmp_path, expired):
        res = _mixed_result(expired=expired)
        script = save_remediation_script(res, str(tmp_path))
        pack = json.loads(rw.generate_review_pack(res, script, str(tmp_path)).read_text())
        assert [i["interface"] for i in pack["findings"]] == ["GigabitEthernet1/0/1"]
        assert pack["device"]["group"] == "site_lab"
        assert pack["exceptions_excluded"][0]["exception_id"] == "EXC-1"
        flat = json.dumps(pack["command_groups"])
        assert "GigabitEthernet1/0/48" not in flat

    def test_split_excepted_items(self):
        items = [
            {"check_name": "bpdu_guard", "interface": "GigabitEthernet1/0/48", "detail": "d"},
            {"check_name": "bpdu_guard", "interface": "GigabitEthernet1/0/1", "detail": "d"},
        ]
        reg = register(exc(interfaces=["Gi1/0/48"], expires="2020-01-01"))
        allowed, excepted = rw._split_excepted_items(
            items, reg, hostname=HOST, ip=IP, role="access_switch", group="",
            check_map={},
        )
        assert [i["interface"] for i in allowed] == ["GigabitEthernet1/0/1"]
        assert excepted[0]["exception_state"] == "expired"


class _FakeConnection:
    def __init__(self):
        self.sent: list[str] = []

    def find_prompt(self):
        return f"{HOST}#"

    def send_config_set(self, commands, cmd_verify=False, exit_config_mode=True):
        self.sent.extend(commands)
        return "ok"

    def save_config(self):
        return "ok"

    def disconnect(self):
        pass


class _FakeCreds:
    def __init__(self, *a, **kw):
        pass

    def get_secret_with_fallback(self):
        return "user", "pass"

    def get_enable_secret(self):
        return None


class TestApplyTimeGuard:
    """A pack approved *before* an exception existed must not push the excepted change."""

    @pytest.fixture
    def env(self, tmp_path, monkeypatch):
        cfg_dir = tmp_path / "cfg"
        shutil.copytree(CONFIG_DIR, cfg_dir)
        out = tmp_path / "reports"

        # Generate and approve a pack while no exception exists.
        res = apply(
            register(),
            finding(interface="GigabitEthernet1/0/48"),
            finding(interface="GigabitEthernet1/0/1"),
            group="site_lab",
        )
        script = save_remediation_script(res, str(out))
        pack = json.loads(rw.generate_review_pack(res, script, str(out)).read_text())
        rw.approve_review_pack(str(out), pack["pack_id"], "tester", "CHG1",
                               require_ticket_id=False)

        conn = _FakeConnection()
        opened: list[bool] = []

        def fake_open(*a, **kw):
            opened.append(True)
            return conn, None

        monkeypatch.setattr(rw, "CredentialHandler", _FakeCreds)
        monkeypatch.setattr(rw, "_open_device_connection_with_creds", fake_open)
        monkeypatch.setattr(rw, "_validate_linux_only", lambda: None)
        # The device still fails everything, as if exceptions were not applied
        # on the device side — the guard must not depend on the drift check.
        monkeypatch.setattr(
            rw, "_collect_fail_set",
            lambda *a, **kw: {("bpdu_guard", "GigabitEthernet1/0/48"),
                              ("bpdu_guard", "GigabitEthernet1/0/1")},
        )
        settings = rw.get_remediation_settings({"remediation": {
            "execution": {"enabled": True, "generate_post_report": False,
                          "save_config": False},
        }})
        return cfg_dir, out, pack["pack_id"], conn, opened, settings

    def _add_exception(self, cfg_dir: Path, **kw):
        (cfg_dir / "exceptions.yaml").write_text(yaml.safe_dump({"exceptions": [exc(**kw)]}))

    @pytest.mark.parametrize("preflight", [True, False])
    @pytest.mark.parametrize("expires", ["2099-01-01", "2020-01-01"])
    def test_excepted_item_is_not_pushed(self, env, preflight, expires):
        cfg_dir, out, pack_id, conn, _opened, settings = env
        settings["execution_preflight_drift_check"] = preflight
        self._add_exception(cfg_dir, interfaces=["Gi1/0/48"], expires=expires)

        summary = rw.apply_approved_pack(
            str(cfg_dir), str(out), pack_id, remediation_settings=settings
        )
        assert summary["skipped_for_exceptions"] == 1
        assert "interface GigabitEthernet1/0/1" in conn.sent
        assert "interface GigabitEthernet1/0/48" not in conn.sent

    def test_fully_excepted_pack_never_connects(self, env):
        cfg_dir, out, pack_id, conn, opened, settings = env
        self._add_exception(cfg_dir, expires="2020-01-01")
        with pytest.raises(RuntimeError, match="covered by a policy exception"):
            rw.apply_approved_pack(str(cfg_dir), str(out), pack_id,
                                   remediation_settings=settings)
        assert opened == [] and conn.sent == []

    def test_group_exception_matches_legacy_pack_without_group(self, env):
        cfg_dir, out, pack_id, conn, _opened, settings = env
        pack_path = rw.ReviewStore(rw.get_review_db_path(str(out))).get_pack_path(pack_id)
        pack = json.loads(pack_path.read_text())
        del pack["device"]["group"]                     # written by an older version
        pack_path.write_text(json.dumps(pack))
        self._add_exception(cfg_dir, hostnames=None, groups=["some_other_site"],
                            interfaces=["Gi1/0/48"])
        rw.apply_approved_pack(str(cfg_dir), str(out), pack_id, remediation_settings=settings)
        assert "interface GigabitEthernet1/0/48" not in conn.sent


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

class TestReports:
    def _result(self):
        reg = register(
            exc(interfaces=["Gi1/0/48"], expires="2020-01-01", owner="NetEng", ticket="CHG1"),
            exc(id="EXC-2", checks=["portfast"]),
        )
        res = apply(
            reg,
            finding(interface="GigabitEthernet1/0/48"),
            finding(interface="GigabitEthernet1/0/1"),
            finding("root_guard", status=Status.PASS),
        )
        return res, reg

    def test_json(self, tmp_path):
        res, _ = self._result()
        data = json.loads(save_json(res, str(tmp_path)).read_text())
        assert data["exception"] == 1 and data["exception_expired"] == 1
        covered = [f for f in data["findings"] if f["status"] == "EXCEPTION"]
        assert covered[0]["exception"]["id"] == "EXC-1"
        assert covered[0]["exception"]["state"] == "expired"
        assert covered[0]["exception"]["original_status"] == "FAIL"
        assert [u["id"] for u in data["exceptions"]["unused"]] == ["EXC-2"]

    def test_csv(self, tmp_path):
        res, _ = self._result()
        with open(save_csv([res], str(tmp_path)), newline="") as fh:
            rows = list(csv.DictReader(fh))
        covered = [r for r in rows if r["status"] == "EXCEPTION"]
        assert covered[0]["exception_id"] == "EXC-1"
        assert covered[0]["exception_state"] == "expired"
        assert covered[0]["exception_owner"] == "NetEng"

    def test_html(self, tmp_path):
        res, reg = self._result()
        page = save_html(res, str(tmp_path)).read_text()
        assert 'data-status="EXCEPTION"' in page and 'data-exception="expired"' in page
        assert "Not remediated" in page and "need review" in page
        assert 'data-filter="EXPIRED"' in page
        consolidated = save_consolidated_html(
            [res], str(tmp_path), exception_register=reg
        ).read_text()
        assert "Exception register" in consolidated
        assert "EXC-2" in consolidated  # unused exceptions are listed too

    def test_console(self):
        res, reg = self._result()
        con = Console(record=True, width=200)
        print_report(res, console=con)
        print_exception_summary([res], reg, console=con)
        text = con.export_text()
        assert "EXPIRED" in text and "EXC-1" in text
        assert "not remediated" in text

    def test_register_rows_usage(self):
        res, reg = self._result()
        reg.rules.append(ExceptionRule.from_entry(exc(id="FAR", hostnames=["ELSEWHERE"])))
        rows = {r["id"]: r for r in register_rows([res], reg)}
        assert rows["EXC-1"]["usage"] == "in_use" and rows["EXC-1"]["state"] == "expired"
        assert rows["EXC-2"]["usage"] == "unused"
        assert rows["FAR"]["usage"] == "out_of_scope"
        assert list(rows)[0] == "EXC-1"  # expired first

    def test_delta_reports_findings_moved_to_exception(self, tmp_path):
        baseline_res = apply(register(), finding(interface="GigabitEthernet1/0/48"))
        baseline = json.loads(save_json(baseline_res, str(tmp_path)).read_text())
        current, _ = self._result()
        delta = compute_delta(baseline, current)
        assert delta["excepted_count"] == 1
        assert delta["excepted"][0]["exception_id"] == "EXC-1"
        assert delta["resolved_count"] == 0
