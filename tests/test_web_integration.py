"""Tests for web-facing integration helpers."""

import json
from pathlib import Path

import pytest

from compliance_audit.remediation_api import (
    approve_review_pack_api,
    list_review_packs_api,
    reject_review_pack_api,
    to_json,
)
from compliance_audit.remediation_workflow import (
    ReviewStore,
    apply_all_approved_packs,
    get_remediation_settings,
)
from compliance_audit.report_artifacts import (
    load_report_artifact_index,
    read_report_content,
    resolve_report_path,
    update_report_artifact_index,
)


def _seed_review_pack(output_dir: Path, *, pack_id: str = "pack-001") -> None:
    script_path = output_dir / "demo_remediation.txt"
    script_path.write_text("configure terminal\nend\n", encoding="utf-8")

    pack_path = output_dir / f"{pack_id}.json"
    pack = {
        "schema_version": 1,
        "pack_id": pack_id,
        "created_ts": "2026-01-01T00:00:00Z",
        "device": {
            "hostname": "ZZ-LAB1-001ASW001",
            "ip": "192.0.2.10",
            "role": "access_switch",
            "role_display": "Access Switch",
            "ios_version": "17.9",
        },
        "summary": {"findings_count": 1, "score_pct": 85.0},
        "script": {"path": str(script_path), "sha256": "demo"},
        "risk": {"counts": {"low": 1, "medium": 0, "high": 0}, "highest": "low"},
        "lifecycle": {"status": "pending"},
        "approval": {
            "approved_by": "",
            "approved_at": "",
            "ticket_id": "",
            "expires_at": "",
            "rejected_by": "",
            "rejected_at": "",
            "reject_reason": "",
        },
        "execution": {"status": "", "applied_at": "", "summary": ""},
        "findings": [],
        "command_groups": {"global": [], "sections": []},
    }
    pack_path.write_text(json.dumps(pack, indent=2), encoding="utf-8")
    ReviewStore(output_dir / "db" / "remediation_reviews.db").upsert_from_pack(
        pack, pack_path
    )


def test_remediation_settings_default_allow_bulk_apply():
    settings = get_remediation_settings(None)
    assert settings["execution_allow_bulk_apply"] is True


def test_remediation_settings_can_disable_bulk_apply():
    settings = get_remediation_settings(
        {"remediation": {"execution": {"allow_bulk_apply": False}}}
    )
    assert settings["execution_allow_bulk_apply"] is False


def test_remediation_api_list_approve_reject_json_payloads(tmp_path: Path):
    _seed_review_pack(tmp_path, pack_id="pack-123")

    listing = list_review_packs_api(str(tmp_path), status="pending")
    assert listing["count"] == 1
    assert listing["packs"][0]["pack_id"] == "pack-123"
    assert json.loads(to_json(listing))["operation"] == "list_review_packs"

    approved = approve_review_pack_api(
        str(tmp_path),
        "pack-123",
        approver="web.user",
        ticket_id="CHG-1001",
        expires_hours=24,
    )
    assert approved["status"] == "approved"
    assert approved["approved_by"] == "web.user"

    rejected = reject_review_pack_api(
        str(tmp_path),
        "pack-123",
        approver="web.user",
        reason="Outside scope",
    )
    assert rejected["status"] == "rejected"
    assert rejected["reject_reason"] == "Outside scope"


def test_apply_all_respects_bulk_policy_gate():
    with pytest.raises(RuntimeError, match="allow_bulk_apply=false"):
        apply_all_approved_packs(
            config_path="unused",
            output_dir="unused",
            remediation_settings={"execution_allow_bulk_apply": False},
        )


def test_report_path_resolution_and_content_read(tmp_path: Path):
    html = tmp_path / "device_report.html"
    html.write_text("<html><body>ok</body></html>", encoding="utf-8")

    resolved = resolve_report_path(tmp_path, "device_report.html")
    assert resolved == html.resolve()

    payload = read_report_content(tmp_path, "device_report.html")
    assert payload["mime_type"] == "text/html"
    assert "ok" in payload["content_text"]
    assert isinstance(payload["content_bytes"], bytes)


def test_report_path_blocks_traversal(tmp_path: Path):
    with pytest.raises(ValueError, match="escapes the allowed root"):
        resolve_report_path(tmp_path, "../outside.html")


def test_report_path_blocks_traversal_windows_style(tmp_path: Path):
    with pytest.raises(ValueError, match="escapes the allowed root"):
        resolve_report_path(tmp_path, "..\\outside.html")


def test_report_artifact_index_includes_html_and_run_id(tmp_path: Path):
    html = tmp_path / "consolidated_report_20260101_120000.html"
    html.write_text("<html></html>", encoding="utf-8")

    update_report_artifact_index(
        str(tmp_path),
        html,
        report_type="consolidated_html",
        run_id="audit-20260101T120000Z",
    )
    index = load_report_artifact_index(str(tmp_path))
    assert index["artifacts"]
    record = index["artifacts"][0]
    assert record["mime_type"] == "text/html"
    assert record["run_id"] == "audit-20260101T120000Z"
    assert record["path"].endswith(".html")
