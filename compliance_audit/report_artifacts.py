"""Helpers for report artifact indexing and safe report file serving."""

from __future__ import annotations

import json
import mimetypes
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

INDEX_FILENAME = "report_artifacts_index.json"

#: Device audits run in a thread pool and every one updates the index.  An
#: unguarded read-modify-write let one thread read the file while another
#: had truncated it to rewrite it, and the JSON error failed that device's
#: whole audit.  The lock serialises updates within the process; the atomic
#: replace means a reader in any process sees the old or new file, never half.
_INDEX_LOCK = threading.Lock()


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_report_artifact_index_path(output_dir: str) -> Path:
    """Return the canonical JSON index path for report artifacts."""
    return Path(output_dir) / INDEX_FILENAME


def _load_index(path: Path) -> dict:
    if not path.exists():
        return {"schema_version": 1, "generated_at": "", "artifacts": []}

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {"schema_version": 1, "generated_at": "", "artifacts": []}

    artifacts = raw.get("artifacts", [])
    if not isinstance(artifacts, list):
        artifacts = []

    return {
        "schema_version": int(raw.get("schema_version", 1)),
        "generated_at": str(raw.get("generated_at", "")),
        "artifacts": artifacts,
    }


def _guess_mime(path: Path) -> str:
    mime, _ = mimetypes.guess_type(str(path))
    return mime or "application/octet-stream"


def update_report_artifact_index(
    output_dir: str,
    artifact_path: Path,
    *,
    report_type: str,
    run_id: str = "",
    hostname: str = "",
) -> Path:
    """Insert or update one artifact entry in the output-dir index."""
    root = Path(output_dir).resolve()
    path = artifact_path.resolve()
    index_path = get_report_artifact_index_path(output_dir)
    index_path.parent.mkdir(parents=True, exist_ok=True)

    rel = path.relative_to(root)
    record = {
        "path": str(rel),
        "absolute_path": str(path),
        "report_type": str(report_type),
        "run_id": str(run_id),
        "hostname": str(hostname),
        "mime_type": _guess_mime(path),
        "created_at": _utc_now_str(),
    }

    with _INDEX_LOCK:
        index = _load_index(index_path)
        artifacts = index["artifacts"]

        replaced = False
        for idx, item in enumerate(artifacts):
            if isinstance(item, dict) and item.get("absolute_path") == str(path):
                artifacts[idx] = record
                replaced = True
                break
        if not replaced:
            artifacts.append(record)

        index["generated_at"] = _utc_now_str()
        tmp = index_path.with_name(f".{index_path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(index, indent=2), encoding="utf-8")
        os.replace(tmp, index_path)
    return index_path


def load_report_artifact_index(output_dir: str) -> dict:
    """Load artifact index metadata from disk."""
    return _load_index(get_report_artifact_index_path(output_dir))


def resolve_report_path(
    allowed_root: str | Path,
    requested_path: str,
    *,
    allowed_suffixes: Optional[set[str]] = None,
) -> Path:
    """Resolve a requested path under allowed_root with traversal protection."""
    root = Path(allowed_root).resolve()
    # Normalise Windows-style backslash separators so traversal checks work on
    # all platforms (e.g. "..\\outside.html" is a traversal on any OS).
    normalised = requested_path.replace("\\", "/")
    candidate = (root / normalised).resolve()

    if root != candidate and root not in candidate.parents:
        raise ValueError("Requested report path escapes the allowed root.")
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(f"Report file not found: {requested_path}")

    suffixes = allowed_suffixes or {".html", ".htm"}
    if candidate.suffix.lower() not in suffixes:
        raise ValueError(
            f"Unsupported report file type: {candidate.suffix or '<none>'}"
        )
    return candidate


def read_report_content(allowed_root: str | Path, requested_path: str) -> dict:
    """Return MIME + bytes/text payload for an allowed report file."""
    resolved = resolve_report_path(allowed_root, requested_path)
    payload = resolved.read_bytes()
    mime = _guess_mime(resolved)
    return {
        "path": str(resolved),
        "mime_type": mime,
        "content_bytes": payload,
        "content_text": payload.decode("utf-8", errors="replace"),
    }
