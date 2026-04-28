"""SQLite-backed persistence for processed CVE findings.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "findings.db"

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


def _connect() -> sqlite3.Connection:
    """Open a connection and create the table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id                    TEXT PRIMARY KEY,
            topics                TEXT NOT NULL,
            severity              TEXT NOT NULL,
            summary               TEXT NOT NULL,
            source_url            TEXT,
            stored_at             TEXT NOT NULL,
            source_last_modified  TEXT
        )
        """
    )
    return conn



def store_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Persist a batch of findings in a single transaction.

    Each finding dict needs: cve_id, topics (1-5 strings), severity, summary.
    Optional: source_url, source_last_modified.

    Per-row validation runs before the transaction. Invalid rows are skipped
    and reported in `errors`; valid rows commit atomically. INSERT OR REPLACE
    keeps the call idempotent on cve_id.

    Returns: {ok, stored, errors: [{id, error}]}.
    """
    if not findings:
        return {"ok": True, "stored": 0, "errors": []}

    now = datetime.now(timezone.utc).isoformat()
    valid_rows: list[tuple] = []
    errors: list[dict[str, str]] = []

    for finding in findings:
        ok, err = validate_finding(finding)
        if not ok:
            errors.append({"id": str(finding.get("cve_id", "?")), "error": err or ""})
            continue
        valid_rows.append((
            finding["cve_id"],
            json.dumps(finding["topics"]),
            finding["severity"],
            finding["summary"],
            finding.get("source_url", ""),
            now,
            finding.get("source_last_modified"),
        ))

    if valid_rows:
        conn = _connect()
        try:
            conn.executemany(
                "INSERT OR REPLACE INTO findings "
                "(id, topics, severity, summary, source_url, "
                "stored_at, source_last_modified) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                valid_rows,
            )
            conn.commit()
        finally:
            conn.close()

    return {"ok": True, "stored": len(valid_rows), "errors": errors}


def validate_finding(finding: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate one finding dict. Returns (ok, error_message)."""
    cve_id = finding.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id:
        return False, "missing or non-string cve_id"
    if finding.get("severity") not in VALID_SEVERITIES:
        return False, f"invalid severity: {finding.get('severity')!r}"
    topics = finding.get("topics")
    if not isinstance(topics, list) or not topics:
        return False, "topics must be a non-empty list"
    if not all(isinstance(t, str) for t in topics):
        return False, "topics must all be strings"
    summary = finding.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        return False, "missing or empty summary"
    return True, None


def get_critical_findings(cve_ids: list[str]) -> list[dict[str, Any]]:
    """Return stored Critical findings whose id is in the given list."""
    if not cve_ids:
        return []
    placeholders = ",".join("?" for _ in cve_ids)
    conn = _connect()
    try:
        rows = conn.execute(
            f"SELECT id, summary, source_url, topics "
            f"FROM findings WHERE severity = 'Critical' AND id IN ({placeholders})",
            cve_ids,
        ).fetchall()
        return [
            {
                "id": row[0],
                "summary": row[1],
                "source_url": row[2],
                "topics": json.loads(row[3]),
            }
            for row in rows
        ]
    finally:
        conn.close()


def get_latest_modification() -> str | None:
    """Return the most recent source_last_modified across all findings,
    or None if the table is empty."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT MAX(source_last_modified) FROM findings "
            "WHERE source_last_modified IS NOT NULL"
        ).fetchone()
        return row[0] if row and row[0] else None
    finally:
        conn.close()


def find_existing_modifications(cve_ids: list[str]) -> dict[str, str | None]:
    """Look up which of these CVEs are already stored, with their lastModified.

    Returns {cve_id: source_last_modified}. Missing keys mean "not stored".
    The orchestrator uses this to skip the LLM call when the incoming
    last_modified isn't newer than the stored value.
    """
    if not cve_ids:
        return {}
    placeholders = ",".join("?" for _ in cve_ids)
    conn = _connect()
    try:
        rows = conn.execute(
            f"SELECT id, source_last_modified FROM findings WHERE id IN ({placeholders})",
            cve_ids,
        ).fetchall()
        return {row[0]: row[1] for row in rows}
    finally:
        conn.close()
