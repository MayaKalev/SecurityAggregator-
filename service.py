"""FastAPI service.

Endpoints:
  POST /classify    on-demand triage of specific CVE IDs
  GET  /findings    browse stored findings
  GET  /health      basic status (includes poller liveness)

Boot is handled in main.py: optional cold-start batch, spawn the poller
daemon thread, then uvicorn.run(app).
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent import SYSTEM_INSTRUCTIONS_BY_ID, run as agent_run
from storage import _connect

log = logging.getLogger("service")

app = FastAPI(
    title="Security Intelligence Aggregator",
    description="On-demand CVE triage + browsing API on top of the agentic engine.",
)

# Set by main.py before uvicorn boots — used by /health.
_poller_thread: threading.Thread | None = None


class ClassifyRequest(BaseModel):
    cve_ids: list[str]


@app.post("/classify")
def classify(req: ClassifyRequest) -> dict[str, Any]:
    """Fetch these CVE IDs from NVD, classify, store, alert any Critical."""
    if not req.cve_ids:
        raise HTTPException(status_code=400, detail="cve_ids must not be empty")

    log.info("/classify: %d CVE IDs requested", len(req.cve_ids))
    user_msg = (
        f"Process these CVE IDs by calling fetch_security_data with "
        f"cve_ids={req.cve_ids}. Classify each, store via store_findings "
        f"(passing last_modified through), and email any Critical findings "
        f"via send_critical_alert."
    )
    final_text = agent_run(user_msg, SYSTEM_INSTRUCTIONS_BY_ID)
    return {
        "ok": True,
        "requested": len(req.cve_ids),
        "agent_response": final_text,
    }


_VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


@app.get("/findings")
def list_findings(severity: str | None = None, limit: int = 100) -> dict[str, Any]:
    """Read stored findings. Optional severity filter, default limit 100."""
    sql = (
        "SELECT id, severity, topics, summary, source_url, "
        "stored_at, source_last_modified FROM findings"
    )
    args: list[Any] = []
    if severity:
        if severity not in _VALID_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail=f"invalid severity {severity!r}; "
                       f"must be one of {sorted(_VALID_SEVERITIES)}",
            )
        sql += " WHERE severity = ?"
        args.append(severity)
    sql += " ORDER BY stored_at DESC LIMIT ?"
    args.append(max(1, min(limit, 1000)))

    conn = _connect()
    try:
        rows = conn.execute(sql, args).fetchall()
    finally:
        conn.close()

    findings = [
        {
            "id": r[0],
            "severity": r[1],
            "topics": json.loads(r[2]),
            "summary": r[3],
            "source_url": r[4],
            "stored_at": r[5],
            "source_last_modified": r[6],
        }
        for r in rows
    ]
    return {"count": len(findings), "findings": findings}


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "poller_alive": _poller_thread.is_alive() if _poller_thread else False,
    }
