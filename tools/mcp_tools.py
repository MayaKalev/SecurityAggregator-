"""MCP-style tool registry.

Three artifacts per tool:
  - the Python callable
  - a JSON Schema in TOOLS (what the LLM sees)
  - a name -> callable entry in TOOL_DISPATCH (how the agent dispatches)
"""

from __future__ import annotations

import logging
from typing import Any

from clients.email_client import send_email
from clients.nvd_client import nvd_get
from storage import get_critical_findings, store_findings

log = logging.getLogger("tools")

NVD_VULN_URL_PREFIX = "https://nvd.nist.gov/vuln/detail/"
IMPORTANT_SEVERITIES = {"Critical", "High"}
MAX_LOGGED_FINDINGS = 5




# ---------- tool: fetch_security_data ----------

def fetch_security_data(
    results_per_page: int = 100,
    start_idx: int = 0,
    cve_ids: list[str] | None = None,
    last_mod_start_date: str | None = None,
    last_mod_end_date: str | None = None,
) -> dict[str, Any]:
    """Fetch CVEs from NIST NVD.

    Pick exactly one selection mode:
      cve_ids                                 — fetch these specific CVEs
      last_mod_start_date + last_mod_end_date — explicit time window

    Returns: {items, total_results, start_index, results_per_page, next_start_index}.
    Each item has: id, description, source_url, published, last_modified.
    """
    # Require a selection mode — fail loud rather than silently fetching
    # "the latest 100" when the caller forgot to pass anything.
    if not cve_ids and last_mod_start_date is None and last_mod_end_date is None:
        raise ValueError(
            "must specify a selection mode: cve_ids, "
            "or last_mod_start_date + last_mod_end_date"
        )

    if cve_ids:
        return fetch_by_cve_ids(cve_ids)

    if not last_mod_start_date or not last_mod_end_date:
        raise ValueError(
            "last_mod_start_date and last_mod_end_date must be passed together"
        )

    params: dict[str, Any] = {
        "resultsPerPage": max(1, min(results_per_page, 2000)),
        "startIndex": max(0, start_idx),
        "lastModStartDate": last_mod_start_date,
        "lastModEndDate": last_mod_end_date,
    }

    payload = nvd_get(params)
    items = normalize_items(payload.get("vulnerabilities", []))

    total = int(payload.get("totalResults", len(items)))
    res_per_page = int(payload.get("resultsPerPage", len(items)))
    start_idx = int(payload.get("startIndex", start_idx))
    next_start_idx = start_idx + res_per_page if (start_idx + res_per_page) < total else None

    return {
        "items": items,
        "total_results": total,
        "start_index": start_idx,
        "results_per_page": res_per_page,
        "next_start_index": next_start_idx,
    }


def fetch_by_cve_ids(cve_ids: list[str]) -> dict[str, Any]:
    """One nvd_get per ID — NVD's cveId param takes a single value."""
    items: list[dict[str, Any]] = []
    for cve_id in cve_ids:
        payload = nvd_get({"cveId": cve_id})
        found = normalize_items(payload.get("vulnerabilities", []))
        if not found:
            log.warning("nvd: cve_id %s not found", cve_id)
        items.extend(found)

    return {
        "items": items,
        "total_results": len(items),
        "start_index": 0,
        "results_per_page": len(items),
        "next_start_index": None,
    }


def normalize_items(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Shape NVD's vulnerabilities[] blocks into our normalized dicts."""
    items: list[dict[str, Any]] = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        # Prefer the English description; NVD entries are multilingual.
        description = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        items.append(
            {
                "id": cve_id,
                "description": description,
                "source_url": f"{NVD_VULN_URL_PREFIX}{cve_id}",
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
            }
        )
    return items


# ---------- tool: send_critical_alert ----------------------------------------

def send_critical_alert(cve_ids: list[str]) -> dict[str, Any]:
    """Email an alert for any Critical CVEs among these IDs.

    Queries the DB for findings with severity='Critical' whose id is in
    cve_ids, formats one email body, and sends it. If no Critical findings,
    no email is sent. Returns send result + criticals count.
    """
    if not cve_ids:
        return {"ok": True, "criticals": 0, "sent": 0, "dry_run": False,
                "message": "no cve_ids provided"}

    findings = get_critical_findings(cve_ids)
    if not findings:
        log.info("no Critical findings among %d cve_ids — skipping email", len(cve_ids))
        return {"ok": True, "criticals": 0, "sent": 0, "dry_run": False}

    subject = f"[Security Alert] {len(findings)} Critical CVE(s) detected"
    lines = [f"{len(findings)} Critical CVE(s) classified in this run:", ""]
    for f in findings:
        topics = ", ".join(f["topics"])
        lines.append(f"  • {f['id']}  [{topics}]")
        lines.append(f"      {f['summary']}")
        lines.append(f"      {f['source_url']}")
        lines.append("")
    body = "\n".join(lines)

    result = send_email(subject, body)
    return {**result, "criticals": len(findings)}

# ---------- tool: store_findings_tool ----------------------------------------

def log_important_findings(findings: list[dict[str, Any]]) -> None:
    important = [
        finding for finding in findings
        if finding.get("severity") in IMPORTANT_SEVERITIES
    ]
    if not important:
        return
    for finding in important[:MAX_LOGGED_FINDINGS]:
        log.info(
            "finding %s [%s] %s",
            finding["cve_id"],
            finding["severity"],
            finding["summary"],
        )
    omitted = len(important) - MAX_LOGGED_FINDINGS
    if omitted > 0:
        log.info("... %d more Critical/High findings omitted", omitted)

def store_findings_tool(findings: list[dict[str, Any]]) -> dict[str, Any]:
    result = store_findings(findings)
    if result.get("ok"):
        log_important_findings(findings)
    return result


# ---------- MCP-style tool registry ------------------------------------------

# Names here MUST match the keys in TOOL_DISPATCH below.
TOOLS: list[dict[str, Any]] = [
    {
        "name": "fetch_security_data",
        "description": (
            "Fetch CVEs from NVD. Returns "
            "{items, total_results, start_index, results_per_page, next_start_index}. "
            "REQUIRED: pick exactly one selection mode — cve_ids OR an explicit "
            "last_mod_start_date + last_mod_end_date pair. "
            "Do NOT call this in a loop yourself."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Fetch these specific CVE IDs. Mutually exclusive with "
                        "date / pagination params. One HTTP call per ID."
                    ),
                },
                "results_per_page": {
                    "type": "integer",
                    "description": "Number of CVEs per page (1-2000). Ignored when cve_ids is set.",
                    "minimum": 1,
                    "maximum": 2000,
                },
                "start_index": {
                    "type": "integer",
                    "description": "Offset for pagination. Default 0. Ignored when cve_ids is set.",
                    "default": 0,
                    "minimum": 0,
                },
                "last_mod_start_date": {
                    "type": "string",
                    "description": (
                        "ISO-8601 timestamp; only return CVEs modified at or "
                        "after this. Must be paired with last_mod_end_date."
                    ),
                },
                "last_mod_end_date": {
                    "type": "string",
                    "description": (
                        "ISO-8601 timestamp; only return CVEs modified at or "
                        "before this. Must be paired with last_mod_start_date."
                    ),
                },
            },
        },
    },
    {
        "name": "store_findings",
        "description": (
            "Persist a batch of processed CVE findings in one transaction. "
            "Call this ONCE per batch, after classifying every item. Returns "
            "{ok, stored, errors[]}."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "findings": {
                    "type": "array",
                    "minItems": 1,
                    "description": "All classified findings from this batch.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cve_id": {"type": "string"},
                            "topics": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minItems": 1,
                                "maxItems": 5,
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["Low", "Medium", "High", "Critical"],
                            },
                            "summary": {"type": "string"},
                            "source_url": {"type": "string"},
                            "source_last_modified": {
                                "type": "string",
                                "description": (
                                    "Pass through the CVE's last_modified value "
                                    "from the fetch_security_data item. Used "
                                    "for dedup on subsequent runs."
                                ),
                            },
                        },
                        "required": ["cve_id", "topics", "severity", "summary"],
                    },
                },
            },
            "required": ["findings"],
        },
    },
    {
        "name": "send_critical_alert",
        "description": (
            "After store_findings has succeeded, call this ONCE with the IDs "
            "of every CVE you classified. The tool filters to severity='Critical' "
            "itself and emails an alert. If nothing is Critical, no email "
            "is sent — you do NOT need to check first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "All CVE IDs you classified in this run.",
                },
            },
            "required": ["cve_ids"],
        },
    },
]

# Maps the tool name the LLM emits to the Python callable.
# Keep in sync with TOOLS above.
TOOL_DISPATCH = {
    "fetch_security_data": fetch_security_data,
    "store_findings": store_findings_tool,
    "send_critical_alert": send_critical_alert,
}
