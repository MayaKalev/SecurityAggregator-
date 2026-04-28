"""Paginates NVD, dedupes against the DB, invokes the agent per batch.

Called twice during the service lifecycle: once on startup as the
cold-start batch (if --since-days is set), then repeatedly by the
background poller.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from .agent import run as agent_run
from .prompts import SYSTEM_INSTRUCTIONS_BATCH
from storage import find_existing_modifications, get_critical_findings, get_latest_modification
from tools import fetch_security_data

log = logging.getLogger("orchestrator")

# NVD caps any date-range query at 120 days.
NVD_MAX_WINDOW_DAYS = 120


def run_batch(
    since_days: int | None = None,
    from_watermark: bool = False,
    batch_size: int = 20,
    page_size: int = 100,
    max_items: int | None = None,
) -> dict[str, Any]:
    """Process all CVEs in the chosen time window.

    Args:
        since_days: time window (1-120), or 0 for midnight UTC to now.
            Required when from_watermark is False. Ignored when
            from_watermark is True.
        from_watermark: start the window at MAX(source_last_modified).
            Only re-processes things changed since the last run. Falls back
            to midnight UTC today when the DB is empty.
        batch_size: items per agent invocation.
        page_size: items per NVD page (1-2000).
        max_items: maximum total CVEs to process in this run.

    Returns: stats dict with pages, fetched, skipped, classified,
        failed_batches, criticals_found.
    """
    window_kwargs = resolve_window(since_days, from_watermark)
    log.info(
        "scanning %s (page=%d, batch=%d)",
        summarize_window(window_kwargs), page_size, batch_size,
    )

    stats: dict[str, Any] = {
        "pages": 0, "fetched": 0, "skipped": 0,
        "classified": 0, "failed_batches": 0, "criticals_found": 0,
    }
    classified_ids: list[str] = []

    start_index = 0
    while start_index is not None:
        page = fetch_security_data(
            results_per_page=page_size,
            start_idx=start_index,
            **window_kwargs,
        )
        stats["pages"] += 1
        items = page["items"]

        if max_items is not None:
            remaining = max_items - stats["fetched"]
            if remaining <= 0:
                break
            items = items[:remaining]

        stats["fetched"] += len(items)

        filtered = filter_unchanged(items)
        skipped = len(items) - len(filtered)
        stats["skipped"] += skipped
        log.info(
            "page %d: %d fetched, %d already current, %d new (%d in window)",
            stats["pages"], len(items), skipped, len(filtered),
            page["total_results"],
        )

        for batch_idx, batch in enumerate(_chunk(filtered, batch_size), start=1):
            log.info("  batch %d: %d items → agent", batch_idx, len(batch))
            try:
                final_text = agent_run(build_agent_request(batch), SYSTEM_INSTRUCTIONS_BATCH)
                stats["classified"] += len(batch)
                classified_ids.extend(item["id"] for item in batch)
                # Show the agent's digest (first line is the summary).
                log.info("  batch %d done — %s", batch_idx, final_text.split("\n", 1)[0])
            except Exception as exc:
                log.error("  batch %d FAILED (continuing): %s", batch_idx, exc)
                stats["failed_batches"] += 1

        start_index = (
            None if max_items is not None and stats["fetched"] >= max_items
            else page["next_start_index"]
        )

    if classified_ids:
        stats["criticals_found"] = len(get_critical_findings(classified_ids))

    log.info(
        "done — %d classified, %d skipped, %d criticals, %d failed",
        stats["classified"], stats["skipped"],
        stats["criticals_found"], stats["failed_batches"],
    )
    return stats


# ---------- window resolution ------------------------------------------------

def resolve_window(since_days: int | None, from_watermark: bool) -> dict[str, Any]:
    """Translate the CLI flags into a {last_mod_start_date, last_mod_end_date}
    pair for fetch_security_data."""
    now = datetime.now(timezone.utc)

    if not from_watermark:
        if not since_days:
            # No --since-days → start of today (UTC).
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:
            if not 1 <= since_days <= NVD_MAX_WINDOW_DAYS:
                raise ValueError(
                    f"since_days must be 1-{NVD_MAX_WINDOW_DAYS} (NVD's window cap)"
                )
            start = now - timedelta(days=since_days)
        return {
            "last_mod_start_date": start.isoformat(timespec="milliseconds"),
            "last_mod_end_date": now.isoformat(timespec="milliseconds"),
        }

    latest_cve_date = get_latest_modification()
    if not latest_cve_date:
        # First poll with an empty DB — start from midnight UTC today.
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        log.info("no watermark — falling back to midnight UTC today")
        return {
            "last_mod_start_date": midnight.isoformat(timespec="milliseconds"),
            "last_mod_end_date": now.isoformat(timespec="milliseconds"),
        }

    start = _parse_date_isoformat(latest_cve_date)
    cap = now - timedelta(days=NVD_MAX_WINDOW_DAYS - 1)
    if start < cap:
        log.warning(
            "latest %s is older than NVD's %d-day cap — clamping to %s",
            latest_cve_date, NVD_MAX_WINDOW_DAYS, cap.isoformat(timespec="milliseconds"),
        )
        start = cap

    return {
        "last_mod_start_date": start.isoformat(timespec="milliseconds"),
        "last_mod_end_date": now.isoformat(timespec="milliseconds"),
    }


def _parse_date_isoformat(s: str) -> datetime:
    """Parse NVD-flavored ISO-8601. Accepts trailing Z, +00:00, or naive."""
    s = s.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def summarize_window(kwargs: dict[str, Any]) -> str:
    return f"{_short(kwargs['last_mod_start_date'])} → {_short(kwargs['last_mod_end_date'])} UTC"


def _short(iso: str) -> str:
    """Compact a full ISO timestamp like '2026-04-28T00:00:00.000+00:00' → '04-28 00:00'."""
    try:
        dt = _parse_date_isoformat(iso)
        return dt.strftime("%m-%d %H:%M")
    except Exception:
        return iso


# ---------- deduplication + chunking -------------------------------------------------

def filter_unchanged(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep items that are new or have a newer last_modified than the DB."""
    if not items:
        return []
    stored = find_existing_modifications([it["id"] for it in items])
    filtered: list[dict[str, Any]] = []
    for item in items:
        existing = stored.get(item["id"])
        incoming = item.get("last_modified")
        # not in DB
        if existing is None:
            filtered.append(item)
        # modified item
        elif incoming and existing < incoming:
            filtered.append(item)
    return filtered


def _chunk(items: list[Any], size: int) -> Iterator[list[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def build_agent_request(batch: list[dict[str, Any]]) -> str:
    """Format a batch as a user message for the agent."""
    return (
        f"Classify these {len(batch)} CVEs and store each one. "
        f"Pass each item's last_modified through as source_last_modified.\n\n"
        f"items:\n```json\n{json.dumps(batch, indent=2)}\n```"
    )
