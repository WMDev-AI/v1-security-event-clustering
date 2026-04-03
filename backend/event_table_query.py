"""
Shared filter, sort, and paginate logic for event table API responses.
Applies to the full candidate index set before slicing the requested page.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Optional

ALLOWED_SORT = frozenset(
    {
        "index",
        "timestamp",
        "source_ip",
        "dest_ip",
        "dest_port",
        "subsystem",
        "action",
        "severity",
        "content",
    }
)


def serialize_event_row(index: int, event: Any) -> dict:
    """Shape returned to clients (matches existing cluster/MITRE event rows)."""
    return {
        "index": index,
        "timestamp": event.timestamp,
        "source_ip": event.source_ip,
        "dest_ip": event.dest_ip,
        "dest_port": event.dest_port,
        "subsystem": event.subsystem,
        "action": event.action,
        "severity": event.severity,
        "content": (event.content or "")[:800],
    }


def _parse_timestamp_sort_key(val: Any) -> tuple[int, Any]:
    """Return (kind, key) where kind 0 = numeric time, 1 = string fallback."""
    if val is None:
        return (1, "")
    s = str(val).strip()
    if not s:
        return (1, "")
    try:
        ts = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return (0, ts.timestamp())
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return (0, datetime.strptime(s[:26], fmt).timestamp())
        except ValueError:
            continue
    try:
        return (0, float(s))
    except ValueError:
        return (1, s.lower())


def row_matches_filters(row: dict, filters: dict[str, str]) -> bool:
    for key, needle in filters.items():
        if needle is None or str(needle).strip() == "":
            continue
        if key not in row:
            return False
        val = row[key]
        hay = "" if val is None else str(val)
        if str(needle).lower() not in hay.lower():
            return False
    return True


def _sort_tuple(row: dict, sort_by: str, index_fallback: int) -> tuple:
    sb = sort_by if sort_by in ALLOWED_SORT else "index"
    v = row.get(sb)

    if sb == "index":
        try:
            return (0, int(v) if v is not None else index_fallback)
        except (TypeError, ValueError):
            return (0, index_fallback)

    if sb == "dest_port":
        try:
            return (0, int(v) if v is not None else 0)
        except (TypeError, ValueError):
            return (0, 0)

    if sb == "timestamp":
        kind, k = _parse_timestamp_sort_key(v)
        return (kind, k)

    return (0, str(v or "").lower())


def parse_filter_params(
    f_index: Optional[str] = None,
    f_timestamp: Optional[str] = None,
    f_source_ip: Optional[str] = None,
    f_dest_ip: Optional[str] = None,
    f_dest_port: Optional[str] = None,
    f_subsystem: Optional[str] = None,
    f_action: Optional[str] = None,
    f_severity: Optional[str] = None,
    f_content: Optional[str] = None,
) -> dict[str, str]:
    mapping = [
        (f_index, "index"),
        (f_timestamp, "timestamp"),
        (f_source_ip, "source_ip"),
        (f_dest_ip, "dest_ip"),
        (f_dest_port, "dest_port"),
        (f_subsystem, "subsystem"),
        (f_action, "action"),
        (f_severity, "severity"),
        (f_content, "content"),
    ]
    out: dict[str, str] = {}
    for val, col in mapping:
        if val is not None and str(val).strip():
            out[col] = str(val).strip()
    return out


def filter_sort_paginate(
    indices: list[int],
    events: list,
    serialize: Callable[[int, Any], dict],
    page: int,
    limit: int,
    sort_by: str,
    sort_dir: str,
    filters: dict[str, str],
) -> tuple[list[dict], int]:
    """
    Filter all candidate rows by substring filters (AND), sort globally, return one page.
    Returns (rows_for_page, total_matching_count).
    """
    if page < 1:
        page = 1
    if limit < 1:
        limit = 30

    prepared: list[tuple[int, dict]] = []
    for idx in indices:
        row = serialize(idx, events[idx])
        if row_matches_filters(row, filters):
            prepared.append((idx, row))

    total = len(prepared)
    reverse = str(sort_dir).lower() == "desc"
    sb = sort_by if sort_by in ALLOWED_SORT else "index"

    prepared.sort(
        key=lambda item: (_sort_tuple(item[1], sb, item[0]), item[0]),
        reverse=reverse,
    )

    start = (page - 1) * limit
    page_slice = prepared[start : start + limit]
    return [row for _, row in page_slice], total
