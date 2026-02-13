"""Utilities for merging and deduplicating findings from multiple phases."""

from typing import Any, Dict, List, Tuple


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _finding_key(finding: Dict[str, Any]) -> Tuple[str, int, str, str]:
    file_path = _normalize_text(finding.get("file"))
    line = finding.get("line")
    try:
        line_no = int(line)
    except (TypeError, ValueError):
        line_no = 1
    category = _normalize_text(finding.get("category"))
    title = _normalize_text(finding.get("title"))
    return file_path, line_no, category, title


def _severity_rank(value: Any) -> int:
    sev = _normalize_text(value).upper()
    if sev == "HIGH":
        return 3
    if sev == "MEDIUM":
        return 2
    if sev == "LOW":
        return 1
    return 0


def _confidence_value(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def merge_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge duplicate findings and keep the strongest candidate."""
    merged: Dict[Tuple[str, int, str, str], Dict[str, Any]] = {}

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        key = _finding_key(finding)
        existing = merged.get(key)

        if existing is None:
            merged[key] = finding
            continue

        incoming_score = (_severity_rank(finding.get("severity")), _confidence_value(finding.get("confidence")))
        existing_score = (_severity_rank(existing.get("severity")), _confidence_value(existing.get("confidence")))

        if incoming_score > existing_score:
            merged[key] = finding

    return list(merged.values())
