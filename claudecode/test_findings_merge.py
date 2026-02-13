"""Unit tests for findings_merge utilities."""

from claudecode.findings_merge import merge_findings


def test_merge_findings_empty_input():
    assert merge_findings([]) == []


def test_merge_findings_keeps_higher_severity_then_confidence():
    findings = [
        {"file": "a.py", "line": 10, "category": "security", "title": "Issue", "severity": "MEDIUM", "confidence": 0.9},
        {"file": "a.py", "line": 10, "category": "security", "title": "Issue", "severity": "HIGH", "confidence": 0.8},
        {"file": "a.py", "line": 10, "category": "security", "title": "Issue", "severity": "HIGH", "confidence": 0.95},
    ]

    merged = merge_findings(findings)
    assert len(merged) == 1
    assert merged[0]["severity"] == "HIGH"
    assert merged[0]["confidence"] == 0.95


def test_merge_findings_separate_keys_are_preserved():
    findings = [
        {"file": "a.py", "line": 1, "category": "correctness", "title": "One", "severity": "LOW"},
        {"file": "a.py", "line": 2, "category": "correctness", "title": "Two", "severity": "LOW"},
        {"file": "b.py", "line": 1, "category": "security", "title": "One", "severity": "MEDIUM"},
    ]

    merged = merge_findings(findings)
    assert len(merged) == 3

