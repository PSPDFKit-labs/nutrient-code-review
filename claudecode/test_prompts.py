"""Unit tests for multi-phase prompt generation."""

from claudecode.prompts import (
    _build_hybrid_diff_section,
    build_compliance_prompt,
    build_context_discovery_prompt,
    build_quality_prompt,
    build_security_prompt,
    build_triage_prompt,
    build_validation_prompt,
)


def _sample_pr_data():
    return {
        "number": 123,
        "title": "Add new feature",
        "body": "This PR adds a new feature to handle user input",
        "user": "testuser",
        "changed_files": 1,
        "additions": 10,
        "deletions": 5,
        "head": {"repo": {"full_name": "owner/repo"}},
        "files": [{"filename": "app.py"}],
    }


def test_build_hybrid_diff_section_max_lines_zero_omits_inline_diff():
    section = _build_hybrid_diff_section("diff --git a/a.py b/a.py\n+print('x')", 0)

    assert "intentionally omitted" in section
    assert "```diff" not in section


def test_build_hybrid_diff_section_truncates_when_over_limit():
    diff = "\n".join([f"+line {i}" for i in range(20)])

    section = _build_hybrid_diff_section(diff, 5)

    assert "TRUNCATED" in section
    assert "5 lines out of 20" in section


def test_triage_prompt_contains_required_schema():
    prompt = build_triage_prompt(_sample_pr_data(), "diff --git a/app.py b/app.py", 100)

    assert '"skip_review"' in prompt
    assert '"risk_level"' in prompt


def test_context_prompt_contains_discovery_fields():
    prompt = build_context_discovery_prompt(_sample_pr_data(), "diff --git a/app.py b/app.py", 100)

    assert '"claude_md_files"' in prompt
    assert '"priority_files"' in prompt


def test_specialist_prompts_include_findings_schema_and_custom_instructions():
    pr_data = _sample_pr_data()
    context = {"hotspots": ["app.py"]}

    compliance = build_compliance_prompt(pr_data, "diff", 100, context)
    quality = build_quality_prompt(pr_data, "diff", 100, context, custom_review_instructions="Check tx safety")
    security = build_security_prompt(pr_data, "diff", 100, context, custom_security_instructions="Check SSRF")

    for prompt in [compliance, quality, security]:
        assert '"findings"' in prompt
        assert '"confidence"' in prompt

    assert "rule_reference" in compliance
    assert "Check tx safety" in quality
    assert "exploit_preconditions" in security
    assert "Check SSRF" in security


def test_validation_prompt_contains_candidate_findings():
    findings = [{"file": "app.py", "line": 10, "severity": "HIGH"}]

    prompt = build_validation_prompt(_sample_pr_data(), "diff", 100, findings)

    assert "CANDIDATE FINDINGS" in prompt
    assert '"validated_findings"' in prompt
    assert '"finding_index"' in prompt
