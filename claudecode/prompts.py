"""Prompt templates for multi-phase PR review orchestration."""

from typing import Any, Dict, List, Optional

COMPLIANCE_EXTRA_FIELDS = ',\n      "rule_reference": "path/to/CLAUDE.md#section"'
SECURITY_EXTRA_FIELDS = (
    ',\n      "exploit_preconditions": "...",\n      "trust_boundary": "...",\n'
    '      "cwe": "optional CWE-###"'
)


def _format_files_changed(pr_data: Dict[str, Any]) -> str:
    """Format changed files for prompt context."""
    files = pr_data.get("files", [])
    return "\n".join([f"- {f.get('filename', 'unknown')}" for f in files])


def _build_hybrid_diff_section(pr_diff: str, max_lines: int) -> str:
    """Build a bounded inline diff section while requiring tool-based context reads."""
    if not pr_diff:
        return "\nNo inline diff available. Use repository tools to inspect changed files.\n"
    if max_lines == 0:
        return (
            "\nInline diff intentionally omitted (max-diff-lines=0). "
            "Use repository tools to inspect changed files and context.\n"
        )

    lines = pr_diff.splitlines()
    if max_lines > 0 and len(lines) > max_lines:
        shown = "\n".join(lines[:max_lines])
        truncated_note = (
            f"\n[Diff truncated to {max_lines} lines out of {len(lines)} total lines. "
            "You MUST use repository tools to inspect full context and missing hunks.]"
        )
        return f"\nINLINE DIFF ANCHOR (TRUNCATED):\n```diff\n{shown}\n```{truncated_note}\n"

    return (
        "\nINLINE DIFF ANCHOR:\n"
        f"```diff\n{pr_diff}\n```\n"
        "Use this as a starting point only. You MUST validate findings with repository tool reads.\n"
    )

def _build_diff_section(pr_diff: Optional[str], include_diff: bool) -> str:
    """Build unified-prompt diff section for backward compatibility."""
    if pr_diff and include_diff:
        return f"""

PR DIFF CONTENT:
```
{pr_diff}
```

Review the complete diff above. This contains all code changes in the PR.
"""

    return """

IMPORTANT - FILE READING INSTRUCTIONS:
You have access to the repository files. For each file listed above, use the Read tool to examine the changes.
Focus on the files that are most likely to contain issues based on the PR context.

To review effectively:
1. Read each modified file to understand the current code
2. Look at surrounding code context when needed to understand the changes
3. Check related files if you need to understand dependencies or usage patterns
"""


def _base_context_block(pr_data: Dict[str, Any], pr_diff: str, max_diff_lines: int) -> str:
    """Shared context block used across prompts."""
    files_changed = _format_files_changed(pr_data)
    return f"""
PR CONTEXT:
- PR Number: {pr_data.get('number', 'unknown')}
- Title: {pr_data.get('title', 'unknown')}
- Author: {pr_data.get('user', 'unknown')}
- Repository: {pr_data.get('head', {}).get('repo', {}).get('full_name', 'unknown')}
- Files changed: {pr_data.get('changed_files', 0)}
- Lines added: {pr_data.get('additions', 0)}
- Lines deleted: {pr_data.get('deletions', 0)}
- PR body: {pr_data.get('body', '') or 'No description'}

MODIFIED FILES:
{files_changed or '- None listed'}
{_build_hybrid_diff_section(pr_diff, max_diff_lines)}
MANDATORY CONTEXT VALIDATION RULES:
1. You MUST use repository tools to read each relevant changed file before finalizing findings.
2. For every finding, verify at least one additional contextual location (caller, callee, config, or sibling path).
3. Do not rely on inline diff alone, even when diff is fully present.
"""


def _findings_output_schema(extra_fields: str = "") -> str:
    return f"""
OUTPUT JSON SCHEMA (exact keys):
{{
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "HIGH|MEDIUM|LOW",
      "category": "correctness|reliability|performance|maintainability|testing|security|compliance",
      "title": "Short issue title",
      "description": "What is wrong",
      "impact": "Concrete failure mode or exploit path",
      "recommendation": "Actionable fix",
      "confidence": 0.93{extra_fields}
    }}
  ],
  "analysis_summary": {{
    "files_reviewed": 0,
    "high_severity": 0,
    "medium_severity": 0,
    "low_severity": 0,
    "review_completed": true
  }}
}}
"""


def build_triage_prompt(pr_data: Dict[str, Any], pr_diff: str, max_diff_lines: int) -> str:
    """Prompt for triage phase."""
    return f"""
You are the triage specialist for a pull request review.

{_base_context_block(pr_data, pr_diff, max_diff_lines)}

Decide whether review should be skipped.
Skip only if one of the following is true:
- PR is clearly trivial and cannot contain correctness/security/compliance risk
- PR is obviously generated deployment churn with no business logic changes
- There are no meaningful code changes in reviewed files

Return JSON only:
{{
  "skip_review": false,
  "reason": "short reason",
  "risk_level": "low|medium|high"
}}
"""


def build_context_discovery_prompt(pr_data: Dict[str, Any], pr_diff: str, max_diff_lines: int) -> str:
    """Prompt for context discovery phase."""
    return f"""
You are the repository context specialist.

{_base_context_block(pr_data, pr_diff, max_diff_lines)}

Tasks:
1. Find relevant CLAUDE.md files: root and those in changed-file parent paths.
2. Summarize PR intent and risky hotspots.
3. Identify top files for deep review.

Return JSON only:
{{
  "claude_md_files": ["path/CLAUDE.md"],
  "change_summary": "brief summary",
  "hotspots": ["path/to/file"],
  "priority_files": ["path/to/file"]
}}
"""


def build_compliance_prompt(
    pr_data: Dict[str, Any],
    pr_diff: str,
    max_diff_lines: int,
    discovered_context: Dict[str, Any],
) -> str:
    """Prompt for CLAUDE.md compliance analysis."""
    context_json = discovered_context or {}
    return f"""
You are the CLAUDE.md compliance specialist.

{_base_context_block(pr_data, pr_diff, max_diff_lines)}

DISCOVERED CONTEXT:
{context_json}

Focus exclusively on clear CLAUDE.md violations in changed code. Cite concrete violated rule text in each finding.
Reject ambiguous or preference-only claims.

    {_findings_output_schema(COMPLIANCE_EXTRA_FIELDS)}

Return JSON only.
"""


def build_quality_prompt(
    pr_data: Dict[str, Any],
    pr_diff: str,
    max_diff_lines: int,
    discovered_context: Dict[str, Any],
    custom_review_instructions: Optional[str] = None,
) -> str:
    """Prompt for code quality analysis."""
    custom_block = f"\nCUSTOM QUALITY INSTRUCTIONS:\n{custom_review_instructions}\n" if custom_review_instructions else ""
    return f"""
You are the code quality specialist.

{_base_context_block(pr_data, pr_diff, max_diff_lines)}

DISCOVERED CONTEXT:
{discovered_context or {}}

Focus on high-signal issues only:
- correctness and logic defects
- reliability regressions
- significant performance regressions
- maintainability risks with concrete failure/bug potential
- testing gaps only when they block confidence for risky behavior

Exclude style-only feedback and speculative concerns.
{custom_block}
{_findings_output_schema()}

Return JSON only.
"""


def build_security_prompt(
    pr_data: Dict[str, Any],
    pr_diff: str,
    max_diff_lines: int,
    discovered_context: Dict[str, Any],
    custom_security_instructions: Optional[str] = None,
) -> str:
    """Prompt for security analysis with explicit exploitability criteria."""
    custom_block = (
        f"\nCUSTOM SECURITY INSTRUCTIONS:\n{custom_security_instructions}\n"
        if custom_security_instructions
        else ""
    )

    return f"""
You are the security specialist.

{_base_context_block(pr_data, pr_diff, max_diff_lines)}

DISCOVERED CONTEXT:
{discovered_context or {}}

Security review scope:
- injection (SQL/command/template/NoSQL/path traversal)
- authn/authz bypass and privilege escalation
- unsafe deserialization and code execution paths
- crypto and secrets handling flaws
- sensitive data exposure and trust-boundary breaks

For every security finding you MUST provide:
1. exploit or abuse path
2. required attacker preconditions
3. impacted trust boundary or sensitive asset
4. concrete mitigation

Do NOT report:
- generic DoS/rate-limiting comments without concrete exploitability
- speculative attacks without evidence in changed code paths
- issues outside modified scope unless required to prove exploitability
{custom_block}
    {_findings_output_schema(SECURITY_EXTRA_FIELDS)}

Return JSON only.
"""


def build_validation_prompt(
    pr_data: Dict[str, Any],
    pr_diff: str,
    max_diff_lines: int,
    candidate_findings: List[Dict[str, Any]],
) -> str:
    """Prompt for finding validation and deduplication support."""
    return f"""
You are the validation specialist.

{_base_context_block(pr_data, pr_diff, max_diff_lines)}

CANDIDATE FINDINGS:
{candidate_findings}

Validate each finding with strict criteria:
- must be reproducible or clearly inferable from changed code and surrounding context
- must have concrete impact
- confidence must be >= 0.8 to keep
- if two findings are duplicates, keep the stronger one only

Return JSON only:
{{
  "validated_findings": [
    {{
      "finding_index": 0,
      "keep": true,
      "confidence": 0.92,
      "reason": "short reason"
    }}
  ]
}}
"""


def get_unified_review_prompt(
    pr_data: Dict[str, Any],
    pr_diff: Optional[str] = None,
    include_diff: bool = True,
    custom_review_instructions: Optional[str] = None,
    custom_security_instructions: Optional[str] = None,
    review_context: Optional[str] = None,
) -> str:
    """Backward-compatible unified prompt used by tests and direct calls."""
    files_changed = _format_files_changed(pr_data)
    diff_section = _build_diff_section(pr_diff, include_diff)
    custom_review_section = f"\n{custom_review_instructions}\n" if custom_review_instructions else ""
    custom_security_section = f"\n{custom_security_instructions}\n" if custom_security_instructions else ""

    pr_description = (pr_data.get('body', '') or '').strip()
    pr_description_section = ""
    if pr_description:
        if len(pr_description) > 2000:
            pr_description = pr_description[:2000] + "... (truncated)"
        pr_description_section = f"\nPR Description:\n{pr_description}\n"

    review_context_section = review_context or ""

    return f"""
You are a senior engineer conducting a comprehensive code review of GitHub PR #{pr_data.get('number', 'unknown')}: "{pr_data.get('title', 'unknown')}"

CONTEXT:
- Repository: {pr_data.get('head', {}).get('repo', {}).get('full_name', 'unknown')}
- Author: {pr_data.get('user', 'unknown')}
- Files changed: {pr_data.get('changed_files', 0)}
- Lines added: {pr_data.get('additions', 0)}
- Lines deleted: {pr_data.get('deletions', 0)}
{pr_description_section}
Files modified:
{files_changed}{diff_section}{review_context_section}

OBJECTIVE:
Perform a focused, high-signal code review to identify HIGH-CONFIDENCE issues introduced by this PR.

CODE QUALITY CATEGORIES:
- correctness, reliability, performance, maintainability, testing
{custom_review_section}
SECURITY CATEGORIES:
- input validation, authn/authz, crypto/secrets, code execution, data exposure
{custom_security_section}

REQUIRED OUTPUT FORMAT:

{{
  "pr_summary": {{
    "overview": "2-4 sentence summary of what this PR changes and why it matters",
    "file_changes": [
      {{
        "label": "src/auth.py",
        "files": ["src/auth.py"],
        "changes": "Brief description of changes (~10 words)"
      }}
    ]
  }},
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "HIGH|MEDIUM|LOW",
      "category": "correctness|reliability|performance|maintainability|testing|security",
      "title": "Short summary of the issue",
      "description": "What is wrong and where it happens",
      "impact": "Concrete impact or failure mode",
      "recommendation": "Actionable fix or mitigation",
      "confidence": 0.95
    }}
  ]
}}

PR SUMMARY GUIDELINES:
- overview: 2-4 sentences describing WHAT changed and WHY (purpose/goal)
- file_changes: One entry per file or group of related files
- changes: Brief description (~10 words), focus on purpose not implementation
"""
