"""Code review prompt templates."""


def _format_files_changed(pr_data):
    """Format changed files for prompt context."""
    return "\n".join([f"- {f['filename']}" for f in pr_data['files']])


def _build_diff_section(pr_diff, include_diff):
    """Build prompt section for inline diff or agentic file reading."""
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


def get_unified_review_prompt(
    pr_data,
    pr_diff=None,
    include_diff=True,
    custom_review_instructions=None,
    custom_security_instructions=None,
):
    """Generate unified code review + security prompt for Claude Code.

    This prompt covers both code quality (correctness, reliability, performance,
    maintainability, testing) and security in a single pass.

    Args:
        pr_data: PR data dictionary from GitHub API
        pr_diff: Optional complete PR diff in unified format
        include_diff: Whether to include the diff in the prompt (default: True)
        custom_review_instructions: Optional custom review instructions to append
        custom_security_instructions: Optional custom security instructions to append

    Returns:
        Formatted prompt string
    """

    files_changed = _format_files_changed(pr_data)
    diff_section = _build_diff_section(pr_diff, include_diff)

    custom_review_section = ""
    if custom_review_instructions:
        custom_review_section = f"\n{custom_review_instructions}\n"

    custom_security_section = ""
    if custom_security_instructions:
        custom_security_section = f"\n{custom_security_instructions}\n"

    return f"""
You are a senior engineer conducting a comprehensive code review of GitHub PR #{pr_data['number']}: "{pr_data['title']}"

CONTEXT:
- Repository: {pr_data.get('head', {}).get('repo', {}).get('full_name', 'unknown')}
- Author: {pr_data['user']}
- Files changed: {pr_data['changed_files']}
- Lines added: {pr_data['additions']}
- Lines deleted: {pr_data['deletions']}

Files modified:
{files_changed}{diff_section}

OBJECTIVE:
Perform a focused, high-signal code review to identify HIGH-CONFIDENCE issues introduced by this PR. This covers both code quality (correctness, reliability, performance, maintainability, testing) AND security. Do not comment on pre-existing issues or purely stylistic preferences.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you're >80% confident they are real and impactful
2. AVOID NOISE: Skip style nits, subjective preferences, or low-impact suggestions
3. FOCUS ON IMPACT: Prioritize bugs, regressions, data loss, significant performance problems, or security vulnerabilities
4. SCOPE: Only evaluate code introduced or modified in this PR. Ignore unrelated existing issues

CODE QUALITY CATEGORIES:

**Correctness & Logic:**
- Incorrect business logic or wrong results
- Edge cases or null/empty handling regressions
- Incorrect error handling or missing validations leading to bad state
- Invariants broken by changes

**Reliability & Resilience:**
- Concurrency or race conditions introduced by changes
- Resource leaks, timeouts, or missing retries in critical paths
- Partial failure handling or inconsistent state updates
- Idempotency or ordering issues

**Performance & Scalability:**
- Algorithmic regressions in hot paths (O(n^2) where O(n) expected)
- N+1 query patterns
- Excessive synchronous I/O in latency-sensitive code
- Unbounded memory growth introduced by changes

**Maintainability & Design:**
- Changes that significantly increase complexity or make future changes risky
- Tight coupling or unclear responsibility boundaries introduced
- Misleading APIs or brittle contracts

**Testing & Observability:**
- Missing tests for high-risk changes
- Lack of logging/metrics around new critical behavior
- Flaky behavior due to nondeterministic changes
{custom_review_section}
SECURITY CATEGORIES:

**Input Validation Vulnerabilities:**
- SQL injection via unsanitized user input
- Command injection in system calls or subprocesses
- XXE injection in XML parsing
- Template injection in templating engines
- NoSQL injection in database queries
- Path traversal in file operations

**Authentication & Authorization Issues:**
- Authentication bypass logic
- Privilege escalation paths
- Session management flaws
- JWT token vulnerabilities
- Authorization logic bypasses

**Crypto & Secrets Management:**
- Hardcoded API keys, passwords, or tokens
- Weak cryptographic algorithms or implementations
- Improper key storage or management
- Cryptographic randomness issues
- Certificate validation bypasses

**Injection & Code Execution:**
- Remote code execution via deserialization
- Pickle injection in Python
- YAML deserialization vulnerabilities
- Eval injection in dynamic code execution
- XSS vulnerabilities in web applications (reflected, stored, DOM-based)

**Data Exposure:**
- Sensitive data logging or storage
- PII handling violations
- API endpoint data leakage
- Debug information exposure
{custom_security_section}
EXCLUSIONS - DO NOT REPORT:
- Denial of Service (DOS) vulnerabilities or resource exhaustion attacks
- Secrets/credentials stored on disk (these are managed separately)
- Rate limiting concerns or service overload scenarios

Additional notes:
- Even if something is only exploitable from the local network, it can still be a HIGH severity issue

ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research (Use file search tools):
- Identify existing patterns, conventions, and critical paths
- Understand data flow, invariants, and error handling expectations
- Look for established security frameworks and patterns

Phase 2 - Comparative Analysis:
- Compare new changes to existing patterns and contracts
- Identify deviations that introduce risk, regressions, or security issues
- Look for inconsistent handling between similar code paths

Phase 3 - Issue Assessment:
- Examine each modified file for code quality and security implications
- Trace data flow from inputs to sensitive operations
- Identify concurrency, state management, and injection risks

REQUIRED OUTPUT FORMAT:

You MUST output your findings as structured JSON with this exact schema:

{{
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "HIGH",
      "category": "correctness|reliability|performance|maintainability|testing|security",
      "title": "Short summary of the issue",
      "description": "What is wrong and where it happens",
      "impact": "Concrete impact or failure mode (use exploit scenario for security issues)",
      "recommendation": "Actionable fix or mitigation",
      "suggestion": "Exact replacement code (optional). Can be multi-line. Must replace lines from suggestion_start_line to suggestion_end_line.",
      "suggestion_start_line": 42,
      "suggestion_end_line": 44,
      "confidence": 0.95
    }}
  ],
  "analysis_summary": {{
    "files_reviewed": 8,
    "high_severity": 1,
    "medium_severity": 0,
    "low_severity": 0,
    "review_completed": true
  }}
}}

SUGGESTION GUIDELINES:
- Only include `suggestion` if you can provide exact, working replacement code
- For single-line fixes: set suggestion_start_line = suggestion_end_line = the line number
- For multi-line fixes: set the range of lines being replaced
- The suggestion replaces all lines from suggestion_start_line to suggestion_end_line (inclusive)

SEVERITY GUIDELINES:
- **HIGH**: Likely production bug, data loss, significant regression, or directly exploitable security vulnerability
- **MEDIUM**: Real issue with limited scope or specific triggering conditions
- **LOW**: Minor but real issue; use sparingly and only if clearly actionable

CONFIDENCE SCORING:
- 0.9-1.0: Certain issue with clear evidence and impact
- 0.8-0.9: Strong signal with likely real-world impact
- 0.7-0.8: Plausible issue but may require specific conditions
- Below 0.7: Don't report (too speculative)

FINAL REMINDER:
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a senior engineer would confidently raise in a PR review.

Begin your analysis now. Use the repository exploration tools to understand the codebase context, then analyze the PR changes for code quality and security implications.

Your final reply must contain the JSON and nothing else. You should not reply again after outputting the JSON.
"""
