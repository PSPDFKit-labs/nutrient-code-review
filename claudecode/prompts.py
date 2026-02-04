"""Code review prompt templates."""


def get_code_review_prompt(
    pr_data,
    pr_diff=None,
    include_diff=True,
    custom_review_instructions=None,
):
    """Generate code review prompt for Claude Code.

    Note: This prompt focuses on code quality (correctness, reliability, performance,
    maintainability, testing). Security review is handled separately by get_security_review_prompt.

    Args:
        pr_data: PR data dictionary from GitHub API
        pr_diff: Optional complete PR diff in unified format
        include_diff: Whether to include the diff in the prompt (default: True)
        custom_review_instructions: Optional custom review instructions to append

    Returns:
        Formatted prompt string
    """

    files_changed = "\n".join([f"- {f['filename']}" for f in pr_data['files']])

    # Add diff section if provided and include_diff is True
    diff_section = ""
    if pr_diff and include_diff:
        diff_section = f"""

PR DIFF CONTENT:
```
{pr_diff}
```

Review the complete diff above. This contains all code changes in the PR.
"""
    elif pr_diff and not include_diff:
        diff_section = """

NOTE: PR diff was omitted due to size constraints. Please use the file exploration tools to examine the specific files that were changed in this PR.
"""

    # Add custom instructions if provided
    custom_review_section = ""
    if custom_review_instructions:
        custom_review_section = f"\n{custom_review_instructions}\n"

    return f"""
You are a senior engineer conducting a high-signal code review of GitHub PR #{pr_data['number']}: "{pr_data['title']}"

CONTEXT:
- Repository: {pr_data.get('head', {}).get('repo', {}).get('full_name', 'unknown')}
- Author: {pr_data['user']}
- Files changed: {pr_data['changed_files']}
- Lines added: {pr_data['additions']}
- Lines deleted: {pr_data['deletions']}

Files modified:
{files_changed}{diff_section}

OBJECTIVE:
Perform a focused, high-signal code review to identify HIGH-CONFIDENCE issues introduced by this PR. This covers correctness, reliability, performance, maintainability, and testing. Security issues are reviewed separately. Do not comment on pre-existing issues or purely stylistic preferences.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you're >80% confident they are real and impactful
2. AVOID NOISE: Skip style nits, subjective preferences, or low-impact suggestions
3. FOCUS ON IMPACT: Prioritize bugs, regressions, data loss, or significant performance problems
4. SCOPE: Only evaluate code introduced or modified in this PR. Ignore unrelated existing issues
5. NO SECURITY: Do not flag security issues - those are handled by a dedicated security review

REVIEW CATEGORIES TO EXAMINE:

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
ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research (Use file search tools):
- Identify existing patterns, conventions, and critical paths
- Understand data flow, invariants, and error handling expectations
- Note existing testing and observability practices

Phase 2 - Comparative Analysis:
- Compare new changes to existing patterns and contracts
- Identify deviations that introduce risk or regressions
- Look for inconsistent handling between similar code paths

Phase 3 - Issue Assessment:
- Examine each modified file for correctness, reliability, performance, maintainability, and testing implications
- Trace data flow to identify logic errors or state management risks
- Identify concurrency and resource management issues

REQUIRED OUTPUT FORMAT:

You MUST output your findings as structured JSON with this exact schema:

{{
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "HIGH",
      "category": "correctness|reliability|performance|maintainability|testing",
      "title": "Short summary of the issue",
      "description": "What is wrong and where it happens",
      "impact": "Concrete impact or failure mode",
      "recommendation": "Actionable fix or mitigation",
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

SEVERITY GUIDELINES:
- **HIGH**: Likely production bug, data loss, or significant regression
- **MEDIUM**: Real issue with limited scope or specific triggering conditions
- **LOW**: Minor but real issue; use sparingly and only if clearly actionable

CONFIDENCE SCORING:
- 0.9-1.0: Certain issue with clear evidence and impact
- 0.8-0.9: Strong signal with likely real-world impact
- 0.7-0.8: Plausible issue but may require specific conditions
- Below 0.7: Don't report (too speculative)

FINAL REMINDER:
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a senior engineer would confidently raise in a PR review. Do NOT report security issues - those are handled separately.

Begin your analysis now. Use the repository exploration tools to understand the codebase context, then analyze the PR changes for code quality implications.

Your final reply must contain the JSON and nothing else. You should not reply again after outputting the JSON.
"""


def get_security_review_prompt(
    pr_data,
    pr_diff=None,
    include_diff=True,
    custom_security_instructions=None,
):
    """Generate security-focused review prompt for Claude Code."""

    files_changed = "\n".join([f"- {f['filename']}" for f in pr_data['files']])

    diff_section = ""
    if pr_diff and include_diff:
        diff_section = f"""

PR DIFF CONTENT:
```
{pr_diff}
```

Review the complete diff above. This contains all code changes in the PR.
"""
    elif pr_diff and not include_diff:
        diff_section = """

NOTE: PR diff was omitted due to size constraints. Please use the file exploration tools to examine the specific files that were changed in this PR.
"""

    custom_security_section = ""
    if custom_security_instructions:
        custom_security_section = f"\n{custom_security_instructions}\n"

    return f"""
You are a senior security engineer conducting a focused security review of GitHub PR #{pr_data['number']}: "{pr_data['title']}"

CONTEXT:
- Repository: {pr_data.get('head', {}).get('repo', {}).get('full_name', 'unknown')}
- Author: {pr_data['user']}
- Files changed: {pr_data['changed_files']}
- Lines added: {pr_data['additions']}
- Lines deleted: {pr_data['deletions']}

Files modified:
{files_changed}{diff_section}

OBJECTIVE:
Perform a security-focused code review to identify HIGH-CONFIDENCE security vulnerabilities newly introduced by this PR. Do not comment on pre-existing issues or general code quality.

CRITICAL INSTRUCTIONS:
1. MINIMIZE FALSE POSITIVES: Only flag issues where you're >80% confident of actual exploitability
2. AVOID NOISE: Skip theoretical issues, style concerns, or low-impact findings
3. FOCUS ON IMPACT: Prioritize vulnerabilities that could lead to unauthorized access, data breaches, or system compromise
4. EXCLUSIONS: Do NOT report the following issue types:
   - Denial of Service (DOS) vulnerabilities, even if they allow service disruption
   - Secrets or sensitive data stored on disk (these are handled by other processes)
   - Rate limiting or resource exhaustion issues

SECURITY CATEGORIES TO EXAMINE:

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
Additional notes:
- Even if something is only exploitable from the local network, it can still be a HIGH severity issue

ANALYSIS METHODOLOGY:

Phase 1 - Repository Context Research (Use file search tools):
- Identify existing security frameworks and libraries in use
- Look for established secure coding patterns in the codebase
- Examine existing sanitization and validation patterns
- Understand the project's security model and threat model

Phase 2 - Comparative Analysis:
- Compare new code changes against existing security patterns
- Identify deviations from established secure practices
- Look for inconsistent security implementations
- Flag code that introduces new attack surfaces

Phase 3 - Vulnerability Assessment:
- Examine each modified file for security implications
- Trace data flow from user inputs to sensitive operations
- Look for privilege boundaries being crossed unsafely
- Identify injection points and unsafe deserialization

REQUIRED OUTPUT FORMAT:

You MUST output your findings as structured JSON with this exact schema:

{{
  "findings": [
    {{
      "file": "path/to/file.py",
      "line": 42,
      "severity": "HIGH",
      "category": "security",
      "title": "Short summary of the issue",
      "description": "What is wrong and where it happens",
      "impact": "Exploit scenario or concrete impact",
      "recommendation": "Actionable fix or mitigation",
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

SEVERITY GUIDELINES:
- **HIGH**: Directly exploitable vulnerabilities leading to RCE, data breach, or authentication bypass
- **MEDIUM**: Vulnerabilities requiring specific conditions but with significant impact
- **LOW**: Defense-in-depth issues or lower-impact vulnerabilities

CONFIDENCE SCORING:
- 0.9-1.0: Certain exploit path identified, tested if possible
- 0.8-0.9: Clear vulnerability pattern with known exploitation methods
- 0.7-0.8: Suspicious pattern requiring specific conditions to exploit
- Below 0.7: Don't report (too speculative)

FINAL REMINDER:
Focus on HIGH and MEDIUM findings only. Better to miss some theoretical issues than flood the report with false positives. Each finding should be something a security engineer would confidently raise in a PR review.

IMPORTANT EXCLUSIONS - DO NOT REPORT:
- Denial of Service (DOS) vulnerabilities or resource exhaustion attacks
- Secrets/credentials stored on disk (these are managed separately)
- Rate limiting concerns or service overload scenarios
- Memory consumption or CPU exhaustion issues
- Lack of input validation on non-security-critical fields without proven security impact

Begin your analysis now. Use the repository exploration tools to understand the codebase context, then analyze the PR changes for security implications.

Your final reply must contain the JSON and nothing else. You should not reply again after outputting the JSON.
"""


def get_security_audit_prompt(pr_data, pr_diff=None, include_diff=True, custom_scan_instructions=None):
    """Backward-compatible wrapper for previous security-only prompt."""
    return get_security_review_prompt(
        pr_data,
        pr_diff=pr_diff,
        include_diff=include_diff,
        custom_security_instructions=custom_scan_instructions,
    )
