# Claude Code Reviewer

An AI-powered code review GitHub Action using Claude to analyze code changes. Runs two focused passes: a code quality review (correctness, reliability, performance, maintainability, testing) and a dedicated security review. This action provides intelligent, context-aware review for pull requests using Anthropic's Claude Code tool for deep semantic analysis.

Based on the original work from [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review).

## Features

- **AI-Powered Analysis**: Uses Claude's advanced reasoning to detect issues with deep semantic understanding
- **Diff-Aware Scanning**: For PRs, only analyzes changed files
- **PR Comments**: Automatically comments on PRs with findings
- **Contextual Understanding**: Goes beyond pattern matching to understand code semantics and intent
- **Language Agnostic**: Works with any programming language
- **False Positive Filtering**: Advanced filtering to reduce noise and focus on real issues
- **Dual-Pass Review**: Runs focused code quality and security passes separately for better signal

## Quick Start

Add this to your repository's `.github/workflows/code-review.yml`:

```yaml
name: Code Review

permissions:
  pull-requests: write  # Needed for leaving PR comments
  contents: read

on:
  pull_request:

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          fetch-depth: 2
      
      - uses: PSPDFKit-labs/claude-code-review@main
        with:
          comment-pr: true
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
```

## Security Considerations

This action is not hardened against prompt injection attacks and should only be used to review trusted PRs. We recommend [configuring your repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#controlling-changes-from-forks-to-workflows-in-public-repositories) to use the "Require approval for all external contributors" option to ensure workflows only run after a maintainer has reviewed the PR.

## Configuration Options

### Action Inputs

| Input | Description | Default | Required |
|-------|-------------|---------|----------|
| `claude-api-key` | Anthropic Claude API key for code review analysis. <br>*Note*: This API key needs to be enabled for both the Claude API and Claude Code usage. | None | Yes |
| `comment-pr` | Whether to comment on PRs with findings | `true` | No |
| `upload-results` | Whether to upload results as artifacts | `true` | No |
| `exclude-directories` | Comma-separated list of directories to exclude from scanning | None | No |
| `claude-model` | Claude [model name](https://docs.anthropic.com/en/docs/about-claude/models/overview#model-names) to use. Defaults to Opus 4.5. | `claude-opus-4-5-20251101` | No |
| `claudecode-timeout` | Timeout for ClaudeCode analysis in minutes | `20` | No |
| `run-every-commit` | Run ClaudeCode on every commit (skips cache check). Warning: May increase false positives on PRs with many commits. | `false` | No |
| `false-positive-filtering-instructions` | Path to custom false positive filtering instructions text file | None | No |
| `custom-review-instructions` | Path to custom code review instructions text file to append to the audit prompt | None | No |
| `custom-security-scan-instructions` | Path to custom security scan instructions text file to append to the security section | None | No |
| `run-general-review` | Whether to run the code quality review pass (correctness, reliability, performance, maintainability, testing) | `true` | No |
| `run-security-review` | Whether to run the dedicated security review pass | `true` | No |

### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of code review findings |
| `results-file` | Path to the results JSON file |

## How It Works

### Architecture

```
claudecode/
├── github_action_audit.py  # Main audit script for GitHub Actions
├── prompts.py              # Code review prompt templates
├── findings_filter.py      # False positive filtering logic
├── claude_api_client.py    # Claude API client for false positive filtering
├── json_parser.py          # Robust JSON parsing utilities
├── requirements.txt        # Python dependencies
├── test_*.py               # Test suites
└── evals/                  # Eval tooling to test CC on arbitrary PRs
```

### Workflow

1. **PR Analysis**: When a pull request is opened, Claude analyzes the diff to understand what changed
2. **Contextual Review**: Claude examines the code changes in context, understanding the purpose and potential impacts
3. **Finding Generation**: Issues are identified with detailed explanations, severity ratings, and remediation guidance
4. **False Positive Filtering**: Advanced filtering removes low-impact or false positive prone findings to reduce noise
5. **PR Comments**: Findings are posted as review comments on the specific lines of code

## Review Capabilities

### Types of Issues Detected

- **Correctness & Logic**: Wrong results, edge cases, invariant breaks
- **Reliability & Resilience**: Concurrency issues, partial failure handling, idempotency risks
- **Performance & Scalability**: Algorithmic regressions, N+1 queries, hot-path slowdowns
- **Maintainability & Design**: Risky complexity increases, brittle contracts
- **Testing & Observability**: Missing tests for high-risk changes, missing diagnostics
- **Security**: Injection, auth bypass, unsafe deserialization, sensitive data exposure

### False Positive Filtering

The tool automatically excludes a variety of low-signal findings to focus on high-impact issues:
- Purely stylistic or formatting concerns
- Documentation-only changes without behavioral impact
- Hypothetical issues without a clear failure mode
- Security-only exclusions for low-signal categories (e.g., generic DOS/rate limit comments)

The false positive filtering can also be tuned as needed for a given project's goals.

### Benefits Over Traditional SAST

- **Contextual Understanding**: Understands code semantics and intent, not just patterns
- **Lower False Positives**: AI-powered analysis reduces noise by understanding when code is actually risky
- **Detailed Explanations**: Provides clear explanations of why something is an issue and how to fix it
- **Adaptive Learning**: Can be customized with organization-specific requirements

## Installation & Setup

### GitHub Actions

Follow the Quick Start guide above. The action handles all dependencies automatically.

### Local Development

To run the reviewer locally against a specific PR, see the [evaluation framework documentation](claudecode/evals/README.md).

<a id="security-review-slash-command"></a>

## Claude Code Integration: /code-review Command

This repository includes `/code-review` and `/security-review` [slash commands](https://docs.anthropic.com/en/docs/claude-code/slash-commands) that provide the same review capabilities as the GitHub Action workflow. Use `/code-review` for a broad review (correctness, reliability, performance, maintainability, testing, and security), and `/security-review` for a security-focused review.

### Customizing the Command

The default commands are designed to work well in most cases, but they can also be customized based on your specific requirements. To do so:

1. Copy the [`code-review.md`](https://github.com/PSPDFKit-labs/claude-code-review/blob/main/.claude/commands/code-review.md?plain=1) or [`security-review.md`](https://github.com/PSPDFKit-labs/claude-code-review/blob/main/.claude/commands/security-review.md?plain=1) file from this repository to your project's `.claude/commands/` folder.
2. Edit the copied file to customize the review instructions.

## Custom Scanning Configuration

It is also possible to configure custom scanning and false positive filtering instructions, see the [`docs/`](docs/) folder for more details.

## Testing

Run the test suite to validate functionality:

```bash
cd claude-code-review
# Run all tests
pytest claudecode -v
```

## Support

For issues or questions:
- Open an issue in this repository
- Check the [GitHub Actions logs](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/viewing-workflow-run-history) for debugging information

## License

MIT License - see [LICENSE](LICENSE) file for details.
