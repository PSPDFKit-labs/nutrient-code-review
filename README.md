# Nutrient Code Reviewer

An AI-powered code review GitHub Action using Claude to analyze code changes. Uses a unified multi-agent approach for both code quality (correctness, reliability, performance, maintainability, testing) and security in a single pass. This action provides intelligent, context-aware review for pull requests using Anthropic's Claude Code tool for deep semantic analysis.

Based on the original work from [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review).

## Features

- **AI-Powered Analysis**: Uses Claude's advanced reasoning to detect issues with deep semantic understanding
- **Diff-Aware Scanning**: For PRs, only analyzes changed files
- **PR Comments**: Automatically comments on PRs with findings
- **Contextual Understanding**: Goes beyond pattern matching to understand code semantics and intent
- **Language Agnostic**: Works with any programming language
- **False Positive Filtering**: Advanced filtering to reduce noise and focus on real issues
- **Unified Multi-Agent Review**: Combines code quality and security analysis in a single efficient pass

## Quick Start

Add this to your repository's `.github/workflows/code-review.yml`:

```yaml
name: Code Review

permissions:
  pull-requests: write  # Needed for leaving PR comments
  contents: read

on:
  pull_request:
    types: [opened, synchronize, reopened, labeled, review_requested]
  issue_comment:
    types: [created] # Enables bot mentions for re-reviews

jobs:
  review:
    runs-on: ubuntu-latest
    # IMPORTANT: This condition prevents the job from running on non-PR events,
    # saving GitHub Actions minutes. Without this, the runner starts and bills
    # for ~20-40 seconds even when the action skips internally.
    if: github.event_name == 'pull_request' || (github.event_name == 'issue_comment' && github.event.issue.pull_request)
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          fetch-depth: 2

      - uses: PSPDFKit-labs/nutrient-code-review@main
        with:
          comment-pr: true
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
          require-label: 'READY TO REVIEW' # If this isn't set, the action will trigger any time *any* label is applied
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
| `claude-model` | Claude [model name](https://docs.anthropic.com/en/docs/about-claude/models/overview#model-names) to use. Defaults to Opus 4.5. For large PRs (>400k char diffs), consider using `claude-sonnet-4-5-20250929` (1M context). | `claude-opus-4-5-20251101` | No |
| `claudecode-timeout` | Timeout for ClaudeCode analysis in minutes | `20` | No |
| `max-diff-chars` | Maximum diff characters to include in prompt. Set to `0` for agentic mode (Claude uses git commands to explore). See [Diff Size Configuration](#diff-size-configuration) below. | `400000` | No |
| `max-diff-lines` | **[DEPRECATED]** Use `max-diff-chars` instead. Converts lines to chars (line × 80). | None | No |
| `run-every-commit` | Run ClaudeCode on every commit (skips cache check). Warning: May increase false positives on PRs with many commits. **Deprecated**: Use `trigger-on-commit` instead. | `false` | No |
| `trigger-on-open` | Run review when PR is first opened | `true` | No |
| `trigger-on-commit` | Run review on every new commit | `false` | No |
| `trigger-on-review-request` | Run review when someone requests a review from the bot | `true` | No |
| `trigger-on-mention` | Run review when bot is mentioned in a PR comment | `true` | No |
| `enable-heuristic-filtering` | Use pattern-based heuristic rules to filter common false positives (e.g., stylistic issues, low-signal security warnings) | `true` | No |
| `enable-claude-filtering` | Use Claude API to validate and filter findings. This reduces false positives but increases API costs by making additional validation calls to Claude. | `false` | No |
| `false-positive-filtering-instructions` | Path to custom false positive filtering instructions text file | None | No |
| `custom-review-instructions` | Path to custom code review instructions text file to append to the audit prompt | None | No |
| `custom-security-scan-instructions` | Path to custom security scan instructions text file to append to the security section | None | No |
| `dismiss-stale-reviews` | Dismiss previous bot reviews when posting a new review (useful for follow-up commits) | `true` | No |
| `skip-draft-prs` | Skip code review on draft pull requests | `true` | No |
| `require-label` | Only run review if this label is present. Leave empty to review all PRs. Add `labeled` to your workflow `pull_request` types to trigger on label addition. | None | No |

### Action Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of code review findings |
| `results-file` | Path to the results JSON file |

### Diff Size Configuration

The action handles PRs of any size using three review modes:

#### Review Modes

1. **Full Diff Mode** (default for small PRs)
   - Entire diff embedded in prompt
   - Fastest and most comprehensive
   - Works for diffs up to ~400k characters

2. **Partial Diff Mode** (automatic for large PRs)
   - First N files embedded in prompt
   - Claude uses git commands to explore remaining files
   - Balances embedded context with agentic exploration

3. **Full Agentic Mode** (set `max-diff-chars: 0`)
   - No diff embedded
   - Claude uses git commands to explore all changes
   - Most flexible for massive PRs (1000+ files)

#### Configuration

**`max-diff-chars`** - Maximum diff characters to embed (default: 400,000)

```yaml
# Default: 400k chars (fits in 200k token models)
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    max-diff-chars: 400000  # ~100k tokens

# Large PRs: Use 1M context model with higher limit
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    claude-model: claude-sonnet-4-5-20250929  # 1M context
    max-diff-chars: 800000  # ~200k tokens

# Always use agentic mode (no embedded diff)
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    max-diff-chars: 0  # Force agentic exploration
```

**Model Selection for Large Diffs:**

| Diff Size | Recommended Model | Context Window |
|-----------|-------------------|----------------|
| < 400k chars | `claude-opus-4-5-20251101` (default) | 200k tokens |
| 400k - 800k chars | `claude-sonnet-4-5-20250929` | 1M tokens |
| > 800k chars | Set `max-diff-chars: 0` (agentic mode) | Any model |

**Backward Compatibility:**

`max-diff-lines` is deprecated but still supported. If used, it converts to characters: `max_diff_chars = max_diff_lines × 80`

### Re-Review Trigger Configuration

The action supports multiple triggers for when reviews should be run, allowing fine-grained control over bot behavior:

#### Default Behavior
By default, the bot reviews PRs **once** when first opened, and will re-review when:
- Someone explicitly requests a review from the bot
- The bot is mentioned in a PR comment

The bot will **not** automatically re-review on new commits unless configured to do so.

#### Trigger Options

| Trigger | Input | Default | Description |
|---------|-------|---------|-------------|
| **PR Open** | `trigger-on-open` | `true` | Run review when PR is first opened or reopened |
| **New Commit** | `trigger-on-commit` | `false` | Run review automatically on every new commit to the PR |
| **Review Request** | `trigger-on-review-request` | `true` | Run review when someone requests a review from the bot via GitHub's UI |
| **Bot Mention** | `trigger-on-mention` | `true` | Run review when the bot is mentioned in a PR comment. The bot automatically detects its own identity (e.g., `@github-actions` for default token, or custom app name). |

#### Usage Examples

**Review only on explicit request (minimal usage):**
```yaml
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    trigger-on-open: false
    trigger-on-commit: false
```

**Review on every commit (maximum coverage, higher API costs):**
```yaml
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    trigger-on-commit: true
```

**Disable bot mention trigger:**
```yaml
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    trigger-on-mention: false
```

#### Appeal Workflow

The bot supports a "review appeal" workflow where developers can request a re-review on the same commit:

1. **Initial Review**: Bot reviews code at commit SHA X and finds issues
2. **Developer Response**: Developer replies to review comments with context or explanations
3. **Request Re-Review**: Developer uses GitHub's "Request review" feature (without pushing new code)
4. **Bot Re-Reviews**: Bot runs again on the same SHA X and can provide updated feedback

This allows developers to get a fresh review without needing to push a new commit.

#### Workflow Configuration

To enable all trigger types, your workflow file should include:

```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened, labeled, review_requested]
  issue_comment:
    types: [created]
```

**Note**: The `synchronize` type is included for commit-based triggers, but the bot will only run on new commits if `trigger-on-commit: true` is set.

### Preventing Duplicate Reviews (Recommended)

When multiple workflow triggers fire simultaneously (e.g., a new commit + a label addition), you may end up running duplicate reviews on the same code, wasting API costs. To prevent this, add a `concurrency` setting to your workflow file:

```yaml
name: Code Review

concurrency:
  group: code-review-${{ github.event.pull_request.number || github.event.issue.number }}
  cancel-in-progress: true  # Cancels older runs when new commits arrive

on:
  pull_request:
    types: [opened, synchronize, reopened, labeled, review_requested]
  issue_comment:
    types: [created]

jobs:
  review:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request' || (github.event_name == 'issue_comment' && github.event.issue.pull_request)
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          fetch-depth: 2
      - uses: PSPDFKit-labs/nutrient-code-review@main
        with:
          claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
```

#### How Concurrency Control Works

- **Prevents simultaneous runs**: Only one review runs at a time per PR
- **Cancels older reviews**: When a new commit arrives, the previous review is cancelled
- **Reduces costs**: Workflow cancellation stops execution before new API calls are made
- **Handles multiple event types**: The expression `github.event.pull_request.number || github.event.issue.number` ensures both `pull_request` and `issue_comment` events are grouped correctly by PR number

**Important**: While cancellation significantly reduces costs, API requests that are already in-flight to Anthropic will complete and be charged. This is a limitation of how API cancellation works—you cannot stop requests that have already been sent.

#### Alternative: Queue Instead of Cancel

If you prefer to keep the older run and cancel newer ones (queue behavior):

```yaml
concurrency:
  group: code-review-${{ github.event.pull_request.number || github.event.issue.number }}
  cancel-in-progress: false  # Queues new runs instead
```

### Billing Optimization (Recommended)

**Important:** Always add a job-level `if:` condition to prevent wasting GitHub Actions minutes on non-PR events.

Without this condition, the runner starts and bills for ~20-40 seconds even when the action skips internally. The `if:` condition prevents the job from starting at all:

```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request' || (github.event_name == 'issue_comment' && github.event.issue.pull_request)
```

**Why this matters:**
- Without job-level `if:`: Runner starts → action installs dependencies → determines to skip → **~20-40s billed**
- With job-level `if:`: Job never starts for non-PR events → **0s billed**

This is especially important if you use `workflow_dispatch` or other event types that might not be PR-related.

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

The tool uses a two-tier filtering approach to focus on high-impact issues:

**1. Pattern-Based Heuristic Filtering (Enabled by Default)**

Uses regex patterns to automatically filter out common false positives:
- Purely stylistic or formatting concerns
- Documentation-only changes without behavioral impact
- Hypothetical issues without a clear failure mode
- Security-only exclusions for low-signal categories (e.g., generic DOS/rate limit comments)

This filtering is fast and free (no additional API costs). You can disable it if you want to see all raw findings:

```yaml
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    enable-heuristic-filtering: false  # See all findings without pattern filtering
```

**2. Claude API Filtering (Optional)**

For even more precise filtering, you can enable `enable-claude-filtering: true` to use Claude API to validate each finding. This provides:
- More intelligent context-aware filtering
- Better understanding of project-specific patterns
- Reduced false positives

**Note**: This option increases API costs as it makes additional validation calls to Claude for each finding. It's disabled by default.

```yaml
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    enable-claude-filtering: true  # Optional: More precise filtering at higher cost
```

**Filtering Configuration Examples:**

```yaml
# Maximum filtering (recommended for most projects)
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    enable-heuristic-filtering: true   # Pattern-based filtering (default)
    enable-claude-filtering: true      # AI-powered validation (costs more)

# Minimal filtering (see all findings)
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    enable-heuristic-filtering: false  # No pattern filtering
    enable-claude-filtering: false     # No AI validation (default)

# Default configuration (balanced)
- uses: PSPDFKit-labs/nutrient-code-review@main
  with:
    claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
    # enable-heuristic-filtering: true (default)
    # enable-claude-filtering: false (default)
```

The false positive filtering can also be tuned with custom instructions - see the [`docs/`](docs/) folder for more details.

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

<a id="review-slash-command"></a>

## Claude Code Integration: /review Command

This repository includes a `/review` [slash command](https://docs.anthropic.com/en/docs/claude-code/slash-commands) that provides the same review capabilities as the GitHub Action workflow. The command performs a comprehensive review covering code quality (correctness, reliability, performance, maintainability, testing) and security using a multi-agent approach.

### Customizing the Command

The default command is designed to work well in most cases, but it can also be customized based on your specific requirements. To do so:

1. Copy the [`review.md`](https://github.com/PSPDFKit-labs/nutrient-code-review/blob/main/.claude/commands/review.md?plain=1) file from this repository to your project's `.claude/commands/` folder.
2. Edit the copied file to customize the review instructions.

## Custom Scanning Configuration

It is also possible to configure custom scanning and false positive filtering instructions, see the [`docs/`](docs/) folder for more details.

## Using a Custom GitHub App

By default, reviews are posted as "github-actions[bot]". To use a custom name and avatar:

1. **Create a GitHub App** at `https://github.com/settings/apps/new`
   - Set your desired name and avatar
   - Permissions: Pull requests (Read & Write), Contents (Read)
   - Uncheck "Webhook > Active"

2. **Store secrets** in your repository:
   - `APP_ID` - The App ID from settings
   - `APP_PRIVATE_KEY` - Generated private key

3. **Update your workflow**:
   ```yaml
   - name: Generate App Token
     id: app-token
     uses: actions/create-github-app-token@v1
     with:
       app-id: ${{ secrets.APP_ID }}
       private-key: ${{ secrets.APP_PRIVATE_KEY }}

   - uses: PSPDFKit-labs/nutrient-code-review@main
     with:
       claude-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
     env:
       GITHUB_TOKEN: ${{ steps.app-token.outputs.token }}
   ```

Review dismissal works automatically with custom apps since reviews are identified by content, not bot username.

**Note**: When using a custom app, the bot mention trigger will automatically detect and respond to mentions of your custom app's name (e.g., `@MyCodeReviewer`), not `@github-actions`.

## Testing

Run the test suite to validate functionality:

```bash
# Python tests
pytest claudecode -v

# JavaScript tests
cd scripts && npm test

# Bash script tests
./scripts/test-determine-claudecode-enablement.sh
```

## Support

For issues or questions:
- Open an issue in this repository
- Check the [GitHub Actions logs](https://docs.github.com/en/actions/monitoring-and-troubleshooting-workflows/viewing-workflow-run-history) for debugging information

## License

MIT License - see [LICENSE](LICENSE) file for details.
