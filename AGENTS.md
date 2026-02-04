# Claude Code Review - Agent Guidelines

## Project Overview

AI-powered code review tool using Claude to analyze PRs for code quality and security issues. Uses a unified multi-agent approach for comprehensive analysis in a single pass.

## Architecture

```
claudecode/
├── github_action_audit.py   # Main orchestrator - entry point
├── prompts.py               # Review prompt templates
├── findings_filter.py       # False positive filtering
├── claude_api_client.py     # Claude API client
├── json_parser.py           # JSON extraction utilities
├── constants.py             # Configuration constants
└── evals/                   # Evaluation framework
```

## Key Patterns

### Prompt Structure
- `get_unified_review_prompt()` - Combined code quality + security review
- Prompts require JSON-only output with specific schema
- Always include confidence scores (0.7-1.0 threshold)

### Finding Categories
- **Code Quality:** correctness, reliability, performance, maintainability, testing
- **Security:** security (injection, auth, crypto, data exposure)

### Severity Levels
- **HIGH**: Production bugs, data loss, exploitable vulnerabilities
- **MEDIUM**: Limited scope, specific conditions required
- **LOW**: Minor issues, use sparingly

### Filtering Pipeline
1. Hard exclusion rules (regex patterns in `HardExclusionRules`)
2. Claude API validation (optional, uses `claude_api_client.py`)
3. Directory exclusion filtering

## Testing

```bash
pytest claudecode -v  # Run all tests (177 passing)
```

## Code Style
- Python 3.9+
- Type hints encouraged
- Comprehensive docstrings
- Tests required for new functionality

## Key Files

| File | Purpose |
|------|---------|
| `action.yml` | GitHub Action definition |
| `.claude/commands/review.md` | Slash command for Claude Code |
| `docs/` | Customization documentation |

## Common Tasks

### Adding a review category
1. Update category lists in `prompts.py`
2. Add exclusion patterns in `findings_filter.py` if needed
3. Add tests in `test_prompts.py`

### Modifying filtering rules
1. Edit `HardExclusionRules` in `findings_filter.py`
2. Add tests in `test_hard_exclusion_rules.py`
