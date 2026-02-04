# Custom Code Review Instructions

The Claude Code Reviewer Action supports custom code review instructions, allowing you to add organization-specific review priorities and standards.

## Overview

The default general review covers correctness, reliability, performance, maintainability, testing, and security. However, organizations often have specific requirements based on their:
- Architecture and invariants
- Performance or latency SLOs
- Testing and release practices
- Domain-specific constraints

The `custom-review-instructions` input allows you to extend the general review focus beyond the defaults.

## Usage

1. Create a text file containing your custom review instructions (e.g., `.github/custom-review-instructions.txt`)
2. Reference it in your workflow:

```yaml
- uses: PSPDFKit-labs/claude-code-review@main
  with:
    custom-review-instructions: .github/custom-review-instructions.txt
```

## File Format

The file should contain additional review guidance in plain text. Consider using headings and bullet points to keep it clear. Aim for:
- Specific requirements or invariants to protect
- Known fragile areas to scrutinize
- Performance/scale constraints to enforce
- Testing expectations for high-risk changes

### Example Structure:
```
**Architecture Invariants:**
- All writes must be idempotent for retry safety
- API responses must include correlation IDs

**Performance Constraints:**
- No new O(n^2) algorithms in request handlers
- P95 latency must remain under 200ms

**Testing Expectations:**
- Add unit tests for all validation branches
- Include integration tests for payment flows
```

## Best Practices

1. **Be Concrete**: Focus on actionable rules and invariants
2. **Keep It Short**: Favor a concise list over an exhaustive checklist
3. **Avoid Duplicates**: Don’t restate the default categories unless you need emphasis
4. **Review Regularly**: Update instructions as your architecture evolves

## Example

See [examples/custom-review-instructions.txt](../examples/custom-review-instructions.txt) for a ready-to-use template.
