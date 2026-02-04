# Custom False Positive Filtering Instructions

The Claude Code Reviewer Action supports custom false positive filtering instructions, allowing you to tailor the review to your specific environment and requirements.

## Overview

By default, the review includes a comprehensive set of exclusions and criteria for filtering out low-signal findings. However, every organization has unique requirements, technology stacks, and risk tolerances. The `false-positive-filtering-instructions` input allows you to provide your own custom criteria.

## Usage

1. Create a text file containing your custom filtering instructions (e.g., `.github/false-positive-filtering.txt`)
2. Reference it in your workflow:

```yaml
- uses: PSPDFKit-labs/claude-code-review@main
  with:
    false-positive-filtering-instructions: .github/false-positive-filtering.txt
```

## File Format

The file should contain plain text with three main sections:

### 1. HARD EXCLUSIONS
List patterns that should be automatically excluded from findings.

### 2. SIGNAL QUALITY CRITERIA
Questions to assess whether a finding represents a real, actionable issue.

### 3. PRECEDENTS
Specific guidance for common patterns in your environment.

## Example

See [examples/custom-false-positive-filtering.txt](../examples/custom-false-positive-filtering.txt) for a complete example tailored to a modern cloud-native application.

## Default Instructions

If no custom file is provided, the action uses default instructions tuned to work well for most applications.

## Best Practices

1. **Start with defaults**: Begin with the default instructions and modify based on false positives you encounter
2. **Be specific**: Include details about your architecture and conventions
3. **Document assumptions**: Explain why certain patterns are excluded
4. **Version control**: Track changes to your filtering instructions alongside your code
5. **Team review**: Have your reviewers agree on the filtering instructions

## Common Customizations

- **Technology-specific exclusions**: Exclude findings that don't apply to your tech stack
- **Infrastructure assumptions**: Document controls at the infrastructure level
- **Compliance requirements**: Adjust criteria based on your compliance needs
- **Development practices**: Reflect your team's review standards
