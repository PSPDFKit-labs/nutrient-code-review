"""JSON Schema for Claude Code review output."""

# JSON Schema for validating review output structure
REVIEW_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "pr_summary": {
            "type": "object",
            "properties": {
                "overview": {"type": "string"},
                "file_changes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string"},
                            "files": {"type": "array", "items": {"type": "string"}},
                            "changes": {"type": "string"}
                        },
                        "required": ["label", "files", "changes"]
                    }
                }
            },
            "required": ["overview", "file_changes"]
        },
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                    "category": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "impact": {"type": "string"},
                    "recommendation": {"type": "string"},
                    "suggestion": {"type": "string"},
                    "suggestion_start_line": {"type": "integer"},
                    "suggestion_end_line": {"type": "integer"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1}
                },
                "required": ["file", "line", "severity", "category", "title", "description", "impact", "recommendation", "confidence"]
            }
        }
    },
    "required": ["pr_summary", "findings"]
}