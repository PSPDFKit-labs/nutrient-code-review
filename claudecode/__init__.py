"""
ClaudeCode - AI-Powered PR Code Review Tool

A standalone review tool that uses Claude Code for comprehensive
analysis of GitHub pull requests.
"""

__version__ = "1.0.0"
__author__ = "Anthropic"

# Import main components for easier access
from claudecode.github_action_audit import (
    GitHubActionClient,
    SimpleClaudeRunner,
    main
)

__all__ = [
    "GitHubActionClient",
    "SimpleClaudeRunner",
    "main"
]
