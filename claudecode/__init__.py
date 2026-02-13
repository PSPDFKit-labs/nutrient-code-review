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
    get_review_model_config,
    main
)
from claudecode.review_orchestrator import ReviewModelConfig, ReviewOrchestrator

__all__ = [
    "GitHubActionClient",
    "SimpleClaudeRunner",
    "ReviewModelConfig",
    "ReviewOrchestrator",
    "get_review_model_config",
    "main"
]
