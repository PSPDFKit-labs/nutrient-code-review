"""
Constants and configuration values for ClaudeCode.
"""

import os

# API Configuration
DEFAULT_CLAUDE_MODEL = os.environ.get('CLAUDE_MODEL') or 'claude-opus-5'
DEFAULT_TIMEOUT_SECONDS = 180  # 3 minutes
DEFAULT_MAX_RETRIES = 3
RATE_LIMIT_BACKOFF_MAX = 30  # Maximum backoff time for rate limits
GITHUB_REQUEST_TIMEOUT = 30  # Timeout for GitHub API HTTP requests
# Concurrency for per-finding Claude API validation calls
FILTER_MAX_WORKERS = 4

# Token Limits
PROMPT_TOKEN_LIMIT = 16384  # Output cap for filter/validator API calls

# File-content windowing for per-finding filter prompts
FILTER_FILE_CONTEXT_LINES = 150  # Lines of context around the finding line
FILTER_FILE_MAX_CHARS = 40000  # Hard cap on file content embedded per finding

# Diff Construction Limits
DEFAULT_MAX_DIFF_CHARS = 800000  # 800k characters (~200k tokens; fits comfortably in 1M context models)
# Conversion factor for deprecated MAX_DIFF_LINES -> MAX_DIFF_CHARS
CHARS_PER_LINE_ESTIMATE = 80  # Average characters per line for conversion

# Exit Codes
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIGURATION_ERROR = 2

# Subprocess Configuration
SUBPROCESS_TIMEOUT = 1200  # 20 minutes for Claude Code execution

