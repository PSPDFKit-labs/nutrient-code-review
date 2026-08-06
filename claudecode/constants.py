"""
Constants and configuration values for ClaudeCode.
"""

import os

# API Configuration
DEFAULT_CLAUDE_MODEL = os.environ.get('CLAUDE_MODEL') or 'claude-opus-4-8'
DEFAULT_GPT_MODEL = 'gpt-5.6-sol'
DEFAULT_SYNTHESIZER_PROVIDER = 'openai'
DEFAULT_SYNTHESIZER_MODEL = 'gpt-5.6-terra'
DEFAULT_TIMEOUT_SECONDS = 180  # 3 minutes
DEFAULT_MAX_RETRIES = 3
RATE_LIMIT_BACKOFF_MAX = 30  # Maximum backoff time for rate limits

# Token Limits
PROMPT_TOKEN_LIMIT = 16384  # Output cap for filter/validator API calls

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
