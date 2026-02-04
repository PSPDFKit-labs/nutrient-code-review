"""Claude API client for direct Anthropic API calls."""

import os
import json
import time
from typing import Dict, Any, Tuple, Optional
from pathlib import Path

from anthropic import Anthropic

from claudecode.constants import (
    DEFAULT_CLAUDE_MODEL, DEFAULT_TIMEOUT_SECONDS, DEFAULT_MAX_RETRIES,
    RATE_LIMIT_BACKOFF_MAX, PROMPT_TOKEN_LIMIT,
)
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.logger import get_logger

logger = get_logger(__name__)


class ClaudeAPIClient:
    """Client for calling Claude API directly for review analysis tasks."""
    
    def __init__(self, 
                 model: Optional[str] = None,
                 api_key: Optional[str] = None,
                 timeout_seconds: Optional[int] = None,
                 max_retries: Optional[int] = None):
        """Initialize Claude API client.
        
        Args:
            model: Claude model to use
            api_key: Anthropic API key (if None, reads from ANTHROPIC_API_KEY env var)
            timeout_seconds: Request timeout in seconds
            max_retries: Maximum retry attempts for API calls
        """
        self.model = model or DEFAULT_CLAUDE_MODEL
        self.timeout_seconds = timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        self.max_retries = max_retries or DEFAULT_MAX_RETRIES
        
        # Get API key from environment or parameter
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "No Anthropic API key found. Please set ANTHROPIC_API_KEY environment variable "
                "or provide api_key parameter."
            )
        
        # Initialize Anthropic client
        self.client = Anthropic(api_key=self.api_key)
        logger.info("Claude API client initialized successfully")
    
    def validate_api_access(self) -> Tuple[bool, str]:
        """Validate that API access is working.
        
        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Simple test call to verify API access
            self.client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=10,
                messages=[{"role": "user", "content": "Hello"}],
                timeout=10
            )
            logger.info("Claude API access validated successfully")
            return True, ""
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Claude API validation failed: {error_msg}")
            return False, f"API validation failed: {error_msg}"
    
    def call_with_retry(self, 
                       prompt: str,
                       system_prompt: Optional[str] = None,
                       max_tokens: int = PROMPT_TOKEN_LIMIT) -> Tuple[bool, str, str]:
        """Make Claude API call with retry logic.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            max_tokens: Maximum tokens to generate
            
        Returns:
            Tuple of (success, response_text, error_message)
        """
        retries = 0
        last_error = None
        
        while retries <= self.max_retries:
            try:
                logger.info(f"Claude API call attempt {retries + 1}/{self.max_retries + 1}")
                
                # Prepare messages
                messages = [{"role": "user", "content": prompt}]
                
                # Build API call parameters
                api_params = {
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "messages": messages,
                    "timeout": self.timeout_seconds
                }
                
                if system_prompt:
                    api_params["system"] = system_prompt
                
                # Make API call
                start_time = time.time()
                response = self.client.messages.create(**api_params)
                duration = time.time() - start_time
                
                # Extract text from response
                response_text = ""
                for content_block in response.content:
                    if hasattr(content_block, 'text'):
                        response_text += content_block.text
                
                logger.info(f"Claude API call successful in {duration:.1f}s")
                return True, response_text, ""
                
            except Exception as e:
                error_msg = str(e)
                last_error = error_msg
                logger.error(f"Claude API call failed: {error_msg}")
                
                # Check if it's a rate limit error
                if "rate limit" in error_msg.lower() or "429" in error_msg:
                    logger.warning("Rate limit detected, increasing backoff")
                    backoff_time = min(RATE_LIMIT_BACKOFF_MAX, 5 * (retries + 1))  # Progressive backoff
                    time.sleep(backoff_time)
                elif "timeout" in error_msg.lower():
                    logger.warning("Timeout detected, retrying")
                    time.sleep(2)
                else:
                    # For other errors, shorter backoff
                    time.sleep(1)
                
                retries += 1
        
        # All retries exhausted
        return False, "", f"API call failed after {self.max_retries + 1} attempts: {last_error}"
    
    def analyze_single_finding(self, 
                              finding: Dict[str, Any], 
                              pr_context: Optional[Dict[str, Any]] = None,
                              custom_filtering_instructions: Optional[str] = None) -> Tuple[bool, Dict[str, Any], str]:
        """Analyze a single review finding to filter false positives using Claude API.
        
        Args:
            finding: Single review finding to analyze
            pr_context: Optional PR context for better analysis
            
        Returns:
            Tuple of (success, analysis_result, error_message)
        """
        try:
            # Generate analysis prompt with file content
            prompt = self._generate_single_finding_prompt(finding, pr_context, custom_filtering_instructions)
            system_prompt = self._generate_system_prompt()
            
            # Call Claude API
            success, response_text, error_msg = self.call_with_retry(
                prompt=prompt,
                system_prompt=system_prompt,
                max_tokens=PROMPT_TOKEN_LIMIT 
            )
            
            if not success:
                return False, {}, error_msg
            
            # Parse JSON response using json_parser
            success, analysis_result = parse_json_with_fallbacks(response_text, "Claude API response")
            if success:
                logger.info("Successfully parsed Claude API response for single finding")
                return True, analysis_result, ""
            else:
                # Fallback: return error
                return False, {}, "Failed to parse JSON response"
                
        except Exception as e:
            logger.exception(f"Error during single finding review analysis: {str(e)}")
            return False, {}, f"Single finding review analysis failed: {str(e)}"

    
    def _generate_system_prompt(self) -> str:
        """Generate system prompt for review analysis."""
        return """You are a senior code reviewer evaluating findings from an automated review tool.
Your task is to filter out false positives and low-signal findings to reduce noise.
You must maintain high recall (don't miss real issues) while improving precision.

Respond ONLY with valid JSON in the exact format specified in the user prompt.
Do not include explanatory text, markdown formatting, or code blocks."""
    
    def _generate_single_finding_prompt(self, 
                                       finding: Dict[str, Any], 
                                       pr_context: Optional[Dict[str, Any]] = None,
                                       custom_filtering_instructions: Optional[str] = None) -> str:
        """Generate prompt for analyzing a single review finding.
        
        Args:
            finding: Single review finding
            pr_context: Optional PR context
            
        Returns:
            Formatted prompt string
        """
        pr_info = ""
        if pr_context and isinstance(pr_context, dict):
            pr_info = f"""
PR Context:
- Repository: {pr_context.get('repo_name', 'unknown')}
- PR #{pr_context.get('pr_number', 'unknown')}
- Title: {pr_context.get('title', 'unknown')}
- Description: {(pr_context.get('description') or 'No description')[:500]}...
"""
        
        # Get file content if available
        file_path = finding.get('file', '')
        file_content = ""
        if file_path:
            success, content, error = self._read_file(file_path)
            if success:
                file_content = f"""

File Content ({file_path}):
```
{content}
```"""
            else:
                file_content = f"""

File Content ({file_path}): Error reading file - {error}
"""
        
        finding_json = json.dumps(finding, indent=2)
        
        # Use custom filtering instructions if provided, otherwise use defaults
        if custom_filtering_instructions:
            filtering_section = custom_filtering_instructions
        else:
            filtering_section = """HARD EXCLUSIONS - Automatically exclude findings matching these patterns:
1. Purely stylistic or formatting preferences (naming, spacing, comment wording) with no functional impact.
2. Documentation-only issues or typos that do not affect behavior or safety.
3. Refactor suggestions without a concrete bug, regression, or risk reduction.
4. Hypothetical issues without a clear failure mode or reproducible impact.

SECURITY-SPECIFIC EXCLUSIONS (apply ONLY if the category indicates security):
1. Denial of Service (DOS) or resource exhaustion concerns without concrete exploitability.
2. Rate limiting recommendations without a specific abuse path.
3. Memory safety issues in memory-safe languages (e.g., Rust).

SIGNAL QUALITY CRITERIA - For remaining findings, assess:
1. Is there a concrete failure mode or exploit path?
2. Is the impact meaningful (bug, regression, security risk, data loss)?
3. Are there specific code locations and reproduction steps?
4. Would this be actionable for the team?

PRECEDENTS -
1. Keep findings that indicate a likely production issue, security vulnerability, or significant regression.
2. Only include MEDIUM findings if they are obvious and concrete issues.
3. For security findings, prefer concrete exploitability and avoid theoretical best-practice gaps."""
        
        return f"""I need you to analyze a code review finding from an automated audit and determine if it's a false positive.

{pr_info}

{filtering_section}

Assign a confidence score from 1-10:
- 1-3: Low confidence, likely false positive or noise
- 4-6: Medium confidence, needs investigation  
- 7-10: High confidence, likely true issue

Finding to analyze:
```json
{finding_json}
```
{file_content}

Respond with EXACTLY this JSON structure (no markdown, no code blocks):
{{
  "original_severity": "HIGH",
  "confidence_score": 8,
  "keep_finding": true,
  "exclusion_reason": null,
  "justification": "Clear off-by-one error that causes data loss on edge cases"
}}"""

    
    def _read_file(self, file_path: str) -> Tuple[bool, str, str]:
        """Read a file and format it with line numbers.
        
        Args:
            file_path: Path to the file to read
            
        Returns:
            Tuple of (success, formatted_content, error_message)
        """
        try:
            # Check if REPO_PATH is set and use it as base path
            repo_path = os.environ.get('REPO_PATH')
            if repo_path:
                # Convert file_path to Path and check if it's absolute
                path = Path(file_path)
                if not path.is_absolute():
                    # Make it relative to REPO_PATH
                    path = Path(repo_path) / file_path
            else:
                path = Path(file_path)
            
            if not path.exists():
                return False, "", f"File not found: {path}"
            
            if not path.is_file():
                return False, "", f"Path is not a file: {path}"
            
            # Read file with error handling for encoding issues
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                # Try with latin-1 encoding as fallback
                with open(path, 'r', encoding='latin-1') as f:
                    content = f.read()
            
            return True, content, ""
            
        except Exception as e:
            error_msg = f"Error reading file {file_path}: {str(e)}"
            logger.error(error_msg)
            return False, "", error_msg


def get_claude_api_client(model: str = DEFAULT_CLAUDE_MODEL,
                         api_key: Optional[str] = None,
                         timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> ClaudeAPIClient:
    """Convenience function to get Claude API client.
    
    Args:
        model: Claude model identifier
        api_key: Optional API key (reads from environment if not provided)
        timeout_seconds: API call timeout
        
    Returns:
        Initialized ClaudeAPIClient instance
    """
    return ClaudeAPIClient(
        model=model,
        api_key=api_key,
        timeout_seconds=timeout_seconds
    )
