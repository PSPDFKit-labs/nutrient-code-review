#!/usr/bin/env python3
"""
Simplified PR Code Review for GitHub Actions
Runs Claude Code review on current working directory and outputs findings to stdout
"""

import os
import sys
import json
import subprocess
import requests
from typing import Dict, Any, List, Tuple, Optional
from pathlib import Path
import re
import time 

# Import existing components we can reuse
from claudecode.prompts import get_unified_review_prompt
from claudecode.findings_filter import FindingsFilter
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.format_pr_comments import format_pr_comments_for_prompt, is_bot_comment
from claudecode.constants import (
    EXIT_CONFIGURATION_ERROR,
    DEFAULT_CLAUDE_MODEL,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    SUBPROCESS_TIMEOUT,
    DEFAULT_MAX_DIFF_CHARS,
    CHARS_PER_LINE_ESTIMATE
)
from claudecode.logger import get_logger
from claudecode.review_schema import REVIEW_OUTPUT_SCHEMA

logger = get_logger(__name__)

class ConfigurationError(ValueError):
    """Raised when configuration is invalid or missing."""
    pass

class AuditError(ValueError):
    """Raised when code review operations fail."""
    pass

class GitHubActionClient:
    """Simplified GitHub API client for GitHub Actions environment."""

    # Built-in patterns for files that should always be excluded
    BUILTIN_EXCLUDED_PATTERNS = [
        # Package manager lock files
        'package-lock.json',
        'yarn.lock',
        'pnpm-lock.yaml',
        'Gemfile.lock',
        'Pipfile.lock',
        'poetry.lock',
        'composer.lock',
        'Cargo.lock',
        'go.sum',
        'pubspec.lock',
        'Podfile.lock',
        'packages.lock.json',
        # Generated/compiled files
        '*.min.js',
        '*.min.css',
        '*.bundle.js',
        '*.chunk.js',
        '*.map',
        '*.pb.go',
        '*.pb.swift',
        '*.generated.*',
        '*.g.dart',
        '*.freezed.dart',
        # Binary files
        '*.png',
        '*.jpg',
        '*.jpeg',
        '*.gif',
        '*.ico',
        '*.webp',
        '*.svg',
        '*.woff',
        '*.woff2',
        '*.ttf',
        '*.eot',
        '*.pdf',
        '*.zip',
        '*.tar.gz',
        '*.jar',
        '*.pyc',
        '*.so',
        '*.dylib',
        '*.dll',
        '*.exe',
    ]

    # Built-in directories that should always be excluded
    BUILTIN_EXCLUDED_DIRS = [
        'node_modules',
        'vendor',
        'dist',
        'build',
        '.next',
        '__pycache__',
        '.gradle',
        'Pods',
        'DerivedData',
    ]

    def __init__(self):
        """Initialize GitHub client using environment variables."""
        self.github_token = os.environ.get('GITHUB_TOKEN')
        if not self.github_token:
            raise ValueError("GITHUB_TOKEN environment variable required")

        self.headers = {
            'Authorization': f'Bearer {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'X-GitHub-Api-Version': '2022-11-28'
        }

        # Get excluded directories from environment (user-specified)
        exclude_dirs = os.environ.get('EXCLUDE_DIRECTORIES', '')
        user_excluded_dirs = [d.strip() for d in exclude_dirs.split(',') if d.strip()] if exclude_dirs else []

        # Combine built-in and user-specified exclusions
        self.excluded_dirs = list(set(self.BUILTIN_EXCLUDED_DIRS + user_excluded_dirs))
        if user_excluded_dirs:
            print(f"[Debug] User excluded directories: {user_excluded_dirs}", file=sys.stderr)
        print(f"[Debug] Total excluded directories: {self.excluded_dirs}", file=sys.stderr)
    
    def get_pr_data(self, repo_name: str, pr_number: int, max_diff_chars: int = 400000) -> Dict[str, Any]:
        """Get PR metadata and construct diff in one pass with early termination.

        Fetches files page-by-page while building the diff. Stops fetching when
        max_diff_chars is reached, saving API calls for large PRs.

        When max_diff_chars == 0 (agentic mode), only fetches PR metadata without files,
        as Claude will use git commands to explore changes.

        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            max_diff_chars: Maximum diff characters (0 = agentic mode, don't fetch files)

        Returns:
            Dictionary containing:
            - PR metadata (number, title, body, user, etc.)
            - files: List of files fetched (empty if agentic mode)
            - pr_diff: Constructed diff text (empty if agentic mode)
            - is_truncated: Whether we stopped fetching due to max_chars
            - diff_stats: {files_included, total_files from PR metadata}
        """
        # Get PR metadata first (contains total changed_files count)
        pr_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        response = requests.get(pr_url, headers=self.headers)
        response.raise_for_status()
        pr_metadata = response.json()

        # Extract total files from PR metadata
        total_files_in_pr = pr_metadata['changed_files']

        # Agentic mode: Don't fetch files, Claude uses git commands
        if max_diff_chars == 0:
            logger.info(f"Agentic mode enabled (MAX_DIFF_CHARS=0): Skipping file fetch for PR #{pr_number} ({total_files_in_pr} files in PR)")
            return {
                'number': pr_metadata['number'],
                'title': pr_metadata['title'],
                'body': pr_metadata.get('body', ''),
                'user': pr_metadata['user']['login'],
                'created_at': pr_metadata['created_at'],
                'updated_at': pr_metadata['updated_at'],
                'state': pr_metadata['state'],
                'head': {
                    'ref': pr_metadata['head']['ref'],
                    'sha': pr_metadata['head']['sha'],
                    'repo': {
                        'full_name': pr_metadata['head']['repo']['full_name'] if pr_metadata['head']['repo'] else repo_name
                    }
                },
                'base': {
                    'ref': pr_metadata['base']['ref'],
                    'sha': pr_metadata['base']['sha']
                },
                'files': [],
                'additions': pr_metadata['additions'],
                'deletions': pr_metadata['deletions'],
                'changed_files': pr_metadata['changed_files'],
                # Diff data (empty for agentic mode)
                'pr_diff': '',
                'is_truncated': False,
                'diff_stats': {'files_included': 0, 'total_files': total_files_in_pr, 'included_file_list': []}
            }

        # Setup for incremental diff construction
        diff_sections = []
        current_chars = 0
        files_with_patches = 0
        is_truncated = False
        fetched_files = []
        included_files = []  # Track which files made it into the diff

        # Fetch files page-by-page, building diff incrementally
        page = 1
        per_page = 100

        while True:
            files_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files"
            params = {'per_page': per_page, 'page': page}

            try:
                response = requests.get(files_url, headers=self.headers, params=params)
                response.raise_for_status()
                files_data = response.json()

                if not files_data:
                    break

                # Process each file in this page
                for file_data in files_data:
                    filename = file_data['filename']

                    # Skip excluded files
                    if self._is_excluded(filename):
                        continue

                    # Store file metadata
                    file_obj = {
                        'filename': filename,
                        'status': file_data['status'],
                        'additions': file_data['additions'],
                        'deletions': file_data['deletions'],
                        'changes': file_data['changes'],
                        'patch': file_data.get('patch', ''),
                        'previous_filename': file_data.get('previous_filename')
                    }
                    fetched_files.append(file_obj)

                    # Try to add to diff (only files with patches)
                    patch = file_data.get('patch', '')
                    if not patch:
                        logger.debug(f"Skipping {filename} (no patch - binary/rename-only)")
                        continue  # Skip files without patches (binaries, etc.)

                    # Build diff section
                    diff_section = self._format_file_diff(file_obj)
                    section_chars = len(diff_section)

                    # Check if adding this would exceed limit
                    if current_chars + section_chars > max_diff_chars:
                        is_truncated = True
                        # Early termination - stop fetching more files
                        logger.info(f"Diff truncated at {files_with_patches} files ({current_chars} chars, would exceed max {max_diff_chars})")
                        break

                    # Add to diff
                    diff_sections.append(diff_section)
                    current_chars += section_chars
                    files_with_patches += 1
                    included_files.append(filename)
                    logger.debug(f"Added {filename} to diff ({section_chars} chars, total: {current_chars}/{max_diff_chars})")

                # If truncated, stop pagination
                if is_truncated:
                    break

                # GitHub API supports up to 3000 files
                # Stop if no more pages
                if len(files_data) < per_page:
                    break

                page += 1

            except requests.RequestException as e:
                logger.warning(f"Failed to fetch files page {page}: {e}")
                # Continue with files we have so far rather than failing completely
                break

        logger.info(f"Fetched {len(fetched_files)} files for PR #{pr_number} (total in PR: {total_files_in_pr})")

        pr_diff = '\n'.join(diff_sections)
        diff_char_count = len(pr_diff)

        diff_stats = {
            'files_included': files_with_patches,
            'total_files': total_files_in_pr,  # From PR metadata, not fetched count
            'included_file_list': included_files  # Actual list of files in the diff
        }

        # Log diff construction summary
        skipped_files = len(fetched_files) - files_with_patches
        logger.info(f"Diff construction complete: {files_with_patches} files in diff ({diff_char_count} chars), "
                   f"{skipped_files} files skipped (no patch), {total_files_in_pr - len(fetched_files)} files not fetched")

        return {
            'number': pr_metadata['number'],
            'title': pr_metadata['title'],
            'body': pr_metadata.get('body', ''),
            'user': pr_metadata['user']['login'],
            'created_at': pr_metadata['created_at'],
            'updated_at': pr_metadata['updated_at'],
            'state': pr_metadata['state'],
            'head': {
                'ref': pr_metadata['head']['ref'],
                'sha': pr_metadata['head']['sha'],
                'repo': {
                    'full_name': pr_metadata['head']['repo']['full_name'] if pr_metadata['head']['repo'] else repo_name
                }
            },
            'base': {
                'ref': pr_metadata['base']['ref'],
                'sha': pr_metadata['base']['sha']
            },
            'files': fetched_files,
            'additions': pr_metadata['additions'],
            'deletions': pr_metadata['deletions'],
            'changed_files': pr_metadata['changed_files'],
            # Diff data
            'pr_diff': pr_diff,
            'is_truncated': is_truncated,
            'diff_stats': diff_stats
        }

    def _format_file_diff(self, file_data: Dict[str, Any]) -> str:
        """Format unified diff section for a single file.

        Handles all file statuses: added, removed, modified, renamed, etc.

        Args:
            file_data: File dictionary with filename, status, patch, etc.

        Returns:
            Formatted unified diff section for this file
        """
        filename = file_data['filename']
        status = file_data.get('status', 'modified')
        previous_filename = file_data.get('previous_filename')
        patch = file_data.get('patch', '')

        # Build diff header based on file status
        diff_lines = []
        diff_lines.append(f"diff --git a/{previous_filename or filename} b/{filename}")

        if status == 'added':
            diff_lines.append("new file mode 100644")
            diff_lines.append("--- /dev/null")
            diff_lines.append(f"+++ b/{filename}")
        elif status == 'removed':
            diff_lines.append("deleted file mode 100644")
            diff_lines.append(f"--- a/{filename}")
            diff_lines.append("+++ /dev/null")
        elif status == 'renamed':
            diff_lines.append("similarity index 100%")
            diff_lines.append(f"rename from {previous_filename}")
            diff_lines.append(f"rename to {filename}")
            diff_lines.append(f"--- a/{previous_filename}")
            diff_lines.append(f"+++ b/{filename}")
        else:  # modified, changed, copied, unchanged
            diff_lines.append(f"--- a/{filename}")
            diff_lines.append(f"+++ b/{filename}")

        # Add patch content
        diff_lines.append(patch)

        return '\n'.join(diff_lines) + '\n'

    def get_pr_comments(self, repo_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get all review comments for a PR with pagination.

        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number

        Returns:
            List of comment dictionaries from GitHub API
        """
        all_comments = []
        page = 1
        per_page = 100

        while True:
            url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/comments"
            params = {'per_page': per_page, 'page': page}

            try:
                response = requests.get(url, headers=self.headers, params=params)
                response.raise_for_status()
                comments = response.json()

                if not comments:
                    break

                all_comments.extend(comments)

                # Check if there are more pages
                if len(comments) < per_page:
                    break

                page += 1

            except requests.RequestException as e:
                logger.warning(f"Failed to fetch comments page {page}: {e}")
                break

        return all_comments

    def get_comment_reactions(self, repo_name: str, comment_id: int) -> Dict[str, int]:
        """Get reactions for a specific comment, excluding bot reactions.

        Args:
            repo_name: Repository name in format "owner/repo"
            comment_id: The comment ID to fetch reactions for

        Returns:
            Dictionary with reaction counts (e.g., {'+1': 3, '-1': 1})
        """
        url = f"https://api.github.com/repos/{repo_name}/pulls/comments/{comment_id}/reactions"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            reactions = response.json()

            # Count reactions, excluding those from bots
            counts = {}
            for reaction in reactions:
                user = reaction.get('user', {})
                # Skip bot reactions (the bot adds its own 👍👎 as seeds)
                if user.get('type') == 'Bot':
                    continue

                content = reaction.get('content', '')
                if content:
                    counts[content] = counts.get(content, 0) + 1

            return counts

        except requests.RequestException as e:
            logger.debug(f"Failed to fetch reactions for comment {comment_id}: {e}")
            return {}

    def _is_excluded(self, filepath: str) -> bool:
        """Check if a file should be excluded based on directory or file patterns."""
        import fnmatch

        # Check directory exclusions
        for excluded_dir in self.excluded_dirs:
            # Normalize excluded directory (remove leading ./ if present)
            if excluded_dir.startswith('./'):
                normalized_excluded = excluded_dir[2:]
            else:
                normalized_excluded = excluded_dir

            # Check if file starts with excluded directory
            if filepath.startswith(excluded_dir + '/'):
                return True
            if filepath.startswith(normalized_excluded + '/'):
                return True

            # Check if excluded directory appears anywhere in the path
            if '/' + normalized_excluded + '/' in filepath:
                return True

        # Check file pattern exclusions
        filename = filepath.split('/')[-1]
        for pattern in self.BUILTIN_EXCLUDED_PATTERNS:
            if fnmatch.fnmatch(filename, pattern):
                return True
            # Also check full path for patterns like *.generated.*
            if fnmatch.fnmatch(filepath, pattern):
                return True

        return False
    
    def _filter_generated_files(self, diff_text: str) -> str:
        """Filter out generated files and excluded directories from diff content."""
        
        file_sections = re.split(r'(?=^diff --git)', diff_text, flags=re.MULTILINE)
        filtered_sections = []
        
        for section in file_sections:
            if not section.strip():
                continue
                
            # Skip generated files
            if ('@generated by' in section or 
                '@generated' in section or 
                'Code generated by OpenAPI Generator' in section or
                'Code generated by protoc-gen-go' in section):
                continue
            
            # Extract filename from diff header
            match = re.match(r'^diff --git a/(.*?) b/', section)
            if match:
                filename = match.group(1)
                if self._is_excluded(filename):
                    print(f"[Debug] Filtering out excluded file: {filename}", file=sys.stderr)
                    continue
            
            filtered_sections.append(section)
        
        return ''.join(filtered_sections)


class SimpleClaudeRunner:
    """Simplified Claude Code runner for GitHub Actions."""
    
    def __init__(self, timeout_minutes: Optional[int] = None):
        """Initialize Claude runner.
        
        Args:
            timeout_minutes: Timeout for Claude execution (defaults to SUBPROCESS_TIMEOUT)
        """
        if timeout_minutes is not None:
            self.timeout_seconds = timeout_minutes * 60
        else:
            self.timeout_seconds = SUBPROCESS_TIMEOUT
    
    def run_code_review(self, repo_dir: Path, prompt: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Run Claude Code review.
        
        Args:
            repo_dir: Path to repository directory
            prompt: Code review prompt
            
        Returns:
            Tuple of (success, error_message, parsed_results)
        """
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}
        
        # Check prompt size
        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB", file=sys.stderr)
        
        try:
            # Construct Claude Code command
            # Use stdin for prompt to avoid "argument list too long" error
            cmd = [
                'claude',
                '--output-format', 'json',
                '--model', DEFAULT_CLAUDE_MODEL,
                '--disallowed-tools', 'Bash(ps:*)',
                '--json-schema', json.dumps(REVIEW_OUTPUT_SCHEMA)
            ]
            
            # Run Claude Code with retry logic
            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
                result = subprocess.run(
                    cmd,
                    input=prompt,  # Pass prompt via stdin
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds
                )

                # Parse JSON output (even if returncode != 0, to detect specific errors)
                success, parsed_result = parse_json_with_fallbacks(result.stdout, "Claude Code output")

                if success:
                    # Check for "Prompt is too long" error that should trigger fallback to agentic mode
                    if (isinstance(parsed_result, dict) and
                        parsed_result.get('type') == 'result' and
                        parsed_result.get('subtype') == 'success' and
                        parsed_result.get('is_error') and
                        parsed_result.get('result') == 'Prompt is too long'):
                        return False, "PROMPT_TOO_LONG", {}

                    # Check for error_during_execution that should trigger retry
                    if (isinstance(parsed_result, dict) and
                        parsed_result.get('type') == 'result' and
                        parsed_result.get('subtype') == 'error_during_execution' and
                        attempt == 0):
                        continue  # Retry

                    # If returncode is 0, extract review findings
                    if result.returncode == 0:
                        parsed_results = self._extract_review_findings(parsed_result)
                        return True, "", parsed_results

                # Handle non-zero return codes after parsing
                if result.returncode != 0:
                    if attempt == NUM_RETRIES - 1:
                        error_details = f"Claude Code execution failed with return code {result.returncode}\n"
                        error_details += f"Stderr: {result.stderr}\n"
                        error_details += f"Stdout: {result.stdout[:500]}..."  # First 500 chars
                        return False, error_details, {}
                    else:
                        time.sleep(5*attempt)
                        # Note: We don't do exponential backoff here to keep the runtime reasonable
                        continue  # Retry

                # Parse failed
                if attempt == 0:
                    continue  # Retry once
                else:
                    return False, "Failed to parse Claude output", {}
            
            return False, "Unexpected error in retry logic", {}
            
        except subprocess.TimeoutExpired:
            return False, f"Claude Code execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"Claude Code execution error: {str(e)}", {}
    
    def _extract_review_findings(self, claude_output: Any) -> Dict[str, Any]:
        """Extract review findings and PR summary from Claude's JSON response."""
        if isinstance(claude_output, dict):
            # Only accept Claude Code wrapper with result field
            # Direct format without wrapper is not supported
            if 'result' in claude_output:
                result_text = claude_output['result']
                if isinstance(result_text, str):
                    # Try to extract JSON from the result text
                    success, result_json = parse_json_with_fallbacks(result_text, "Claude result text")
                    if success and result_json and 'findings' in result_json and 'pr_summary' in result_json:
                        return result_json

        # Return empty structure if no findings found
        return {
            'findings': [],
            'pr_summary': {}
        }

    def validate_claude_available(self) -> Tuple[bool, str]:
        """Validate that Claude Code is available."""
        try:
            result = subprocess.run(
                ['claude', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Also check if API key is configured
                api_key = os.environ.get('ANTHROPIC_API_KEY', '')
                if not api_key:
                    return False, "ANTHROPIC_API_KEY environment variable is not set"
                return True, ""
            else:
                error_msg = f"Claude Code returned exit code {result.returncode}"
                if result.stderr:
                    error_msg += f". Stderr: {result.stderr}"
                if result.stdout:
                    error_msg += f". Stdout: {result.stdout}"
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            return False, "Claude Code command timed out"
        except FileNotFoundError:
            return False, "Claude Code is not installed or not in PATH"
        except Exception as e:
            return False, f"Failed to check Claude Code: {str(e)}"




def get_environment_config() -> Tuple[str, int]:
    """Get and validate environment configuration.
    
    Returns:
        Tuple of (repo_name, pr_number)
        
    Raises:
        ConfigurationError: If required environment variables are missing or invalid
    """
    repo_name = os.environ.get('GITHUB_REPOSITORY')
    pr_number_str = os.environ.get('PR_NUMBER')
    
    if not repo_name:
        raise ConfigurationError('GITHUB_REPOSITORY environment variable required')
    
    if not pr_number_str:
        raise ConfigurationError('PR_NUMBER environment variable required')
    
    try:
        pr_number = int(pr_number_str)
    except ValueError:
        raise ConfigurationError(f'Invalid PR_NUMBER: {pr_number_str}')
        
    return repo_name, pr_number


def initialize_clients() -> Tuple[GitHubActionClient, SimpleClaudeRunner]:
    """Initialize GitHub and Claude clients.
    
    Returns:
        Tuple of (github_client, claude_runner)
        
    Raises:
        ConfigurationError: If client initialization fails
    """
    try:
        github_client = GitHubActionClient()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize GitHub client: {str(e)}')
    
    try:
        claude_runner = SimpleClaudeRunner()
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize Claude runner: {str(e)}')
        
    return github_client, claude_runner


def initialize_findings_filter(custom_filtering_instructions: Optional[str] = None) -> FindingsFilter:
    """Initialize findings filter based on environment configuration.
    
    Args:
        custom_filtering_instructions: Optional custom filtering instructions
        
    Returns:
        FindingsFilter instance
        
    Raises:
        ConfigurationError: If filter initialization fails
    """
    try:
        # Check if we should use heuristic (pattern-based) filtering
        use_heuristic_filtering = os.environ.get('ENABLE_HEURISTIC_FILTERING', 'true').lower() == 'true'

        # Check if we should use Claude API filtering
        use_claude_filtering = os.environ.get('ENABLE_CLAUDE_FILTERING', 'false').lower() == 'true'
        api_key = os.environ.get('ANTHROPIC_API_KEY')

        if use_claude_filtering and api_key:
            # Use full filtering with Claude API
            return FindingsFilter(
                use_hard_exclusions=use_heuristic_filtering,
                use_claude_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions
            )
        else:
            # Fallback to filtering with hard rules only
            return FindingsFilter(
                use_hard_exclusions=use_heuristic_filtering,
                use_claude_filtering=False
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {str(e)}')



def run_code_review(claude_runner: SimpleClaudeRunner, prompt: str) -> Dict[str, Any]:
    """Run the code review with Claude Code.
    
    Args:
        claude_runner: Claude runner instance
        prompt: The review prompt
        
    Returns:
        Review results dictionary
        
    Raises:
        AuditError: If the review fails
    """
    # Get repo directory from environment or use current directory
    repo_path = os.environ.get('REPO_PATH')
    repo_dir = Path(repo_path) if repo_path else Path.cwd()
    success, error_msg, results = claude_runner.run_code_review(repo_dir, prompt)
    
    if not success:
        raise AuditError(f'Code review failed: {error_msg}')
        
    return results


def apply_findings_filter(findings_filter, original_findings: List[Dict[str, Any]], 
                         pr_context: Dict[str, Any], github_client: GitHubActionClient) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Apply findings filter to reduce false positives.
    
    Args:
        findings_filter: Filter instance
        original_findings: Original findings from audit
        pr_context: PR context information
        github_client: GitHub client with exclusion logic
        
    Returns:
        Tuple of (kept_findings, excluded_findings, analysis_summary)
    """
    # Apply FindingsFilter
    filter_success, filter_results, filter_stats = findings_filter.filter_findings(
        original_findings, pr_context
    )
    
    if filter_success:
        kept_findings = filter_results.get('filtered_findings', [])
        excluded_findings = filter_results.get('excluded_findings', [])
        analysis_summary = filter_results.get('analysis_summary', {})
    else:
        # Filtering failed, keep all findings
        kept_findings = original_findings
        excluded_findings = []
        analysis_summary = {}
    
    # Apply final directory exclusion filtering
    final_kept_findings = []
    directory_excluded_findings = []
    
    for finding in kept_findings:
        if _is_finding_in_excluded_directory(finding, github_client):
            directory_excluded_findings.append(finding)
        else:
            final_kept_findings.append(finding)
    
    # Update excluded findings list
    all_excluded_findings = excluded_findings + directory_excluded_findings
    
    # Update analysis summary with directory filtering stats
    analysis_summary['directory_excluded_count'] = len(directory_excluded_findings)
    
    return final_kept_findings, all_excluded_findings, analysis_summary


def _is_finding_in_excluded_directory(finding: Dict[str, Any], github_client: GitHubActionClient) -> bool:
    """Check if a finding references a file in an excluded directory.
    
    Args:
        finding: Review finding dictionary
        github_client: GitHub client with exclusion logic
        
    Returns:
        True if finding should be excluded, False otherwise
    """
    file_path = finding.get('file', '')
    if not file_path:
        return False
    
    return github_client._is_excluded(file_path)


def main():
    """Main execution function for GitHub Action."""
    try:
        # Get environment configuration
        try:
            repo_name, pr_number = get_environment_config()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Load custom filtering instructions if provided
        custom_filtering_instructions = None
        filtering_file = os.environ.get('FALSE_POSITIVE_FILTERING_INSTRUCTIONS', '')
        if filtering_file and Path(filtering_file).exists():
            try:
                with open(filtering_file, 'r', encoding='utf-8') as f:
                    custom_filtering_instructions = f.read()
                    logger.info(f"Loaded custom filtering instructions from {filtering_file}")
            except Exception as e:
                logger.warning(f"Failed to read filtering instructions file {filtering_file}: {e}")
        
        # Load custom review instructions if provided
        custom_review_instructions = None
        review_file = os.environ.get('CUSTOM_REVIEW_INSTRUCTIONS', '')
        if review_file and Path(review_file).exists():
            try:
                with open(review_file, 'r', encoding='utf-8') as f:
                    custom_review_instructions = f.read()
                    logger.info(f"Loaded custom review instructions from {review_file}")
            except Exception as e:
                logger.warning(f"Failed to read review instructions file {review_file}: {e}")

        # Load custom security scan instructions if provided (appended to security section)
        custom_security_instructions = None
        security_scan_file = os.environ.get('CUSTOM_SECURITY_SCAN_INSTRUCTIONS', '')
        if security_scan_file and Path(security_scan_file).exists():
            try:
                with open(security_scan_file, 'r', encoding='utf-8') as f:
                    custom_security_instructions = f.read()
                    logger.info(f"Loaded custom security scan instructions from {security_scan_file}")
            except Exception as e:
                logger.warning(f"Failed to read security scan instructions file {security_scan_file}: {e}")
        
        # Initialize components
        try:
            github_client, claude_runner = initialize_clients()
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
            
        # Initialize findings filter
        try:
            findings_filter = initialize_findings_filter(custom_filtering_instructions)
        except ConfigurationError as e:
            print(json.dumps({'error': str(e)}))
            sys.exit(EXIT_CONFIGURATION_ERROR)
        
        # Validate Claude Code is available
        claude_ok, claude_error = claude_runner.validate_claude_available()
        if not claude_ok:
            print(json.dumps({'error': f'Claude Code not available: {claude_error}'}))
            sys.exit(EXIT_GENERAL_ERROR)
        
        # Parse max diff chars setting (with backward compatibility for max_diff_lines)
        max_diff_chars_str = os.environ.get('MAX_DIFF_CHARS', '')
        max_diff_lines_str = os.environ.get('MAX_DIFF_LINES', '')

        if max_diff_chars_str:
            # New parameter takes precedence
            try:
                max_diff_chars = int(max_diff_chars_str)
            except ValueError:
                max_diff_chars = DEFAULT_MAX_DIFF_CHARS
        elif max_diff_lines_str:
            # Backward compatibility: convert lines to chars
            try:
                max_diff_lines = int(max_diff_lines_str)
                max_diff_chars = max_diff_lines * CHARS_PER_LINE_ESTIMATE
                logger.info(f"[DEPRECATED] MAX_DIFF_LINES used ({max_diff_lines} lines). "
                           f"Converted to {max_diff_chars} chars. Please use MAX_DIFF_CHARS instead.")
            except ValueError:
                max_diff_chars = DEFAULT_MAX_DIFF_CHARS
        else:
            # Use default
            max_diff_chars = DEFAULT_MAX_DIFF_CHARS

        # Get PR data with integrated diff construction
        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number, max_diff_chars)
        except Exception as e:
            print(json.dumps({'error': f'Failed to fetch PR data: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # Extract diff data from pr_data
        pr_diff = pr_data['pr_diff']
        is_truncated = pr_data['is_truncated']
        diff_stats = pr_data['diff_stats']

        diff_char_count = len(pr_diff)

        # Determine review mode
        force_agentic_mode = max_diff_chars == 0  # User explicitly requested agentic mode
        use_partial_diff_mode = is_truncated and not force_agentic_mode

        # Log mode selection
        if force_agentic_mode:
            logger.info(f"Using full agentic mode (MAX_DIFF_CHARS=0)")
        elif use_partial_diff_mode:
            included = diff_stats['files_included']
            total = diff_stats['total_files']
            logger.info(f"Using partial diff mode ({included}/{total} files, {diff_char_count:,} chars)")
        else:
            logger.info(f"Using full diff mode ({diff_char_count:,} chars, {diff_stats['files_included']} files)")

        # Fetch PR comments and build review context
        review_context = None
        try:
            pr_comments = github_client.get_pr_comments(repo_name, pr_number)
            if pr_comments:
                # Build threads: find bot comments, their replies, and reactions
                bot_comment_threads = []
                for comment in pr_comments:
                    if is_bot_comment(comment):
                        # This is a bot comment (thread root)
                        reactions = github_client.get_comment_reactions(repo_name, comment['id'])

                        # Find replies to this comment
                        replies = [
                            c for c in pr_comments
                            if c.get('in_reply_to_id') == comment['id']
                        ]
                        # Sort replies by creation time
                        replies.sort(key=lambda c: c.get('created_at', ''))

                        bot_comment_threads.append({
                            'bot_comment': comment,
                            'replies': replies,
                            'reactions': reactions,
                        })

                # Sort threads by bot comment creation time (oldest first)
                bot_comment_threads.sort(key=lambda t: t['bot_comment'].get('created_at', ''))

                if bot_comment_threads:
                    review_context = format_pr_comments_for_prompt(bot_comment_threads)
                    if review_context:
                        logger.info(f"Fetched previous review context ({len(review_context)} chars)")
        except Exception as e:
            logger.warning(f"Failed to fetch review context (continuing without it): {e}")
            review_context = None

        # Prepare diff metadata for prompt
        diff_metadata = None
        if use_partial_diff_mode:
            diff_metadata = {
                'is_truncated': True,
                'stats': diff_stats
            }

        # Get repo directory from environment or use current directory
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()

        def run_review(include_diff: bool, diff_metadata=None):
            prompt_text = get_unified_review_prompt(
                pr_data,
                pr_diff if include_diff else None,
                include_diff=include_diff,
                custom_review_instructions=custom_review_instructions,
                custom_security_instructions=custom_security_instructions,
                review_context=review_context,
                diff_metadata=diff_metadata,
            )
            return claude_runner.run_code_review(repo_dir, prompt_text), len(prompt_text)

        all_findings = []
        pr_summary_from_review = {}

        try:
            if force_agentic_mode:
                # Full agentic mode - no diff
                (success, error_msg, review_results), prompt_len = run_review(include_diff=False)
            elif use_partial_diff_mode:
                # Partial diff mode - include truncated diff with metadata
                (success, error_msg, review_results), prompt_len = run_review(
                    include_diff=True,
                    diff_metadata=diff_metadata
                )
            else:
                # Full diff mode
                (success, error_msg, review_results), prompt_len = run_review(include_diff=True)

            # Fallback to full agentic if prompt still too long
            if not success and error_msg == "PROMPT_TOO_LONG":
                logger.info(f"Prompt too long ({prompt_len} chars), falling back to full agentic mode")
                (success, error_msg, review_results), prompt_len = run_review(include_diff=False)

            if not success:
                raise AuditError(f'Code review failed: {error_msg}')

            pr_summary_from_review = review_results.get('pr_summary', {})
            for finding in review_results.get('findings', []):
                if isinstance(finding, dict):
                    # Set review_type based on category
                    category = finding.get('category', '').lower()
                    if category == 'security':
                        finding.setdefault('review_type', 'security')
                    else:
                        finding.setdefault('review_type', 'general')
                all_findings.append(finding)

        except AuditError as e:
            print(json.dumps({'error': f'Code review failed: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # Filter findings to reduce false positives
        original_findings = all_findings
        
        # Prepare PR context for better filtering
        pr_context = {
            'repo_name': repo_name,
            'pr_number': pr_number,
            'title': pr_data.get('title', ''),
            'description': pr_data.get('body', '')
        }
        
        # Apply findings filter (including final directory exclusion)
        kept_findings, excluded_findings, analysis_summary = apply_findings_filter(
            findings_filter, original_findings, pr_context, github_client
        )
        
        # Prepare output summary
        def severity_counts(findings_list):
            high = len([f for f in findings_list if isinstance(f, dict) and f.get('severity', '').upper() == 'HIGH'])
            medium = len([f for f in findings_list if isinstance(f, dict) and f.get('severity', '').upper() == 'MEDIUM'])
            low = len([f for f in findings_list if isinstance(f, dict) and f.get('severity', '').upper() == 'LOW'])
            return high, medium, low

        high_count, medium_count, low_count = severity_counts(kept_findings)

        # Calculate files_reviewed by merging:
        # 1. Files included in embedded diff (from diff_stats)
        # 2. Additional files mentioned in pr_summary (Claude explored via git commands)
        all_reviewed_files = set()

        # Add files from embedded diff
        if diff_stats and 'included_file_list' in diff_stats:
            all_reviewed_files.update(diff_stats['included_file_list'])

        # Add files from pr_summary (files Claude explored beyond the embedded diff)
        if isinstance(pr_summary_from_review, dict):
            file_changes = pr_summary_from_review.get('file_changes', [])
            if isinstance(file_changes, list):
                for entry in file_changes:
                    if isinstance(entry, dict):
                        files_list = entry.get('files', [])
                        if isinstance(files_list, list):
                            all_reviewed_files.update(files_list)

        files_reviewed = len(all_reviewed_files)

        # Prepare output
        output = {
            'pr_number': pr_number,
            'repo': repo_name,
            'pr_summary': pr_summary_from_review,
            'findings': kept_findings,
            'analysis_summary': {
                'files_reviewed': files_reviewed,
                'high_severity': high_count,
                'medium_severity': medium_count,
                'low_severity': low_count,
                'review_completed': True
            },
            'filtering_summary': {
                'total_original_findings': len(original_findings),
                'excluded_findings': len(excluded_findings),
                'kept_findings': len(kept_findings),
                'filter_analysis': analysis_summary,
                'excluded_findings_details': excluded_findings  # Include full details of what was filtered
            }
        }
        
        # Output JSON to stdout
        print(json.dumps(output, indent=2))
        
        # Exit with appropriate code
        high_severity_count = len([f for f in kept_findings if f.get('severity', '').upper() == 'HIGH'])
        sys.exit(EXIT_GENERAL_ERROR if high_severity_count > 0 else EXIT_SUCCESS)
        
    except Exception as e:
        print(json.dumps({'error': f'Unexpected error: {str(e)}'}))
        sys.exit(EXIT_CONFIGURATION_ERROR)


if __name__ == '__main__':
    main()
