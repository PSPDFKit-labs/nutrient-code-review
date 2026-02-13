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
from claudecode.findings_filter import FindingsFilter
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.format_pr_comments import format_pr_comments_for_prompt, is_bot_comment
from claudecode.prompts import get_unified_review_prompt  # Backward-compatible import for tests/extensions.
from claudecode.review_orchestrator import ReviewModelConfig, ReviewOrchestrator
from claudecode.constants import (
    EXIT_CONFIGURATION_ERROR,
    DEFAULT_CLAUDE_MODEL,
    EXIT_SUCCESS,
    EXIT_GENERAL_ERROR,
    SUBPROCESS_TIMEOUT
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
    
    def get_pr_data(self, repo_name: str, pr_number: int) -> Dict[str, Any]:
        """Get PR metadata and files from GitHub API.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Dictionary containing PR data
        """
        # Get PR metadata
        pr_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        response = requests.get(pr_url, headers=self.headers)
        response.raise_for_status()
        pr_data = response.json()
        
        # Get PR files with pagination support
        files_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}/files?per_page=100"
        response = requests.get(files_url, headers=self.headers)
        response.raise_for_status()
        files_data = response.json()
        
        return {
            'number': pr_data['number'],
            'title': pr_data['title'],
            'body': pr_data.get('body', ''),
            'user': pr_data['user']['login'],
            'created_at': pr_data['created_at'],
            'updated_at': pr_data['updated_at'],
            'state': pr_data['state'],
            'head': {
                'ref': pr_data['head']['ref'],
                'sha': pr_data['head']['sha'],
                'repo': {
                    'full_name': pr_data['head']['repo']['full_name'] if pr_data['head']['repo'] else repo_name
                }
            },
            'base': {
                'ref': pr_data['base']['ref'],
                'sha': pr_data['base']['sha']
            },
            'files': [
                {
                    'filename': f['filename'],
                    'status': f['status'],
                    'additions': f['additions'],
                    'deletions': f['deletions'],
                    'changes': f['changes'],
                    'patch': f.get('patch', '')
                }
                for f in files_data
                if not self._is_excluded(f['filename'])
            ],
            'additions': pr_data['additions'],
            'deletions': pr_data['deletions'],
            'changed_files': pr_data['changed_files']
        }
    
    def get_pr_diff(self, repo_name: str, pr_number: int) -> str:
        """Get complete PR diff in unified format.
        
        Args:
            repo_name: Repository name in format "owner/repo"
            pr_number: Pull request number
            
        Returns:
            Complete PR diff in unified format
        """
        url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        headers = dict(self.headers)
        headers['Accept'] = 'application/vnd.github.diff'
        
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        return self._filter_generated_files(response.text)

    def get_pr_comments(self, repo_name: str, pr_number: int) -> List[Dict[str, Any]]:
        """Get all review comments for a PR with pagination."""
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
                if len(comments) < per_page:
                    break
                page += 1
            except requests.RequestException as e:
                logger.warning(f"Failed to fetch comments page {page}: {e}")
                break

        return all_comments

    def get_comment_reactions(self, repo_name: str, comment_id: int) -> Dict[str, int]:
        """Get reactions for a specific comment, excluding bot reactions."""
        url = f"https://api.github.com/repos/{repo_name}/pulls/comments/{comment_id}/reactions"

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            reactions = response.json()

            counts: Dict[str, int] = {}
            for reaction in reactions:
                user = reaction.get('user', {})
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

    def is_excluded(self, filepath: str) -> bool:
        """Public wrapper for exclusion checks."""
        return self._is_excluded(filepath)
    
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
    
    def run_prompt(
        self,
        repo_dir: Path,
        prompt: str,
        model: Optional[str] = None,
        json_schema: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, Any]:
        """Run a single Claude prompt and return parsed JSON payload or text."""
        if not repo_dir.exists():
            return False, f"Repository directory does not exist: {repo_dir}", {}

        prompt_size = len(prompt.encode('utf-8'))
        if prompt_size > 1024 * 1024:  # 1MB
            print(f"[Warning] Large prompt size: {prompt_size / 1024 / 1024:.2f}MB", file=sys.stderr)

        model_name = model or DEFAULT_CLAUDE_MODEL
        try:
            cmd = [
                'claude',
                '--output-format', 'json',
                '--model', model_name,
                '--disallowed-tools', 'Bash(ps:*)',
            ]
            if json_schema:
                cmd.extend(['--json-schema', json.dumps(json_schema)])

            NUM_RETRIES = 3
            for attempt in range(NUM_RETRIES):
                result = subprocess.run(
                    cmd,
                    input=prompt,
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds
                )

                if result.returncode != 0:
                    if attempt == NUM_RETRIES - 1:
                        error_details = f"Claude Code execution failed with return code {result.returncode}\n"
                        error_details += f"Stderr: {result.stderr}\n"
                        error_details += f"Stdout: {result.stdout[:500]}..."
                        return False, error_details, {}
                    time.sleep(5 * (attempt + 1))
                    continue

                success, parsed_result = parse_json_with_fallbacks(result.stdout, "Claude Code output")
                if success:
                    if (isinstance(parsed_result, dict) and 
                        parsed_result.get('type') == 'result' and 
                        parsed_result.get('subtype') == 'success' and
                        parsed_result.get('is_error') and
                        parsed_result.get('result') == 'Prompt is too long'):
                        return False, "PROMPT_TOO_LONG", {}

                    if (isinstance(parsed_result, dict) and 
                        parsed_result.get('type') == 'result' and 
                        parsed_result.get('subtype') == 'error_during_execution' and
                        attempt < NUM_RETRIES - 1):
                        continue

                    if isinstance(parsed_result, dict) and 'result' in parsed_result and isinstance(parsed_result['result'], str):
                        nested_success, nested = parse_json_with_fallbacks(parsed_result['result'], "Claude result text")
                        if nested_success:
                            return True, "", nested
                    return True, "", parsed_result

                if attempt == 0:
                    continue
                return False, "Failed to parse Claude output", {}

            return False, "Unexpected error in retry logic", {}
        except subprocess.TimeoutExpired:
            return False, f"Claude Code execution timed out after {self.timeout_seconds // 60} minutes", {}
        except Exception as e:
            return False, f"Claude Code execution error: {str(e)}", {}

    def run_code_review(self, repo_dir: Path, prompt: str, model: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """Run code review prompt and normalize to findings payload."""
        success, error_msg, parsed = self.run_prompt(
            repo_dir,
            prompt,
            model=model or DEFAULT_CLAUDE_MODEL,
            json_schema=REVIEW_OUTPUT_SCHEMA,
        )
        if not success:
            return False, error_msg, {}
        if isinstance(parsed, dict) and 'findings' in parsed:
            return True, "", parsed
        return True, "", self._extract_review_findings(parsed)
    
    def _extract_review_findings(self, claude_output: Any) -> Dict[str, Any]:
        """Extract review findings from Claude's JSON response."""
        if isinstance(claude_output, dict):
            if 'result' in claude_output:
                result_text = claude_output['result']
                if isinstance(result_text, str):
                    # Try to extract JSON from the result text
                    success, result_json = parse_json_with_fallbacks(result_text, "Claude result text")
                    if success and result_json and 'findings' in result_json:
                        if 'pr_summary' not in result_json:
                            result_json['pr_summary'] = {}
                        return result_json
        
        # Return empty structure if no findings found
        return {
            'findings': [],
            'pr_summary': {},
            'analysis_summary': {
                'files_reviewed': 0,
                'high_severity': 0,
                'medium_severity': 0,
                'low_severity': 0,
                'review_completed': False,
            }
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
        # Check if we should use Claude API filtering
        use_claude_filtering = os.environ.get('ENABLE_CLAUDE_FILTERING', 'false').lower() == 'true'
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        
        if use_claude_filtering and api_key:
            # Use full filtering with Claude API
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=True,
                api_key=api_key,
                custom_filtering_instructions=custom_filtering_instructions
            )
        else:
            # Fallback to filtering with hard rules only
            return FindingsFilter(
                use_hard_exclusions=True,
                use_claude_filtering=False
            )
    except Exception as e:
        raise ConfigurationError(f'Failed to initialize findings filter: {str(e)}')


def get_review_model_config() -> ReviewModelConfig:
    """Resolve per-phase model configuration from environment."""
    return ReviewModelConfig.from_env(os.environ, DEFAULT_CLAUDE_MODEL)


def get_max_diff_lines() -> int:
    """Return bounded inline diff budget in lines."""
    max_diff_lines_str = os.environ.get('MAX_DIFF_LINES', '5000')
    try:
        parsed = int(max_diff_lines_str)
    except ValueError:
        parsed = 5000
    return max(0, parsed)



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
        
        # Get PR data
        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number)
            pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        except Exception as e:
            print(json.dumps({'error': f'Failed to fetch PR data: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # Backward-compatible context collection for review thread history.
        review_context = None
        try:
            pr_comments = github_client.get_pr_comments(repo_name, pr_number)
            if pr_comments:
                bot_comment_threads = []
                for comment in pr_comments:
                    if is_bot_comment(comment):
                        reactions = github_client.get_comment_reactions(repo_name, comment['id'])
                        replies = [
                            c for c in pr_comments
                            if c.get('in_reply_to_id') == comment['id']
                        ]
                        replies.sort(key=lambda c: c.get('created_at', ''))
                        bot_comment_threads.append({
                            'bot_comment': comment,
                            'replies': replies,
                            'reactions': reactions,
                        })
                bot_comment_threads.sort(key=lambda t: t['bot_comment'].get('created_at', ''))
                if bot_comment_threads:
                    review_context = format_pr_comments_for_prompt(bot_comment_threads)
                    if review_context:
                        logger.info(f"Fetched previous review context ({len(review_context)} chars)")
        except Exception as e:
            logger.warning(f"Failed to fetch review context (continuing without it): {e}")
            review_context = None

        max_diff_lines = get_max_diff_lines()
        diff_line_count = len(pr_diff.splitlines())
        if max_diff_lines and diff_line_count > max_diff_lines:
            print(f"[Info] Hybrid mode with truncated inline diff ({max_diff_lines}/{diff_line_count} lines)", file=sys.stderr)
        else:
            print(f"[Info] Hybrid mode with full inline diff ({diff_line_count} lines)", file=sys.stderr)

        # Get repo directory from environment or use current directory
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()
        model_config = get_review_model_config()
        orchestrator = ReviewOrchestrator(
            claude_runner=claude_runner,
            findings_filter=findings_filter,
            github_client=github_client,
            model_config=model_config,
            max_diff_lines=max_diff_lines,
        )

        success, review_results, review_error = orchestrator.run(
            repo_dir=repo_dir,
            pr_data=pr_data,
            pr_diff=pr_diff,
            custom_review_instructions=custom_review_instructions,
            custom_security_instructions=custom_security_instructions,
        )
        if not success:
            print(json.dumps({'error': f'Code review failed: {review_error}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        findings = review_results.get('findings', [])
        analysis_summary = review_results.get('analysis_summary', {})
        high_count = len([f for f in findings if isinstance(f, dict) and f.get('severity', '').upper() == 'HIGH'])
        medium_count = len([f for f in findings if isinstance(f, dict) and f.get('severity', '').upper() == 'MEDIUM'])
        low_count = len([f for f in findings if isinstance(f, dict) and f.get('severity', '').upper() == 'LOW'])
        files_reviewed = analysis_summary.get('files_reviewed', pr_data.get('changed_files', 0))
        try:
            files_reviewed = int(files_reviewed)
        except (TypeError, ValueError):
            files_reviewed = 0

        # Prepare output
        output = {
            'pr_number': pr_number,
            'repo': repo_name,
            'findings': findings,
            'analysis_summary': {
                'files_reviewed': files_reviewed,
                'high_severity': high_count,
                'medium_severity': medium_count,
                'low_severity': low_count,
                'review_completed': True
            },
            'filtering_summary': review_results.get('filtering_summary', {
                'total_original_findings': len(findings),
                'excluded_findings': 0,
                'kept_findings': len(findings),
            })
        }
        
        # Output JSON to stdout
        print(json.dumps(output, indent=2))
        
        # Exit with appropriate code
        high_severity_count = len([f for f in findings if isinstance(f, dict) and f.get('severity', '').upper() == 'HIGH'])
        sys.exit(EXIT_GENERAL_ERROR if high_severity_count > 0 else EXIT_SUCCESS)
        
    except Exception as e:
        print(json.dumps({'error': f'Unexpected error: {str(e)}'}))
        sys.exit(EXIT_CONFIGURATION_ERROR)


if __name__ == '__main__':
    main()
