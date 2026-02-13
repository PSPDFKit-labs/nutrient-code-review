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
                
                # Parse JSON output
                success, parsed_result = parse_json_with_fallbacks(result.stdout, "Claude Code output")
                
                if success:
                    # Check for "Prompt is too long" error that should trigger retry without diff
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
                    
                    # Extract review findings
                    parsed_results = self._extract_review_findings(parsed_result)
                    return True, "", parsed_results
                else:
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
        
        # Get PR data
        try:
            pr_data = github_client.get_pr_data(repo_name, pr_number)
            pr_diff = github_client.get_pr_diff(repo_name, pr_number)
        except Exception as e:
            print(json.dumps({'error': f'Failed to fetch PR data: {str(e)}'}))
            sys.exit(EXIT_GENERAL_ERROR)

        # Determine whether to embed diff or use agentic file reading
        max_diff_lines_str = os.environ.get('MAX_DIFF_LINES', '5000')
        try:
            max_diff_lines = int(max_diff_lines_str)
        except ValueError:
            max_diff_lines = 5000

        diff_line_count = len(pr_diff.splitlines())
        use_agentic_mode = max_diff_lines == 0 or diff_line_count > max_diff_lines

        if use_agentic_mode:
            print(f"[Info] Using agentic file reading mode (diff has {diff_line_count} lines, threshold: {max_diff_lines})", file=sys.stderr)
        else:
            print(f"[Debug] Embedding diff in prompt ({diff_line_count} lines)", file=sys.stderr)

        # Get repo directory from environment or use current directory
        repo_path = os.environ.get('REPO_PATH')
        repo_dir = Path(repo_path) if repo_path else Path.cwd()

        def run_review(include_diff: bool):
            prompt_text = get_unified_review_prompt(
                pr_data,
                pr_diff if include_diff else None,
                include_diff=include_diff,
                custom_review_instructions=custom_review_instructions,
                custom_security_instructions=custom_security_instructions,
            )
            return claude_runner.run_code_review(repo_dir, prompt_text), len(prompt_text)

        all_findings = []
        pr_summary_from_review = {}

        try:
            (success, error_msg, review_results), prompt_len = run_review(include_diff=not use_agentic_mode)

            # Fallback to agentic mode if prompt still too long
            if not success and error_msg == "PROMPT_TOO_LONG":
                print(f"[Info] Prompt too long ({prompt_len} chars), falling back to agentic mode", file=sys.stderr)
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

        # Calculate files_reviewed from pr_summary.file_changes
        files_reviewed = 0
        if isinstance(pr_summary_from_review, dict):
            file_changes = pr_summary_from_review.get('file_changes', [])
            if isinstance(file_changes, list):
                # Count unique files from all 'files' arrays
                all_files = set()
                for entry in file_changes:
                    if isinstance(entry, dict):
                        files_list = entry.get('files', [])
                        if isinstance(files_list, list):
                            all_files.update(files_list)
                files_reviewed = len(all_files)

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
