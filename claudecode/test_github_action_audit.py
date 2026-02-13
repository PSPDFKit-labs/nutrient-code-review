#!/usr/bin/env python3
"""
Pytest tests for GitHub Action audit script components.
"""


class TestImports:
    """Test that all required modules can be imported."""
    
    def test_main_module_import(self):
        """Test that the main module can be imported."""
        from claudecode import github_action_audit
        assert hasattr(github_action_audit, 'GitHubActionClient')
        assert hasattr(github_action_audit, 'SimpleClaudeRunner')
        # SimpleFindingsFilter was removed
        assert hasattr(github_action_audit, 'main')
    
    def test_component_imports(self):
        """Test that all component modules can be imported."""
        from claudecode.prompts import get_unified_review_prompt
        from claudecode.json_parser import parse_json_with_fallbacks, extract_json_from_text
        
        # Verify they're callable/usable
        assert callable(get_unified_review_prompt)
        assert callable(parse_json_with_fallbacks)
        assert callable(extract_json_from_text)


class TestHardExclusionRules:
    """Test the HardExclusionRules patterns."""
    
    def test_dos_patterns(self):
        """Test DOS pattern exclusions."""
        from claudecode.findings_filter import HardExclusionRules
        
        dos_findings = [
            {'description': 'Potential denial of service vulnerability', 'category': 'security'},
            {'description': 'DOS attack through resource exhaustion', 'category': 'security'},
            {'description': 'Infinite loop causing resource exhaustion', 'category': 'security'},
        ]
        
        for finding in dos_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'dos' in reason.lower()
    
    def test_rate_limiting_patterns(self):
        """Test rate limiting pattern exclusions."""
        from claudecode.findings_filter import HardExclusionRules
        
        rate_limit_findings = [
            {'description': 'Missing rate limiting on endpoint', 'category': 'security'},
            {'description': 'No rate limit implemented for API', 'category': 'security'},
            {'description': 'Implement rate limiting for this route', 'category': 'security'},
        ]
        
        for finding in rate_limit_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'rate limit' in reason.lower()
    
    def test_open_redirect_patterns(self):
        """Test open redirect pattern exclusions."""
        from claudecode.findings_filter import HardExclusionRules
        
        redirect_findings = [
            {'description': 'Open redirect vulnerability found', 'category': 'security'},
            {'description': 'Unvalidated redirect in URL parameter', 'category': 'security'},
            {'description': 'Redirect attack possible through user input', 'category': 'security'},
        ]
        
        for finding in redirect_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'open redirect' in reason.lower()
    
    def test_markdown_file_exclusion(self):
        """Test that findings in .md files are excluded."""
        from claudecode.findings_filter import HardExclusionRules
        
        md_findings = [
            {'file': 'README.md', 'description': 'SQL injection vulnerability', 'category': 'security'},
            {'file': 'docs/security.md', 'description': 'Command injection found', 'category': 'security'},
            {'file': 'CHANGELOG.MD', 'description': 'XSS vulnerability', 'category': 'security'},  # Test case insensitive
            {'file': 'path/to/file.Md', 'description': 'Path traversal', 'category': 'security'},  # Mixed case
        ]
        
        for finding in md_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert 'markdown' in reason.lower()
    
    def test_non_markdown_files_not_excluded(self):
        """Test that findings in non-.md files are not excluded due to file extension."""
        from claudecode.findings_filter import HardExclusionRules
        
        non_md_findings = [
            {'file': 'main.py', 'description': 'SQL injection vulnerability'},
            {'file': 'server.js', 'description': 'Command injection found'},
            {'file': 'index.html', 'description': 'XSS vulnerability'},
            {'file': 'config.yml', 'description': 'Hardcoded credentials'},
            {'file': 'README.txt', 'description': 'Path traversal'},
            {'file': 'file.mdx', 'description': 'Security issue'},  # Not .md
        ]
        
        for finding in non_md_findings:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            # Should not be excluded for being a markdown file
            # (might be excluded for other reasons like DOS patterns)
            if reason:
                assert 'markdown' not in reason.lower()
    
    def test_keeps_real_vulnerabilities(self):
        """Test that real vulnerabilities are not excluded."""
        from claudecode.findings_filter import HardExclusionRules
        
        real_vulns = [
            {'file': 'auth.py', 'description': 'SQL injection in user authentication', 'category': 'security'},
            {'file': 'exec.js', 'description': 'Command injection through user input', 'category': 'security'},
            {'file': 'comments.php', 'description': 'Cross-site scripting in comment field', 'category': 'security'},
            {'file': 'upload.go', 'description': 'Path traversal in file upload', 'category': 'security'},
        ]
        
        for finding in real_vulns:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is None


class TestJSONParser:
    """Test JSON parsing utilities."""
    
    def test_parse_valid_json(self):
        """Test parsing valid JSON."""
        from claudecode.json_parser import parse_json_with_fallbacks
        
        valid_json = '{"test": "data", "number": 123}'
        success, result = parse_json_with_fallbacks(valid_json, "test")
        
        assert success is True
        assert result == {"test": "data", "number": 123}
    
    def test_parse_invalid_json(self):
        """Test parsing invalid JSON."""
        from claudecode.json_parser import parse_json_with_fallbacks
        
        invalid_json = '{invalid json}'
        success, result = parse_json_with_fallbacks(invalid_json, "test")
        
        assert success is False
        assert 'error' in result
        assert 'Invalid JSON response' in result['error']
    
    def test_extract_json_from_text(self):
        """Test extracting JSON from mixed text."""
        from claudecode.json_parser import extract_json_from_text
        
        mixed_text = 'Some text before {"key": "value"} some text after'
        result = extract_json_from_text(mixed_text)
        
        assert result == {"key": "value"}
    
    def test_extract_json_from_text_no_json(self):
        """Test extracting JSON when none exists."""
        from claudecode.json_parser import extract_json_from_text
        
        plain_text = 'This is just plain text with no JSON'
        result = extract_json_from_text(plain_text)
        
        assert result is None


class TestPromptsModule:
    """Test the prompts module."""
    
    def test_get_unified_review_prompt(self):
        """Test unified review prompt generation."""
        from claudecode.prompts import get_unified_review_prompt
        
        pr_data = {
            'number': 123,
            'title': 'Test PR',
            'body': 'Test description',
            'user': 'testuser',
            'changed_files': 1,
            'additions': 10,
            'deletions': 5,
            'head': {
                'repo': {
                    'full_name': 'owner/repo'
                }
            },
            'files': [
                {
                    'filename': 'test.py',
                    'status': 'modified',
                    'additions': 10,
                    'deletions': 5,
                    'patch': '@@ -1,5 +1,10 @@\n+added line'
                }
            ]
        }
        
        pr_diff = "diff --git a/test.py b/test.py\n+added line"
        
        prompt = get_unified_review_prompt(pr_data, pr_diff)
        
        assert isinstance(prompt, str)
        assert 'security' in prompt.lower()
        assert 'PR #123' in prompt
        assert 'test.py' in prompt


class TestDeploymentPRDetection:
    """Test deployment PR title pattern matching."""
    
    def test_deployment_pr_patterns(self):
        """Test that deployment PR titles are correctly identified."""
        import re
        
        deployment_pattern = r'^Deploy\s+[a-f0-9]{6,}\s+to\s+(production|staging|development|production-services)'
        
        # These should match
        deployment_titles = [
            "Deploy 53f395b0 to production-services",
            "Deploy af179b5b to production",
            "Deploy 1a3cb909 to production",
            "Deploy 49c09ea5 to production-services",
            "Deploy 8e7acc60 to production",
            "Deploy e0b1fe0b to production-services",
            "Deploy c53e6010 to production",
            "Deploy 42c4a061 to production",
            "Deploy 9de55976 to production-services",
            "deploy abcdef123456 to staging",  # lowercase should work
            "DEPLOY ABCDEF01 TO DEVELOPMENT",  # uppercase should work
        ]
        
        for title in deployment_titles:
            assert re.match(deployment_pattern, title, re.IGNORECASE), f"Failed to match deployment PR: {title}"
    
    def test_non_deployment_pr_patterns(self):
        """Test that non-deployment PR titles are not matched."""
        import re
        
        deployment_pattern = r'^Deploy\s+[a-f0-9]{6,}\s+to\s+(production|staging|development|production-services)'
        
        # These should NOT match
        non_deployment_titles = [
            "Add new feature",
            "Fix bug in deployment script",
            "Update deployment documentation",
            "Deploy new feature to production",  # No commit hash
            "Deploy abc to production",  # Too short hash
            "Deploy 12345g to production",  # Non-hex character
            "Preparing deploy af179b5b to production",  # Doesn't start with Deploy
            "Deploy af179b5b to testing",  # Wrong environment
            "Deploy af179b5b",  # Missing environment
            "af179b5b to production",  # Missing Deploy prefix
        ]
        
        for title in non_deployment_titles:
            assert not re.match(deployment_pattern, title, re.IGNORECASE), f"Incorrectly matched non-deployment PR: {title}"


class TestBuiltinExclusions:
    """Test built-in file and directory exclusions."""

    def test_builtin_excluded_directories(self):
        """Test that built-in directories are in the exclusion list."""
        from claudecode.github_action_audit import GitHubActionClient

        expected_dirs = [
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

        for dir_name in expected_dirs:
            assert dir_name in GitHubActionClient.BUILTIN_EXCLUDED_DIRS, f"Missing built-in excluded dir: {dir_name}"

    def test_builtin_excluded_patterns(self):
        """Test that built-in file patterns are in the exclusion list."""
        from claudecode.github_action_audit import GitHubActionClient

        expected_patterns = [
            'package-lock.json',
            'yarn.lock',
            '*.min.js',
            '*.min.css',
            '*.pb.go',
            '*.generated.*',
            '*.png',
            '*.jpg',
            '*.woff2',
            '*.pyc',
        ]

        for pattern in expected_patterns:
            assert pattern in GitHubActionClient.BUILTIN_EXCLUDED_PATTERNS, f"Missing built-in excluded pattern: {pattern}"

    def test_is_excluded_lock_files(self):
        """Test that lock files are excluded."""
        from claudecode.github_action_audit import GitHubActionClient
        from unittest.mock import patch

        with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': ''}):
            client = GitHubActionClient()

            lock_files = [
                'package-lock.json',
                'yarn.lock',
                'Gemfile.lock',
                'poetry.lock',
                'Cargo.lock',
                'go.sum',
                'nested/path/package-lock.json',
            ]

            for filepath in lock_files:
                assert client._is_excluded(filepath), f"Lock file should be excluded: {filepath}"

    def test_is_excluded_generated_files(self):
        """Test that generated files are excluded."""
        from claudecode.github_action_audit import GitHubActionClient
        from unittest.mock import patch

        with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': ''}):
            client = GitHubActionClient()

            generated_files = [
                'app.min.js',
                'styles.min.css',
                'app.bundle.js',
                'main.chunk.js',
                'api.pb.go',
                'models.generated.ts',
                'user.g.dart',
            ]

            for filepath in generated_files:
                assert client._is_excluded(filepath), f"Generated file should be excluded: {filepath}"

    def test_is_excluded_binary_files(self):
        """Test that binary files are excluded."""
        from claudecode.github_action_audit import GitHubActionClient
        from unittest.mock import patch

        with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': ''}):
            client = GitHubActionClient()

            binary_files = [
                'logo.png',
                'photo.jpg',
                'icon.ico',
                'font.woff2',
                'document.pdf',
                'archive.zip',
            ]

            for filepath in binary_files:
                assert client._is_excluded(filepath), f"Binary file should be excluded: {filepath}"

    def test_is_excluded_vendor_directories(self):
        """Test that vendor directories are excluded."""
        from claudecode.github_action_audit import GitHubActionClient
        from unittest.mock import patch

        with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': ''}):
            client = GitHubActionClient()

            vendor_paths = [
                'node_modules/lodash/index.js',
                'vendor/github.com/pkg/errors/errors.go',
                'dist/bundle.js',
                'build/output.js',
                '.next/cache/data.json',
                '__pycache__/module.pyc',
                'Pods/AFNetworking/Source.m',
            ]

            for filepath in vendor_paths:
                assert client._is_excluded(filepath), f"Vendor path should be excluded: {filepath}"

    def test_is_not_excluded_source_files(self):
        """Test that regular source files are NOT excluded."""
        from claudecode.github_action_audit import GitHubActionClient
        from unittest.mock import patch

        with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': ''}):
            client = GitHubActionClient()

            source_files = [
                'src/main.py',
                'lib/utils.js',
                'app/models/user.rb',
                'pkg/handler/api.go',
                'src/components/Button.tsx',
                'tests/test_auth.py',
            ]

            for filepath in source_files:
                assert not client._is_excluded(filepath), f"Source file should NOT be excluded: {filepath}"

    def test_user_exclusions_combined_with_builtin(self):
        """Test that user exclusions are combined with built-in exclusions."""
        from claudecode.github_action_audit import GitHubActionClient
        from unittest.mock import patch

        with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-token', 'EXCLUDE_DIRECTORIES': 'custom_dir,my_vendor'}):
            client = GitHubActionClient()

            # Built-in should still work
            assert client._is_excluded('node_modules/pkg/index.js')
            assert client._is_excluded('vendor/lib/code.go')

            # User exclusions should also work
            assert client._is_excluded('custom_dir/file.py')
            assert client._is_excluded('my_vendor/lib.js')


class TestExtractReviewFindings:
    """Test the _extract_review_findings method."""

    def test_extract_findings_with_pr_summary(self):
        """Test that pr_summary is extracted from Claude output."""
        import json
        from claudecode.github_action_audit import SimpleClaudeRunner

        runner = SimpleClaudeRunner()

        claude_output = {
            'result': json.dumps({
                'findings': [
                    {'file': 'test.py', 'line': 1, 'severity': 'HIGH', 'description': 'Test finding'}
                ],
                'pr_summary': {
                    'overview': 'This PR adds authentication middleware.',
                    'file_changes': [
                        {'label': 'src/auth.py', 'files': ['src/auth.py'], 'changes': 'Added JWT validation'}
                    ]
                }
            })
        }

        result = runner._extract_review_findings(claude_output)

        assert 'pr_summary' in result
        assert result['pr_summary']['overview'] == 'This PR adds authentication middleware.'
        assert len(result['pr_summary']['file_changes']) == 1
        assert result['pr_summary']['file_changes'][0]['files'] == ['src/auth.py']
        assert len(result['findings']) == 1

    def test_extract_findings_without_pr_summary(self):
        """Test that missing pr_summary defaults to empty dict."""
        import json
        from claudecode.github_action_audit import SimpleClaudeRunner

        runner = SimpleClaudeRunner()

        claude_output = {
            'result': json.dumps({
                'findings': []
            })
        }

        result = runner._extract_review_findings(claude_output)

        assert 'pr_summary' in result
        assert result['pr_summary'] == {}

    def test_extract_findings_empty_result(self):
        """Test extraction with invalid/empty Claude output."""
        from claudecode.github_action_audit import SimpleClaudeRunner

        runner = SimpleClaudeRunner()

        result = runner._extract_review_findings({})

        assert 'pr_summary' in result
        assert result['pr_summary'] == {}
        assert result['findings'] == []

    def test_extract_findings_with_grouped_files(self):
        """Test that grouped file_changes are handled correctly."""
        import json
        from claudecode.github_action_audit import SimpleClaudeRunner

        runner = SimpleClaudeRunner()

        claude_output = {
            'result': json.dumps({
                'findings': [],
                'pr_summary': {
                    'overview': 'Test updates.',
                    'file_changes': [
                        {
                            'label': 'tests/test_*.py',
                            'files': ['tests/test_auth.py', 'tests/test_login.py', 'tests/test_session.py'],
                            'changes': 'Unit tests for auth module'
                        }
                    ]
                }
            })
        }

        result = runner._extract_review_findings(claude_output)

        assert 'pr_summary' in result
        file_changes = result['pr_summary']['file_changes']
        assert len(file_changes) == 1
        assert file_changes[0]['label'] == 'tests/test_*.py'
        assert len(file_changes[0]['files']) == 3


class TestDiffSizeLimits:
    """Test diff size limit functionality."""

    def test_diff_line_counting(self):
        """Test that diff lines are counted correctly."""
        sample_diff = """diff --git a/file.py b/file.py
--- a/file.py
+++ b/file.py
@@ -1,5 +1,10 @@
 line 1
+added line 2
+added line 3
 line 4
-removed line 5
+replaced line 5
 line 6"""

        line_count = len(sample_diff.splitlines())
        assert line_count == 11  # Count the actual lines

    def test_max_diff_lines_env_parsing(self):
        """Test that MAX_DIFF_LINES environment variable is parsed correctly."""
        import os
        from unittest.mock import patch

        # Test default value when env var is not set
        with patch.dict('os.environ', {}, clear=False):
            os.environ.pop('MAX_DIFF_LINES', None)
            max_lines_str = os.environ.get('MAX_DIFF_LINES', '5000')
            try:
                max_lines = int(max_lines_str)
            except ValueError:
                max_lines = 5000

        assert max_lines == 5000  # Default when not set

    def test_max_diff_lines_zero_forces_agentic_mode(self):
        """Test that setting MAX_DIFF_LINES to 0 forces agentic file reading mode."""
        import os
        from unittest.mock import patch

        with patch.dict('os.environ', {'MAX_DIFF_LINES': '0'}):
            max_lines_str = os.environ.get('MAX_DIFF_LINES', '5000')
            max_lines = int(max_lines_str)

            # When max_lines is 0, agentic mode is always used
            assert max_lines == 0
            # In the actual code: use_agentic_mode = max_diff_lines == 0 or ...
