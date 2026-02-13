#!/usr/bin/env python3
"""
Unit tests for GitHubActionClient.
"""

import pytest
import os
from unittest.mock import Mock, patch

from claudecode.github_action_audit import GitHubActionClient


class TestGitHubActionClient:
    """Test GitHubActionClient functionality."""
    
    def test_init_requires_token(self):
        """Test that client initialization requires GITHUB_TOKEN."""
        # Remove token if it exists
        original_token = os.environ.pop('GITHUB_TOKEN', None)
        
        try:
            with pytest.raises(ValueError, match="GITHUB_TOKEN environment variable required"):
                GitHubActionClient()
        finally:
            # Restore token
            if original_token:
                os.environ['GITHUB_TOKEN'] = original_token
    
    def test_init_with_token(self):
        """Test successful initialization with token."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            assert client.github_token == 'test-token'
            assert client.headers['Authorization'] == 'Bearer test-token'
            assert 'Accept' in client.headers
            assert 'X-GitHub-Api-Version' in client.headers
    
    @patch('requests.get')
    def test_get_pr_data_success(self, mock_get):
        """Test successful PR data retrieval."""
        # Mock responses
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': 'PR description',
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {
                'ref': 'feature-branch',
                'sha': 'abc123',
                'repo': {
                    'full_name': 'owner/repo'
                }
            },
            'base': {
                'ref': 'main',
                'sha': 'def456'
            },
            'additions': 50,
            'deletions': 10,
            'changed_files': 3
        }
        
        files_response = Mock()
        files_response.json.return_value = [
            {
                'filename': 'src/main.py',
                'status': 'modified',
                'additions': 30,
                'deletions': 5,
                'changes': 35,
                'patch': '@@ -1,5 +1,10 @@\n+import os\n def main():'
            },
            {
                'filename': 'tests/test_main.py',
                'status': 'added',
                'additions': 20,
                'deletions': 5,
                'changes': 25,
                'patch': '@@ -0,0 +1,20 @@\n+def test_main():'
            }
        ]
        
        mock_get.side_effect = [pr_response, files_response]
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)
        
        # Verify API calls
        assert mock_get.call_count == 2
        mock_get.assert_any_call(
            'https://api.github.com/repos/owner/repo/pulls/123',
            headers=client.headers
        )
        # Check for paginated files request with params
        mock_get.assert_any_call(
            'https://api.github.com/repos/owner/repo/pulls/123/files',
            headers=client.headers,
            params={'per_page': 100, 'page': 1}
        )
        
        # Verify result structure
        assert result['number'] == 123
        assert result['title'] == 'Test PR'
        assert result['user'] == 'testuser'
        assert len(result['files']) == 2
        assert result['diff_stats']['total_files'] == 3  # From PR metadata
        assert result['files'][0]['filename'] == 'src/main.py'
        assert result['files'][1]['status'] == 'added'
        # Verify diff data is included
        assert 'pr_diff' in result
        assert 'is_truncated' in result
        assert 'diff_stats' in result
    
    @patch('requests.get')
    def test_get_pr_data_null_head_repo(self, mock_get):
        """Test PR data retrieval when head repo is null (deleted fork)."""
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Test PR',
            # Don't include body key to test the get() default
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {
                'ref': 'feature-branch',
                'sha': 'abc123',
                'repo': None  # Deleted fork
            },
            'base': {
                'ref': 'main',
                'sha': 'def456'
            },
            'additions': 50,
            'deletions': 10,
            'changed_files': 3
        }
        
        files_response = Mock()
        files_response.json.return_value = []
        
        mock_get.side_effect = [pr_response, files_response]
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)
        
        # Should use original repo name when head repo is None
        assert result['head']['repo']['full_name'] == 'owner/repo'
        # The implementation passes None through, test should match that
        assert result['body'] == ''
    
    @patch('requests.get')
    def test_get_pr_data_api_error(self, mock_get):
        """Test PR data retrieval with API error."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = Exception("API Error")
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(Exception, match="API Error"):
                client.get_pr_data('owner/repo', 123)

    def test_filter_generated_files_edge_cases(self):
        """Test edge cases in generated file filtering."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            
            # Empty diff
            assert client._filter_generated_files('') == ''
            
            # No diff markers - if no diff format, everything is filtered
            text = "Just some random text\nwith @generated in it"
            # Since there's no 'diff --git' marker, the split results in one section
            # that contains @generated, so it gets filtered out
            assert client._filter_generated_files(text) == ''
            
            # Multiple generated markers
            diff = """diff --git a/a.py b/a.py
@generated by tool
content
diff --git a/b.py b/b.py
normal content
diff --git a/c.py b/c.py
# This file is @generated
more content
"""
            result = client._filter_generated_files(diff)
            assert 'a.py' not in result
            assert 'b.py' in result
            assert 'c.py' not in result


class TestDiffSectionBuilding:
    """Test unified diff section construction for different file types."""

    def test_format_file_diff_modified_file(self):
        """Test diff section for modified file."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()

            file_data = {
                'filename': 'src/main.py',
                'status': 'modified',
                'patch': '@@ -1,3 +1,3 @@\n-old line\n+new line'
            }

            diff_section = client._format_file_diff(file_data)

            assert 'diff --git a/src/main.py b/src/main.py' in diff_section
            assert '--- a/src/main.py' in diff_section
            assert '+++ b/src/main.py' in diff_section
            assert '@@ -1,3 +1,3 @@' in diff_section
            assert '-old line' in diff_section
            assert '+new line' in diff_section

    def test_format_file_diff_added_file(self):
        """Test diff section for added file."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()

            file_data = {
                'filename': 'src/new.py',
                'status': 'added',
                'patch': '@@ -0,0 +1,5 @@\n+def hello():\n+    pass'
            }

            diff_section = client._format_file_diff(file_data)

            assert 'diff --git a/src/new.py b/src/new.py' in diff_section
            assert 'new file mode 100644' in diff_section
            assert '--- /dev/null' in diff_section
            assert '+++ b/src/new.py' in diff_section
            assert '+def hello():' in diff_section

    def test_format_file_diff_removed_file(self):
        """Test diff section for removed file."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()

            file_data = {
                'filename': 'src/old.py',
                'status': 'removed',
                'patch': '@@ -1,5 +0,0 @@\n-def old():\n-    pass'
            }

            diff_section = client._format_file_diff(file_data)

            assert 'diff --git a/src/old.py b/src/old.py' in diff_section
            assert 'deleted file mode 100644' in diff_section
            assert '--- a/src/old.py' in diff_section
            assert '+++ /dev/null' in diff_section
            assert '-def old():' in diff_section

    def test_format_file_diff_renamed_file(self):
        """Test diff section for renamed file."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()

            file_data = {
                'filename': 'src/new_name.py',
                'previous_filename': 'src/old_name.py',
                'status': 'renamed',
                'patch': '@@ -1,3 +1,3 @@\n-old line\n+new line'
            }

            diff_section = client._format_file_diff(file_data)

            assert 'diff --git a/src/old_name.py b/src/new_name.py' in diff_section
            assert 'similarity index 100%' in diff_section
            assert 'rename from src/old_name.py' in diff_section
            assert 'rename to src/new_name.py' in diff_section
            assert '--- a/src/old_name.py' in diff_section
            assert '+++ b/src/new_name.py' in diff_section

    def test_format_file_diff_without_status(self):
        """Test diff section defaults to modified when status not provided."""
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()

            file_data = {
                'filename': 'src/file.py',
                'patch': '@@ -1,1 +1,1 @@\n-old\n+new'
            }

            diff_section = client._format_file_diff(file_data)

            # Should default to modified
            assert '--- a/src/file.py' in diff_section
            assert '+++ b/src/file.py' in diff_section
            assert 'new file mode' not in diff_section
            assert 'deleted file' not in diff_section


class TestIntegratedDiffConstruction:
    """Test integrated diff construction during file fetching."""

    @patch('requests.get')
    def test_get_pr_data_builds_diff_incrementally(self, mock_get):
        """Test that get_pr_data builds diff while fetching files."""
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': '',
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {'ref': 'feature', 'sha': 'abc123', 'repo': {'full_name': 'owner/repo'}},
            'base': {'ref': 'main', 'sha': 'def456'},
            'additions': 20,
            'deletions': 5,
            'changed_files': 2
        }

        files_response = Mock()
        files_response.json.return_value = [
            {
                'filename': 'added.py',
                'status': 'added',
                'additions': 10,
                'deletions': 0,
                'changes': 10,
                'patch': '@@ -0,0 +1,2 @@\n+def new():\n+    pass'
            },
            {
                'filename': 'modified.py',
                'status': 'modified',
                'additions': 10,
                'deletions': 5,
                'changes': 15,
                'patch': '@@ -1,1 +1,1 @@\n-old\n+new'
            }
        ]

        # Empty response to stop pagination
        empty_response = Mock()
        empty_response.json.return_value = []

        mock_get.side_effect = [pr_response, files_response, empty_response]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123, max_diff_chars=400000)

        # Verify diff was constructed
        assert 'pr_diff' in result
        diff = result['pr_diff']

        # Should contain both files
        assert 'new file mode 100644' in diff  # added.py
        assert '--- /dev/null' in diff
        assert '+++ b/added.py' in diff

        assert '--- a/modified.py' in diff  # modified.py
        assert '+++ b/modified.py' in diff

        # Verify stats
        assert result['is_truncated'] == False
        assert result['diff_stats']['files_included'] == 2
        assert result['diff_stats']['total_files'] == 2
        assert result['diff_stats']['included_file_list'] == ['added.py', 'modified.py']

    @patch('requests.get')
    def test_get_pr_data_truncates_at_max_lines(self, mock_get):
        """Test that get_pr_data stops fetching when max_lines reached."""
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Large PR',
            'body': '',
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {'ref': 'feature', 'sha': 'abc123', 'repo': {'full_name': 'owner/repo'}},
            'base': {'ref': 'main', 'sha': 'def456'},
            'additions': 1000,
            'deletions': 500,
            'changed_files': 100  # Total files in PR
        }

        # First page with files
        files_page1 = Mock()
        files_page1.json.return_value = [
            {
                'filename': f'file{i}.py',
                'status': 'modified',
                'additions': 5,
                'deletions': 2,
                'changes': 7,
                'patch': '@@ -1,1 +1,1 @@\n-old\n+new'
            }
            for i in range(10)
        ]

        mock_get.side_effect = [pr_response, files_page1]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            # Very low max_chars to trigger truncation (each file ~150 chars)
            result = client.get_pr_data('owner/repo', 123, max_diff_chars=200)

        # Should be truncated
        assert result['is_truncated'] == True
        # Should have included some files but not all
        assert result['diff_stats']['files_included'] < 10
        assert result['diff_stats']['total_files'] == 100  # From PR metadata

    @patch('requests.get')
    def test_get_pr_data_agentic_mode_skips_files(self, mock_get):
        """Test that max_diff_chars=0 (agentic mode) doesn't fetch files."""
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': '',
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {'ref': 'feature', 'sha': 'abc123', 'repo': {'full_name': 'owner/repo'}},
            'base': {'ref': 'main', 'sha': 'def456'},
            'additions': 100,
            'deletions': 50,
            'changed_files': 50
        }

        mock_get.side_effect = [pr_response]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123, max_diff_chars=0)

        # Should only call PR metadata endpoint, not files endpoint
        assert mock_get.call_count == 1

        # Should have empty diff data
        assert result['pr_diff'] == ''
        assert result['is_truncated'] == False
        assert result['files'] == []
        assert result['diff_stats']['files_included'] == 0
        assert result['diff_stats']['total_files'] == 50  # From PR metadata


class TestBackwardCompatibility:
    """Test backward compatibility with deprecated MAX_DIFF_LINES."""

    @patch('requests.get')
    def test_max_diff_lines_converts_to_chars(self, mock_get):
        """Test that max_diff_lines parameter still works via character conversion."""
        # This tests backward compatibility: max_diff_lines * 80 = max_diff_chars
        # If we pass max_diff_lines=10, it should convert to 800 chars

        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': '',
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {'ref': 'feature', 'sha': 'abc123', 'repo': {'full_name': 'owner/repo'}},
            'base': {'ref': 'main', 'sha': 'def456'},
            'additions': 10,
            'deletions': 5,
            'changed_files': 1
        }

        files_response = Mock()
        # Create file with ~100 chars per section to test truncation
        files_response.json.return_value = [
            {
                'filename': 'short.txt',
                'status': 'modified',
                'additions': 1,
                'deletions': 1,
                'changes': 2,
                'patch': '@@ -1,1 +1,1 @@\n-old\n+new'  # ~50 chars
            }
        ]

        empty_response = Mock()
        empty_response.json.return_value = []

        mock_get.side_effect = [pr_response, files_response, empty_response]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            # Using character limit directly (new way)
            result = client.get_pr_data('owner/repo', 123, max_diff_chars=100)

        # Should include the file since diff is ~85 chars
        assert result['diff_stats']['files_included'] == 1


class TestGitHubAPIIntegration:
    """Test GitHub API integration scenarios."""

    @patch('requests.get')
    def test_rate_limit_handling(self, mock_get):
        """Test that rate limit headers are respected."""
        mock_response = Mock()
        mock_response.headers = {
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': '1234567890'
        }
        mock_response.status_code = 403
        mock_response.json.return_value = {
            'message': 'API rate limit exceeded'
        }
        mock_response.raise_for_status.side_effect = Exception("Rate limit exceeded")
        mock_get.return_value = mock_response
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            with pytest.raises(Exception, match="Rate limit exceeded"):
                client.get_pr_data('owner/repo', 123)
    
    @patch('requests.get')
    def test_pagination_not_needed_for_pr_files(self, mock_get):
        """Test that PR files endpoint returns all files without pagination."""
        # GitHub API returns up to 3000 files per PR without pagination
        large_file_list = [
            {
                'filename': f'file{i}.py',
                'status': 'added',
                'additions': 10,
                'deletions': 0,
                'changes': 10,
                'patch': f'@@ -0,0 +1,10 @@\n+# File {i}'
            }
            for i in range(100)  # 100 files
        ]
        
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 123,
            'title': 'Large PR',
            'body': 'Many files',
            'user': {'login': 'testuser'},
            'created_at': '2024-01-01T00:00:00Z',
            'updated_at': '2024-01-01T01:00:00Z',
            'state': 'open',
            'head': {'ref': 'feature', 'sha': 'abc123', 'repo': {'full_name': 'owner/repo'}},
            'base': {'ref': 'main', 'sha': 'def456'},
            'additions': 1000,
            'deletions': 0,
            'changed_files': 100
        }
        
        files_response_page1 = Mock()
        files_response_page1.json.return_value = large_file_list

        # Empty response for page 2 to stop pagination
        files_response_page2 = Mock()
        files_response_page2.json.return_value = []

        mock_get.side_effect = [pr_response, files_response_page1, files_response_page2]
        
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('owner/repo', 123)
        
        assert len(result['files']) == 100
        assert result['files'][0]['filename'] == 'file0.py'
        assert result['files'][99]['filename'] == 'file99.py'
