#!/usr/bin/env python3
"""
Unit tests for main function and full workflow.
"""

import pytest
import json
import os
from unittest.mock import Mock, patch
from pathlib import Path

from claudecode.github_action_audit import main


class TestMainFunction:
    """Test main function execution flow."""
    
    def test_main_missing_environment_vars(self, capsys):
        """Test main with missing environment variables."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 2  # EXIT_CONFIGURATION_ERROR
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'error' in output
            assert 'GITHUB_REPOSITORY' in output['error']
    
    def test_main_missing_pr_number(self, capsys):
        """Test main with missing PR number."""
        with patch.dict(os.environ, {'GITHUB_REPOSITORY': 'owner/repo'}, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 2  # EXIT_CONFIGURATION_ERROR
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'PR_NUMBER' in output['error']
    
    def test_main_invalid_pr_number(self, capsys):
        """Test main with invalid PR number."""
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': 'not-a-number'
        }, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 2  # EXIT_CONFIGURATION_ERROR
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'Invalid PR_NUMBER' in output['error']
    
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_github_client_init_failure(self, mock_client_class, capsys):
        """Test main when GitHub client initialization fails."""
        mock_client_class.side_effect = Exception("Token invalid")
        
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'invalid'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 2  # EXIT_CONFIGURATION_ERROR
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'Failed to initialize GitHub client' in output['error']
            assert 'Token invalid' in output['error']
    
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_claude_runner_init_failure(self, mock_client_class, mock_runner_class, capsys):
        """Test main when Claude runner initialization fails."""
        mock_client_class.return_value = Mock()
        mock_runner_class.side_effect = Exception("Runner error")
        
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 2  # EXIT_CONFIGURATION_ERROR
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'Failed to initialize Claude runner' in output['error']
    
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_filter_initialization(self, mock_client_class, mock_runner_class, 
                                       mock_full_filter_class):
        """Test filter initialization logic."""
        # Setup mocks
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (False, "Not available")
        mock_runner_class.return_value = mock_runner
        
        # Test with full filtering enabled
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token',
            'ENABLE_CLAUDE_FILTERING': 'true',
            'ANTHROPIC_API_KEY': 'test-api-key'
        }):
            with pytest.raises(SystemExit):
                main()
            
            # Should initialize full filter
            mock_full_filter_class.assert_called_once()
            call_kwargs = mock_full_filter_class.call_args[1]
            assert call_kwargs['use_hard_exclusions'] is True
            assert call_kwargs['use_claude_filtering'] is True
            assert call_kwargs['api_key'] == 'test-api-key'
        
        # Reset mocks
        mock_full_filter_class.reset_mock()
        
        # Test with filtering disabled
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token',
            'ENABLE_CLAUDE_FILTERING': 'false'
        }):
            with pytest.raises(SystemExit):
                main()
            
            # Should use FindingsFilter with hard exclusions only
            mock_full_filter_class.assert_called_once()
            call_kwargs = mock_full_filter_class.call_args[1]
            assert call_kwargs['use_hard_exclusions'] is True
            assert call_kwargs['use_claude_filtering'] is False
    
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_claude_not_available(self, mock_client_class, mock_runner_class, 
                                      mock_filter_class, capsys):
        """Test when Claude is not available."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (False, "Claude not installed")
        mock_runner_class.return_value = mock_runner
        
        mock_filter_class.return_value = Mock()
        
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1  # Claude not available, exit 1
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'Claude Code not available' in output['error']
            assert 'Claude not installed' in output['error']
    
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_pr_data_fetch_failure(self, mock_client_class, mock_runner_class,
                                        mock_filter_class, mock_prompt_func, capsys):
        """Test when PR data fetch fails."""
        mock_client = Mock()
        mock_client.get_pr_data.side_effect = Exception("API error")
        mock_client_class.return_value = mock_client
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner_class.return_value = mock_runner
        
        mock_filter_class.return_value = Mock()
        
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1  # API error, exit 1
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'Failed to fetch PR data' in output['error']
            assert 'API error' in output['error']
    
    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_successful_audit_no_findings(self, mock_client_class, mock_runner_class,
                                               mock_filter_class, mock_code_prompt_func,
                                               mock_security_prompt_func, mock_cwd, capsys):
        """Test successful audit with no findings."""
        # Setup mocks
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': 'Description'
        }
        mock_client.get_pr_diff.return_value = "diff content"
        mock_client_class.return_value = mock_client
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_code_review.side_effect = [
            (
                True,
                "",
                {
                    'findings': [],
                    'analysis_summary': {
                        'files_reviewed': 5,
                        'high_severity': 0,
                        'medium_severity': 0,
                        'low_severity': 0
                    }
                }
            ),
            (
                True,
                "",
                {
                    'findings': [],
                    'analysis_summary': {
                        'files_reviewed': 5,
                        'high_severity': 0,
                        'medium_severity': 0,
                        'low_severity': 0
                    }
                }
            )
        ]
        mock_runner_class.return_value = mock_runner
        
        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (
            True,
            {
                'filtered_findings': [],
                'excluded_findings': [],
                'analysis_summary': {}
            },
            Mock()  # filter_stats
        )
        mock_filter_class.return_value = mock_filter
        
        mock_code_prompt_func.return_value = "review prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp/repo')
        
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 0  # No findings, exit 0
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            
            assert output['pr_number'] == 123
            assert output['repo'] == 'owner/repo'
            assert len(output['findings']) == 0
            assert output['filtering_summary']['total_original_findings'] == 0
    
    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_successful_audit_with_findings(self, mock_client_class, mock_runner_class,
                                                mock_filter_class, mock_code_prompt_func,
                                                mock_security_prompt_func, mock_cwd, capsys):
        """Test successful audit with high severity findings."""
        # Setup mocks
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': 'Description'
        }
        mock_client.get_pr_diff.return_value = "diff content"
        mock_client._is_excluded.return_value = False  # Don't exclude any files in tests
        mock_client_class.return_value = mock_client
        
        findings = [
            {
                'file': 'test.py',
                'line': 10,
                'severity': 'HIGH',
                'description': 'SQL injection'
            },
            {
                'file': 'main.py',
                'line': 20,
                'severity': 'MEDIUM',
                'description': 'Weak crypto'
            }
        ]
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_code_review.side_effect = [
            (
                True,
                "",
                {
                    'findings': findings,
                    'analysis_summary': {
                        'files_reviewed': 2,
                        'high_severity': 1,
                        'medium_severity': 1,
                        'low_severity': 0
                    }
                }
            ),
            (
                True,
                "",
                {
                    'findings': [],
                    'analysis_summary': {
                        'files_reviewed': 2,
                        'high_severity': 0,
                        'medium_severity': 0,
                        'low_severity': 0
                    }
                }
            )
        ]
        mock_runner_class.return_value = mock_runner
        
        # Filter keeps only high severity
        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (
            True,
            {
                'filtered_findings': [findings[0]],
                'excluded_findings': [findings[1]],
                'analysis_summary': {
                    'total_findings': 2,
                    'kept_findings': 1,
                    'excluded_findings': 1
                }
            },
            Mock()  # filter_stats
        )
        mock_filter_class.return_value = mock_filter
        
        mock_code_prompt_func.return_value = "review prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp/repo')
        
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1  # High severity finding, exit 1
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            
            assert len(output['findings']) == 1
            assert output['findings'][0]['severity'] == 'HIGH'
            assert output['filtering_summary']['total_original_findings'] == 2
            assert output['filtering_summary']['excluded_findings'] == 1
            assert output['filtering_summary']['kept_findings'] == 1
    
    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_with_full_filter(self, mock_client_class, mock_runner_class,
                                   mock_code_prompt_func, mock_security_prompt_func,
                                   mock_cwd, capsys):
        """Test main with full FindingsFilter (LLM-based)."""
        # Setup mocks
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {
            'number': 123,
            'title': 'Test PR',
            'body': 'Description'
        }
        mock_client.get_pr_diff.return_value = "diff content"
        mock_client._is_excluded.return_value = False  # Don't exclude any files in tests
        mock_client_class.return_value = mock_client
        
        findings = [{'file': 'test.py', 'line': 10, 'severity': 'HIGH', 'description': 'Issue'}]
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_code_review.side_effect = [
            (True, "", {'findings': findings}),
            (True, "", {'findings': []})
        ]
        mock_runner_class.return_value = mock_runner
        
        mock_code_prompt_func.return_value = "prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp')
        
        # Mock FindingsFilter to return findings properly
        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (
            True,
            {
                'filtered_findings': findings,
                'excluded_findings': [],
                'analysis_summary': {
                    'total_findings': 1,
                    'kept_findings': 1,
                    'excluded_findings': 0
                }
            },
            Mock()  # filter_stats
        )
        
        with patch('claudecode.github_action_audit.FindingsFilter', return_value=mock_filter):
            with patch.dict(os.environ, {
                'GITHUB_REPOSITORY': 'owner/repo',
                'PR_NUMBER': '123',
                'GITHUB_TOKEN': 'test-token',
                'ENABLE_CLAUDE_FILTERING': 'false',  # Use simple filter
            }):
                with pytest.raises(SystemExit):
                    main()
                
                captured = capsys.readouterr()
                output = json.loads(captured.out)
                
                # Check that we got successful results
                assert 'findings' in output
                assert len(output['findings']) == 1
                assert output['findings'][0]['severity'] == 'HIGH'
    
    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_main_filter_failure_keeps_all_findings(self, mock_client_class, mock_runner_class,
                                                    mock_code_prompt_func, mock_security_prompt_func,
                                                    mock_cwd, capsys):
        """Test that filter failure keeps all findings with SimpleFindingsFilter."""
        # Setup mocks
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {'number': 123, 'title': 'Test', 'body': ''}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client._is_excluded.return_value = False  # Don't exclude any files in tests
        mock_client_class.return_value = mock_client
        
        findings = [
            {'file': 'a.py', 'line': 1, 'severity': 'HIGH', 'description': 'Issue 1'},
            {'file': 'b.py', 'line': 2, 'severity': 'HIGH', 'description': 'Issue 2'}
        ]
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_code_review.side_effect = [
            (True, "", {'findings': findings}),
            (True, "", {'findings': []})
        ]
        mock_runner_class.return_value = mock_runner
        
        mock_code_prompt_func.return_value = "prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp')
        
        # Mock FindingsFilter to keep all findings
        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (
            True,
            {
                'filtered_findings': findings,
                'excluded_findings': [],
                'analysis_summary': {
                    'total_findings': 2,
                    'kept_findings': 2,
                    'excluded_findings': 0
                }
            },
            Mock()  # filter_stats
        )
        
        with patch('claudecode.github_action_audit.FindingsFilter', return_value=mock_filter):
            with patch.dict(os.environ, {
                'GITHUB_REPOSITORY': 'owner/repo',
                'PR_NUMBER': '123',
                'GITHUB_TOKEN': 'test-token',
                'ENABLE_CLAUDE_FILTERING': 'false',  # Use simple filter
            }):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                assert exc_info.value.code == 1  # Has HIGH findings
                
                captured = capsys.readouterr()
                output = json.loads(captured.out)
                
                # All findings should be kept
                assert len(output['findings']) == 2
    
    def test_main_unexpected_error(self, capsys):
        """Test unexpected error handling."""
        with patch('claudecode.github_action_audit.GitHubActionClient') as mock_class:
            mock_class.side_effect = Exception("Unexpected error!")
            
            with patch.dict(os.environ, {
                'GITHUB_REPOSITORY': 'owner/repo',
                'PR_NUMBER': '123',
                'GITHUB_TOKEN': 'test-token'
            }):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                assert exc_info.value.code == 2  # EXIT_CONFIGURATION_ERROR
                
                captured = capsys.readouterr()
                output = json.loads(captured.out)
                assert 'Unexpected error' in output['error']


class TestAuditFailureModes:
    """Test various audit failure scenarios."""
    
    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_audit_failure(self, mock_client_class, mock_runner_class,
                          mock_filter_class, mock_code_prompt_func,
                          mock_security_prompt_func, mock_cwd, capsys):
        """Test when security audit fails."""
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {'number': 123}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client_class.return_value = mock_client
        
        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_code_review.return_value = (
            False,
            "Claude execution failed",
            {}
        )
        mock_runner_class.return_value = mock_runner
        
        mock_filter_class.return_value = Mock()
        mock_code_prompt_func.return_value = "prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp')
        
        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()
            
            assert exc_info.value.code == 1  # Audit failure, exit 1
            
            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'Code review failed' in output['error']
            assert 'Claude execution failed' in output['error']


class TestDualPassToggles:
    """Test dual-pass review toggle functionality."""

    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_only_general_review_when_security_disabled(self, mock_client_class, mock_runner_class,
                                                        mock_filter_class, mock_code_prompt_func,
                                                        mock_security_prompt_func, mock_cwd, capsys):
        """Test that only general review runs when security review is disabled."""
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {'number': 123, 'title': 'Test', 'body': ''}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client._is_excluded.return_value = False
        mock_client_class.return_value = mock_client

        findings = [{'file': 'test.py', 'line': 1, 'severity': 'MEDIUM', 'description': 'Issue'}]

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        # Only one call should be made (general review only)
        mock_runner.run_code_review.return_value = (True, "", {'findings': findings})
        mock_runner_class.return_value = mock_runner

        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (
            True,
            {'filtered_findings': findings, 'excluded_findings': [], 'analysis_summary': {}},
            Mock()
        )
        mock_filter_class.return_value = mock_filter

        mock_code_prompt_func.return_value = "general prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp')

        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token',
            'RUN_GENERAL_REVIEW': 'true',
            'RUN_SECURITY_REVIEW': 'false'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0  # No HIGH findings

            # Verify only one review call was made
            assert mock_runner.run_code_review.call_count == 1
            # Verify security prompt was NOT called
            mock_security_prompt_func.assert_not_called()
            # Verify general prompt WAS called
            mock_code_prompt_func.assert_called()

    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_only_security_review_when_general_disabled(self, mock_client_class, mock_runner_class,
                                                        mock_filter_class, mock_code_prompt_func,
                                                        mock_security_prompt_func, mock_cwd, capsys):
        """Test that only security review runs when general review is disabled."""
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {'number': 123, 'title': 'Test', 'body': ''}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client._is_excluded.return_value = False
        mock_client_class.return_value = mock_client

        findings = [{'file': 'test.py', 'line': 1, 'severity': 'MEDIUM', 'description': 'Security issue'}]

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        # Only one call should be made (security review only)
        mock_runner.run_code_review.return_value = (True, "", {'findings': findings})
        mock_runner_class.return_value = mock_runner

        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (
            True,
            {'filtered_findings': findings, 'excluded_findings': [], 'analysis_summary': {}},
            Mock()
        )
        mock_filter_class.return_value = mock_filter

        mock_code_prompt_func.return_value = "general prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp')

        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token',
            'RUN_GENERAL_REVIEW': 'false',
            'RUN_SECURITY_REVIEW': 'true'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0  # No HIGH findings

            # Verify only one review call was made
            assert mock_runner.run_code_review.call_count == 1
            # Verify general prompt was NOT called
            mock_code_prompt_func.assert_not_called()
            # Verify security prompt WAS called
            mock_security_prompt_func.assert_called()

    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_error_when_both_passes_disabled(self, mock_client_class, mock_runner_class,
                                             mock_filter_class, capsys):
        """Test that error is raised when both review passes are disabled."""
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {'number': 123, 'title': 'Test', 'body': ''}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client_class.return_value = mock_client

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner_class.return_value = mock_runner

        mock_filter_class.return_value = Mock()

        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token',
            'RUN_GENERAL_REVIEW': 'false',
            'RUN_SECURITY_REVIEW': 'false'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 2  # Configuration error

            captured = capsys.readouterr()
            output = json.loads(captured.out)
            assert 'error' in output
            assert 'RUN_GENERAL_REVIEW' in output['error']
            assert 'RUN_SECURITY_REVIEW' in output['error']


class TestReviewTypeMetadata:
    """Test that findings are tagged with correct review_type."""

    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_findings_have_correct_review_type(self, mock_client_class, mock_runner_class,
                                               mock_filter_class, mock_code_prompt_func,
                                               mock_security_prompt_func, mock_cwd, capsys):
        """Test that findings from each pass have correct review_type metadata."""
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {'number': 123, 'title': 'Test', 'body': ''}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client._is_excluded.return_value = False
        mock_client_class.return_value = mock_client

        general_findings = [
            {'file': 'test.py', 'line': 1, 'severity': 'MEDIUM', 'description': 'General issue'}
        ]
        security_findings = [
            {'file': 'auth.py', 'line': 5, 'severity': 'HIGH', 'description': 'Security issue'}
        ]

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_code_review.side_effect = [
            (True, "", {'findings': general_findings}),
            (True, "", {'findings': security_findings})
        ]
        mock_runner_class.return_value = mock_runner

        # Filter passes through all findings
        def filter_side_effect(findings, context):
            return (
                True,
                {'filtered_findings': findings, 'excluded_findings': [], 'analysis_summary': {}},
                Mock()
            )

        mock_filter = Mock()
        mock_filter.filter_findings.side_effect = filter_side_effect
        mock_filter_class.return_value = mock_filter

        mock_code_prompt_func.return_value = "general prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp')

        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token',
            'RUN_GENERAL_REVIEW': 'true',
            'RUN_SECURITY_REVIEW': 'true'
        }):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1  # Has HIGH finding

            captured = capsys.readouterr()
            output = json.loads(captured.out)

            # Check that we have findings from both passes
            assert len(output['findings']) == 2

            # Find the general finding and verify review_type
            general_finding = next(f for f in output['findings'] if f['file'] == 'test.py')
            assert general_finding['review_type'] == 'general'

            # Find the security finding and verify review_type
            security_finding = next(f for f in output['findings'] if f['file'] == 'auth.py')
            assert security_finding['review_type'] == 'security'

    @patch('pathlib.Path.cwd')
    @patch('claudecode.github_action_audit.get_security_review_prompt')
    @patch('claudecode.github_action_audit.get_code_review_prompt')
    @patch('claudecode.github_action_audit.FindingsFilter')
    @patch('claudecode.github_action_audit.SimpleClaudeRunner')
    @patch('claudecode.github_action_audit.GitHubActionClient')
    def test_review_type_not_overwritten_if_already_set(self, mock_client_class, mock_runner_class,
                                                        mock_filter_class, mock_code_prompt_func,
                                                        mock_security_prompt_func, mock_cwd, capsys):
        """Test that review_type is not overwritten if finding already has it."""
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {'number': 123, 'title': 'Test', 'body': ''}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client._is_excluded.return_value = False
        mock_client_class.return_value = mock_client

        # Finding already has review_type set (e.g., from a custom analyzer)
        general_findings = [
            {'file': 'test.py', 'line': 1, 'severity': 'MEDIUM', 'description': 'Issue', 'review_type': 'custom'}
        ]

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_code_review.side_effect = [
            (True, "", {'findings': general_findings}),
            (True, "", {'findings': []})
        ]
        mock_runner_class.return_value = mock_runner

        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (
            True,
            {'filtered_findings': general_findings, 'excluded_findings': [], 'analysis_summary': {}},
            Mock()
        )
        mock_filter_class.return_value = mock_filter

        mock_code_prompt_func.return_value = "general prompt"
        mock_security_prompt_func.return_value = "security prompt"
        mock_cwd.return_value = Path('/tmp')

        with patch.dict(os.environ, {
            'GITHUB_REPOSITORY': 'owner/repo',
            'PR_NUMBER': '123',
            'GITHUB_TOKEN': 'test-token'
        }):
            with pytest.raises(SystemExit):
                main()

            captured = capsys.readouterr()
            output = json.loads(captured.out)

            # The existing review_type should be preserved (setdefault doesn't overwrite)
            assert output['findings'][0]['review_type'] == 'custom'
