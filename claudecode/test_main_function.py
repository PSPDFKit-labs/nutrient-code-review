#!/usr/bin/env python3
"""Unit tests for main function and multi-phase workflow."""

import json
import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from claudecode.github_action_audit import main


def _mock_multiphase_success(mock_runner, findings=None):
    findings = findings or []
    mock_runner.run_prompt.side_effect = [
        (True, "", {"skip_review": False, "reason": "", "risk_level": "medium"}),
        (True, "", {"claude_md_files": [], "change_summary": "", "hotspots": [], "priority_files": []}),
        (True, "", {"findings": findings}),
        (True, "", {"findings": []}),
        (True, "", {"findings": []}),
        (
            True,
            "",
            {
                "validated_findings": [
                    {"finding_index": idx, "keep": True, "confidence": 0.95, "reason": "valid"}
                    for idx in range(len(findings))
                ]
            },
        ),
    ]


class TestMainFunction:
    def test_main_missing_environment_vars(self, capsys):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 2
            output = json.loads(capsys.readouterr().out)
            assert "GITHUB_REPOSITORY" in output["error"]

    @patch("claudecode.github_action_audit.SimpleClaudeRunner")
    @patch("claudecode.github_action_audit.GitHubActionClient")
    def test_main_pr_data_fetch_failure(self, mock_client_class, mock_runner_class, capsys):
        mock_client = Mock()
        mock_client.get_pr_data.side_effect = Exception("API error")
        mock_client_class.return_value = mock_client

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner_class.return_value = mock_runner

        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo", "PR_NUMBER": "123", "GITHUB_TOKEN": "test-token"}):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1
            output = json.loads(capsys.readouterr().out)
            assert "Failed to fetch PR data" in output["error"]

    @patch("pathlib.Path.cwd")
    @patch("claudecode.github_action_audit.FindingsFilter")
    @patch("claudecode.github_action_audit.SimpleClaudeRunner")
    @patch("claudecode.github_action_audit.GitHubActionClient")
    def test_main_successful_audit_no_findings(self, mock_client_class, mock_runner_class, mock_filter_class, mock_cwd, capsys):
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {"number": 123, "title": "Test PR", "body": "Description"}
        mock_client.get_pr_diff.return_value = "diff content"
        mock_client.is_excluded.return_value = False
        mock_client_class.return_value = mock_client

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        _mock_multiphase_success(mock_runner, findings=[])
        mock_runner_class.return_value = mock_runner

        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (True, {"filtered_findings": [], "excluded_findings": [], "analysis_summary": {}}, Mock())
        mock_filter_class.return_value = mock_filter

        mock_cwd.return_value = Path("/tmp/repo")

        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo", "PR_NUMBER": "123", "GITHUB_TOKEN": "test-token"}):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0
            output = json.loads(capsys.readouterr().out)
            assert output["pr_number"] == 123
            assert output["repo"] == "owner/repo"
            assert output["findings"] == []

    @patch("pathlib.Path.cwd")
    @patch("claudecode.github_action_audit.FindingsFilter")
    @patch("claudecode.github_action_audit.SimpleClaudeRunner")
    @patch("claudecode.github_action_audit.GitHubActionClient")
    def test_main_successful_audit_with_high_finding(self, mock_client_class, mock_runner_class, mock_filter_class, mock_cwd, capsys):
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {"number": 123, "title": "Test PR", "body": "Description"}
        mock_client.get_pr_diff.return_value = "diff content"
        mock_client.is_excluded.return_value = False
        mock_client_class.return_value = mock_client

        findings = [
            {
                "file": "test.py",
                "line": 10,
                "severity": "HIGH",
                "category": "security",
                "description": "SQL injection",
            }
        ]

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        _mock_multiphase_success(mock_runner, findings=findings)
        mock_runner_class.return_value = mock_runner

        mock_filter = Mock()
        mock_filter.filter_findings.return_value = (True, {"filtered_findings": findings, "excluded_findings": [], "analysis_summary": {}}, Mock())
        mock_filter_class.return_value = mock_filter

        mock_cwd.return_value = Path("/tmp/repo")

        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo", "PR_NUMBER": "123", "GITHUB_TOKEN": "test-token"}):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1
            output = json.loads(capsys.readouterr().out)
            assert len(output["findings"]) == 1
            assert output["findings"][0]["review_type"] == "security"


class TestAuditFailureModes:
    @patch("pathlib.Path.cwd")
    @patch("claudecode.github_action_audit.FindingsFilter")
    @patch("claudecode.github_action_audit.SimpleClaudeRunner")
    @patch("claudecode.github_action_audit.GitHubActionClient")
    def test_audit_failure(self, mock_client_class, mock_runner_class, mock_filter_class, mock_cwd, capsys):
        mock_client = Mock()
        mock_client.get_pr_data.return_value = {"number": 123}
        mock_client.get_pr_diff.return_value = "diff"
        mock_client_class.return_value = mock_client

        mock_runner = Mock()
        mock_runner.validate_claude_available.return_value = (True, "")
        mock_runner.run_prompt.return_value = (False, "Claude execution failed", {})
        mock_runner_class.return_value = mock_runner

        mock_filter_class.return_value = Mock()
        mock_cwd.return_value = Path("/tmp")

        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "owner/repo", "PR_NUMBER": "123", "GITHUB_TOKEN": "test-token"}):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1
            output = json.loads(capsys.readouterr().out)
            assert "Code review failed" in output["error"]
            assert "Claude execution failed" in output["error"]
