#!/usr/bin/env python3
"""Unit tests for SimpleClaudeRunner."""

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

from claudecode.constants import DEFAULT_CLAUDE_MODEL
from claudecode.github_action_audit import SimpleClaudeRunner


class TestSimpleClaudeRunner:
    def test_init(self):
        runner = SimpleClaudeRunner(timeout_minutes=30)
        assert runner.timeout_seconds == 1800

        runner2 = SimpleClaudeRunner()
        assert runner2.timeout_seconds == 1200

    @patch("subprocess.run")
    def test_validate_claude_available_success(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="claude version 1.0.0", stderr="")

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            runner = SimpleClaudeRunner()
            success, error = runner.validate_claude_available()

        assert success is True
        assert error == ""

    @patch("subprocess.run")
    def test_validate_claude_available_no_api_key(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="claude version 1.0.0", stderr="")

        env = os.environ.copy()
        env.pop("ANTHROPIC_API_KEY", None)
        with patch.dict(os.environ, env, clear=True):
            runner = SimpleClaudeRunner()
            success, error = runner.validate_claude_available()

        assert success is False
        assert "ANTHROPIC_API_KEY" in error

    def test_run_prompt_missing_directory(self):
        runner = SimpleClaudeRunner()
        success, error, results = runner.run_prompt(Path("/non/existent/path"), "test prompt")

        assert success is False
        assert "Repository directory does not exist" in error
        assert results == {}

    @patch("subprocess.run")
    def test_run_prompt_success_with_nested_json(self, mock_run):
        wrapped = {"result": json.dumps({"findings": [{"file": "test.py", "line": 1}]})}
        mock_run.return_value = Mock(returncode=0, stdout=json.dumps(wrapped), stderr="")

        runner = SimpleClaudeRunner()
        with patch("pathlib.Path.exists", return_value=True):
            success, error, results = runner.run_prompt(Path("/tmp/test"), "test prompt")

        assert success is True
        assert error == ""
        assert results["findings"][0]["file"] == "test.py"

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "claude"
        assert "--output-format" in cmd
        assert "json" in cmd
        assert "--model" in cmd
        assert DEFAULT_CLAUDE_MODEL in cmd
        assert "--disallowed-tools" in cmd
        assert "Bash(ps:*)" in cmd

    @patch("subprocess.run")
    def test_run_prompt_adds_json_schema_when_provided(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout='{"ok": true}', stderr="")

        runner = SimpleClaudeRunner()
        with patch("pathlib.Path.exists", return_value=True):
            success, _, _ = runner.run_prompt(
                Path("/tmp/test"),
                "test prompt",
                json_schema={"type": "object", "properties": {"ok": {"type": "boolean"}}},
            )

        assert success is True
        cmd = mock_run.call_args[0][0]
        assert "--json-schema" in cmd

    @patch("subprocess.run")
    def test_run_prompt_retry_on_failure(self, mock_run):
        mock_run.side_effect = [
            Mock(returncode=1, stdout="", stderr="Temporary error"),
            Mock(returncode=0, stdout='{"findings": []}', stderr=""),
        ]

        runner = SimpleClaudeRunner()
        with patch("pathlib.Path.exists", return_value=True):
            success, error, _ = runner.run_prompt(Path("/tmp/test"), "test prompt")

        assert success is True
        assert error == ""
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    def test_run_prompt_json_parse_failure(self, mock_run):
        mock_run.side_effect = [
            Mock(returncode=0, stdout="Invalid JSON", stderr=""),
            Mock(returncode=0, stdout="Still invalid", stderr=""),
        ]

        runner = SimpleClaudeRunner()
        with patch("pathlib.Path.exists", return_value=True):
            success, error, _ = runner.run_prompt(Path("/tmp/test"), "test prompt")

        assert success is False
        assert "Failed to parse Claude output" in error
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    def test_run_prompt_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(["claude"], 1200)

        runner = SimpleClaudeRunner()
        with patch("pathlib.Path.exists", return_value=True):
            success, error, results = runner.run_prompt(Path("/tmp/test"), "test prompt")

        assert success is False
        assert "timed out" in error
        assert results == {}
