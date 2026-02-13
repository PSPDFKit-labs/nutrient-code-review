#!/usr/bin/env python3
"""Pytest tests for github_action_audit module components."""


class TestImports:
    def test_main_module_import(self):
        from claudecode import github_action_audit

        assert hasattr(github_action_audit, "GitHubActionClient")
        assert hasattr(github_action_audit, "SimpleClaudeRunner")
        assert hasattr(github_action_audit, "main")

    def test_component_imports(self):
        from claudecode.json_parser import extract_json_from_text, parse_json_with_fallbacks
        from claudecode.prompts import build_triage_prompt

        assert callable(parse_json_with_fallbacks)
        assert callable(extract_json_from_text)
        assert callable(build_triage_prompt)


class TestHardExclusionRules:
    def test_dos_patterns(self):
        from claudecode.findings_filter import HardExclusionRules

        for finding in [
            {"description": "Potential denial of service vulnerability", "category": "security"},
            {"description": "DOS attack through resource exhaustion", "category": "security"},
            {"description": "Infinite loop causing resource exhaustion", "category": "security"},
        ]:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert "dos" in reason.lower()

    def test_markdown_file_exclusion(self):
        from claudecode.findings_filter import HardExclusionRules

        for finding in [
            {"file": "README.md", "description": "SQL injection vulnerability", "category": "security"},
            {"file": "docs/security.md", "description": "Command injection found", "category": "security"},
        ]:
            reason = HardExclusionRules.get_exclusion_reason(finding)
            assert reason is not None
            assert "markdown" in reason.lower()


class TestJSONParser:
    def test_parse_valid_json(self):
        from claudecode.json_parser import parse_json_with_fallbacks

        success, result = parse_json_with_fallbacks('{"test": "data", "number": 123}', "test")
        assert success is True
        assert result == {"test": "data", "number": 123}

    def test_extract_json_from_text(self):
        from claudecode.json_parser import extract_json_from_text

        assert extract_json_from_text('Some text before {"key": "value"} some text after') == {"key": "value"}


class TestBuiltinExclusions:
    def test_builtin_excluded_directories(self):
        from claudecode.github_action_audit import GitHubActionClient

        for dir_name in ["node_modules", "vendor", "dist", "build", ".next", "__pycache__", ".gradle", "Pods", "DerivedData"]:
            assert dir_name in GitHubActionClient.BUILTIN_EXCLUDED_DIRS

    def test_is_excluded_source_files(self):
        from unittest.mock import patch

        from claudecode.github_action_audit import GitHubActionClient

        with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token", "EXCLUDE_DIRECTORIES": ""}):
            client = GitHubActionClient()

            assert not client.is_excluded("src/main.py")
            assert not client.is_excluded("tests/test_auth.py")

    def test_user_exclusions_combined_with_builtin(self):
        from unittest.mock import patch

        from claudecode.github_action_audit import GitHubActionClient

        with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token", "EXCLUDE_DIRECTORIES": "custom_dir,my_vendor"}):
            client = GitHubActionClient()

            assert client.is_excluded("node_modules/pkg/index.js")
            assert client.is_excluded("custom_dir/file.py")


class TestDiffSizeLimits:
    def test_diff_line_counting(self):
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

        assert len(sample_diff.splitlines()) == 11
