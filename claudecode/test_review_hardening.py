#!/usr/bin/env python3
"""
Tests for review hardening and performance fixes:
- claudecode-timeout wiring (CLAUDE_TIMEOUT env)
- reactions summary short-circuit (N+1 avoidance)
- windowed file content in filter prompts
- API validation model
- greedy diff packing (oversized files don't evict later files)
- parallel Claude API filtering preserves order
"""

import os
import json
from unittest.mock import Mock, patch

import pytest

from claudecode.github_action_audit import (
    GitHubActionClient,
    initialize_clients,
)
from claudecode.claude_api_client import ClaudeAPIClient
from claudecode.constants import SUBPROCESS_TIMEOUT
from claudecode.findings_filter import FindingsFilter


class TestClaudeTimeoutWiring:
    """The claudecode-timeout input (CLAUDE_TIMEOUT env) must be honored."""

    def _init_runner(self, env):
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token', **env}):
            _, runner = initialize_clients()
        return runner

    def test_timeout_env_applied(self):
        runner = self._init_runner({'CLAUDE_TIMEOUT': '45'})
        assert runner.timeout_seconds == 45 * 60

    def test_missing_timeout_uses_default(self):
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}, clear=False):
            os.environ.pop('CLAUDE_TIMEOUT', None)
            _, runner = initialize_clients()
        assert runner.timeout_seconds == SUBPROCESS_TIMEOUT

    def test_invalid_timeout_uses_default(self):
        runner = self._init_runner({'CLAUDE_TIMEOUT': 'nonsense'})
        assert runner.timeout_seconds == SUBPROCESS_TIMEOUT

    def test_non_positive_timeout_uses_default(self):
        runner = self._init_runner({'CLAUDE_TIMEOUT': '0'})
        assert runner.timeout_seconds == SUBPROCESS_TIMEOUT


class TestReactionsShortCircuit:
    """Reactions endpoint should only be hit when human reactions may exist."""

    def test_seed_only_summary_skips_fetch(self):
        comment = {'reactions': {'total_count': 2, '+1': 1, '-1': 1}}
        assert GitHubActionClient.has_potential_user_reactions(comment) is False

    def test_zero_reactions_skips_fetch(self):
        comment = {'reactions': {'total_count': 0, '+1': 0, '-1': 0}}
        assert GitHubActionClient.has_potential_user_reactions(comment) is False

    def test_extra_thumbs_up_fetches(self):
        comment = {'reactions': {'total_count': 3, '+1': 2, '-1': 1}}
        assert GitHubActionClient.has_potential_user_reactions(comment) is True

    def test_single_thumb_fetches(self):
        # Could be a human thumb on a comment whose seeding partially failed
        comment = {'reactions': {'total_count': 1, '+1': 1, '-1': 0}}
        assert GitHubActionClient.has_potential_user_reactions(comment) is True

    def test_non_thumb_reaction_fetches(self):
        # heart with one seed missing: total consistent count-wise but not thumbs
        comment = {'reactions': {'total_count': 2, '+1': 1, '-1': 0, 'heart': 1}}
        assert GitHubActionClient.has_potential_user_reactions(comment) is True

    def test_missing_summary_fetches(self):
        assert GitHubActionClient.has_potential_user_reactions({}) is True
        assert GitHubActionClient.has_potential_user_reactions({'reactions': 'weird'}) is True

    def test_null_counters_do_not_crash(self):
        # Defensive: null counter values must not raise, and must fetch
        comment = {'reactions': {'total_count': 1, '+1': None, '-1': 0}}
        assert GitHubActionClient.has_potential_user_reactions(comment) is True
        comment = {'reactions': {'total_count': None}}
        assert GitHubActionClient.has_potential_user_reactions(comment) is True


class TestFileWindowing:
    """Filter prompts should embed numbered, windowed file content."""

    def test_small_file_returned_whole_with_line_numbers(self):
        content = "alpha\nbeta\ngamma"
        result = ClaudeAPIClient._format_file_window(content, focus_line=2)
        assert "1\talpha" in result
        assert "2\tbeta" in result
        assert "3\tgamma" in result
        assert "omitted" not in result

    def test_large_file_windowed_around_focus_line(self):
        lines = [f"line{i}" for i in range(1, 2001)]
        content = "\n".join(lines)
        result = ClaudeAPIClient._format_file_window(content, focus_line=1000, context_lines=50)
        assert "line1000" in result
        assert "line949" not in result  # outside the window
        assert "line1051" not in result
        assert "earlier lines omitted" in result
        assert "later lines omitted" in result

    def test_large_file_without_focus_line_truncated_from_top(self):
        lines = [f"line{i}" for i in range(1, 2001)]
        content = "\n".join(lines)
        result = ClaudeAPIClient._format_file_window(content, focus_line=None, context_lines=50)
        assert "line1" in result
        assert "line100" in result
        assert "line101" not in result

    def test_hard_char_cap_shrinks_window_but_keeps_anchor(self):
        content = "\n".join([f"L{i:03d}" + "x" * 500 for i in range(1, 101)])
        result = ClaudeAPIClient._format_file_window(content, focus_line=None,
                                                     context_lines=200, max_chars=1000)
        assert len(result) <= 1000
        assert "L001" in result  # anchor (top of file) survives the cap
        assert "later lines omitted" in result

    def test_focus_line_survives_char_cap(self):
        # Long lines: a naive tail-truncation would cut the focus line away.
        content = "\n".join([f"L{i:03d} " + "x" * 400 for i in range(1, 301)])
        result = ClaudeAPIClient._format_file_window(content, focus_line=150,
                                                     context_lines=150, max_chars=2000)
        assert len(result) <= 2000
        assert "L150" in result  # the flagged line is always present
        assert "earlier lines omitted" in result
        assert "later lines omitted" in result

    def test_oversized_focus_line_included_truncated(self):
        content = "short\n" + "y" * 100000 + "\nshort"
        result = ClaudeAPIClient._format_file_window(content, focus_line=2,
                                                     context_lines=150, max_chars=1000)
        assert "yyy" in result
        assert "line truncated" in result
        assert len(result) < 5000

    def test_focus_line_beyond_eof_clamped_to_file_end(self):
        # A stale finding can reference a line past EOF; the window must show
        # the end of the file rather than an empty range.
        lines = [f"line{i}" for i in range(1, 401)]
        content = "\n".join(lines)
        result = ClaudeAPIClient._format_file_window(content, focus_line=1000,
                                                     context_lines=150, max_chars=40000)
        assert "line400" in result
        assert "line250" in result  # context window before the clamped focus
        assert "earlier lines omitted" in result


class TestApiValidationModel:
    """API validation must ping the model filtering actually uses, so a
    misconfigured/retired CLAUDE_MODEL is caught up front (the original bug:
    a hardcoded retired model silently disabled filtering for every run)."""

    def test_validation_uses_configured_model(self):
        with patch('claudecode.claude_api_client.Anthropic') as mock_anthropic:
            client = ClaudeAPIClient(model='claude-opus-5', api_key='test-key')
            client.validate_api_access()
        call_kwargs = mock_anthropic.return_value.messages.create.call_args[1]
        assert call_kwargs['model'] == 'claude-opus-5'


class TestGreedyDiffPacking:
    """An oversized file must not evict smaller files that still fit."""

    @patch('requests.get')
    def test_oversized_file_skipped_but_smaller_files_packed(self, mock_get):
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 1, 'title': 'PR', 'body': '', 'user': {'login': 'u'},
            'created_at': '2024-01-01T00:00:00Z', 'updated_at': '2024-01-01T00:00:00Z',
            'state': 'open',
            'head': {'ref': 'f', 'sha': 'a', 'repo': {'full_name': 'o/r'}},
            'base': {'ref': 'main', 'sha': 'b'},
            'additions': 10, 'deletions': 0, 'changed_files': 3,
        }

        files_page = Mock()
        files_page.json.return_value = [
            {'filename': 'small_a.py', 'status': 'modified', 'additions': 1,
             'deletions': 0, 'changes': 1, 'patch': '+a'},
            {'filename': 'huge_generated.py', 'status': 'modified', 'additions': 1,
             'deletions': 0, 'changes': 1, 'patch': 'x' * 10000},
            {'filename': 'small_b.py', 'status': 'modified', 'additions': 1,
             'deletions': 0, 'changes': 1, 'patch': '+b'},
        ]

        mock_get.side_effect = [pr_response, files_page]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('o/r', 1, max_diff_chars=500)

        included = result['diff_stats']['included_file_list']
        assert 'small_a.py' in included
        assert 'huge_generated.py' not in included
        # The file after the oversized one must still be packed
        assert 'small_b.py' in included
        assert result['is_truncated'] is True

    @patch('requests.get')
    def test_pagination_continues_past_skipped_file_when_budget_remains(self, mock_get):
        """An oversized file on page 1 must not stop page 2 from being packed."""
        pr_response = Mock()
        pr_response.json.return_value = {
            'number': 1, 'title': 'PR', 'body': '', 'user': {'login': 'u'},
            'created_at': '2024-01-01T00:00:00Z', 'updated_at': '2024-01-01T00:00:00Z',
            'state': 'open',
            'head': {'ref': 'f', 'sha': 'a', 'repo': {'full_name': 'o/r'}},
            'base': {'ref': 'main', 'sha': 'b'},
            'additions': 10, 'deletions': 0, 'changed_files': 101,
        }

        def small_file(name):
            return {'filename': name, 'status': 'modified', 'additions': 1,
                    'deletions': 0, 'changes': 1, 'patch': '+x'}

        # Page 1: 100 files (full page -> pagination continues), the second
        # one oversized. Page 2: one more small file that must still be packed.
        page1_files = [small_file(f'file{i:03d}.py') for i in range(100)]
        page1_files[1] = {**small_file('huge.py'), 'patch': 'x' * 50000}
        page1 = Mock()
        page1.json.return_value = page1_files
        page2 = Mock()
        page2.json.return_value = [small_file('zz_last.py')]

        mock_get.side_effect = [pr_response, page1, page2]

        with patch.dict(os.environ, {'GITHUB_TOKEN': 'test-token'}):
            client = GitHubActionClient()
            result = client.get_pr_data('o/r', 1, max_diff_chars=20000)

        included = result['diff_stats']['included_file_list']
        assert 'huge.py' not in included
        assert 'file099.py' in included
        assert 'zz_last.py' in included  # page 2 was still fetched and packed
        assert result['is_truncated'] is True
        assert mock_get.call_count == 3


class TestParallelClaudeFiltering:
    """Parallel per-finding validation must preserve finding-result pairing."""

    def test_results_stay_paired_with_findings(self):
        findings = [
            {'file': f'f{i}.py', 'line': i, 'severity': 'HIGH', 'category': 'correctness',
             'title': f'finding {i}', 'description': 'd', 'impact': 'i',
             'recommendation': 'r', 'confidence': 0.9}
            for i in range(6)
        ]

        def fake_analyze(finding, pr_context, custom_instructions):
            # Keep only even-numbered findings
            idx = int(finding['file'][1])
            keep = idx % 2 == 0
            return True, {
                'confidence_score': 10 if keep else 1,
                'keep_finding': keep,
                'exclusion_reason': None if keep else 'test exclusion',
                'justification': f'for {finding["file"]}',
            }, ""

        filt = FindingsFilter(use_hard_exclusions=False, use_claude_filtering=False)
        # Manually enable Claude filtering with a mocked client
        filt.use_claude_filtering = True
        filt.claude_client = Mock()
        filt.claude_client.analyze_single_finding.side_effect = fake_analyze

        success, results, stats = filt.filter_findings(findings, {})

        assert success is True
        kept_files = {f['file'] for f in results['filtered_findings']}
        assert kept_files == {'f0.py', 'f2.py', 'f4.py'}
        # Each kept finding carries the justification computed for *itself*
        for f in results['filtered_findings']:
            assert f['_filter_metadata']['justification'] == f'for {f["file"]}'
        assert stats.claude_excluded == 3
        assert stats.kept_findings == 3
