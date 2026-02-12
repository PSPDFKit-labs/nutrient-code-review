"""Unit tests for the format_pr_comments module."""

import pytest
from claudecode.format_pr_comments import (
    format_pr_comments_for_prompt,
    is_bot_comment,
    _truncate_replies,
    _parse_bot_comment,
    _format_timestamp,
    BOT_COMMENT_MARKER,
)


def _make_bot_comment(
    comment_id: int,
    file_path: str = "app.py",
    line: int = 42,
    title: str = "SQL Injection",
    severity: str = "HIGH",
    category: str = "security",
    impact: str = "Attacker can access database",
    recommendation: str = "Use parameterized queries",
    created_at: str = "2024-01-15T10:00:00Z",
):
    """Create a bot comment for testing."""
    body = f"""{BOT_COMMENT_MARKER} {title}**

**Severity:** {severity}
**Category:** {category}

**Impact:** {impact}

**Recommendation:** {recommendation}
"""
    return {
        'id': comment_id,
        'body': body,
        'path': file_path,
        'line': line,
        'created_at': created_at,
        'user': {'login': 'github-actions[bot]', 'type': 'Bot'},
        'in_reply_to_id': None,
    }


def _make_user_reply(
    comment_id: int,
    in_reply_to_id: int,
    body: str,
    username: str = "testuser",
    created_at: str = "2024-01-15T11:00:00Z",
):
    """Create a user reply comment for testing."""
    return {
        'id': comment_id,
        'body': body,
        'path': 'app.py',
        'line': 42,
        'created_at': created_at,
        'user': {'login': username, 'type': 'User'},
        'in_reply_to_id': in_reply_to_id,
    }


def _make_thread(bot_comment, replies=None, reactions=None):
    """Create a thread structure for testing."""
    return {
        'bot_comment': bot_comment,
        'replies': replies or [],
        'reactions': reactions or {},
    }


class TestFormatPrCommentsForPrompt:
    """Tests for format_pr_comments_for_prompt function."""

    def test_no_threads(self):
        """Test with no threads."""
        result = format_pr_comments_for_prompt([])
        assert result == ""

    def test_single_thread_no_replies(self):
        """Test with single bot comment, no replies."""
        bot_comment = _make_bot_comment(1)
        threads = [_make_thread(bot_comment)]

        result = format_pr_comments_for_prompt(threads)

        assert "PREVIOUS REVIEW CONTEXT" in result
        assert "SQL Injection" in result
        assert "HIGH" in result
        assert "security" in result
        assert "app.py:42" in result

    def test_thread_with_user_replies(self):
        """Test with bot comment and user replies."""
        bot_comment = _make_bot_comment(1)
        user_reply = _make_user_reply(
            2, 1,
            "This is a false positive - we sanitize input at the controller level.",
            username="alice"
        )
        threads = [_make_thread(bot_comment, replies=[user_reply])]

        result = format_pr_comments_for_prompt(threads)

        assert "PREVIOUS REVIEW CONTEXT" in result
        assert "SQL Injection" in result
        assert "alice" in result
        assert "false positive" in result
        assert "sanitize input" in result

    def test_multiple_threads(self):
        """Test with multiple bot findings and replies."""
        bot_comment1 = _make_bot_comment(
            1, "auth.py", 10, "Hardcoded Password", "HIGH", "security"
        )
        bot_comment2 = _make_bot_comment(
            2, "api.py", 50, "N+1 Query", "MEDIUM", "performance",
            created_at="2024-01-15T10:30:00Z"
        )
        reply1 = _make_user_reply(3, 1, "Fixed in commit abc123")
        reply2 = _make_user_reply(4, 2, "This is by design for now")

        threads = [
            _make_thread(bot_comment1, replies=[reply1]),
            _make_thread(bot_comment2, replies=[reply2]),
        ]

        result = format_pr_comments_for_prompt(threads)

        assert "THREAD 1" in result
        assert "THREAD 2" in result
        assert "Hardcoded Password" in result
        assert "N+1 Query" in result
        assert "Fixed in commit" in result
        assert "by design" in result

    def test_reactions_included(self):
        """Test that reactions are included when provided."""
        bot_comment = _make_bot_comment(1)
        threads = [_make_thread(bot_comment, reactions={'-1': 2})]

        result = format_pr_comments_for_prompt(threads)

        # Should show 2 thumbs down
        assert "👎 2" in result

    def test_all_reaction_types(self):
        """Test that all GitHub reaction types are converted to emojis."""
        bot_comment = _make_bot_comment(1)
        reactions = {
            '+1': 3,
            '-1': 1,
            'laugh': 2,
            'confused': 1,
            'heart': 4,
            'hooray': 2,
            'rocket': 1,
            'eyes': 3,
        }
        threads = [_make_thread(bot_comment, reactions=reactions)]

        result = format_pr_comments_for_prompt(threads)

        # All reactions should be converted to emojis
        assert "👍 3" in result
        assert "👎 1" in result
        assert "😄 2" in result
        assert "😕 1" in result
        assert "❤️ 4" in result
        assert "🎉 2" in result
        assert "🚀 1" in result
        assert "👀 3" in result

    def test_truncate_long_replies(self):
        """Test that very long reply threads are truncated."""
        bot_comment = _make_bot_comment(1)

        # Create 10 replies (exceeds MAX_REPLIES_PER_THREAD of 5)
        replies = [
            _make_user_reply(
                i + 10, 1, f"Reply {i}",
                created_at=f"2024-01-15T{10+i:02d}:00:00Z"
            )
            for i in range(10)
        ]

        threads = [_make_thread(bot_comment, replies=replies)]
        result = format_pr_comments_for_prompt(threads)

        # Should mention truncation
        assert "earlier replies omitted" in result
        # Should have the later replies (5-9)
        assert "Reply 9" in result
        assert "Reply 8" in result


class TestIsBotComment:
    """Tests for is_bot_comment function."""

    def test_with_marker_and_bot(self):
        """Test bot comment true case."""
        bot_comment = {'body': f'{BOT_COMMENT_MARKER} Test**', 'user': {'type': 'Bot'}}
        assert is_bot_comment(bot_comment) is True

    def test_without_marker_user_type(self):
        """Test non-bot comment detection."""
        user_comment = {'body': 'Regular comment', 'user': {'type': 'User'}}
        assert is_bot_comment(user_comment) is False

    def test_by_user_type(self):
        """Test bot comment detection but not our bot."""
        bot_comment = {'body': 'Some automated message', 'user': {'type': 'Bot'}}
        assert is_bot_comment(bot_comment) is False

    def test_with_marker(self):
        """Test comment with marker but not from a bot."""
        bot_comment = {'body': f'{BOT_COMMENT_MARKER} Test**', 'user': {'type': 'User'}}
        assert is_bot_comment(bot_comment) is False


class TestTruncateReplies:
    """Tests for _truncate_replies function."""

    def test_no_truncation_needed(self):
        """Test when replies are under the limit."""
        bot_comment = _make_bot_comment(1)
        replies = [_make_user_reply(i, 1, f"Reply {i}") for i in range(3)]
        threads = [_make_thread(bot_comment, replies=replies)]

        result = _truncate_replies(threads)

        assert len(result[0]['replies']) == 3
        assert 'truncated_replies' not in result[0]

    def test_truncation_applied(self):
        """Test when replies exceed the limit."""
        bot_comment = _make_bot_comment(1)
        replies = [
            _make_user_reply(i, 1, f"Reply {i}", created_at=f"2024-01-15T{10+i:02d}:00:00Z")
            for i in range(10)
        ]
        threads = [_make_thread(bot_comment, replies=replies)]

        result = _truncate_replies(threads)

        assert len(result[0]['replies']) == 5
        assert result[0]['truncated_replies'] == 5


class TestParseBotComment:
    """Tests for _parse_bot_comment function."""

    def test_parse_full_comment(self):
        """Test parsing structured data from bot comment."""
        body = f"""{BOT_COMMENT_MARKER} SQL Injection Vulnerability**

**Severity:** HIGH
**Category:** security

**Impact:** Attacker can execute arbitrary SQL queries

**Recommendation:** Use parameterized queries
"""
        result = _parse_bot_comment(body)

        assert result['title'] == "SQL Injection Vulnerability"
        assert result['severity'] == "HIGH"
        assert result['category'] == "security"
        assert "arbitrary SQL" in result['impact']
        assert "parameterized" in result['recommendation']


class TestFormatTimestamp:
    """Tests for _format_timestamp function."""

    def test_valid_timestamp(self):
        """Test formatting valid ISO timestamp."""
        result = _format_timestamp("2024-01-15T10:30:00Z")
        assert "2024-01-15" in result
        assert "10:30" in result

    def test_invalid_timestamp(self):
        """Test handling invalid timestamp."""
        result = _format_timestamp("invalid")
        assert result == "invalid"


class TestPromptsIntegration:
    """Test prompts.py integration with review context."""

    def test_unified_prompt_with_review_context(self):
        """Test that review context is included in unified prompt."""
        from claudecode.prompts import get_unified_review_prompt

        pr_data = {
            "number": 123,
            "title": "Test PR",
            "body": "Test description",
            "user": "testuser",
            "changed_files": 1,
            "additions": 10,
            "deletions": 5,
            "head": {"repo": {"full_name": "owner/repo"}},
            "files": [{"filename": "app.py"}],
        }

        review_context = """
═══════════════════════════════════════════════════════════════
PREVIOUS REVIEW CONTEXT
═══════════════════════════════════════════════════════════════
THREAD 1 - app.py:42
Bot Finding (2024-01-15): SQL Injection
User Reply: This is a false positive
"""

        prompt = get_unified_review_prompt(
            pr_data,
            pr_diff="diff --git a/app.py b/app.py",
            review_context=review_context
        )

        assert "PREVIOUS REVIEW CONTEXT" in prompt
        assert "SQL Injection" in prompt
        assert "false positive" in prompt

    def test_unified_prompt_without_review_context(self):
        """Test that prompt works without review context."""
        from claudecode.prompts import get_unified_review_prompt

        pr_data = {
            "number": 123,
            "title": "Test PR",
            "body": "Test description",
            "user": "testuser",
            "changed_files": 1,
            "additions": 10,
            "deletions": 5,
            "head": {"repo": {"full_name": "owner/repo"}},
            "files": [{"filename": "app.py"}],
        }

        prompt = get_unified_review_prompt(
            pr_data,
            pr_diff="diff --git a/app.py b/app.py",
            review_context=None
        )

        assert "PREVIOUS REVIEW CONTEXT" not in prompt
        assert "CONTEXT:" in prompt

    def test_unified_prompt_includes_pr_description(self):
        """Test that PR description is included in prompt."""
        from claudecode.prompts import get_unified_review_prompt

        pr_data = {
            "number": 123,
            "title": "Test PR",
            "body": "This PR adds important security fixes for the auth module.",
            "user": "testuser",
            "changed_files": 1,
            "additions": 10,
            "deletions": 5,
            "head": {"repo": {"full_name": "owner/repo"}},
            "files": [{"filename": "auth.py"}],
        }

        prompt = get_unified_review_prompt(pr_data, pr_diff="diff")

        assert "PR Description:" in prompt
        assert "security fixes for the auth module" in prompt