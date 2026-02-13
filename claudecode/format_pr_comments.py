"""Format PR comments for review context in prompts."""

from typing import Dict, Any, List
from datetime import datetime

from claudecode.logger import get_logger

logger = get_logger(__name__)

# Maximum characters for review context to avoid prompt bloat
MAX_CONTEXT_CHARS = 15000
# Maximum replies to include per thread
MAX_REPLIES_PER_THREAD = 5
# Bot comment marker pattern
BOT_COMMENT_MARKER = "🤖 **Code Review Finding:"

# GitHub reaction content to emoji mapping
REACTION_EMOJI_MAP = {
    '+1': '👍',
    '-1': '👎',
    'laugh': '😄',
    'confused': '😕',
    'heart': '❤️',
    'hooray': '🎉',
    'rocket': '🚀',
    'eyes': '👀',
}


def is_bot_comment(comment: Dict[str, Any]) -> bool:
    """Check if a comment was posted by this bot.

    Args:
        comment: Comment dictionary from GitHub API.

    Returns:
        True if this is a bot review comment.
    """
    body = comment.get('body', '')
    user = comment.get('user', {})

    return BOT_COMMENT_MARKER in body and user.get('type') == 'Bot'


def format_pr_comments_for_prompt(
    bot_comment_threads: List[Dict[str, Any]],
) -> str:
    """Format bot comment threads as review context for the prompt.

    Takes pre-built thread structures and formats them for Claude to consider
    during re-review.

    Args:
        bot_comment_threads: List of thread dicts, each containing:
            - 'bot_comment': The original bot finding comment
            - 'replies': List of user reply comments
            - 'reactions': Dict of reaction counts (e.g., {'+1': 2, '-1': 1})

    Returns:
        Formatted string with previous review threads, or empty string if none.
    """
    if not bot_comment_threads:
        logger.info("No bot comment threads to format")
        return ""

    # Apply reply truncation
    threads = _truncate_replies(bot_comment_threads)

    logger.info(f"Formatting {len(threads)} bot comment thread(s)")
    return _format_threads_for_prompt(threads)


def _truncate_replies(threads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Truncate long reply threads to keep prompt size manageable.

    Args:
        threads: List of thread dictionaries.

    Returns:
        Threads with replies truncated to MAX_REPLIES_PER_THREAD.
    """
    result = []
    for thread in threads:
        thread_copy = dict(thread)
        replies = thread_copy.get('replies', [])

        if len(replies) > MAX_REPLIES_PER_THREAD:
            truncated_count = len(replies) - MAX_REPLIES_PER_THREAD
            thread_copy['replies'] = replies[-MAX_REPLIES_PER_THREAD:]
            thread_copy['truncated_replies'] = truncated_count

        result.append(thread_copy)

    return result


def _parse_bot_comment(body: str) -> Dict[str, str]:
    """Parse structured data from bot comment body.

    Args:
        body: The comment body text.

    Returns:
        Dictionary with extracted fields (title, severity, category, etc.)
    """
    result = {
        'title': '',
        'severity': '',
        'category': '',
        'impact': '',
        'recommendation': ''
    }

    # Extract title from "🤖 **Code Review Finding: {title}**"
    if BOT_COMMENT_MARKER in body:
        start = body.find(BOT_COMMENT_MARKER) + len(BOT_COMMENT_MARKER)
        end = body.find('**', start)
        if end > start:
            result['title'] = body[start:end].strip()

    # Extract severity
    if '**Severity:**' in body:
        start = body.find('**Severity:**') + len('**Severity:**')
        end = body.find('\n', start)
        if end > start:
            result['severity'] = body[start:end].strip()

    # Extract category
    if '**Category:**' in body:
        start = body.find('**Category:**') + len('**Category:**')
        end = body.find('\n', start)
        if end > start:
            result['category'] = body[start:end].strip()

    # Extract impact
    if '**Impact:**' in body:
        start = body.find('**Impact:**') + len('**Impact:**')
        end = body.find('\n\n', start)
        if end == -1:
            end = body.find('**Recommendation:**', start)
        if end > start:
            result['impact'] = body[start:end].strip()

    # Extract recommendation
    if '**Recommendation:**' in body:
        start = body.find('**Recommendation:**') + len('**Recommendation:**')
        end = body.find('\n\n', start)
        if end == -1:
            end = body.find('```', start)  # Code suggestion block
        if end == -1:
            end = len(body)
        if end > start:
            result['recommendation'] = body[start:end].strip()

    return result


def _format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp to readable format.

    Args:
        iso_timestamp: ISO 8601 timestamp string.

    Returns:
        Human-readable timestamp.
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M UTC')
    except (ValueError, AttributeError):
        return iso_timestamp


def _format_threads_for_prompt(threads: List[Dict[str, Any]]) -> str:
    """Format threads as readable text for Claude's prompt.

    Args:
        threads: List of thread dictionaries.

    Returns:
        Formatted string for inclusion in prompt.
    """
    if not threads:
        return ""

    lines = [
        "",
        "═" * 65,
        "PREVIOUS REVIEW CONTEXT",
        "═" * 65,
        "",
        "The following findings were raised in previous reviews of this PR.",
        "Review user responses to determine if issues should be re-raised.",
        ""
    ]

    for i, thread in enumerate(threads, 1):
        bot_comment = thread['bot_comment']
        replies = thread['replies']
        reactions = thread.get('reactions', {})

        # Get file and line info
        file_path = bot_comment.get('path', 'unknown')
        line = bot_comment.get('line') or bot_comment.get('original_line', '?')

        # Parse bot comment structure
        parsed = _parse_bot_comment(bot_comment.get('body', ''))

        # Format thread header
        lines.append(f"THREAD {i} - {file_path}:{line}")
        lines.append("─" * 65)

        # Bot finding
        timestamp = _format_timestamp(bot_comment.get('created_at', ''))
        lines.append(f"Bot Finding ({timestamp})")

        if parsed['severity']:
            lines.append(f"  Severity: {parsed['severity']}")
        if parsed['category']:
            lines.append(f"  Category: {parsed['category']}")
        if parsed['title']:
            lines.append(f"  Title: {parsed['title']}")
        if parsed['impact']:
            lines.append(f"  Impact: {parsed['impact'][:500]}...")  # Truncate long impacts
        if parsed['recommendation']:
            lines.append(f"  Recommendation: {parsed['recommendation'][:500]}...")

        # Add user reactions (excluding bot's own reactions)
        if reactions:
            reaction_parts = []
            for reaction, count in reactions.items():
                if count > 0:
                    emoji = REACTION_EMOJI_MAP.get(reaction, reaction)
                    reaction_parts.append(f"{emoji} {count}")

            if reaction_parts:
                lines.append(f"  User Reactions: {', '.join(reaction_parts)}")

        lines.append("")

        # Truncation notice
        if thread.get('truncated_replies'):
            lines.append(f"  ({thread['truncated_replies']} earlier replies omitted)")
            lines.append("")

        # User replies
        for reply in replies:
            user = reply.get('user', {}).get('login', 'unknown')
            reply_timestamp = _format_timestamp(reply.get('created_at', ''))
            reply_body = reply.get('body', '').strip()

            # Truncate very long replies
            if len(reply_body) > 1000:
                reply_body = reply_body[:1000] + "... (truncated)"

            lines.append(f"User Reply ({user}, {reply_timestamp}):")
            # Indent reply text
            for reply_line in reply_body.split('\n'):
                lines.append(f"  {reply_line}")
            lines.append("")

        lines.append("─" * 65)
        lines.append("")

    # Add instructions for re-review
    lines.extend([
        "═" * 65,
        "INSTRUCTIONS FOR RE-REVIEW",
        "═" * 65,
        "",
        "When reviewing this PR with the above context:",
        "",
        "1. CHECK IF ISSUES WERE ADDRESSED: Compare previous findings against",
        "   the current diff. If code was changed to fix the issue, do NOT",
        "   re-raise it.",
        "",
        "2. EVALUATE USER RESPONSES: Read user replies carefully. Valid",
        "   dismissals include:",
        "   - Demonstrating the issue is a false positive with evidence",
        "   - Showing existing mitigations the bot missed",
        "   - Providing strong technical justification",
        "",
        "   Invalid dismissals include:",
        "   - \"We'll fix this later\" (without code change)",
        "   - Misunderstanding the vulnerability/issue",
        "   - Ignoring the issue without explanation",
        "",
        "3. CONSIDER USER REACTIONS: Reactions provide additional signal:",
        "   - 👎 (thumbs down) suggests users found the finding unhelpful",
        "   - 👍 (thumbs up) suggests users found the finding valuable",
        "   - High 👎 count with no reply may indicate obvious false positive",
        "   - Use reactions as one input, but prioritize reply content",
        "",
        "4. RE-RAISE WHEN APPROPRIATE: If an issue was invalidly dismissed",
        "   or remains unaddressed, re-raise it with:",
        "   - Reference to the previous discussion",
        "   - Response to the user's dismissal reasoning",
        "   - Updated title: \"[Issue Title] (previously raised)\"",
        "",
        "5. DO NOT REPEAT RESOLVED ISSUES: If code was changed to address",
        "   a finding, do not mention it unless the fix is incomplete.",
        "",
        "═" * 65,
        ""
    ])

    result = '\n'.join(lines)

    # Truncate if too long
    if len(result) > MAX_CONTEXT_CHARS:
        logger.warning(f"Review context truncated from {len(result)} to {MAX_CONTEXT_CHARS} chars")
        result = result[:MAX_CONTEXT_CHARS] + "\n\n(Review context truncated due to length)\n"

    return result