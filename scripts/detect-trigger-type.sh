#!/bin/bash
#
# Detects which trigger fired a ClaudeCode review run.
# Extracted from action.yml's "Detect trigger type" step so the comment-matching
# regexes can be exercised by a standalone test suite.
#
# Expected environment variables:
#   - EVENT_NAME: The GitHub event name (pull_request, issue_comment, etc.)
#   - EVENT_ACTION: The GitHub event action (opened, synchronize, ready_for_review, etc.)
#   - COMMENT_BODY: The PR comment body (for issue_comment events)
#   - APP_SLUG: GitHub App slug used for bot mention detection
#
# Outputs to GITHUB_OUTPUT:
#   - trigger_type: one of open, ready_for_review, commit, review_request, label,
#     slash_command, mention, unknown
#

set -euo pipefail

TRIGGER_TYPE="unknown"

if [ "$EVENT_NAME" == "pull_request" ]; then
  case "$EVENT_ACTION" in
    opened|reopened)
      TRIGGER_TYPE="open"
      ;;
    ready_for_review)
      TRIGGER_TYPE="ready_for_review"
      ;;
    synchronize)
      TRIGGER_TYPE="commit"
      ;;
    review_requested)
      TRIGGER_TYPE="review_request"
      ;;
    labeled)
      TRIGGER_TYPE="label"
      ;;
  esac
elif [ "$EVENT_NAME" == "issue_comment" ]; then
  # Check if comment uses review command trigger (the whole comment must be
  # just "review" or "review please" - not merely start with the word, so
  # ordinary conversation like "review the design doc" doesn't trigger a run)
  if echo "$COMMENT_BODY" | grep -qiE '^[[:space:]]*review([[:space:]]+please)?[[:space:]]*$'; then
    TRIGGER_TYPE="slash_command"
    echo "Detected review command in comment"
  fi

  # Check if comment mentions this specific bot
  # Escape special regex characters in bot login to prevent regex injection
  if [ "$TRIGGER_TYPE" == "unknown" ] && [ -n "${APP_SLUG:-}" ]; then
    ESCAPED_BOT=$(printf '%s\n' "$APP_SLUG" | sed 's/[]\/$*.^[]/\\&/g')
    if echo "$COMMENT_BODY" | grep -qE "@${ESCAPED_BOT}\\b"; then
      TRIGGER_TYPE="mention"
      echo "Detected mention of @$APP_SLUG in comment"
    fi
  fi
fi

echo "trigger_type=$TRIGGER_TYPE" >> "$GITHUB_OUTPUT"
echo "Detected trigger type: $TRIGGER_TYPE"
