#!/bin/bash
#
# Determines whether ClaudeCode should run based on trigger type and configuration.
# This script encapsulates the complex logic for deciding when to run code reviews.
#
# Expected environment variables:
#   - GITHUB_EVENT_NAME: The GitHub event name (pull_request, issue_comment, etc.)
#   - PR_NUMBER: The pull request number
#   - GITHUB_SHA: The commit SHA being reviewed
#   - TRIGGER_TYPE: The detected trigger type (open, ready_for_review, commit, review_request, mention, slash_command, label)
#   - TRIGGER_ON_OPEN: Whether to run on PR open (true/false)
#   - TRIGGER_ON_COMMIT: Whether to run on new commits (true/false)
#   - TRIGGER_ON_REVIEW_REQUEST: Whether to run on review requests (true/false)
#   - TRIGGER_ON_MENTION: Whether to run on bot mentions (true/false)
#   - TRIGGER_ON_REVIEW_COMMAND: Whether to run on review command comments (true/false)
#   - TRIGGER_ON_READY_FOR_REVIEW: Whether to run when draft PR is marked ready (true/false)
#   - RUN_EVERY_COMMIT: Legacy flag for running on commits (true/false)
#   - SKIP_DRAFT_PRS: Whether to skip draft PRs (true/false)
#   - IS_DRAFT: Whether the PR is a draft (true/false)
#   - REQUIRE_LABEL: Required label name (optional)
#   - PR_LABELS: JSON array of PR labels
#   - IS_PR: Whether issue comment is on a PR (true/false, for issue_comment events)
#   - COMMENT_TRIGGER_PERMISSION: Minimum commenter permission for mention/slash_command
#     triggers (admin, maintain, write, triage, read, any; defaults to write)
#   - COMMENTER: Login of the commenter (for log messages)
#   - COMMENTER_PERMISSION: The commenter's repository permission (empty or none if unknown)
#
# Outputs to GITHUB_OUTPUT:
#   - enable_claudecode: "true" or "false"
#   - silence_claudecode_comments: "true" or "false" (reserved for future use)
#

set -euo pipefail

# Check if ClaudeCode should be enabled
ENABLE_CLAUDECODE="true"
SILENCE_CLAUDECODE_COMMENTS="false"

# Only run on pull requests or issue comments on PRs
if [ "$GITHUB_EVENT_NAME" != "pull_request" ] && [ "$GITHUB_EVENT_NAME" != "issue_comment" ]; then
  echo "Event type $GITHUB_EVENT_NAME is not supported, skipping"
  ENABLE_CLAUDECODE="false"
fi

# For issue_comment events, check if it's on a PR
if [ "$ENABLE_CLAUDECODE" == "true" ] && [ "$GITHUB_EVENT_NAME" == "issue_comment" ]; then
  if [ "${IS_PR:-false}" != "true" ]; then
    echo "Issue comment is not on a PR, skipping"
    ENABLE_CLAUDECODE="false"
  fi
fi

# 1. Check trigger-specific enablement
if [ "$ENABLE_CLAUDECODE" == "true" ]; then
  case "$TRIGGER_TYPE" in
    open)
      if [ "${TRIGGER_ON_OPEN:-true}" != "true" ]; then
        echo "Trigger 'open' is disabled via trigger-on-open input"
        ENABLE_CLAUDECODE="false"
      fi
      ;;
    ready_for_review)
      if [ "${TRIGGER_ON_READY_FOR_REVIEW:-true}" != "true" ]; then
        echo "Trigger 'ready_for_review' is disabled via trigger-on-ready-for-review input"
        ENABLE_CLAUDECODE="false"
      fi
      ;;
    commit)
      # Check both new and legacy input names (run-every-commit is alias for trigger-on-commit)
      if [ "${TRIGGER_ON_COMMIT:-false}" != "true" ] && [ "${RUN_EVERY_COMMIT:-false}" != "true" ]; then
        echo "Trigger 'commit' is disabled via trigger-on-commit/run-every-commit input"
        ENABLE_CLAUDECODE="false"
      fi
      ;;
    review_request)
      if [ "${TRIGGER_ON_REVIEW_REQUEST:-true}" != "true" ]; then
        echo "Trigger 'review_request' is disabled via trigger-on-review-request input"
        ENABLE_CLAUDECODE="false"
      fi
      ;;
    mention)
      if [ "${TRIGGER_ON_MENTION:-true}" != "true" ]; then
        echo "Trigger 'mention' is disabled via trigger-on-mention input"
        ENABLE_CLAUDECODE="false"
      fi
      ;;
    slash_command)
      if [ "${TRIGGER_ON_REVIEW_COMMAND:-true}" != "true" ]; then
        echo "Trigger 'slash_command' is disabled via trigger-on-review-command input"
        ENABLE_CLAUDECODE="false"
      fi
      ;;
    label)
      # Label trigger uses the existing require-label logic below
      ;;
    *)
      echo "Unknown trigger type: $TRIGGER_TYPE"
      ENABLE_CLAUDECODE="false"
      ;;
  esac
fi

# 1b. Comment-triggered reviews require a minimum repository permission, so users
# without access cannot start reviews (and spend API credits) on any PR.
permission_rank() {
  case "$1" in
    admin) echo 5 ;;
    maintain) echo 4 ;;
    write) echo 3 ;;
    triage) echo 2 ;;
    read) echo 1 ;;
    *) echo 0 ;;
  esac
}

if [ "$ENABLE_CLAUDECODE" == "true" ]; then
  case "$TRIGGER_TYPE" in
    mention|slash_command)
      REQUIRED_PERMISSION="${COMMENT_TRIGGER_PERMISSION:-write}"
      ACTUAL_PERMISSION="${COMMENTER_PERMISSION:-none}"
      if [ "$REQUIRED_PERMISSION" != "any" ]; then
        REQUIRED_RANK=$(permission_rank "$REQUIRED_PERMISSION")
        if [ "$REQUIRED_RANK" -eq 0 ]; then
          echo "::error::Invalid comment-trigger-permission '$REQUIRED_PERMISSION' (expected admin, maintain, write, triage, read, or any)"
          ENABLE_CLAUDECODE="false"
        elif [ "$(permission_rank "$ACTUAL_PERMISSION")" -lt "$REQUIRED_RANK" ]; then
          echo "Commenter @${COMMENTER:-unknown} has '$ACTUAL_PERMISSION' permission; comment-triggered reviews require '$REQUIRED_PERMISSION' or higher, skipping"
          ENABLE_CLAUDECODE="false"
        fi
      fi
      ;;
  esac
fi

# 2. Check SHA-based deduplication (with exception for GitHub review requests)
if [ "$ENABLE_CLAUDECODE" == "true" ] && [ -f ".claudecode-marker/marker.json" ]; then
  if ! MARKER_SHA=$(jq -r '.sha // empty' .claudecode-marker/marker.json 2>/dev/null); then
    echo "Warning: Failed to parse marker SHA, proceeding with review"
  elif [ -n "$MARKER_SHA" ] && [ "$MARKER_SHA" == "$GITHUB_SHA" ]; then
    # A GitHub review request is the existing appeal mechanism. Ordinary review
    # comments and mentions still deduplicate after a successful same-SHA run.
    if [ "$TRIGGER_TYPE" == "review_request" ]; then
      echo "Explicit review request on same SHA $GITHUB_SHA - allowing re-review (appeal mechanism)"
    else
      echo "Review already completed for SHA $GITHUB_SHA, skipping duplicate (trigger: $TRIGGER_TYPE)"
      ENABLE_CLAUDECODE="false"
    fi
  fi
fi

# 3. Check if required label is present
if [ "$ENABLE_CLAUDECODE" == "true" ] && [ -n "${REQUIRE_LABEL:-}" ]; then
  if echo "$PR_LABELS" | jq -e --arg label "$REQUIRE_LABEL" 'index($label) != null' > /dev/null 2>&1; then
    echo "Required label '$REQUIRE_LABEL' found on PR #$PR_NUMBER"
  else
    echo "Skipping code review: required label '$REQUIRE_LABEL' not found on PR #$PR_NUMBER"
    ENABLE_CLAUDECODE="false"
  fi
fi

# 4. Skip draft PRs if configured (explicit comment-driven triggers bypass this)
if [ "$ENABLE_CLAUDECODE" == "true" ] && [ "${SKIP_DRAFT_PRS:-false}" == "true" ] && [ "${IS_DRAFT:-false}" == "true" ]; then
  case "$TRIGGER_TYPE" in
    mention|slash_command)
      echo "Draft PR #$PR_NUMBER, but trigger '$TRIGGER_TYPE' was explicitly requested via comment - running anyway"
      ;;
    *)
      echo "Skipping code review for draft PR #$PR_NUMBER"
      ENABLE_CLAUDECODE="false"
      ;;
  esac
fi

# 5. Final status
echo "enable_claudecode=$ENABLE_CLAUDECODE" >> "$GITHUB_OUTPUT"
echo "silence_claudecode_comments=$SILENCE_CLAUDECODE_COMMENTS" >> "$GITHUB_OUTPUT"

if [ "$ENABLE_CLAUDECODE" == "true" ]; then
  echo "ClaudeCode is enabled for this run (trigger: $TRIGGER_TYPE, PR: #$PR_NUMBER, SHA: $GITHUB_SHA)"
else
  echo "ClaudeCode is disabled for this run"
fi
