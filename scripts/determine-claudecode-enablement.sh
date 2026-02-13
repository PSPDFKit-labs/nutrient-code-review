#!/bin/bash
#
# Determines whether ClaudeCode should run based on trigger type and configuration.
# This script encapsulates the complex logic for deciding when to run code reviews.
#
# Expected environment variables:
#   - GITHUB_EVENT_NAME: The GitHub event name (pull_request, issue_comment, etc.)
#   - PR_NUMBER: The pull request number
#   - GITHUB_SHA: The commit SHA being reviewed
#   - TRIGGER_TYPE: The detected trigger type (open, commit, review_request, mention, label)
#   - TRIGGER_ON_OPEN: Whether to run on PR open (true/false)
#   - TRIGGER_ON_COMMIT: Whether to run on new commits (true/false)
#   - TRIGGER_ON_REVIEW_REQUEST: Whether to run on review requests (true/false)
#   - TRIGGER_ON_MENTION: Whether to run on bot mentions (true/false)
#   - SKIP_DRAFT_PRS: Whether to skip draft PRs (true/false)
#   - IS_DRAFT: Whether the PR is a draft (true/false)
#   - REQUIRE_LABEL: Required label name (optional)
#   - PR_LABELS: JSON array of PR labels
#   - IS_PR: Whether issue comment is on a PR (true/false, for issue_comment events)
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
    commit)
      if [ "${TRIGGER_ON_COMMIT:-false}" != "true" ]; then
        echo "Trigger 'commit' is disabled via trigger-on-commit input"
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
    label)
      # Label trigger uses the existing require-label logic below
      ;;
    *)
      echo "Unknown trigger type: $TRIGGER_TYPE"
      ENABLE_CLAUDECODE="false"
      ;;
  esac
fi

# 2. Check SHA-based deduplication (with exception for explicit review requests)
if [ "$ENABLE_CLAUDECODE" == "true" ] && [ -f ".claudecode-marker/marker.json" ]; then
  if ! MARKER_SHA=$(jq -r '.sha // empty' .claudecode-marker/marker.json 2>/dev/null); then
    echo "Warning: Failed to parse marker SHA, proceeding with review"
  elif [ -n "$MARKER_SHA" ] && [ "$MARKER_SHA" == "$GITHUB_SHA" ]; then
    # Allow explicit review requests to bypass deduplication (for appeal workflow)
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

# 4. Skip draft PRs if configured
if [ "$ENABLE_CLAUDECODE" == "true" ] && [ "${SKIP_DRAFT_PRS:-false}" == "true" ] && [ "${IS_DRAFT:-false}" == "true" ]; then
  echo "Skipping code review for draft PR #$PR_NUMBER"
  ENABLE_CLAUDECODE="false"
fi

# 5. Final status
echo "enable_claudecode=$ENABLE_CLAUDECODE" >> "$GITHUB_OUTPUT"
echo "silence_claudecode_comments=$SILENCE_CLAUDECODE_COMMENTS" >> "$GITHUB_OUTPUT"

if [ "$ENABLE_CLAUDECODE" == "true" ]; then
  echo "ClaudeCode is enabled for this run (trigger: $TRIGGER_TYPE, PR: #$PR_NUMBER, SHA: $GITHUB_SHA)"
else
  echo "ClaudeCode is disabled for this run"
fi
