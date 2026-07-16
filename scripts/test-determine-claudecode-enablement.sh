#!/bin/bash
#
# Test suite for determine-claudecode-enablement.sh
#
# Run with: ./test-determine-claudecode-enablement.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_UNDER_TEST="$SCRIPT_DIR/determine-claudecode-enablement.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Setup function - creates temp directory for test files
setup_test() {
    TEST_DIR=$(mktemp -d)
    export GITHUB_OUTPUT="$TEST_DIR/github_output"
    touch "$GITHUB_OUTPUT"
}

# Teardown function - cleans up temp directory and environment
teardown_test() {
    rm -rf "$TEST_DIR"

    # Unset all environment variables that tests might set
    unset GITHUB_EVENT_NAME PR_NUMBER GITHUB_SHA TRIGGER_TYPE
    unset TRIGGER_ON_OPEN TRIGGER_ON_COMMIT TRIGGER_ON_REVIEW_REQUEST TRIGGER_ON_MENTION
    unset TRIGGER_ON_REVIEW_COMMAND TRIGGER_ON_READY_FOR_REVIEW
    unset RUN_EVERY_COMMIT SKIP_DRAFT_PRS IS_DRAFT REQUIRE_LABEL PR_LABELS IS_PR
}

# Helper to run the script and capture output
run_script() {
    # Clear previous output
    > "$GITHUB_OUTPUT"

    # Run the script (capture stdout/stderr)
    if "$SCRIPT_UNDER_TEST" > "$TEST_DIR/stdout" 2>&1; then
        SCRIPT_EXIT_CODE=0
    else
        SCRIPT_EXIT_CODE=$?
    fi

    # Read the outputs
    ENABLE_CLAUDECODE=$(grep "^enable_claudecode=" "$GITHUB_OUTPUT" | cut -d= -f2)
    SILENCE_COMMENTS=$(grep "^silence_claudecode_comments=" "$GITHUB_OUTPUT" | cut -d= -f2)
}

# Assertion helpers
assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="$3"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [ "$expected" = "$actual" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}✓${NC} $message"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}✗${NC} $message"
        echo -e "  Expected: ${YELLOW}$expected${NC}"
        echo -e "  Actual:   ${YELLOW}$actual${NC}"
    fi
}

# Test cases

test_unsupported_event_type() {
    echo "Test: Unsupported event type (workflow_dispatch)"
    setup_test

    export GITHUB_EVENT_NAME="workflow_dispatch"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="unknown"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable for unsupported event type"

    teardown_test
}

test_pull_request_event_open_trigger_enabled() {
    echo "Test: Pull request opened with trigger enabled"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="open"
    export TRIGGER_ON_OPEN="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for PR open trigger"

    teardown_test
}

test_pull_request_event_open_trigger_disabled() {
    echo "Test: Pull request opened with trigger disabled"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="open"
    export TRIGGER_ON_OPEN="false"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable when open trigger is off"

    teardown_test
}

test_commit_trigger_with_new_input() {
    echo "Test: Commit trigger with trigger-on-commit enabled"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="commit"
    export TRIGGER_ON_COMMIT="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for commit trigger (new input)"

    teardown_test
}

test_commit_trigger_with_legacy_input() {
    echo "Test: Commit trigger with run-every-commit (legacy) enabled"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="commit"
    export TRIGGER_ON_COMMIT="false"
    export RUN_EVERY_COMMIT="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for legacy run-every-commit"

    teardown_test
}

test_commit_trigger_disabled() {
    echo "Test: Commit trigger disabled"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="commit"
    export TRIGGER_ON_COMMIT="false"
    export RUN_EVERY_COMMIT="false"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable when commit trigger is off"

    teardown_test
}

test_review_request_trigger() {
    echo "Test: Review request trigger enabled"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="review_request"
    export TRIGGER_ON_REVIEW_REQUEST="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for review request trigger"

    teardown_test
}

test_mention_trigger() {
    echo "Test: Bot mention trigger enabled"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="mention"
    export TRIGGER_ON_MENTION="true"
    export IS_PR="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for mention trigger"

    teardown_test
}

test_sha_deduplication_different_sha() {
    echo "Test: SHA deduplication with different SHA"
    setup_test

    # Create marker with different SHA
    mkdir -p .claudecode-marker
    cat > .claudecode-marker/marker.json << EOF
{
  "sha": "old-sha-123"
}
EOF

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="new-sha-456"
    export TRIGGER_TYPE="open"
    export TRIGGER_ON_OPEN="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable when SHA is different"

    rm -rf .claudecode-marker
    teardown_test
}

test_sha_deduplication_same_sha_non_review() {
    echo "Test: SHA deduplication with same SHA (non-review trigger)"
    setup_test

    # Create marker with same SHA
    mkdir -p .claudecode-marker
    cat > .claudecode-marker/marker.json << EOF
{
  "sha": "abc123"
}
EOF

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="commit"
    export TRIGGER_ON_COMMIT="true"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable when SHA matches (not review request)"

    rm -rf .claudecode-marker
    teardown_test
}

test_sha_deduplication_same_sha_review_request() {
    echo "Test: SHA deduplication with same SHA (review request - appeal workflow)"
    setup_test

    # Create marker with same SHA
    mkdir -p .claudecode-marker
    cat > .claudecode-marker/marker.json << EOF
{
  "sha": "abc123"
}
EOF

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="review_request"
    export TRIGGER_ON_REVIEW_REQUEST="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for review request even with same SHA (appeal workflow)"

    rm -rf .claudecode-marker
    teardown_test
}

test_required_label_present() {
    echo "Test: Required label is present"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="open"
    export TRIGGER_ON_OPEN="true"
    export REQUIRE_LABEL="ready-for-review"
    export PR_LABELS='["bug", "ready-for-review", "enhancement"]'

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable when required label is present"

    teardown_test
}

test_required_label_missing() {
    echo "Test: Required label is missing"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="open"
    export TRIGGER_ON_OPEN="true"
    export REQUIRE_LABEL="ready-for-review"
    export PR_LABELS='["bug", "enhancement"]'

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable when required label is missing"

    teardown_test
}

test_skip_draft_prs_enabled() {
    echo "Test: Skip draft PRs (enabled)"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="open"
    export TRIGGER_ON_OPEN="true"
    export SKIP_DRAFT_PRS="true"
    export IS_DRAFT="true"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable for draft PRs when skip is enabled"

    teardown_test
}

test_skip_draft_prs_disabled() {
    echo "Test: Skip draft PRs (disabled)"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="open"
    export TRIGGER_ON_OPEN="true"
    export SKIP_DRAFT_PRS="false"
    export IS_DRAFT="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable draft PRs when skip is disabled"

    teardown_test
}

test_ready_for_review_trigger() {
    echo "Test: Ready-for-review trigger enabled"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="ready_for_review"
    export TRIGGER_ON_READY_FOR_REVIEW="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for ready-for-review trigger"

    teardown_test
}

test_ready_for_review_trigger_disabled() {
    echo "Test: Ready-for-review trigger disabled via input"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="ready_for_review"
    export TRIGGER_ON_READY_FOR_REVIEW="false"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable when ready-for-review trigger is off"

    teardown_test
}

test_slash_command_trigger() {
    echo "Test: Review comment command trigger enabled"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="slash_command"
    export TRIGGER_ON_REVIEW_COMMAND="true"
    export IS_PR="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for review comment command trigger"

    teardown_test
}

test_slash_command_trigger_disabled() {
    echo "Test: Review comment command trigger disabled via input"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="slash_command"
    export TRIGGER_ON_REVIEW_COMMAND="false"
    export IS_PR="true"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable when review comment command trigger is off"

    teardown_test
}

test_skip_draft_prs_mention_bypasses() {
    echo "Test: Skip draft PRs does not apply to bot mention trigger"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="mention"
    export TRIGGER_ON_MENTION="true"
    export IS_PR="true"
    export SKIP_DRAFT_PRS="true"
    export IS_DRAFT="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable a mention-triggered review on a draft PR despite skip-draft-prs"

    teardown_test
}

test_skip_draft_prs_slash_command_bypasses() {
    echo "Test: Skip draft PRs does not apply to review comment command trigger"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="slash_command"
    export TRIGGER_ON_REVIEW_COMMAND="true"
    export IS_PR="true"
    export SKIP_DRAFT_PRS="true"
    export IS_DRAFT="true"

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable a review-command-triggered review on a draft PR despite skip-draft-prs"

    teardown_test
}

test_skip_draft_prs_commit_still_skipped() {
    echo "Test: Skip draft PRs still applies to automatic commit trigger"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="commit"
    export TRIGGER_ON_COMMIT="true"
    export SKIP_DRAFT_PRS="true"
    export IS_DRAFT="true"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should still skip an automatic commit-triggered review on a draft PR"

    teardown_test
}

test_issue_comment_not_on_pr() {
    echo "Test: Issue comment not on a PR"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="mention"
    export TRIGGER_ON_MENTION="true"
    export IS_PR="false"

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable when issue comment is not on a PR"

    teardown_test
}

test_default_values() {
    echo "Test: Default values (trigger-on-open defaults to true)"
    setup_test

    export GITHUB_EVENT_NAME="pull_request"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="open"
    # Don't set TRIGGER_ON_OPEN - should default to true

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should use default value (true) for trigger-on-open"

    teardown_test
}

test_issue_comment_with_required_label_present() {
    echo "Test: Issue comment (mention) with required label present"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="mention"
    export TRIGGER_ON_MENTION="true"
    export IS_PR="true"
    export REQUIRE_LABEL="ready-for-review"
    export PR_LABELS='["bug", "ready-for-review", "enhancement"]'

    run_script

    assert_equals "true" "$ENABLE_CLAUDECODE" "Should enable for issue_comment when required label is present"

    teardown_test
}

test_issue_comment_with_required_label_missing() {
    echo "Test: Issue comment (mention) with required label missing"
    setup_test

    export GITHUB_EVENT_NAME="issue_comment"
    export PR_NUMBER="123"
    export GITHUB_SHA="abc123"
    export TRIGGER_TYPE="mention"
    export TRIGGER_ON_MENTION="true"
    export IS_PR="true"
    export REQUIRE_LABEL="ready-for-review"
    export PR_LABELS='["bug", "enhancement"]'

    run_script

    assert_equals "false" "$ENABLE_CLAUDECODE" "Should disable for issue_comment when required label is missing"

    teardown_test
}

# Run all tests
echo "========================================"
echo "Testing: determine-claudecode-enablement.sh"
echo "========================================"
echo ""

test_unsupported_event_type
test_pull_request_event_open_trigger_enabled
test_pull_request_event_open_trigger_disabled
test_commit_trigger_with_new_input
test_commit_trigger_with_legacy_input
test_commit_trigger_disabled
test_review_request_trigger
test_mention_trigger
test_ready_for_review_trigger
test_ready_for_review_trigger_disabled
test_slash_command_trigger
test_slash_command_trigger_disabled
test_skip_draft_prs_mention_bypasses
test_skip_draft_prs_slash_command_bypasses
test_skip_draft_prs_commit_still_skipped
test_sha_deduplication_different_sha
test_sha_deduplication_same_sha_non_review
test_sha_deduplication_same_sha_review_request
test_required_label_present
test_required_label_missing
test_skip_draft_prs_enabled
test_skip_draft_prs_disabled
test_issue_comment_not_on_pr
test_default_values
test_issue_comment_with_required_label_present
test_issue_comment_with_required_label_missing

echo ""
echo "========================================"
echo "Test Results"
echo "========================================"
echo -e "Total:  $TESTS_RUN"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi