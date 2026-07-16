#!/bin/bash
#
# Test suite for detect-trigger-type.sh
#
# Run with: ./test-detect-trigger-type.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_UNDER_TEST="$SCRIPT_DIR/detect-trigger-type.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

setup_test() {
    TEST_DIR=$(mktemp -d)
    export GITHUB_OUTPUT="$TEST_DIR/github_output"
    touch "$GITHUB_OUTPUT"
}

teardown_test() {
    rm -rf "$TEST_DIR"
    unset EVENT_NAME EVENT_ACTION COMMENT_BODY APP_SLUG
}

run_script() {
    > "$GITHUB_OUTPUT"
    "$SCRIPT_UNDER_TEST" > "$TEST_DIR/stdout" 2>&1
    TRIGGER_TYPE=$(grep "^trigger_type=" "$GITHUB_OUTPUT" | cut -d= -f2)
}

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

test_pr_opened() {
    echo "Test: pull_request opened -> open"
    setup_test
    export EVENT_NAME="pull_request"
    export EVENT_ACTION="opened"
    run_script
    assert_equals "open" "$TRIGGER_TYPE" "Should detect 'open' for opened action"
    teardown_test
}

test_pr_reopened() {
    echo "Test: pull_request reopened -> open"
    setup_test
    export EVENT_NAME="pull_request"
    export EVENT_ACTION="reopened"
    run_script
    assert_equals "open" "$TRIGGER_TYPE" "Should detect 'open' for reopened action"
    teardown_test
}

test_pr_ready_for_review() {
    echo "Test: pull_request ready_for_review -> ready_for_review"
    setup_test
    export EVENT_NAME="pull_request"
    export EVENT_ACTION="ready_for_review"
    run_script
    assert_equals "ready_for_review" "$TRIGGER_TYPE" "Should detect 'ready_for_review' as its own trigger"
    teardown_test
}

test_pr_synchronize() {
    echo "Test: pull_request synchronize -> commit"
    setup_test
    export EVENT_NAME="pull_request"
    export EVENT_ACTION="synchronize"
    run_script
    assert_equals "commit" "$TRIGGER_TYPE" "Should detect 'commit' for synchronize action"
    teardown_test
}

test_pr_review_requested() {
    echo "Test: pull_request review_requested -> review_request"
    setup_test
    export EVENT_NAME="pull_request"
    export EVENT_ACTION="review_requested"
    run_script
    assert_equals "review_request" "$TRIGGER_TYPE" "Should detect 'review_request' for review_requested action"
    teardown_test
}

test_pr_labeled() {
    echo "Test: pull_request labeled -> label"
    setup_test
    export EVENT_NAME="pull_request"
    export EVENT_ACTION="labeled"
    run_script
    assert_equals "label" "$TRIGGER_TYPE" "Should detect 'label' for labeled action"
    teardown_test
}

test_review_command_exact() {
    echo "Test: comment 'review' -> slash_command"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="review"
    run_script
    assert_equals "slash_command" "$TRIGGER_TYPE" "Should detect exact 'review' comment"
    teardown_test
}

test_review_command_please() {
    echo "Test: comment 'review please' -> slash_command"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="review please"
    run_script
    assert_equals "slash_command" "$TRIGGER_TYPE" "Should detect 'review please' comment"
    teardown_test
}

test_review_command_case_and_whitespace() {
    echo "Test: comment '  REVIEW PLEASE  ' -> slash_command"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="  REVIEW PLEASE  "
    run_script
    assert_equals "slash_command" "$TRIGGER_TYPE" "Should be case-insensitive and ignore surrounding whitespace"
    teardown_test
}

test_review_command_does_not_match_prefix() {
    echo "Test: comment 'review the design doc' -> not slash_command"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="review the design doc"
    run_script
    assert_equals "unknown" "$TRIGGER_TYPE" "Should not trigger on ordinary comments starting with 'review'"
    teardown_test
}

test_review_command_does_not_match_reviewing() {
    echo "Test: comment 'reviewing this now' -> not slash_command"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="reviewing this now"
    run_script
    assert_equals "unknown" "$TRIGGER_TYPE" "Should not match 'reviewing'"
    teardown_test
}

test_review_command_does_not_match_mid_sentence() {
    echo "Test: comment 'let's review the doc' -> not slash_command"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="let's review the doc"
    run_script
    assert_equals "unknown" "$TRIGGER_TYPE" "Should not match when 'review' isn't the whole comment"
    teardown_test
}

test_mention_trigger() {
    echo "Test: comment '@github-actions please take a look' -> mention"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="@github-actions please take a look"
    export APP_SLUG="github-actions"
    run_script
    assert_equals "mention" "$TRIGGER_TYPE" "Should detect bot mention"
    teardown_test
}

test_review_command_takes_precedence_over_mention_check() {
    echo "Test: comment 'review' with APP_SLUG set -> slash_command (not evaluated as mention)"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="review"
    export APP_SLUG="github-actions"
    run_script
    assert_equals "slash_command" "$TRIGGER_TYPE" "Review command check should win when both could apply"
    teardown_test
}

test_unrelated_comment() {
    echo "Test: unrelated comment -> unknown"
    setup_test
    export EVENT_NAME="issue_comment"
    export COMMENT_BODY="thanks for the PR!"
    export APP_SLUG="github-actions"
    run_script
    assert_equals "unknown" "$TRIGGER_TYPE" "Should not detect any trigger for unrelated comments"
    teardown_test
}

test_unsupported_event() {
    echo "Test: workflow_dispatch -> unknown"
    setup_test
    export EVENT_NAME="workflow_dispatch"
    run_script
    assert_equals "unknown" "$TRIGGER_TYPE" "Should default to unknown for unhandled events"
    teardown_test
}

# Run all tests
echo "========================================"
echo "Testing: detect-trigger-type.sh"
echo "========================================"
echo ""

test_pr_opened
test_pr_reopened
test_pr_ready_for_review
test_pr_synchronize
test_pr_review_requested
test_pr_labeled
test_review_command_exact
test_review_command_please
test_review_command_case_and_whitespace
test_review_command_does_not_match_prefix
test_review_command_does_not_match_reviewing
test_review_command_does_not_match_mid_sentence
test_mention_trigger
test_review_command_takes_precedence_over_mention_check
test_unrelated_comment
test_unsupported_event

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
