#!/bin/bash
#
# Test suite for git-credentials.sh
#
# Run with: ./test-git-credentials.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_UNDER_TEST="$SCRIPT_DIR/git-credentials.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

TESTS_RUN=0
TESTS_FAILED=0

assert_equals() {
    local expected="$1" actual="$2" message="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ "$expected" = "$actual" ]; then
        echo -e "${GREEN}✓${NC} $message"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}✗${NC} $message"
        echo "  Expected: $expected"
        echo "  Actual:   $actual"
    fi
}

setup_repo() {
    TEST_DIR=$(mktemp -d)
    REPO="$TEST_DIR/repo with spaces"
    STATE="$TEST_DIR/state"
    mkdir -p "$REPO"
    git -C "$REPO" init -q
    # actions/checkout v4/v5 layout
    git -C "$REPO" config --local http.https://github.com/.extraheader "AUTHORIZATION: basic dG9rZW4="
    # actions/checkout v6 layout: credentials in an included file
    git -C "$REPO" config --local "includeIf.gitdir:$REPO/.git.path" "$TEST_DIR/git-credentials-1234.config"
    # Unrelated settings that must be left alone
    git -C "$REPO" config --local core.autocrlf false
    git -C "$REPO" config --local "includeIf.gitdir:$REPO/.git.path" "$TEST_DIR/team settings.config" --add 2>/dev/null \
        || git -C "$REPO" config --local --add "includeIf.gitdir:$REPO/.git.path" "$TEST_DIR/team settings.config"
    git -C "$REPO" config --local --add http.https://github.com/.extraheader "X-Second: value"
}

teardown_repo() {
    rm -rf "$TEST_DIR"
}

local_config() {
    git -C "$REPO" config --local --list
}

test_hide_removes_credentials_and_keeps_other_config() {
    echo "Test: hide removes credential entries only"
    setup_repo
    (cd "$REPO" && "$SCRIPT_UNDER_TEST" hide "$STATE" >/dev/null)

    local config
    config=$(local_config)
    assert_equals "" "$(grep -i 'extraheader' <<<"$config" || true)" "extraheader entries removed"
    assert_equals "" "$(grep 'git-credentials-' <<<"$config" || true)" "credential include removed"
    assert_equals "1" "$(grep -c 'team settings.config' <<<"$config")" "unrelated include kept"
    assert_equals "1" "$(grep -c 'core.autocrlf=false' <<<"$config")" "unrelated setting kept"
    assert_equals "600" "$(stat -c '%a' "$STATE" 2>/dev/null || stat -f '%Lp' "$STATE")" "state file is private"
    teardown_repo
}

test_restore_round_trips() {
    echo "Test: restore brings back every hidden value"
    setup_repo
    local before after
    before=$(local_config | sort)
    (cd "$REPO" && "$SCRIPT_UNDER_TEST" hide "$STATE" >/dev/null)
    (cd "$REPO" && "$SCRIPT_UNDER_TEST" restore "$STATE" >/dev/null)
    after=$(local_config | sort)

    assert_equals "$before" "$after" "config identical after hide + restore"
    assert_equals "missing" "$([ -e "$STATE" ] && echo present || echo missing)" "state file deleted"
    teardown_repo
}

test_restore_without_state_is_noop() {
    echo "Test: restore without a state file does nothing"
    setup_repo
    local before
    before=$(local_config)
    (cd "$REPO" && "$SCRIPT_UNDER_TEST" restore "$TEST_DIR/does-not-exist")
    assert_equals "$before" "$(local_config)" "config unchanged"
    teardown_repo
}

test_hide_outside_repository() {
    echo "Test: hide outside a git repository succeeds"
    local dir
    dir=$(mktemp -d)
    (cd "$dir" && "$SCRIPT_UNDER_TEST" hide "$dir/state" >/dev/null)
    assert_equals "0" "$?" "exits successfully"
    rm -rf "$dir"
}

test_hide_removes_credentials_and_keeps_other_config
test_restore_round_trips
test_restore_without_state_is_noop
test_hide_outside_repository

echo ""
echo "Total: $TESTS_RUN, failed: $TESTS_FAILED"
if [ "$TESTS_FAILED" -ne 0 ]; then
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
echo -e "${GREEN}All tests passed!${NC}"
