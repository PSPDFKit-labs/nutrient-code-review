"""Tests for provider-neutral review orchestration."""

import json
import time

import pytest

from claudecode.review_ensemble import (
    ReviewConfigurationError,
    ReviewExecutionError,
    build_synthesis_prompt,
    parse_reviewers,
    run_reviewers,
    synthesize_reviews,
    validate_synthesizer,
)
from claudecode.review_schema import REVIEW_OUTPUT_SCHEMA, REVIEW_OUTPUT_SCHEMA_PATH


RESULT = {
    "pr_summary": {"overview": "Summary", "file_changes": []},
    "findings": [],
}


class FakeRunner:
    def __init__(self, result=None, delay=0, error=""):
        self.result = result or RESULT
        self.delay = delay
        self.error = error
        self.calls = []

    def run_code_review(self, repo_dir, prompt):
        self.calls.append((repo_dir, prompt))
        time.sleep(self.delay)
        if self.error:
            return False, self.error, {}
        return True, "", self.result


def test_parse_reviewers_defaults_to_claude_and_deduplicates():
    assert parse_reviewers("") == ("claude",)
    assert parse_reviewers(" claude, openai,claude ") == ("claude", "openai")


def test_parse_reviewers_rejects_unknown_provider():
    with pytest.raises(ReviewConfigurationError, match="Unsupported reviewer"):
        parse_reviewers("claude,mystery")


def test_validate_synthesizer_requires_supported_provider_and_model():
    assert validate_synthesizer("openai", "gpt-5.6-terra") == (
        "openai",
        "gpt-5.6-terra",
    )
    with pytest.raises(ReviewConfigurationError):
        validate_synthesizer("mystery", "model")
    with pytest.raises(ReviewConfigurationError):
        validate_synthesizer("openai", "")


def test_single_reviewer_result_is_returned_unchanged(tmp_path):
    runner = FakeRunner(result=RESULT)
    results = run_reviewers({"claude": runner}, tmp_path, "review")
    final = synthesize_reviews(results, None, tmp_path)
    assert final is RESULT
    assert runner.calls == [(tmp_path, "review")]


def test_multiple_reviewers_run_concurrently_and_are_synthesized(tmp_path):
    source_result = {
        "pr_summary": {"overview": "Summary", "file_changes": []},
        "findings": [
            {
                "file": "example.py",
                "line": 1,
                "severity": "MEDIUM",
                "category": "correctness",
                "title": "Issue",
                "description": "Description",
                "impact": "Impact",
                "recommendation": "Recommendation",
                "confidence": 0.9,
            }
        ],
    }
    claude = FakeRunner(result=source_result, delay=0.08)
    openai = FakeRunner(result=source_result, delay=0.08)
    combined = {
        "pr_summary": {"overview": "Combined", "file_changes": []},
        "findings": [],
    }
    synthesizer = FakeRunner(result=combined)

    started = time.monotonic()
    results = run_reviewers(
        {"claude": claude, "openai": openai}, tmp_path, "review"
    )
    elapsed = time.monotonic() - started
    final = synthesize_reviews(results, synthesizer, tmp_path)

    assert elapsed < 0.14
    assert final == combined
    synthesis_prompt = synthesizer.calls[0][1]
    synthesis_payload = json.loads(
        synthesis_prompt.split("Provider review documents:\n", 1)[1]
    )
    assert synthesis_payload["claude"]["findings"][0]["sources"] == ["claude"]
    assert synthesis_payload["openai"]["findings"][0]["sources"] == ["openai"]


def test_reviewer_failure_fails_the_ensemble(tmp_path):
    with pytest.raises(ReviewExecutionError, match="openai: unavailable"):
        run_reviewers(
            {
                "claude": FakeRunner(),
                "openai": FakeRunner(error="unavailable"),
            },
            tmp_path,
            "review",
        )


def test_synthesis_prompt_contains_valid_provider_json():
    prompt = build_synthesis_prompt({"claude": RESULT, "openai": RESULT})
    encoded = prompt.split("Provider review documents:\n", 1)[1]
    payload = json.loads(encoded)
    assert set(payload) == {"claude", "openai"}


def test_shared_schema_is_loaded_from_the_committed_json_file():
    assert json.loads(REVIEW_OUTPUT_SCHEMA_PATH.read_text(encoding="utf-8")) == (
        REVIEW_OUTPUT_SCHEMA
    )
