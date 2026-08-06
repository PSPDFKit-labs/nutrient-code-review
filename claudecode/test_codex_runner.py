"""Tests for the non-interactive OpenAI Codex reviewer."""

import json
import os
from unittest.mock import Mock, patch

from claudecode.github_action_audit import (
    SimpleClaudeRunner,
    SimpleCodexRunner,
    initialize_review_runners,
    write_provider_results,
)
from claudecode.constants import (
    DEFAULT_GPT_MODEL,
    DEFAULT_SYNTHESIZER_MODEL,
    DEFAULT_SYNTHESIZER_PROVIDER,
)


RESULT = {
    "pr_summary": {"overview": "Reviewed", "file_changes": []},
    "findings": [],
}


@patch("subprocess.run")
def test_validate_codex_available_requires_cli_and_key(mock_run):
    mock_run.return_value = Mock(returncode=0, stdout="codex-cli 1.0", stderr="")
    with patch.dict(os.environ, {"CODEX_API_KEY": "key"}, clear=True):
        assert SimpleCodexRunner("gpt-5.6-sol").validate_codex_available() == (
            True,
            "",
        )

    with patch.dict(os.environ, {}, clear=True):
        available, error = SimpleCodexRunner(
            "gpt-5.6-sol"
        ).validate_codex_available()
        assert available is False
        assert "CODEX_API_KEY" in error


@patch("subprocess.run")
def test_codex_runner_emits_shared_json_and_scopes_secrets(mock_run, tmp_path):
    def run_command(command, **kwargs):
        output_index = command.index("--output-last-message") + 1
        with open(command[output_index], "w", encoding="utf-8") as output:
            json.dump(RESULT, output)
        return Mock(returncode=0, stdout="", stderr="")

    mock_run.side_effect = run_command
    environment = {
        "CODEX_API_KEY": "openai-key",
        "ANTHROPIC_API_KEY": "anthropic-key",
        "GITHUB_TOKEN": "github-token",
        "GH_TOKEN": "gh-token",
        "OPENAI_API_KEY": "legacy-openai-key",
    }
    with patch.dict(os.environ, environment, clear=True):
        success, error, result = SimpleCodexRunner("gpt-5.6-sol").run_code_review(
            tmp_path, "review this"
        )

    assert success is True
    assert error == ""
    assert result == RESULT
    command = mock_run.call_args.args[0]
    assert command[:2] == ["codex", "exec"]
    assert "--ephemeral" in command
    assert "--ignore-user-config" in command
    assert "--ignore-rules" in command
    assert command[command.index("--sandbox") + 1] == "read-only"
    assert command[command.index("--model") + 1] == "gpt-5.6-sol"
    child_env = mock_run.call_args.kwargs["env"]
    assert child_env["CODEX_API_KEY"] == "openai-key"
    assert "ANTHROPIC_API_KEY" not in child_env
    assert "GITHUB_TOKEN" not in child_env
    assert "GH_TOKEN" not in child_env
    assert "OPENAI_API_KEY" not in child_env


def test_claude_only_configuration_does_not_initialize_codex():
    with patch.dict(os.environ, {"REVIEWERS": "claude"}, clear=True):
        names, runners, synthesizer = initialize_review_runners()

    assert names == ("claude",)
    assert isinstance(runners["claude"], SimpleClaudeRunner)
    assert synthesizer is None


def test_default_openai_and_synthesizer_configuration_uses_named_constants():
    with patch.dict(
        os.environ, {"REVIEWERS": "claude,openai"}, clear=True
    ):
        _, runners, synthesizer = initialize_review_runners()

    assert runners["openai"].model == DEFAULT_GPT_MODEL
    assert DEFAULT_SYNTHESIZER_PROVIDER == "openai"
    assert isinstance(synthesizer, SimpleCodexRunner)
    assert synthesizer.model == DEFAULT_SYNTHESIZER_MODEL


def test_two_reviewers_initialize_configured_synthesizer():
    environment = {
        "REVIEWERS": "claude,openai",
        "OPENAI_MODEL": "review-model",
        "SYNTHESIZER_PROVIDER": "openai",
        "SYNTHESIZER_MODEL": "synthesis-model",
    }
    with patch.dict(os.environ, environment, clear=True):
        names, runners, synthesizer = initialize_review_runners()

    assert names == ("claude", "openai")
    assert isinstance(runners["claude"], SimpleClaudeRunner)
    assert isinstance(runners["openai"], SimpleCodexRunner)
    assert runners["openai"].model == "review-model"
    assert isinstance(synthesizer, SimpleCodexRunner)
    assert synthesizer.model == "synthesis-model"


def test_provider_results_are_written_as_complete_json_documents(tmp_path):
    with patch.dict(
        os.environ, {"PROVIDER_RESULTS_DIR": str(tmp_path)}, clear=True
    ):
        write_provider_results({"claude": RESULT, "synthesized": RESULT})

    assert json.loads((tmp_path / "claude.json").read_text()) == RESULT
    assert json.loads((tmp_path / "synthesized.json").read_text()) == RESULT
