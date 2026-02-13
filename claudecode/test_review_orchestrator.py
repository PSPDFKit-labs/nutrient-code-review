"""Unit tests for review_orchestrator."""

from pathlib import Path
from unittest.mock import Mock

from claudecode.review_orchestrator import ReviewModelConfig, ReviewOrchestrator


def test_review_model_config_from_env_with_fallbacks():
    env = {
        "CLAUDE_MODEL": "global-model",
        "MODEL_TRIAGE": "triage-model",
        "MODEL_SECURITY": "security-model",
    }
    cfg = ReviewModelConfig.from_env(env, "default-model")
    assert cfg.triage == "triage-model"
    assert cfg.compliance == "global-model"
    assert cfg.quality == "global-model"
    assert cfg.security == "security-model"
    assert cfg.validation == "global-model"


def test_orchestrator_invalid_triage_schema_fails():
    runner = Mock()
    runner.run_prompt.return_value = (
        True,
        "",
        {"findings": [{"file": "a.py", "line": 3, "severity": "HIGH", "category": "security", "title": "Issue"}]},
    )
    findings_filter = Mock()
    github_client = Mock()
    github_client.is_excluded.return_value = False
    cfg = ReviewModelConfig("t", "c", "q", "s", "v")

    orchestrator = ReviewOrchestrator(runner, findings_filter, github_client, cfg, 100)
    ok, result, err = orchestrator.run(
        repo_dir=Path("."),
        pr_data={"number": 1, "changed_files": 1, "head": {"repo": {"full_name": "x/y"}}},
        pr_diff="diff --git a/a.py b/a.py",
    )

    assert ok is False
    assert result == {}
    assert "invalid schema" in err.lower()
