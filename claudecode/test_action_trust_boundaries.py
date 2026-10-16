"""Guards for what pull request content can influence in the action and workflow."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_steps():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    return action, action["runs"]["steps"]


def step_index(steps, name):
    return next(i for i, step in enumerate(steps) if step.get("name") == name)


def test_tooling_runs_from_snapshot_taken_before_pr_checkout():
    _, steps = load_steps()
    snapshot = step_index(steps, "Snapshot action files")
    assert snapshot == 0
    for checkout in ("Checkout exact PR head", "Checkout PR head for legacy issue_comment callers"):
        assert snapshot < step_index(steps, checkout)

    # Only the snapshot step may read the action path; every later step must use
    # the snapshot, which a PR checkout into the workspace cannot replace.
    for step in steps[1:]:
        assert "github.action_path" not in yaml.safe_dump(step), step.get("name")


def test_comment_triggers_require_write_permission_by_default():
    action, steps = load_steps()
    assert action["inputs"]["comment-trigger-permission"]["default"] == "write"
    assert step_index(steps, "Check commenter permission") < step_index(steps, "Determine ClaudeCode enablement")
    enablement = steps[step_index(steps, "Determine ClaudeCode enablement")]
    assert enablement["env"]["COMMENT_TRIGGER_PERMISSION"] == "${{ inputs.comment-trigger-permission }}"
    assert enablement["env"]["COMMENTER_PERMISSION"] == "${{ steps.commenter.outputs.permission }}"


def test_repository_workflow_gates_comment_triggered_runs():
    workflow = yaml.safe_load((ROOT / ".github/workflows/code-review.yml").read_text())
    steps = workflow["jobs"]["code-review"]["steps"]
    assert steps[0]["id"] == "gate"
    gate_script = steps[0]["run"]
    assert ".head.repo.full_name" in gate_script
    assert "admin|maintain|write" in gate_script
    for step in steps[1:]:
        assert step["if"] == "github.event_name == 'pull_request' || steps.gate.outputs.allowed == 'true'"
