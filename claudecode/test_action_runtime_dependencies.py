import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from action_runtime_dependencies import collect_action_uses, find_legacy_runtimes, load_metadata

ROOT = Path(__file__).resolve().parents[1]
METADATA = load_metadata(ROOT / "scripts/fixtures/action-runtime-metadata.json")
LEGACY_CACHE = "actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830"
CURRENT_CACHE = "actions/cache@caa296126883cff596d87d8935842f9db880ef25"


def write_action(path, using, steps=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"runs:\n  using: {using}\n{steps}")


def test_root_action_has_only_node24_runtime_dependencies():
    assert find_legacy_runtimes(ROOT / "action.yml", METADATA) == []


def test_checker_rejects_legacy_runtime_dependency(tmp_path):
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    for step in action["runs"]["steps"]:
        if step.get("uses", "").startswith("actions/cache@"):
            step["uses"] = LEGACY_CACHE
            break
    action_file = tmp_path / "action.yml"
    action_file.write_text(yaml.safe_dump(action))

    errors = find_legacy_runtimes(action_file, METADATA)

    assert len(errors) == 1
    assert LEGACY_CACHE in errors[0]
    assert "node20" in errors[0]


def test_checker_resolves_nested_local_actions_from_workspace_root(tmp_path):
    write_action(
        tmp_path / "action.yml",
        "composite",
        "  steps:\n    - uses: ./outer\n",
    )
    write_action(
        tmp_path / "outer/action.yml",
        "composite",
        "  steps:\n    - uses: ./inner\n",
    )
    write_action(
        tmp_path / "inner/action.yml",
        "composite",
        f"  steps:\n    - uses: {LEGACY_CACHE}\n",
    )
    write_action(
        tmp_path / "outer/inner/action.yml",
        "composite",
        f"  steps:\n    - uses: {CURRENT_CACHE}\n",
    )

    errors = find_legacy_runtimes(tmp_path / "action.yml", METADATA)

    assert len(errors) == 1
    assert LEGACY_CACHE in errors[0]
    assert str(tmp_path / "inner/action.yml") in errors[0]


def test_checker_handles_action_yaml_and_repeated_local_references(tmp_path):
    nested = tmp_path / "nested"
    write_action(
        nested / "action.yaml",
        "composite",
        "  steps:\n    - uses: actions/cache/save@caa296126883cff596d87d8935842f9db880ef25\n",
    )
    write_action(
        tmp_path / "action.yml",
        "composite",
        "  steps:\n    - uses: ./nested\n    - uses: ./nested\n"
        "    - uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3\n",
    )

    assert [uses for _, uses in collect_action_uses(tmp_path / "action.yml")] == [
        "actions/cache/save@caa296126883cff596d87d8935842f9db880ef25",
        "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3",
    ]
    assert find_legacy_runtimes(tmp_path / "action.yml", METADATA) == []


def test_checker_rejects_local_and_root_node20_actions(tmp_path):
    local_root = tmp_path / "local-root.yml"
    write_action(
        local_root,
        "composite",
        "  steps:\n    - uses: ./local-node20\n",
    )
    write_action(tmp_path / "local-node20/action.yml", "node20")
    root_node20 = tmp_path / "root-node20.yml"
    write_action(root_node20, "node20")

    local_errors = find_legacy_runtimes(local_root, METADATA)
    root_errors = find_legacy_runtimes(root_node20, METADATA)

    assert len(local_errors) == 1
    assert "local-node20/action.yml" in local_errors[0]
    assert "node20" in local_errors[0]
    assert len(root_errors) == 1
    assert "root-node20.yml" in root_errors[0]
    assert "node20" in root_errors[0]


def test_checker_accepts_node24_and_docker_local_actions(tmp_path):
    write_action(
        tmp_path / "action.yml",
        "composite",
        "  steps:\n    - uses: ./node24\n    - uses: ./docker\n",
    )
    write_action(tmp_path / "node24/action.yml", "node24")
    write_action(tmp_path / "docker/action.yml", "docker")

    assert find_legacy_runtimes(tmp_path / "action.yml", METADATA) == []


def test_checker_cli_returns_nonzero_for_unsupported_local_runtime(tmp_path):
    write_action(
        tmp_path / "action.yml",
        "composite",
        "  steps:\n    - uses: ./local-node20\n",
    )
    write_action(tmp_path / "local-node20/action.yml", "node20")

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check-action-runtime-dependencies.py"),
            str(tmp_path / "action.yml"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    assert "unsupported runtime 'node20'" in result.stderr


def test_root_action_preserves_cache_and_node_contracts():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    steps = action["runs"]["steps"]
    uses = [step.get("uses") for step in steps]

    assert uses.count("actions/cache@caa296126883cff596d87d8935842f9db880ef25") == 1
    assert uses.count("actions/cache/save@caa296126883cff596d87d8935842f9db880ef25") == 1
    node_setup = next(step for step in steps if step.get("name") == "Set up Node.js")
    assert node_setup["with"] == {"node-version": "18", "package-manager-cache": False}


def test_repository_ci_uses_node24_actions_without_changing_application_nodes():
    test_workflow = yaml.safe_load((ROOT / ".github/workflows/test-claudecode.yml").read_text())
    test_steps = test_workflow["jobs"]["test-claudecode"]["steps"]
    test_uses = [step.get("uses") for step in test_steps if "uses" in step]
    assert test_uses == [
        "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444",
        "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6",
    ]
    assert all(METADATA[uses]["runtime"] == "node24" for uses in test_uses)
    assert test_steps[2]["with"] == {"node-version": "20", "package-manager-cache": False}

    review_workflow = yaml.safe_load((ROOT / ".github/workflows/code-review.yml").read_text())
    assert review_workflow["jobs"]["code-review"]["steps"][0]["uses"] == (
        "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"
    )


def test_yaml_is_test_only_and_installed_by_test_ci():
    runtime_requirements = (ROOT / "claudecode/requirements.txt").read_text()
    dev_requirements = (ROOT / "claudecode/requirements-dev.txt").read_text()
    workflow = (ROOT / ".github/workflows/test-claudecode.yml").read_text()

    assert "PyYAML" not in runtime_requirements
    assert "PyYAML>=6.0.2" in dev_requirements
    assert "pip install -r claudecode/requirements-dev.txt" in workflow


def test_all_fixture_records_are_runtime_declarations():
    assert all(record["runtime"] in {"node20", "node24", "composite", "docker"} for record in METADATA.values())
