import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from action_runtime_dependencies import collect_action_uses, find_legacy_runtimes, load_metadata
from action_runtime_metadata import compare, manifest_urls, render_fixture, upstream_record, upstream_runtime

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


def run_checker(*args):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/check-action-runtime-dependencies.py"), *map(str, args)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_checker_cli_reports_missing_action_file_as_usage_error(tmp_path):
    result = run_checker(tmp_path / "missing/action.yml")

    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "missing/action.yml" in result.stderr


def test_checker_cli_rejects_workflow_file_as_usage_error(tmp_path):
    workflow = tmp_path / "workflow.yml"
    workflow.write_text("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n")

    result = run_checker(workflow)

    assert result.returncode == 2
    assert "Traceback" not in result.stderr
    assert "not an action manifest" in result.stderr
    assert str(workflow) in result.stderr


def test_checker_accepts_docker_container_steps(tmp_path):
    write_action(
        tmp_path / "action.yml",
        "composite",
        f"  steps:\n    - uses: docker://alpine:3.20\n    - uses: {CURRENT_CACHE}\n",
    )

    assert collect_action_uses(tmp_path / "action.yml") == [(tmp_path / "action.yml", CURRENT_CACHE)]
    assert find_legacy_runtimes(tmp_path / "action.yml", METADATA) == []


def test_root_action_preserves_cache_and_node_contracts():
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    steps = action["runs"]["steps"]
    uses = [step.get("uses") for step in steps]

    assert uses.count("actions/cache@caa296126883cff596d87d8935842f9db880ef25") == 1
    assert uses.count("actions/cache/save@caa296126883cff596d87d8935842f9db880ef25") == 1
    node_setup = next(step for step in steps if step.get("name") == "Set up Node.js")
    assert node_setup["with"] == {"node-version": "18", "package-manager-cache": False}


REQUIRED_TEST_CI_ACTIONS = {
    "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444",
    "oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6",
}
CURRENT_CHECKOUT = "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd"


def external_uses(steps):
    return {step["uses"] for step in steps if "uses" in step and not step["uses"].startswith("./")}


def assert_recorded_node24(uses_set):
    for uses in sorted(uses_set):
        runtime = METADATA.get(uses, {}).get("runtime")
        assert runtime == "node24", (
            f"{uses} is recorded as {runtime!r}; add or refresh its record in "
            "scripts/fixtures/action-runtime-metadata.json (see refresh-action-runtime-metadata.py)"
        )


def test_repository_ci_uses_node24_actions_without_changing_application_nodes():
    test_workflow = yaml.safe_load((ROOT / ".github/workflows/test-claudecode.yml").read_text())
    test_steps = test_workflow["jobs"]["test-claudecode"]["steps"]
    test_uses = external_uses(test_steps)
    assert REQUIRED_TEST_CI_ACTIONS <= test_uses, f"missing pins: {REQUIRED_TEST_CI_ACTIONS - test_uses}"
    assert_recorded_node24(test_uses)
    node_setup = next(step for step in test_steps if step.get("name") == "Set up Node.js")
    assert node_setup["with"] == {"node-version": "20", "package-manager-cache": False}

    review_workflow = yaml.safe_load((ROOT / ".github/workflows/code-review.yml").read_text())
    review_uses = external_uses(review_workflow["jobs"]["code-review"]["steps"])
    assert CURRENT_CHECKOUT in review_uses
    assert_recorded_node24(review_uses)


def test_yaml_is_test_only_and_installed_by_test_ci():
    runtime_requirements = (ROOT / "claudecode/requirements.txt").read_text()
    dev_requirements = (ROOT / "claudecode/requirements-dev.txt").read_text()
    workflow = (ROOT / ".github/workflows/test-claudecode.yml").read_text()

    assert "PyYAML" not in runtime_requirements
    assert "PyYAML>=6.0.2" in dev_requirements
    assert "pip install -r claudecode/requirements-dev.txt" in workflow


def test_all_fixture_records_are_runtime_declarations():
    assert all(record["runtime"] in {"node16", "node20", "node24", "composite", "docker"} for record in METADATA.values())


def test_external_composite_requires_recorded_dependencies(tmp_path):
    composite = "example/composite@" + "a" * 40
    write_action(tmp_path / "action.yml", "composite", f"  steps:\n    - uses: {composite}\n")

    metadata = {**METADATA, composite: {"runtime": "composite"}}
    errors = find_legacy_runtimes(tmp_path / "action.yml", metadata)
    assert len(errors) == 1
    assert "no recorded dependencies" in errors[0]

    metadata[composite] = {"runtime": "composite", "dependencies": [LEGACY_CACHE]}
    errors = find_legacy_runtimes(tmp_path / "action.yml", metadata)
    assert len(errors) == 1
    assert LEGACY_CACHE in errors[0]
    assert "node20" in errors[0]
    assert composite in errors[0]

    metadata[composite] = {"runtime": "composite", "dependencies": [CURRENT_CACHE]}
    assert find_legacy_runtimes(tmp_path / "action.yml", metadata) == []

    metadata[composite] = {"runtime": "composite", "dependencies": []}
    assert find_legacy_runtimes(tmp_path / "action.yml", metadata) == []


def test_external_composite_dependency_cycle_is_reported(tmp_path):
    first = "example/first@" + "1" * 40
    second = "example/second@" + "2" * 40
    write_action(tmp_path / "action.yml", "composite", f"  steps:\n    - uses: {first}\n")
    metadata = {
        **METADATA,
        first: {"runtime": "composite", "dependencies": [second]},
        second: {"runtime": "composite", "dependencies": [first]},
    }

    errors = find_legacy_runtimes(tmp_path / "action.yml", metadata)

    assert len(errors) == 1
    assert "dependency cycle" in errors[0]


def test_refresh_manifest_urls_handle_action_subpaths():
    assert manifest_urls(CURRENT_CACHE) == [
        "https://raw.githubusercontent.com/actions/cache/caa296126883cff596d87d8935842f9db880ef25/action.yml",
        "https://raw.githubusercontent.com/actions/cache/caa296126883cff596d87d8935842f9db880ef25/action.yaml",
    ]
    assert manifest_urls("actions/cache/save@caa296126883cff596d87d8935842f9db880ef25")[0] == (
        "https://raw.githubusercontent.com/actions/cache/caa296126883cff596d87d8935842f9db880ef25/save/action.yml"
    )


def test_refresh_compare_reports_differences_and_preserves_other_fields():
    manifests = {
        manifest_urls(LEGACY_CACHE)[0]: "runs:\n  using: node20\n",
        manifest_urls(CURRENT_CACHE)[1]: "runs:\n  using: node24\n",  # only action.yaml exists
    }
    metadata = {
        LEGACY_CACHE: {"runtime": "node24", "dependencies": ["keep-me"]},
        CURRENT_CACHE: {"runtime": "node24"},
    }

    differences, refreshed = compare(metadata, manifests.get)

    assert differences == {LEGACY_CACHE: ({"runtime": "node24"}, {"runtime": "node20"})}
    assert refreshed[LEGACY_CACHE] == {"runtime": "node20", "dependencies": ["keep-me"]}
    assert refreshed[CURRENT_CACHE] == {"runtime": "node24"}


def test_refresh_reports_missing_or_malformed_manifests():
    try:
        upstream_runtime(CURRENT_CACHE, lambda url: None)
    except ValueError as exc:
        assert "no action.yml or action.yaml" in str(exc)
    else:
        raise AssertionError("missing manifest must raise")

    try:
        upstream_runtime(CURRENT_CACHE, lambda url: "name: not an action\n")
    except ValueError as exc:
        assert "no runs.using" in str(exc)
    else:
        raise AssertionError("manifest without runs.using must raise")


def test_render_fixture_round_trips_checked_in_layout():
    fixture = ROOT / "scripts/fixtures/action-runtime-metadata.json"
    assert render_fixture(load_metadata(fixture)) == fixture.read_text()


def test_every_workflow_job_uses_node24_actions():
    workflow_files = sorted(ROOT.glob(".github/workflows/*.yml")) + sorted(ROOT.glob(".github/workflows/*.yaml"))
    assert workflow_files, "no workflow files found under .github/workflows"
    for workflow_file in workflow_files:
        workflow = yaml.safe_load(workflow_file.read_text())
        jobs = workflow.get("jobs") or {}
        assert jobs, f"{workflow_file} has no jobs"
        for job in jobs.values():
            assert_recorded_node24(external_uses(job.get("steps") or []))


def test_checker_rejects_mutable_action_references(tmp_path):
    write_action(tmp_path / "action.yml", "composite", "  steps:\n    - uses: actions/checkout@v5\n")

    try:
        find_legacy_runtimes(tmp_path / "action.yml", METADATA)
    except ValueError as exc:
        assert "not pinned to a full commit SHA" in str(exc)
        assert "actions/checkout@v5" in str(exc)
    else:
        raise AssertionError("tag pins must be rejected")

    result = run_checker(tmp_path / "action.yml")
    assert result.returncode == 2
    assert "not pinned to a full commit SHA" in result.stderr

    short_sha = tmp_path / "short.yml"
    write_action(short_sha, "composite", "  steps:\n    - uses: actions/checkout@93cb6ef\n")
    assert run_checker(short_sha).returncode == 2


def test_refresh_derives_composite_dependencies_from_upstream_steps():
    composite = "example/composite@" + "c" * 40
    manifests = {
        manifest_urls(composite)[0]: (
            "runs:\n  using: composite\n  steps:\n"
            f"    - uses: {CURRENT_CACHE}\n"
            "    - uses: ./setup\n"
            "    - uses: docker://alpine:3.20\n"
            f"    - uses: {CURRENT_CACHE}\n"
            "    - run: echo no uses\n      shell: bash\n"
        ),
    }

    record = upstream_record(composite, manifests.get)

    assert record == {
        "runtime": "composite",
        "dependencies": [CURRENT_CACHE, "example/composite/setup@" + "c" * 40],
    }

    differences, refreshed = compare({composite: {"runtime": "composite", "dependencies": [CURRENT_CACHE]}}, manifests.get)
    assert composite in differences
    assert differences[composite][1]["dependencies"] == record["dependencies"]
    assert refreshed[composite] == record

    differences, _ = compare({composite: record}, manifests.get)
    assert differences == {}
