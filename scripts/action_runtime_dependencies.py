"""Validate JavaScript runtimes for actions invoked by local composite actions.

External references are resolved against an offline fixture of recorded
``runs.using`` values keyed by exact ``owner/repo[/path]@sha`` references. The
fixture is maintained evidence, not live data: it is only as trustworthy as its
last refresh. ``scripts/refresh-action-runtime-metadata.py --check`` compares
every record with the upstream manifest at that SHA.

External composite actions are not traversed. Their fixture record must list the
resolved external ``dependencies`` so they can be validated recursively; a
composite record without that list is rejected.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

SUPPORTED_RUNTIMES = {"node24", "composite", "docker"}  # local declarations
SUPPORTED_EXTERNAL_RUNTIMES = {"node24", "docker"}  # composite handled via recorded dependencies


def _action_file(action_directory: Path) -> Path:
    for name in ("action.yml", "action.yaml"):
        candidate = action_directory / name
        if candidate.is_file():
            return candidate
    raise ValueError(f"No action.yml or action.yaml in local action {action_directory}")


def _external_action(uses: str) -> str:
    if "@" not in uses:
        raise ValueError(f"Action reference is not pinned: {uses}")
    return uses


def _action_references(action_file: Path) -> tuple[list[tuple[Path, str]], list[tuple[Path, object]]]:
    """Return external references and local action runtime declarations."""
    external: list[tuple[Path, str]] = []
    runtimes: list[tuple[Path, object]] = []
    visited: set[Path] = set()
    workspace_root = action_file.resolve().parent

    def visit(candidate: Path) -> None:
        candidate = candidate.resolve()
        if candidate in visited:
            return
        visited.add(candidate)
        data = yaml.safe_load(candidate.read_text())
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, dict):
            raise ValueError(f"{candidate}: not an action manifest (no 'runs' mapping)")
        runtime = runs.get("using")
        runtimes.append((candidate, runtime))
        if runtime != "composite":
            return
        for step in runs.get("steps", []):
            uses = step.get("uses")
            if not uses:
                continue
            if uses.startswith("docker://"):
                continue  # container steps have no JavaScript runtime
            if uses.startswith("./"):
                local_path = uses.split("@", 1)[0]
                visit(_action_file(workspace_root / local_path))
            else:
                external.append((candidate, _external_action(uses)))

    visit(action_file)
    return external, runtimes


def collect_action_uses(action_file: Path) -> list[tuple[Path, str]]:
    """Return external `uses` references reachable through local composites."""
    external, _ = _action_references(action_file)
    return external


def find_legacy_runtimes(action_file: Path, metadata: dict[str, dict[str, object]]) -> list[str]:
    """Return errors for invoked actions whose recorded runtime is not Node 24-safe."""
    external, runtimes = _action_references(action_file)
    errors = []
    for source, runtime in runtimes:
        if runtime not in SUPPORTED_RUNTIMES:
            errors.append(f"{source}: declares unsupported runtime {runtime!r}")
    for source, uses in external:
        errors.extend(_external_errors(str(source), uses, metadata, ()))
    return errors


def _external_errors(
    source: str, uses: str, metadata: dict[str, dict[str, object]], chain: tuple[str, ...]
) -> list[str]:
    if uses in chain:
        return [f"{source}: dependency cycle {' -> '.join((*chain, uses))}"]
    record = metadata.get(uses)
    if record is None:
        return [f"{source}: no recorded runtime metadata for {uses}"]
    runtime = record.get("runtime")
    if runtime in SUPPORTED_EXTERNAL_RUNTIMES:
        return []
    if runtime != "composite":
        return [f"{source}: {uses} declares unsupported runtime {runtime!r}"]
    dependencies = record.get("dependencies")
    if not isinstance(dependencies, list):
        return [f"{source}: composite {uses} has no recorded dependencies; record its resolved external actions"]
    errors: list[str] = []
    for dependency in dependencies:
        errors.extend(_external_errors(f"{source} -> {uses}", str(dependency), metadata, (*chain, uses)))
    return errors


def load_metadata(path: Path) -> dict[str, dict[str, object]]:
    return json.loads(path.read_text())
