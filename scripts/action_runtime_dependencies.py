"""Validate JavaScript runtimes for actions invoked by local composite actions."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

SUPPORTED_RUNTIMES = {"node24", "composite", "docker"}


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
        data = yaml.safe_load(candidate.read_text()) or {}
        runs = data.get("runs", {})
        runtime = runs.get("using")
        runtimes.append((candidate, runtime))
        if runtime != "composite":
            return
        for step in runs.get("steps", []):
            uses = step.get("uses")
            if not uses:
                continue
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


def find_legacy_runtimes(action_file: Path, metadata: dict[str, dict[str, str]]) -> list[str]:
    """Return errors for invoked actions whose recorded runtime is not Node 24-safe."""
    external, runtimes = _action_references(action_file)
    errors = []
    for source, runtime in runtimes:
        if runtime not in SUPPORTED_RUNTIMES:
            errors.append(f"{source}: declares unsupported runtime {runtime!r}")
    for source, uses in external:
        record = metadata.get(uses)
        if record is None:
            errors.append(f"{source}: no recorded runtime metadata for {uses}")
            continue
        runtime = record.get("runtime")
        if runtime not in SUPPORTED_RUNTIMES:
            errors.append(f"{source}: {uses} declares unsupported runtime {runtime!r}")
    return errors


def load_metadata(path: Path) -> dict[str, dict[str, str]]:
    return json.loads(path.read_text())
