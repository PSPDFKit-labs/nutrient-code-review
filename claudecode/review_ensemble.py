"""Provider-neutral orchestration for one or more code review agents."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Tuple

from claudecode.constants import DEFAULT_SYNTHESIZER_PROVIDER


SUPPORTED_REVIEWERS = ("claude", "openai")


class ReviewConfigurationError(ValueError):
    """Raised when reviewer or synthesizer configuration is invalid."""


class ReviewExecutionError(RuntimeError):
    """Raised when a configured reviewer or synthesizer does not complete."""


def parse_reviewers(value: str) -> Tuple[str, ...]:
    """Parse a comma-separated reviewer list while preserving caller order."""
    reviewers = []
    for raw_name in (value or "claude").split(","):
        name = raw_name.strip().lower()
        if not name:
            continue
        if name not in SUPPORTED_REVIEWERS:
            supported = ", ".join(SUPPORTED_REVIEWERS)
            raise ReviewConfigurationError(
                f"Unsupported reviewer '{name}'. Supported reviewers: {supported}"
            )
        if name not in reviewers:
            reviewers.append(name)

    if not reviewers:
        raise ReviewConfigurationError("At least one reviewer must be configured")
    return tuple(reviewers)


def validate_synthesizer(provider: str, model: str) -> Tuple[str, str]:
    """Validate and normalize synthesizer configuration."""
    normalized_provider = (provider or DEFAULT_SYNTHESIZER_PROVIDER).strip().lower()
    if normalized_provider not in SUPPORTED_REVIEWERS:
        supported = ", ".join(SUPPORTED_REVIEWERS)
        raise ReviewConfigurationError(
            f"Unsupported synthesizer provider '{normalized_provider}'. "
            f"Supported providers: {supported}"
        )
    normalized_model = (model or "").strip()
    if not normalized_model:
        raise ReviewConfigurationError("A synthesizer model must be configured")
    return normalized_provider, normalized_model


def validate_review_result(result: Any, producer: str) -> Dict[str, Any]:
    """Validate the stable top-level contract shared by all model calls."""
    if not isinstance(result, dict):
        raise ReviewExecutionError(f"{producer} did not return a JSON object")
    if "pr_summary" not in result:
        # Preserve the historical Claude path, which tolerated an omitted summary.
        result["pr_summary"] = {"overview": "", "file_changes": []}
    if not isinstance(result.get("pr_summary"), dict):
        raise ReviewExecutionError(f"{producer} result has an invalid pr_summary")
    if not isinstance(result.get("findings"), list):
        raise ReviewExecutionError(f"{producer} result is missing findings")
    return result


def _run_one(runner: Any, repo_dir: Path, prompt: str) -> Dict[str, Any]:
    success, error_message, result = runner.run_code_review(repo_dir, prompt)
    if not success:
        raise ReviewExecutionError(error_message)
    return result


def run_reviewers(
    runners: Mapping[str, Any], repo_dir: Path, prompt: str
) -> Dict[str, Dict[str, Any]]:
    """Run configured reviewers concurrently, or directly for one reviewer."""
    if not runners:
        raise ReviewConfigurationError("At least one reviewer runner is required")

    if len(runners) == 1:
        name, runner = next(iter(runners.items()))
        result = _run_one(runner, repo_dir, prompt)
        return {name: validate_review_result(result, name)}

    results: Dict[str, Dict[str, Any]] = {}
    errors = []
    with ThreadPoolExecutor(max_workers=len(runners)) as executor:
        futures = {
            executor.submit(_run_one, runner, repo_dir, prompt): name
            for name, runner in runners.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = validate_review_result(future.result(), name)
            except Exception as error:  # Preserve all failures before returning.
                errors.append(f"{name}: {error}")

    if errors:
        raise ReviewExecutionError("; ".join(errors))
    return {name: results[name] for name in runners}


def _with_source_labels(results: Mapping[str, Dict[str, Any]]) -> Dict[str, Any]:
    labeled = {}
    for provider, result in results.items():
        provider_result = deepcopy(result)
        for finding in provider_result.get("findings", []):
            if isinstance(finding, dict):
                finding["sources"] = [provider]
        labeled[provider] = provider_result
    return labeled


def build_synthesis_prompt(results: Mapping[str, Dict[str, Any]]) -> str:
    """Build the one-shot prompt that combines provider JSON into the same schema."""
    labeled_results = _with_source_labels(results)
    return f"""You are the final code-review synthesizer.

Combine the provider review documents below into one final review document.
Return only JSON matching the configured review-output schema.

Rules:
- Inspect the repository and current diff when needed to adjudicate a finding.
- Merge findings that describe the same underlying problem.
- Preserve a supported finding even if only one provider found it.
- Reject speculative or unsupported findings.
- Reconcile severity, wording, line anchors, and recommendations using the code as evidence.
- Do not invent a finding without a provider source.
- For every final finding, set sources to the provider names that contributed to it.
- Produce one coherent pr_summary; do not mention the synthesis process in public wording.

Provider review documents:
{json.dumps(labeled_results, indent=2, sort_keys=True)}
"""


def synthesize_reviews(
    results: Mapping[str, Dict[str, Any]], synthesizer: Any, repo_dir: Path
) -> Dict[str, Any]:
    """Return one provider result unchanged, or synthesize multiple results."""
    if len(results) == 1:
        # This is the compatibility path: Claude-only output is not rewritten.
        return next(iter(results.values()))
    prompt = build_synthesis_prompt(results)
    result = _run_one(synthesizer, repo_dir, prompt)
    return validate_review_result(result, "synthesizer")
