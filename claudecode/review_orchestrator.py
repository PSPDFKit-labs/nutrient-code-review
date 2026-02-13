"""Multi-phase review orchestration for GitHub Action execution."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from claudecode.findings_merge import merge_findings
from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.logger import get_logger
from claudecode.prompts import (
    build_compliance_prompt,
    build_context_discovery_prompt,
    build_quality_prompt,
    build_security_prompt,
    build_triage_prompt,
    build_validation_prompt,
)

logger = get_logger(__name__)


@dataclass
class ReviewModelConfig:
    """Per-phase model configuration with global fallback."""

    triage: str
    compliance: str
    quality: str
    security: str
    validation: str

    @classmethod
    def from_env(cls, env: Dict[str, str], default_model: str) -> "ReviewModelConfig":
        def resolve(key: str, fallback: str) -> str:
            value = (env.get(key) or "").strip()
            return value or fallback

        global_model = resolve("CLAUDE_MODEL", default_model)
        return cls(
            triage=resolve("MODEL_TRIAGE", global_model),
            compliance=resolve("MODEL_COMPLIANCE", global_model),
            quality=resolve("MODEL_QUALITY", global_model),
            security=resolve("MODEL_SECURITY", global_model),
            validation=resolve("MODEL_VALIDATION", global_model),
        )


class ReviewOrchestrator:
    """Coordinates multi-phase review and returns final findings."""

    def __init__(
        self,
        claude_runner: Any,
        findings_filter: Any,
        github_client: Any,
        model_config: ReviewModelConfig,
        max_diff_lines: int,
    ):
        self.claude_runner = claude_runner
        self.findings_filter = findings_filter
        self.github_client = github_client
        self.model_config = model_config
        self.max_diff_lines = max(0, max_diff_lines)

    def _run_phase(self, repo_dir: Path, prompt: str, model: str, phase_name: str) -> Tuple[bool, Dict[str, Any], str]:
        run_prompt = getattr(self.claude_runner, "run_prompt", None)
        if not callable(run_prompt):
            return False, {}, f"Runner missing run_prompt for {phase_name}"

        raw_result = run_prompt(repo_dir, prompt, model=model)
        if not (isinstance(raw_result, tuple) and len(raw_result) == 3):
            return False, {}, f"Invalid runner response for {phase_name}"

        success, error_msg, raw = raw_result
        if not success:
            return False, {}, error_msg

        if isinstance(raw, dict):
            return True, raw, ""

        parsed_ok, parsed = parse_json_with_fallbacks(str(raw), f"{phase_name} output")
        if not parsed_ok:
            return False, {}, f"Failed to parse {phase_name} output"
        return True, parsed, ""

    def _is_excluded(self, filepath: str) -> bool:
        checker = getattr(self.github_client, "is_excluded", None)
        if callable(checker):
            return bool(checker(filepath))
        raise AttributeError("github_client must implement is_excluded(filepath)")

    def _collect_phase_findings(self, phase_result: Dict[str, Any], source_agent: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for finding in phase_result.get("findings", []):
            if isinstance(finding, dict):
                enriched = finding.copy()
                enriched.setdefault("source_agent", source_agent)
                category = str(enriched.get("category", "")).lower()
                if "review_type" not in enriched:
                    enriched["review_type"] = "security" if category == "security" else "general"
                findings.append(enriched)
        return findings

    def _ensure_review_type(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        enriched = finding.copy()
        category = str(enriched.get("category", "")).lower()
        if "review_type" not in enriched:
            enriched["review_type"] = "security" if category == "security" else "general"
        return enriched

    def run(
        self,
        repo_dir: Path,
        pr_data: Dict[str, Any],
        pr_diff: str,
        custom_review_instructions: Optional[str] = None,
        custom_security_instructions: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any], str]:
        # Phase A: triage
        triage_prompt = build_triage_prompt(pr_data, pr_diff, self.max_diff_lines)
        ok, triage_result, err = self._run_phase(repo_dir, triage_prompt, self.model_config.triage, "triage")
        if not ok:
            return False, {}, f"Triage phase failed: {err}"

        if not isinstance(triage_result, dict) or "skip_review" not in triage_result:
            return False, {}, "Triage phase returned invalid schema"

        if triage_result.get("skip_review") is True:
            logger.info("Skipping review based on triage decision: %s", triage_result.get("reason", ""))
            return True, {
                "findings": [],
                "analysis_summary": {
                    "files_reviewed": 0,
                    "high_severity": 0,
                    "medium_severity": 0,
                    "low_severity": 0,
                    "review_completed": True,
                },
                "triage": triage_result,
            }, ""

        # Phase B: context discovery
        context_prompt = build_context_discovery_prompt(pr_data, pr_diff, self.max_diff_lines)
        ok, context_result, err = self._run_phase(repo_dir, context_prompt, self.model_config.compliance, "context discovery")
        if not ok:
            return False, {}, f"Context discovery phase failed: {err}"

        # Phase C: specialist passes
        compliance_prompt = build_compliance_prompt(pr_data, pr_diff, self.max_diff_lines, context_result)
        quality_prompt = build_quality_prompt(
            pr_data,
            pr_diff,
            self.max_diff_lines,
            context_result,
            custom_review_instructions=custom_review_instructions,
        )
        security_prompt = build_security_prompt(
            pr_data,
            pr_diff,
            self.max_diff_lines,
            context_result,
            custom_security_instructions=custom_security_instructions,
        )

        ok_c, compliance_result, err_c = self._run_phase(repo_dir, compliance_prompt, self.model_config.compliance, "compliance")
        ok_q, quality_result, err_q = self._run_phase(repo_dir, quality_prompt, self.model_config.quality, "quality")
        ok_s, security_result, err_s = self._run_phase(repo_dir, security_prompt, self.model_config.security, "security")

        if not ok_c:
            return False, {}, f"Compliance phase failed: {err_c}"
        if not ok_q:
            return False, {}, f"Quality phase failed: {err_q}"
        if not ok_s:
            return False, {}, f"Security phase failed: {err_s}"

        all_candidates: List[Dict[str, Any]] = []
        all_candidates.extend(self._collect_phase_findings(compliance_result, "compliance"))
        all_candidates.extend(self._collect_phase_findings(quality_result, "quality"))
        all_candidates.extend(self._collect_phase_findings(security_result, "security"))

        all_candidates = merge_findings(all_candidates)

        # Phase D: validation
        validation_prompt = build_validation_prompt(pr_data, pr_diff, self.max_diff_lines, all_candidates)
        ok_v, validation_result, err_v = self._run_phase(repo_dir, validation_prompt, self.model_config.validation, "validation")
        if not ok_v:
            return False, {}, f"Validation phase failed: {err_v}"

        validated: List[Dict[str, Any]] = []
        has_validation_output = isinstance(validation_result, dict) and "validated_findings" in validation_result
        decisions = validation_result.get("validated_findings", []) if isinstance(validation_result, dict) else []
        if not isinstance(decisions, list):
            decisions = []
        for decision in decisions:
            if not isinstance(decision, dict):
                continue
            idx = decision.get("finding_index")
            keep = bool(decision.get("keep"))
            confidence = decision.get("confidence", 0.0)
            try:
                idx_int = int(idx)
            except (TypeError, ValueError):
                continue
            if idx_int < 0 or idx_int >= len(all_candidates):
                continue
            if keep and float(confidence or 0.0) >= 0.8:
                finding = all_candidates[idx_int].copy()
                finding["confidence"] = float(confidence)
                validated.append(finding)

        # If validator did not return decisions at all, preserve candidates.
        # If it explicitly returned validated_findings (including empty list), trust validator output.
        if not has_validation_output:
            validated = all_candidates

        # Apply existing filtering pipeline
        pr_context = {
            "repo_name": pr_data.get("head", {}).get("repo", {}).get("full_name", "unknown"),
            "pr_number": pr_data.get("number"),
            "title": pr_data.get("title", ""),
            "description": pr_data.get("body", ""),
        }
        kept_findings = validated
        original_count = len(all_candidates)
        filter_response = self.findings_filter.filter_findings(validated, pr_context)
        if isinstance(filter_response, tuple) and len(filter_response) == 3:
            filter_success, filter_results, _ = filter_response
            if filter_success and isinstance(filter_results, dict):
                kept_findings = filter_results.get("filtered_findings", validated)

        final_findings: List[Dict[str, Any]] = []
        for finding in kept_findings:
            if not isinstance(finding, dict):
                continue
            if self._is_excluded(finding.get("file", "")):
                continue
            final_findings.append(self._ensure_review_type(finding))

        high = len([f for f in final_findings if str(f.get("severity", "")).upper() == "HIGH"])
        medium = len([f for f in final_findings if str(f.get("severity", "")).upper() == "MEDIUM"])
        low = len([f for f in final_findings if str(f.get("severity", "")).upper() == "LOW"])

        files_reviewed = pr_data.get("changed_files", 0)
        try:
            files_reviewed = int(files_reviewed)
        except (TypeError, ValueError):
            files_reviewed = 0

        return True, {
            "findings": final_findings,
            "analysis_summary": {
                "files_reviewed": files_reviewed,
                "high_severity": high,
                "medium_severity": medium,
                "low_severity": low,
                "review_completed": True,
            },
            "filtering_summary": {
                "total_original_findings": original_count,
                "excluded_findings": max(0, original_count - len(final_findings)),
                "kept_findings": len(final_findings),
            },
            "context_summary": context_result,
            "triage": triage_result,
        }, ""
