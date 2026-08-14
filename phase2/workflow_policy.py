from __future__ import annotations

import re
from dataclasses import dataclass


class WorkflowPolicyError(RuntimeError):
    pass


FULL_SHA_ACTION_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)
STEP_HEADER_RE = re.compile(r"^      - name:\s*(.+?)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class Step:
    name: str
    text: str


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _mapping_after(text: str, key: str, indent: int) -> dict[str, str]:
    prefix = " " * indent + key + ":"
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line == prefix:
            result: dict[str, str] = {}
            child_indent = indent + 2
            for child in lines[index + 1 :]:
                if not child.strip():
                    continue
                current_indent = _line_indent(child)
                if current_indent <= indent:
                    break
                if current_indent != child_indent:
                    continue
                stripped = child.strip()
                if ":" not in stripped:
                    raise WorkflowPolicyError(f"INVALID_{key.upper()}_MAPPING")
                name, value = stripped.split(":", 1)
                result[name.strip()] = value.strip()
            return result
    raise WorkflowPolicyError(f"MISSING_{key.upper()}")


def _job_blocks(text: str) -> dict[str, str]:
    jobs_match = re.search(r"^jobs:\s*$", text, re.MULTILINE)
    if jobs_match is None:
        raise WorkflowPolicyError("MISSING_JOBS")
    tail = text[jobs_match.end() :]
    matches = list(JOB_HEADER_RE.finditer(tail))
    if not matches:
        raise WorkflowPolicyError("MISSING_JOBS")
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(tail)
        blocks[match.group(1)] = tail[start:end]
    return blocks


def _job_scalar(block: str, key: str) -> str | None:
    match = re.search(rf"^    {re.escape(key)}:\s*(.*?)\s*$", block, re.MULTILINE)
    return None if match is None else match.group(1)


def _job_block_value(block: str, key: str) -> str | None:
    lines = block.splitlines()
    prefix = f"    {key}:"
    for index, line in enumerate(lines):
        if not line.startswith(prefix):
            continue
        value = line[len(prefix) :].strip()
        if value not in {">-", ">", "|", "|-"}:
            return value
        parts: list[str] = []
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            if _line_indent(child) <= 4:
                break
            parts.append(child.strip())
        return " ".join(parts)
    return None


def _steps(block: str) -> list[Step]:
    matches = list(STEP_HEADER_RE.finditer(block))
    result: list[Step] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(block)
        result.append(Step(match.group(1), block[start:end]))
    return result


def _step_scalar(step: Step, key: str) -> str | None:
    match = re.search(rf"^        {re.escape(key)}:\s*(.*?)\s*$", step.text, re.MULTILINE)
    return None if match is None else match.group(1)


def _step_mapping(step: Step, key: str) -> dict[str, str]:
    return _mapping_after(step.text, key, 8)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise WorkflowPolicyError(code)


def _needs(value: str | None) -> set[str]:
    if value is None:
        return set()
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        return {item.strip() for item in value[1:-1].split(",") if item.strip()}
    return {value}


def _checkout_step(block: str) -> Step:
    matches = [step for step in _steps(block) if (_step_scalar(step, "uses") or "").startswith("actions/checkout@")]
    _require(len(matches) == 1, "INVALID_CHECKOUT_COUNT")
    return matches[0]


def _validate_checkout(step: Step) -> None:
    uses = _step_scalar(step, "uses")
    _require(uses is not None and FULL_SHA_ACTION_RE.fullmatch(uses) is not None, "UNPINNED_ACTION")
    with_values = _step_mapping(step, "with")
    _require(
        with_values.get("ref") == "${{ needs.static-authorisation.outputs.trusted_sha }}",
        "UNTRUSTED_CHECKOUT_REF",
    )
    _require(with_values.get("persist-credentials") == "false", "PERSISTED_CHECKOUT_CREDENTIALS")


def validate_workflow(text: str) -> None:
    top_permissions = _mapping_after(text, "permissions", 0)
    _require(top_permissions == {"contents": "read", "issues": "read"}, "INVALID_TOP_LEVEL_PERMISSIONS")

    jobs = _job_blocks(text)
    expected_jobs = {
        "static-authorisation",
        "report-static-rejection",
        "source-revalidation",
        "report-source-rejection",
        "trusted-live-check",
    }
    _require(set(jobs) == expected_jobs, "UNAPPROVED_JOB_GRAPH")

    for block in jobs.values():
        for step in _steps(block):
            uses = _step_scalar(step, "uses")
            if uses is not None:
                _require(FULL_SHA_ACTION_RE.fullmatch(uses) is not None, "UNPINNED_ACTION")

    static = jobs["static-authorisation"]
    _require(_mapping_after(static, "permissions", 4) == {"contents": "read", "issues": "read"}, "INVALID_STATIC_PERMISSIONS")
    _require(_job_scalar(static, "environment") is None, "STATIC_ENVIRONMENT_PRESENT")
    _require("actions/checkout@" not in static, "STATIC_CHECKOUT_PRESENT")
    _require("PHASE2_ALLOCATOR_APP_PRIVATE_KEY" not in static, "STATIC_SECRET_PRESENT")
    _require("PHASE2_STATE_REPOSITORY_ID" not in static, "STATIC_STATE_CONFIG_PRESENT")
    _require("github.workflow_sha" in static, "MISSING_TRUSTED_WORKFLOW_SHA")
    _require("phase2/static_intake.py" in static, "MISSING_STATIC_INTAKE")

    source = jobs["source-revalidation"]
    _require(_needs(_job_scalar(source, "needs")) == {"static-authorisation"}, "INVALID_SOURCE_DEPENDENCY")
    _require(_mapping_after(source, "permissions", 4) == {"contents": "read", "issues": "read"}, "INVALID_SOURCE_PERMISSIONS")
    _require(_job_scalar(source, "environment") is None, "SOURCE_ENVIRONMENT_PRESENT")
    _require("PHASE2_ALLOCATOR_APP_PRIVATE_KEY" not in source, "SOURCE_SECRET_PRESENT")
    _require("PHASE2_STATE_REPOSITORY_ID" not in source, "SOURCE_STATE_CONFIG_PRESENT")
    _require("PHASE2_CANDIDATE_SET: ${{ needs.static-authorisation.outputs.candidate_set }}" in source, "MISSING_CANDIDATE_SET_HANDOFF")
    _validate_checkout(_checkout_step(source))
    _require(any(_step_scalar(step, "run") == "python3 -m phase2.source_revalidation" for step in _steps(source)), "MISSING_SOURCE_REVALIDATION")

    for name in ("report-static-rejection", "report-source-rejection"):
        block = jobs[name]
        _require(_mapping_after(block, "permissions", 4) == {"contents": "none", "issues": "write"}, "INVALID_REPORT_PERMISSIONS")
        _require(_job_scalar(block, "environment") is None, "REPORT_ENVIRONMENT_PRESENT")
        _require("PHASE2_ALLOCATOR_APP_PRIVATE_KEY" not in block, "REPORT_SECRET_PRESENT")
        _require("PHASE2_STATE_REPOSITORY_ID" not in block, "REPORT_STATE_CONFIG_PRESENT")

    trusted = jobs["trusted-live-check"]
    _require(
        _needs(_job_scalar(trusted, "needs")) == {"static-authorisation", "source-revalidation"},
        "INVALID_TRUSTED_DEPENDENCIES",
    )
    _require(_job_scalar(trusted, "environment") == "phase-2-allocator", "INVALID_TRUSTED_ENVIRONMENT")
    _require(_mapping_after(trusted, "permissions", 4) == {"contents": "read", "issues": "write"}, "INVALID_TRUSTED_PERMISSIONS")
    condition = _job_block_value(trusted, "if") or ""
    for required in (
        "needs.static-authorisation.outputs.action == 'live_check'",
        "vars.PHASE2_INTAKE_ENABLED == 'true'",
        "needs.source-revalidation.result == 'success'",
        "needs.source-revalidation.outputs.action == 'live_check'",
        "needs.static-authorisation.outputs.action == 'scope_probe'",
    ):
        _require(required in condition, "INVALID_TRUSTED_CONDITION")
    _validate_checkout(_checkout_step(trusted))
    _require(trusted.count("secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY") == 1, "INVALID_PRIVATE_KEY_PLACEMENT")
    _require(trusted.count("secrets.PHASE2_STATE_REPOSITORY_ID") == 1, "INVALID_STATE_SECRET_PLACEMENT")

    outside_trusted = "\n".join(block for name, block in jobs.items() if name != "trusted-live-check")
    _require("secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY" not in outside_trusted, "PRIVATE_KEY_OUTSIDE_TRUSTED_JOB")
    _require("secrets.PHASE2_STATE_REPOSITORY_ID" not in outside_trusted, "STATE_SECRET_OUTSIDE_TRUSTED_JOB")
