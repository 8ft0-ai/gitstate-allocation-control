from __future__ import annotations

import re
from dataclasses import dataclass


class WorkflowPolicyError(RuntimeError):
    pass


FULL_SHA_ACTION_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
JOB_HEADER_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$", re.MULTILINE)
STEP_ITEM_RE = re.compile(r"^      -(?:\s|$)", re.MULTILINE)
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
STATIC_GITHUB_SCRIPT_ACTION = "actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3"
EXPECTED_STATIC_SCRIPT = """const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const files = [
  'phase2/__init__.py', 'phase2/control_surface.py', 'phase2/parser.py',
  'phase2/policy.py', 'phase2/discovery.py', 'phase2/github_api.py',
  'phase2/static_intake.py', 'policy/actors.json'
];
const root = path.join(process.env.RUNNER_TEMP, `phase2-static-${process.env.GITHUB_RUN_ID}`);
for (const file of files) {
  const response = await github.rest.repos.getContent({
    owner: context.repo.owner, repo: context.repo.repo, path: file, ref: process.env.TRUSTED_SHA
  });
  const target = path.join(root, file);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.writeFileSync(target, Buffer.from(response.data.content, 'base64'), { mode: 0o600 });
}
const run = spawnSync('python3', ['-m', 'phase2.static_intake'], {
  cwd: root,
  encoding: 'utf8',
  env: {
    ...process.env,
    GITHUB_TOKEN: process.env.GITHUB_TOKEN,
    GITHUB_ACTOR: process.env.GITHUB_ACTOR,
    PHASE2_TRUSTED_SHA: process.env.TRUSTED_SHA
  }
});
const last = run.stdout.trim().split('\\n').pop();
if (!last) {
  core.setFailed('Static intake returned no result');
  return;
}
const result = JSON.parse(last);
for (const [key, value] of Object.entries(result)) core.setOutput(key, value ?? '');
core.setOutput('trusted_sha', process.env.TRUSTED_SHA);
if (run.status !== 0 || result.action === 'blocked') core.setFailed(`Static intake blocked: ${result.reason_code}`);"""
EXPECTED_REPORT_SCRIPT = """const issue_number = Number(process.env.ISSUE_NUMBER);
if (!Number.isSafeInteger(issue_number) || !process.env.REJECTION_SET) return;
const envelope = JSON.parse(Buffer.from(process.env.REJECTION_SET, 'base64url').toString('utf8'));
const body = `Phase 2 intake rejected.\\n\\n\`\`\`json\\n${JSON.stringify({
  execution_may_begin: false,
  protocol: 'beads-allocation/v0.2',
  rejections: envelope.rejections
})}\\n\`\`\``;
await github.rest.issues.createComment({ ...context.repo, issue_number, body });"""


@dataclass(frozen=True)
class Step:
    name: str | None
    text: str


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _keys_at_indent(text: str, indent: int, code: str) -> set[str]:
    keys: list[str] = []
    for line in text.splitlines():
        if not line.strip() or _line_indent(line) != indent:
            continue
        stripped = line.strip()
        if stripped.startswith("-"):
            continue
        if ":" not in stripped:
            raise WorkflowPolicyError(code)
        key, _ = stripped.split(":", 1)
        if re.fullmatch(r"[A-Za-z0-9_-]+", key) is None:
            raise WorkflowPolicyError(code)
        keys.append(key)
    if len(keys) != len(set(keys)):
        raise WorkflowPolicyError(code)
    return set(keys)


def _top_section(text: str, key: str) -> str:
    lines = text.splitlines()
    header = f"{key}:"
    for index, line in enumerate(lines):
        if line != header:
            continue
        values: list[str] = []
        for child in lines[index + 1 :]:
            if child and _line_indent(child) == 0:
                break
            values.append(child)
        return "\n".join(values).rstrip()
    raise WorkflowPolicyError(f"MISSING_{key.upper()}_SECTION")


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
                name = name.strip()
                if name in result:
                    raise WorkflowPolicyError(f"DUPLICATE_{key.upper()}_MAPPING")
                result[name] = value.strip()
            return result
    raise WorkflowPolicyError(f"MISSING_{key.upper()}")


def _literal_block_after(text: str, key: str, indent: int) -> str:
    prefix = " " * indent + key + ": |"
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line != prefix:
            continue
        child_indent = indent + 2
        values: list[str] = []
        for child in lines[index + 1 :]:
            if child.strip() and _line_indent(child) <= indent:
                break
            if not child.strip():
                values.append("")
                continue
            if _line_indent(child) < child_indent:
                raise WorkflowPolicyError(f"INVALID_{key.upper()}_BLOCK")
            values.append(child[child_indent:])
        return "\n".join(values).rstrip()
    raise WorkflowPolicyError(f"MISSING_{key.upper()}_BLOCK")


def _job_blocks(text: str) -> dict[str, str]:
    jobs_match = re.search(r"^jobs:\s*$", text, re.MULTILINE)
    if jobs_match is None:
        raise WorkflowPolicyError("MISSING_JOBS")
    section = _top_section(text, "jobs")
    direct_names: list[str] = []
    for line in section.splitlines():
        if not line.strip():
            continue
        indent = _line_indent(line)
        if indent < 2:
            raise WorkflowPolicyError("UNAPPROVED_JOB_GRAPH")
        if indent != 2:
            continue
        header = re.fullmatch(r"  ([A-Za-z0-9_-]+):", line)
        if header is None:
            raise WorkflowPolicyError("UNAPPROVED_JOB_GRAPH")
        direct_names.append(header.group(1))
    if not direct_names:
        raise WorkflowPolicyError("MISSING_JOBS")
    if len(direct_names) != len(set(direct_names)):
        raise WorkflowPolicyError("DUPLICATE_JOB")
    matches = list(JOB_HEADER_RE.finditer(section))
    if len(matches) != len(direct_names):
        raise WorkflowPolicyError("UNAPPROVED_JOB_GRAPH")
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        name = match.group(1)
        if name in blocks:
            raise WorkflowPolicyError("DUPLICATE_JOB")
        blocks[name] = section[start:end]
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


def _step_text_scalar(text: str, key: str) -> str | None:
    first = re.search(rf"^      - {re.escape(key)}:\s*(.*?)\s*$", text, re.MULTILINE)
    if first is not None:
        return first.group(1)
    child = re.search(rf"^        {re.escape(key)}:\s*(.*?)\s*$", text, re.MULTILINE)
    return None if child is None else child.group(1)


def _steps(block: str) -> list[Step]:
    matches = list(STEP_ITEM_RE.finditer(block))
    result: list[Step] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(block)
        text = block[start:end]
        result.append(Step(_step_text_scalar(text, "name"), text))
    return result


def _step_scalar(step: Step, key: str) -> str | None:
    return _step_text_scalar(step.text, key)


def _step_mapping(step: Step, key: str) -> dict[str, str]:
    return _mapping_after(step.text, key, 8)


def _step_keys(step: Step) -> set[str]:
    keys: list[str] = []
    first = re.match(r"^      - ([A-Za-z0-9_-]+):", step.text)
    if first is None:
        raise WorkflowPolicyError("INVALID_STEP_STRUCTURE")
    keys.append(first.group(1))
    for line in step.text.splitlines()[1:]:
        if _line_indent(line) != 8:
            continue
        stripped = line.strip()
        if ":" not in stripped:
            raise WorkflowPolicyError("INVALID_STEP_STRUCTURE")
        key, _ = stripped.split(":", 1)
        if re.fullmatch(r"[A-Za-z0-9_-]+", key) is None:
            raise WorkflowPolicyError("INVALID_STEP_STRUCTURE")
        keys.append(key)
    if len(keys) != len(set(keys)):
        raise WorkflowPolicyError("DUPLICATE_STEP_KEY")
    return {key for key in keys if key != "name"}


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


def _require_step_names(block: str, expected: list[str], code: str) -> list[Step]:
    steps = _steps(block)
    _require([step.name for step in steps] == expected, code)
    return steps


def _step_by_run(block: str, command: str) -> Step:
    matches = [step for step in _steps(block) if _step_scalar(step, "run") == command]
    _require(len(matches) == 1, "INVALID_RUN_STEP")
    return matches[0]


def _checkout_step(block: str) -> Step:
    matches = [step for step in _steps(block) if (_step_scalar(step, "uses") or "").startswith("actions/checkout@")]
    _require(len(matches) == 1, "INVALID_CHECKOUT_COUNT")
    return matches[0]


def _validate_checkout(step: Step) -> None:
    uses = _step_scalar(step, "uses")
    _require(uses is not None and FULL_SHA_ACTION_RE.fullmatch(uses) is not None, "UNPINNED_ACTION")
    _require(uses == CHECKOUT_ACTION, "INVALID_CHECKOUT_ACTION")
    with_values = _step_mapping(step, "with")
    _require(
        with_values.get("ref") == "${{ needs.static-authorisation.outputs.trusted_sha }}",
        "UNTRUSTED_CHECKOUT_REF",
    )
    _require(with_values.get("persist-credentials") == "false", "PERSISTED_CHECKOUT_CREDENTIALS")
    _require(with_values.get("fetch-depth") == "1", "INVALID_CHECKOUT_DEPTH")


def _validate_report_step(step: Step, expected_env: dict[str, str], prefix: str) -> None:
    _require(_step_scalar(step, "uses") == STATIC_GITHUB_SCRIPT_ACTION, f"INVALID_{prefix}_ACTION")
    _require(_step_mapping(step, "env") == expected_env, f"INVALID_{prefix}_ENV")
    _require(_step_mapping(step, "with") == {"script": "|"}, f"INVALID_{prefix}_WITH")
    _require(_literal_block_after(step.text, "script", 10) == EXPECTED_REPORT_SCRIPT, f"INVALID_{prefix}_SCRIPT")


def validate_workflow(text: str) -> None:
    _require(
        _keys_at_indent(text, 0, "INVALID_WORKFLOW_KEYS") == {"name", "on", "concurrency", "permissions", "jobs"},
        "INVALID_WORKFLOW_KEYS",
    )
    _require(re.search(r"^name: Phase 2 trusted intake\s*$", text, re.MULTILINE) is not None, "INVALID_WORKFLOW_NAME")
    expected_triggers = """  issue_comment:
    types: [created, edited, deleted]
  schedule:
    - cron: "17 * * * *"
  workflow_dispatch:
    inputs:
      operation:
        description: Trusted manual operation
        required: true
        default: reconcile
        type: choice
        options:
          - reconcile
          - scope_probe"""
    _require(_top_section(text, "on") == expected_triggers, "INVALID_TRIGGERS")
    _require(
        _mapping_after(text, "concurrency", 0)
        == {
            "group": "beads-allocation-v0.2-${{ github.repository }}",
            "cancel-in-progress": "false",
        },
        "INVALID_CONCURRENCY",
    )
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

    expected_job_keys = {
        "static-authorisation": {"runs-on", "permissions", "outputs", "steps"},
        "report-static-rejection": {"needs", "if", "runs-on", "permissions", "steps"},
        "source-revalidation": {"needs", "if", "runs-on", "permissions", "outputs", "steps"},
        "report-source-rejection": {"needs", "if", "runs-on", "permissions", "steps"},
        "trusted-live-check": {"needs", "if", "runs-on", "environment", "permissions", "steps"},
    }
    for name, block in jobs.items():
        _require(_keys_at_indent(block, 4, "INVALID_JOB_KEYS") == expected_job_keys[name], "INVALID_JOB_KEYS")
        _require(_job_scalar(block, "runs-on") == "ubuntu-24.04", "INVALID_JOB_RUNNER")
        for step in _steps(block):
            uses = _step_scalar(step, "uses")
            if uses is not None:
                _require(FULL_SHA_ACTION_RE.fullmatch(uses) is not None, "UNPINNED_ACTION")

    static = jobs["static-authorisation"]
    _require(_mapping_after(static, "permissions", 4) == {"contents": "read", "issues": "read"}, "INVALID_STATIC_PERMISSIONS")
    _require(
        _mapping_after(static, "outputs", 4)
        == {
            "action": "${{ steps.intake.outputs.action }}",
            "candidate_count": "${{ steps.intake.outputs.candidate_count }}",
            "candidate_set": "${{ steps.intake.outputs.candidate_set }}",
            "reason_code": "${{ steps.intake.outputs.reason_code }}",
            "rejection_count": "${{ steps.intake.outputs.rejection_count }}",
            "rejection_set": "${{ steps.intake.outputs.rejection_set }}",
            "report_issue_number": "${{ steps.intake.outputs.report_issue_number }}",
            "source_comment_id": "${{ steps.intake.outputs.source_comment_id }}",
            "trusted_sha": "${{ steps.intake.outputs.trusted_sha }}",
        },
        "INVALID_STATIC_OUTPUTS",
    )
    _require(_job_scalar(static, "environment") is None, "STATIC_ENVIRONMENT_PRESENT")
    _require("actions/checkout@" not in static, "STATIC_CHECKOUT_PRESENT")
    _require("PHASE2_ALLOCATOR_APP_PRIVATE_KEY" not in static, "STATIC_SECRET_PRESENT")
    _require("PHASE2_STATE_REPOSITORY_ID" not in static, "STATIC_STATE_CONFIG_PRESENT")
    static_steps = _steps(static)
    _require(len(static_steps) == 1, "INVALID_STATIC_STEPS")
    static_step = static_steps[0]
    _require(static_step.name == "Run immutable static intake without checkout", "INVALID_STATIC_STEP")
    _require(_step_keys(static_step) == {"id", "uses", "env", "with"}, "INVALID_STATIC_STEP")
    _require(_step_scalar(static_step, "id") == "intake", "INVALID_STATIC_STEP")
    _require(_step_scalar(static_step, "uses") == STATIC_GITHUB_SCRIPT_ACTION, "INVALID_STATIC_ACTION")
    _require(
        _step_mapping(static_step, "env")
        == {
            "GITHUB_TOKEN": "${{ github.token }}",
            "GITHUB_ACTOR": "${{ github.actor }}",
            "TRUSTED_SHA": "${{ github.workflow_sha }}",
        },
        "INVALID_STATIC_ENV",
    )
    _require(_step_mapping(static_step, "with") == {"script": "|"}, "INVALID_STATIC_WITH")
    _require(_literal_block_after(static_step.text, "script", 10) == EXPECTED_STATIC_SCRIPT, "INVALID_STATIC_SCRIPT")

    report_static = jobs["report-static-rejection"]
    _require(_needs(_job_scalar(report_static, "needs")) == {"static-authorisation"}, "INVALID_STATIC_REPORT_DEPENDENCY")
    report_static_steps = _require_step_names(
        report_static,
        ["Post bounded static rejection set"],
        "INVALID_STATIC_REPORT_STEPS",
    )
    _require(_step_keys(report_static_steps[0]) == {"uses", "env", "with"}, "INVALID_STATIC_REPORT_STEPS")
    _validate_report_step(
        report_static_steps[0],
        {
            "ISSUE_NUMBER": "${{ needs.static-authorisation.outputs.report_issue_number }}",
            "REJECTION_SET": "${{ needs.static-authorisation.outputs.rejection_set }}",
        },
        "STATIC_REPORT",
    )
    _require(
        _job_block_value(report_static, "if")
        == "needs.static-authorisation.outputs.rejection_count != '0' && vars.PHASE2_INTAKE_ENABLED == 'true'",
        "INVALID_STATIC_REPORT_CONDITION",
    )

    source = jobs["source-revalidation"]
    _require(_needs(_job_scalar(source, "needs")) == {"static-authorisation"}, "INVALID_SOURCE_DEPENDENCY")
    _require(
        _job_block_value(source, "if")
        == "needs.static-authorisation.outputs.action == 'live_check' && vars.PHASE2_INTAKE_ENABLED == 'true'",
        "INVALID_SOURCE_CONDITION",
    )
    _require(_mapping_after(source, "permissions", 4) == {"contents": "read", "issues": "read"}, "INVALID_SOURCE_PERMISSIONS")
    _require(
        _mapping_after(source, "outputs", 4)
        == {
            "action": "${{ steps.source.outputs.action }}",
            "candidate_count": "${{ steps.source.outputs.candidate_count }}",
            "candidate_set": "${{ steps.source.outputs.candidate_set }}",
            "reason_code": "${{ steps.source.outputs.reason_code }}",
            "rejection_count": "${{ steps.source.outputs.rejection_count }}",
            "rejection_set": "${{ steps.source.outputs.rejection_set }}",
            "report_issue_number": "${{ steps.source.outputs.report_issue_number }}",
            "source_comment_id": "${{ steps.source.outputs.source_comment_id }}",
        },
        "INVALID_SOURCE_OUTPUTS",
    )
    _require(_job_scalar(source, "environment") is None, "SOURCE_ENVIRONMENT_PRESENT")
    _require("PHASE2_ALLOCATOR_APP_PRIVATE_KEY" not in source, "SOURCE_SECRET_PRESENT")
    _require("PHASE2_STATE_REPOSITORY_ID" not in source, "SOURCE_STATE_CONFIG_PRESENT")
    source_steps = _require_step_names(
        source,
        [
            "Checkout immutable trusted content without persisted credentials",
            "Revalidate current source set without App credentials",
        ],
        "INVALID_SOURCE_STEPS",
    )
    _require(_step_keys(source_steps[0]) == {"uses", "with"}, "INVALID_SOURCE_STEPS")
    _require(_step_keys(source_steps[1]) == {"id", "env", "run"}, "INVALID_SOURCE_STEPS")
    _validate_checkout(source_steps[0])
    source_run = source_steps[1]
    _require(_step_scalar(source_run, "run") == "python3 -m phase2.source_revalidation", "INVALID_RUN_STEP")
    _require(
        _step_mapping(source_run, "env")
        == {
            "GITHUB_TOKEN": "${{ github.token }}",
            "PHASE2_CANDIDATE_SET": "${{ needs.static-authorisation.outputs.candidate_set }}",
            "PHASE2_TRUSTED_SHA": "${{ needs.static-authorisation.outputs.trusted_sha }}",
        },
        "INVALID_SOURCE_HANDOFF",
    )

    report_source = jobs["report-source-rejection"]
    _require(_needs(_job_scalar(report_source, "needs")) == {"source-revalidation"}, "INVALID_SOURCE_REPORT_DEPENDENCY")
    report_source_steps = _require_step_names(
        report_source,
        ["Post bounded source rejection set"],
        "INVALID_SOURCE_REPORT_STEPS",
    )
    _require(_step_keys(report_source_steps[0]) == {"uses", "env", "with"}, "INVALID_SOURCE_REPORT_STEPS")
    _validate_report_step(
        report_source_steps[0],
        {
            "ISSUE_NUMBER": "${{ needs.source-revalidation.outputs.report_issue_number }}",
            "REJECTION_SET": "${{ needs.source-revalidation.outputs.rejection_set }}",
        },
        "SOURCE_REPORT",
    )
    _require(
        _job_block_value(report_source, "if")
        == "needs.source-revalidation.outputs.rejection_count != '0' && vars.PHASE2_INTAKE_ENABLED == 'true'",
        "INVALID_SOURCE_REPORT_CONDITION",
    )

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
    expected_trusted_condition = (
        "always() && ( ( needs.static-authorisation.outputs.action == 'live_check' && "
        "vars.PHASE2_INTAKE_ENABLED == 'true' && needs.source-revalidation.result == 'success' && "
        "needs.source-revalidation.outputs.action == 'live_check' ) || "
        "needs.static-authorisation.outputs.action == 'scope_probe' )"
    )
    _require(_job_block_value(trusted, "if") == expected_trusted_condition, "INVALID_TRUSTED_CONDITION")
    trusted_steps = _require_step_names(
        trusted,
        [
            "Checkout immutable protected-default-branch content",
            "Revalidate live installation and bounded scope",
        ],
        "INVALID_TRUSTED_STEPS",
    )
    _require(_step_keys(trusted_steps[0]) == {"uses", "with"}, "INVALID_TRUSTED_STEPS")
    _require(_step_keys(trusted_steps[1]) == {"env", "run"}, "INVALID_TRUSTED_STEPS")
    _validate_checkout(trusted_steps[0])
    trusted_run = trusted_steps[1]
    _require(_step_scalar(trusted_run, "run") == "python3 -m phase2.trusted_intake", "INVALID_RUN_STEP")
    _require(
        _step_mapping(trusted_run, "env")
        == {
            "GITHUB_TOKEN": "${{ github.token }}",
            "PHASE2_ACTION": "${{ needs.static-authorisation.outputs.action }}",
            "PHASE2_ALLOCATOR_APP_ID": "${{ vars.PHASE2_ALLOCATOR_APP_ID }}",
            "PHASE2_ALLOCATOR_INSTALLATION_ID": "${{ vars.PHASE2_ALLOCATOR_INSTALLATION_ID }}",
            "PHASE2_ALLOCATOR_APP_PRIVATE_KEY": "${{ secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY }}",
            "PHASE2_SOURCE_COMMENT_ID": "${{ needs.source-revalidation.outputs.source_comment_id }}",
            "PHASE2_STATE_REPOSITORY_ID": "${{ secrets.PHASE2_STATE_REPOSITORY_ID }}",
            "PHASE2_TRUSTED_SHA": "${{ needs.static-authorisation.outputs.trusted_sha }}",
        },
        "INVALID_TRUSTED_ENV",
    )
    _require(trusted.count("secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY") == 1, "INVALID_PRIVATE_KEY_PLACEMENT")
    _require(trusted.count("secrets.PHASE2_STATE_REPOSITORY_ID") == 1, "INVALID_STATE_SECRET_PLACEMENT")

    outside_trusted = "\n".join(block for name, block in jobs.items() if name != "trusted-live-check")
    _require("secrets.PHASE2_ALLOCATOR_APP_PRIVATE_KEY" not in outside_trusted, "PRIVATE_KEY_OUTSIDE_TRUSTED_JOB")
    _require("secrets.PHASE2_STATE_REPOSITORY_ID" not in outside_trusted, "STATE_SECRET_OUTSIDE_TRUSTED_JOB")