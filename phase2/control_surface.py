from __future__ import annotations

from typing import Any

from .github_api import GitHubAPI


class ControlSurfaceError(RuntimeError):
    pass


def validate_control_surface(api: GitHubAPI, owner: str, repository: str, policy: dict[str, Any]) -> dict[str, Any]:
    issue_number = policy.get("allocation_issue_number")
    required_label = policy.get("allocation_issue_required_label")
    required_state = policy.get("allocation_issue_required_state")
    if not isinstance(issue_number, int) or issue_number <= 0:
        raise ControlSurfaceError("INVALID_CONTROL_SURFACE_POLICY")
    if not isinstance(required_label, str) or not required_label:
        raise ControlSurfaceError("INVALID_CONTROL_SURFACE_POLICY")
    if required_state != "open":
        raise ControlSurfaceError("INVALID_CONTROL_SURFACE_POLICY")

    issue = api.get(f"/repos/{owner}/{repository}/issues/{issue_number}")
    if not isinstance(issue, dict):
        raise ControlSurfaceError("CONTROL_SURFACE_MISMATCH")
    if issue.get("number") != issue_number or issue.get("state") != required_state:
        raise ControlSurfaceError("CONTROL_SURFACE_MISMATCH")
    if isinstance(issue.get("pull_request"), dict):
        raise ControlSurfaceError("CONTROL_SURFACE_MISMATCH")

    labels = issue.get("labels")
    if not isinstance(labels, list):
        raise ControlSurfaceError("CONTROL_SURFACE_MISMATCH")
    names: set[str] = set()
    for label in labels:
        if isinstance(label, dict) and isinstance(label.get("name"), str):
            names.add(label["name"])
        elif isinstance(label, str):
            names.add(label)
        else:
            raise ControlSurfaceError("CONTROL_SURFACE_MISMATCH")
    if required_label not in names:
        raise ControlSurfaceError("CONTROL_SURFACE_MISMATCH")
    return issue
