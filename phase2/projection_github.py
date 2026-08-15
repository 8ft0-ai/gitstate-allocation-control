"""Bounded GitHub issue adapter for Workstream C.

The adapter consumes only a caller-supplied control token through ``GitHubAPI``.
It has no state-repository operation and performs complete issue-comment
pagination before reconciliation decisions are made.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .github_api import GitHubAPI
from .reconciliation import DurableComment, PostedComment

REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubIssueGateway:
    def __init__(self, api: GitHubAPI, repository: str) -> None:
        if not REPOSITORY_RE.fullmatch(repository):
            raise ValueError("invalid repository")
        self.api = api
        self.repository = repository

    @property
    def _base(self) -> str:
        return f"/repos/{self.repository}"

    @staticmethod
    def _posted(value: Any) -> PostedComment:
        if not isinstance(value, dict):
            raise ValueError("GitHub comment response is not an object")
        comment_id = value.get("id")
        html_url = value.get("html_url")
        if not isinstance(comment_id, int) or comment_id <= 0 or not isinstance(html_url, str):
            raise ValueError("GitHub comment response is incomplete")
        return PostedComment(comment_id, html_url)

    def list_comments(self, issue_number: int) -> list[DurableComment]:
        if issue_number <= 0:
            raise ValueError("issue_number must be positive")
        comments: list[DurableComment] = []
        page = 1
        while True:
            value = self.api.get(
                f"{self._base}/issues/{issue_number}/comments?per_page=100&page={page}"
            )
            if not isinstance(value, list):
                raise ValueError("GitHub comments response is not a list")
            for item in value:
                if not isinstance(item, dict):
                    raise ValueError("GitHub comment response item is not an object")
                comment_id = item.get("id")
                body = item.get("body")
                html_url = item.get("html_url")
                if (
                    not isinstance(comment_id, int)
                    or comment_id <= 0
                    or not isinstance(body, str)
                    or not isinstance(html_url, str)
                ):
                    raise ValueError("GitHub comment response item is incomplete")
                comments.append(DurableComment(comment_id, body, html_url))
            if len(value) < 100:
                break
            page += 1
        return comments

    def post_projection(self, issue_number: int, body: str) -> PostedComment:
        return self._posted(
            self.api.post(
                f"{self._base}/issues/{issue_number}/comments",
                {"body": body},
            )
        )

    def invalidate_projection(
        self, issue_number: int, comment: DurableComment, reason_code: str
    ) -> PostedComment:
        body = json.dumps(
            {
                "execution_may_begin": False,
                "projection_comment_id": comment.comment_id,
                "projection_url": comment.html_url,
                "protocol": "beads-allocation/v0.2",
                "reason_code": reason_code,
                "type": "PROJECTION_INVALIDATED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return self._posted(
            self.api.post(
                f"{self._base}/issues/{issue_number}/comments",
                {"body": body},
            )
        )

    def post_summary(self, issue_number: int, body: str) -> PostedComment:
        return self._posted(
            self.api.post(
                f"{self._base}/issues/{issue_number}/comments",
                {"body": body},
            )
        )
