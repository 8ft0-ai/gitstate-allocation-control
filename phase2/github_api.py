from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


API_VERSION = "2022-11-28"


@dataclass
class GitHubAPIError(RuntimeError):
    status: int
    message: str

    def __str__(self) -> str:
        return f"GitHub API returned HTTP {self.status}: {self.message}"


class GitHubAPI:
    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        self.token = token
        self.api_url = api_url.rstrip("/")

    def request_with_status(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str], int]:
        data = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.api_url + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "gitstate-phase2-intake",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read()
                decoded = None if not payload else json.loads(payload)
                return (
                    decoded,
                    {key.lower(): value for key, value in response.headers.items()},
                    int(response.status),
                )
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode("utf-8", "replace")
            raise GitHubAPIError(exc.code, payload[:500]) from exc

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, str]]:
        payload, headers, _ = self.request_with_status(method, path, body)
        return payload, headers

    def get(self, path: str) -> Any:
        return self.request("GET", path)[0]

    def post(self, path: str, body: dict[str, Any]) -> Any:
        return self.request("POST", path, body)[0]
