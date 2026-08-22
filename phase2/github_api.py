from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


API_VERSION = "2022-11-28"
ERROR_BODY_MAX_BYTES = 2048
ERROR_MESSAGE_MAX_CHARS = 500
RATE_LIMIT_HEADER_MAX_CHARS = 64


def _bounded_header(headers: dict[str, str], name: str) -> str | None:
    value = headers.get(name)
    if value is None:
        return None
    return str(value)[:RATE_LIMIT_HEADER_MAX_CHARS]


def _is_rate_limited(status: int, message: str, headers: dict[str, str]) -> bool:
    if status == 429:
        return True
    if status != 403:
        return False
    if headers.get("retry-after"):
        return True
    if headers.get("x-ratelimit-remaining") == "0":
        return True
    lowered = message.lower()
    return "rate limit" in lowered or "secondary rate" in lowered


@dataclass
class GitHubAPIError(RuntimeError):
    status: int
    message: str
    retry_after: str | None = None
    rate_limit_remaining: str | None = None
    rate_limit_reset: str | None = None
    rate_limited: bool = False

    def __str__(self) -> str:
        return f"GitHub API returned HTTP {self.status}: {self.message}"

    def safe_diagnostic(self) -> dict[str, object]:
        diagnostic: dict[str, object] = {
            "http_status": self.status,
            "rate_limited": self.rate_limited,
        }
        if self.retry_after is not None:
            diagnostic["retry_after"] = self.retry_after[:RATE_LIMIT_HEADER_MAX_CHARS]
        if self.rate_limit_remaining is not None:
            diagnostic["rate_limit_remaining"] = self.rate_limit_remaining[
                :RATE_LIMIT_HEADER_MAX_CHARS
            ]
        if self.rate_limit_reset is not None:
            diagnostic["rate_limit_reset"] = self.rate_limit_reset[
                :RATE_LIMIT_HEADER_MAX_CHARS
            ]
        return diagnostic


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
            payload = exc.read(ERROR_BODY_MAX_BYTES).decode("utf-8", "replace")
            message = payload[:ERROR_MESSAGE_MAX_CHARS]
            response_headers = {
                key.lower(): value for key, value in (exc.headers.items() if exc.headers else ())
            }
            raise GitHubAPIError(
                exc.code,
                message,
                retry_after=_bounded_header(response_headers, "retry-after"),
                rate_limit_remaining=_bounded_header(
                    response_headers, "x-ratelimit-remaining"
                ),
                rate_limit_reset=_bounded_header(response_headers, "x-ratelimit-reset"),
                rate_limited=_is_rate_limited(exc.code, message, response_headers),
            ) from exc

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
