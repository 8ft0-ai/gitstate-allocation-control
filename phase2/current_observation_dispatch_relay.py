from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping


FIXED_REPOSITORY = "8ft0-ai/gitstate-allocation-control"
FIXED_OWNER = "8ft0-ai"
FIXED_WORKFLOW = ".github/workflows/phase2-adversarial.yml"
FIXED_OPERATION = "current_observation"
FIXED_METHOD = "workflow_dispatch"
API_HOST = "api.github.com"
API_VERSION = "2026-03-10"
REQUEST_TITLE = "[gitstate-current-observation-dispatch/v1]"
REQUEST_CONTRACT = "gitstate-current-observation-dispatch/v1"
CONSUMPTION_CONTRACT = "gitstate-current-observation-dispatch-consumption/v1"
BOT_LOGIN = "github-actions[bot]"
REF_PATTERN = re.compile(r"^refs/tags/gitstate-current-observation/([0-9a-f]{40})$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
MAX_CERTIFICATE_B64_CHARS = 16_384
MAX_CERTIFICATE_DER_BYTES = 12_288
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_COMMENT_PAGES = 100
COMMENTS_PER_PAGE = 100
HTTP_TIMEOUT_SECONDS = 30
DISPATCH_ENDPOINT = (
    "/repos/8ft0-ai/gitstate-allocation-control/actions/workflows/"
    ".github%2Fworkflows%2Fphase2-adversarial.yml/dispatches"
)


class RelayError(RuntimeError):
    pass


@dataclass(frozen=True)
class ValidatedRequest:
    repository_id: int
    issue_id: int
    issue_number: int
    body: str
    body_sha256: str
    ref: str
    certificate_b64: str

    @property
    def ref_sha(self) -> str:
        match = REF_PATTERN.fullmatch(self.ref)
        if match is None:
            raise RelayError("REQUEST_REF_INVALID")
        return match.group(1)

    @property
    def attempt_identity(self) -> str:
        return f"{REQUEST_CONTRACT}:{self.repository_id}:{self.issue_id}"


@dataclass
class ExecutionProgress:
    request: ValidatedRequest | None = None
    marker_id: int | None = None


@dataclass(frozen=True)
class DispatchOutcome:
    outcome: str
    http_status: int | None = None
    workflow_run_id: int | None = None
    run_url: str | None = None
    html_url: str | None = None

    def safe_payload(self) -> dict[str, object]:
        dispatch_state = "NOT_SENT" if self.outcome == "NOT_SENT" else "SEND_STARTED"
        payload: dict[str, object] = {
            "dispatch_state": dispatch_state,
            "transport_outcome": self.outcome,
        }
        if self.http_status is not None:
            payload["http_status"] = self.http_status
        if self.workflow_run_id is not None:
            payload["workflow_run_id"] = self.workflow_run_id
        if self.run_url is not None:
            payload["run_url"] = self.run_url
        if self.html_url is not None:
            payload["html_url"] = self.html_url
        return payload


def _positive_int(value: object, code: str) -> int:
    if type(value) is not int or value <= 0:
        raise RelayError(code)
    return value


def _env_positive_int(values: Mapping[str, str], name: str) -> int:
    try:
        value = int(values.get(name, ""))
    except (TypeError, ValueError) as exc:
        raise RelayError(f"{name}_INVALID") from exc
    if value <= 0:
        raise RelayError(f"{name}_INVALID")
    return value


def _load_json_object_strict(text: str, *, code: str) -> dict[str, object]:
    if not isinstance(text, str):
        raise RelayError(code)

    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise RelayError(code)
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=pairs_hook)
    except RelayError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise RelayError(code) from exc
    if not isinstance(value, dict):
        raise RelayError(code)
    return value


def parse_request_body(body: str) -> tuple[str, str]:
    if not isinstance(body, str) or not body or "\n" in body or "\r" in body:
        raise RelayError("REQUEST_BODY_INVALID")
    payload = _load_json_object_strict(body, code="REQUEST_BODY_INVALID")
    if set(payload) != {"ref", "current_observation_recipient_cert_b64"}:
        raise RelayError("REQUEST_SCHEMA_INVALID")

    ref = payload.get("ref")
    certificate = payload.get("current_observation_recipient_cert_b64")
    if not isinstance(ref, str) or REF_PATTERN.fullmatch(ref) is None:
        raise RelayError("REQUEST_REF_INVALID")
    if (
        not isinstance(certificate, str)
        or not certificate
        or len(certificate) > MAX_CERTIFICATE_B64_CHARS
        or not certificate.isascii()
    ):
        raise RelayError("REQUEST_CERTIFICATE_INVALID")
    try:
        decoded = base64.b64decode(certificate, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RelayError("REQUEST_CERTIFICATE_INVALID") from exc
    if not decoded or len(decoded) > MAX_CERTIFICATE_DER_BYTES:
        raise RelayError("REQUEST_CERTIFICATE_INVALID")
    return ref, certificate


class GitHubRelayAPI:
    """Fixed-repository GitHub API client with no retry or redirect machinery."""

    def __init__(
        self,
        token: str,
        *,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
    ) -> None:
        if not isinstance(token, str) or not token:
            raise RelayError("GITHUB_TOKEN_MISSING")
        self._token = token
        self._connection_factory = connection_factory
        self.dispatch_calls = 0

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "gitstate-current-observation-dispatch-relay",
        }

    def _connection(self) -> Any:
        return self._connection_factory(API_HOST, 443, timeout=HTTP_TIMEOUT_SECONDS)

    @staticmethod
    def _read_response(response: Any) -> bytes:
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise RelayError("GITHUB_RESPONSE_TOO_LARGE")
        return payload

    @staticmethod
    def _decode_json(payload: bytes, code: str) -> object:
        if not payload:
            raise RelayError(code)
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RelayError(code) from exc

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, object] | None = None,
        expected_status: int = 200,
        error_code: str,
    ) -> object:
        data = (
            None
            if body is None
            else json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        try:
            connection = self._connection()
        except Exception as exc:
            raise RelayError(error_code) from exc
        try:
            connection.request(method, path, body=data, headers=self._headers())
            response = connection.getresponse()
            payload = self._read_response(response)
            status = int(response.status)
        except RelayError:
            raise
        except Exception as exc:
            raise RelayError(error_code) from exc
        finally:
            try:
                connection.close()
            except Exception:
                pass
        if status != expected_status:
            raise RelayError(f"{error_code}_HTTP_{status}")
        return self._decode_json(payload, error_code)

    def get_issue(self, issue_number: int) -> Mapping[str, object]:
        payload = self._request_json(
            "GET",
            f"/repos/{FIXED_REPOSITORY}/issues/{issue_number}",
            error_code="REQUEST_ISSUE_READ_FAILED",
        )
        if not isinstance(payload, Mapping):
            raise RelayError("REQUEST_ISSUE_READ_INVALID")
        return payload

    def list_issue_comments(self, issue_number: int) -> list[Mapping[str, object]]:
        comments: list[Mapping[str, object]] = []
        for page in range(1, MAX_COMMENT_PAGES + 1):
            payload = self._request_json(
                "GET",
                (
                    f"/repos/{FIXED_REPOSITORY}/issues/{issue_number}/comments"
                    f"?per_page={COMMENTS_PER_PAGE}&page={page}"
                ),
                error_code="REQUEST_COMMENTS_READ_FAILED",
            )
            if not isinstance(payload, list) or any(
                not isinstance(item, Mapping) for item in payload
            ):
                raise RelayError("REQUEST_COMMENTS_READ_INVALID")
            comments.extend(payload)
            if len(payload) < COMMENTS_PER_PAGE:
                return comments
        raise RelayError("REQUEST_COMMENTS_TOO_LARGE")

    def get_governed_tag(self, ref: str) -> Mapping[str, object]:
        match = REF_PATTERN.fullmatch(ref)
        if match is None:
            raise RelayError("REQUEST_REF_INVALID")
        sha = match.group(1)
        payload = self._request_json(
            "GET",
            (
                f"/repos/{FIXED_REPOSITORY}/git/ref/tags/"
                f"gitstate-current-observation/{sha}"
            ),
            error_code="REQUEST_TAG_READ_FAILED",
        )
        if not isinstance(payload, Mapping):
            raise RelayError("REQUEST_TAG_READ_INVALID")
        return payload

    def create_consumption_comment(
        self, issue_number: int, body: str
    ) -> Mapping[str, object]:
        payload = self._request_json(
            "POST",
            f"/repos/{FIXED_REPOSITORY}/issues/{issue_number}/comments",
            body={"body": body},
            expected_status=201,
            error_code="CONSUMPTION_MARKER_WRITE_AMBIGUOUS",
        )
        if not isinstance(payload, Mapping):
            raise RelayError("CONSUMPTION_MARKER_ACK_INVALID")
        return payload

    def dispatch_current_observation(
        self,
        *,
        ref: str,
        certificate_b64: str,
    ) -> DispatchOutcome:
        # This is the only call site in the module capable of sending workflow_dispatch.
        self.dispatch_calls += 1
        if self.dispatch_calls != 1:
            raise RelayError("DISPATCH_MUTATION_COUNT_EXCEEDED")
        body = {
            "ref": ref,
            "inputs": {
                "operation": FIXED_OPERATION,
                "current_observation_recipient_cert_b64": certificate_b64,
            },
        }
        data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            connection = self._connection()
        except Exception:
            return DispatchOutcome("NOT_SENT")
        try:
            # SEND_STARTED: every condition after entering request() is terminal and
            # must never be retried by this execution.
            connection.request(
                "POST",
                DISPATCH_ENDPOINT,
                body=data,
                headers=self._headers(),
            )
            response = connection.getresponse()
            payload = self._read_response(response)
            status = int(response.status)
        except Exception:
            try:
                connection.close()
            except Exception:
                pass
            return DispatchOutcome("SENT_OR_ACCEPTANCE_UNKNOWN")
        finally:
            try:
                connection.close()
            except Exception:
                pass

        if status != 200:
            return DispatchOutcome("SENT_OR_ACCEPTANCE_UNKNOWN", http_status=status)
        try:
            decoded = self._decode_json(payload, "DISPATCH_SUCCESS_BODY_INVALID")
        except RelayError:
            return DispatchOutcome("SENT_OR_ACCEPTANCE_UNKNOWN", http_status=status)
        if not isinstance(decoded, Mapping):
            return DispatchOutcome("SENT_OR_ACCEPTANCE_UNKNOWN", http_status=status)
        run_id = decoded.get("workflow_run_id")
        run_url = decoded.get("run_url")
        html_url = decoded.get("html_url")
        if type(run_id) is not int or run_id <= 0:
            return DispatchOutcome("SENT_OR_ACCEPTANCE_UNKNOWN", http_status=status)
        expected_run_url = (
            f"https://api.github.com/repos/{FIXED_REPOSITORY}/actions/runs/{run_id}"
        )
        expected_html_url = (
            f"https://github.com/{FIXED_REPOSITORY}/actions/runs/{run_id}"
        )
        if run_url != expected_run_url or html_url != expected_html_url:
            return DispatchOutcome("SENT_OR_ACCEPTANCE_UNKNOWN", http_status=status)
        return DispatchOutcome(
            "ACCEPTED",
            http_status=status,
            workflow_run_id=run_id,
            run_url=run_url,
            html_url=html_url,
        )


def _load_event(values: Mapping[str, str]) -> Mapping[str, object]:
    event_path = values.get("GITHUB_EVENT_PATH", "")
    if not event_path:
        raise RelayError("EVENT_PATH_MISSING")
    try:
        text = Path(event_path).read_text(encoding="utf-8")
        payload = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RelayError("EVENT_PAYLOAD_INVALID") from exc
    if not isinstance(payload, Mapping):
        raise RelayError("EVENT_PAYLOAD_INVALID")
    return payload


def _require_runtime_identity(values: Mapping[str, str]) -> None:
    required = {
        "GITHUB_REPOSITORY": FIXED_REPOSITORY,
        "GITHUB_EVENT_NAME": "issues",
        "GITHUB_ACTOR": FIXED_OWNER,
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_SERVER_URL": "https://github.com",
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            raise RelayError(f"{key}_MISMATCH")


def _event_request(
    values: Mapping[str, str],
    event: Mapping[str, object],
) -> ValidatedRequest:
    _require_runtime_identity(values)
    if event.get("action") != "opened":
        raise RelayError("EVENT_ACTION_MISMATCH")

    repository = event.get("repository")
    sender = event.get("sender")
    issue = event.get("issue")
    if not all(isinstance(item, Mapping) for item in (repository, sender, issue)):
        raise RelayError("EVENT_IDENTITY_INVALID")

    assert isinstance(repository, Mapping)
    assert isinstance(sender, Mapping)
    assert isinstance(issue, Mapping)

    if repository.get("full_name") != FIXED_REPOSITORY:
        raise RelayError("EVENT_REPOSITORY_MISMATCH")
    repository_id = _positive_int(repository.get("id"), "EVENT_REPOSITORY_ID_INVALID")
    runtime_repository_id = _env_positive_int(values, "GITHUB_REPOSITORY_ID")
    if repository_id != runtime_repository_id:
        raise RelayError("EVENT_REPOSITORY_ID_MISMATCH")

    if sender.get("login") != FIXED_OWNER:
        raise RelayError("EVENT_SENDER_MISMATCH")
    user = issue.get("user")
    if not isinstance(user, Mapping) or user.get("login") != FIXED_OWNER:
        raise RelayError("EVENT_ISSUE_CREATOR_MISMATCH")
    if issue.get("author_association") != "OWNER":
        raise RelayError("EVENT_AUTHOR_ASSOCIATION_MISMATCH")
    if issue.get("title") != REQUEST_TITLE:
        raise RelayError("EVENT_TITLE_MISMATCH")
    if issue.get("state") != "open":
        raise RelayError("EVENT_ISSUE_STATE_MISMATCH")

    issue_id = _positive_int(issue.get("id"), "EVENT_ISSUE_ID_INVALID")
    issue_number = _positive_int(issue.get("number"), "EVENT_ISSUE_NUMBER_INVALID")
    body = issue.get("body")
    if not isinstance(body, str):
        raise RelayError("EVENT_BODY_INVALID")
    ref, certificate = parse_request_body(body)
    return ValidatedRequest(
        repository_id=repository_id,
        issue_id=issue_id,
        issue_number=issue_number,
        body=body,
        body_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        ref=ref,
        certificate_b64=certificate,
    )


def _revalidate_current_issue(api: GitHubRelayAPI, request: ValidatedRequest) -> None:
    current = api.get_issue(request.issue_number)
    if current.get("id") != request.issue_id or current.get("number") != request.issue_number:
        raise RelayError("CURRENT_ISSUE_IDENTITY_MISMATCH")
    user = current.get("user")
    if not isinstance(user, Mapping) or user.get("login") != FIXED_OWNER:
        raise RelayError("CURRENT_ISSUE_CREATOR_MISMATCH")
    if current.get("author_association") != "OWNER":
        raise RelayError("CURRENT_ISSUE_AUTHOR_ASSOCIATION_MISMATCH")
    if current.get("title") != REQUEST_TITLE:
        raise RelayError("CURRENT_ISSUE_TITLE_MISMATCH")
    if current.get("state") != "open":
        raise RelayError("CURRENT_ISSUE_STATE_MISMATCH")
    if current.get("body") != request.body:
        raise RelayError("CURRENT_ISSUE_BODY_MISMATCH")
    ref, certificate = parse_request_body(request.body)
    if ref != request.ref or certificate != request.certificate_b64:
        raise RelayError("CURRENT_ISSUE_SCHEMA_MISMATCH")


def _revalidate_tag(api: GitHubRelayAPI, request: ValidatedRequest) -> None:
    payload = api.get_governed_tag(request.ref)
    obj = payload.get("object")
    if not isinstance(obj, Mapping):
        raise RelayError("REQUEST_TAG_TARGET_INVALID")
    if obj.get("type") != "commit" or obj.get("sha") != request.ref_sha:
        raise RelayError("REQUEST_TAG_TARGET_MISMATCH")


def _workflow_sha(values: Mapping[str, str]) -> str:
    value = values.get("GITHUB_WORKFLOW_SHA", "")
    if SHA40.fullmatch(value) is None:
        raise RelayError("RELAY_WORKFLOW_SHA_INVALID")
    return value


def _marker_body(request: ValidatedRequest, values: Mapping[str, str]) -> str:
    payload = {
        "attempt_identity": request.attempt_identity,
        "relay_run_id": _env_positive_int(values, "GITHUB_RUN_ID"),
        "relay_workflow_sha": _workflow_sha(values),
        "request_body_sha256": request.body_sha256,
        "request_issue_id": request.issue_id,
        "request_issue_number": request.issue_number,
        "validated_ref": request.ref,
    }
    return (
        CONSUMPTION_CONTRACT
        + "\n"
        + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    )


def _parse_bot_marker(
    comment: Mapping[str, object],
) -> tuple[int, Mapping[str, object]] | None:
    user = comment.get("user")
    body = comment.get("body")
    if not isinstance(user, Mapping) or user.get("login") != BOT_LOGIN:
        return None
    if not isinstance(body, str) or not body.startswith(CONSUMPTION_CONTRACT):
        return None
    prefix = CONSUMPTION_CONTRACT + "\n"
    if not body.startswith(prefix):
        raise RelayError("CONSUMPTION_MARKER_AMBIGUOUS")
    payload = _load_json_object_strict(
        body[len(prefix) :],
        code="CONSUMPTION_MARKER_AMBIGUOUS",
    )
    required = {
        "attempt_identity",
        "relay_run_id",
        "relay_workflow_sha",
        "request_body_sha256",
        "request_issue_id",
        "request_issue_number",
        "validated_ref",
    }
    if set(payload) != required:
        raise RelayError("CONSUMPTION_MARKER_AMBIGUOUS")
    comment_id = _positive_int(comment.get("id"), "CONSUMPTION_MARKER_ID_INVALID")
    return comment_id, payload


def _matching_markers(
    comments: list[Mapping[str, object]],
    request: ValidatedRequest,
) -> list[tuple[int, Mapping[str, object]]]:
    result: list[tuple[int, Mapping[str, object]]] = []
    for comment in comments:
        parsed = _parse_bot_marker(comment)
        if parsed is None:
            continue
        comment_id, payload = parsed
        if payload.get("attempt_identity") == request.attempt_identity:
            result.append((comment_id, payload))
    return result


def _validate_marker_payload(
    payload: Mapping[str, object],
    *,
    request: ValidatedRequest,
    expected_body: str,
    values: Mapping[str, str],
) -> None:
    prefix = CONSUMPTION_CONTRACT + "\n"
    expected = _load_json_object_strict(
        expected_body[len(prefix) :],
        code="CONSUMPTION_MARKER_INTERNAL_INVALID",
    )
    if dict(payload) != expected:
        raise RelayError("CONSUMPTION_MARKER_MISMATCH")
    if payload.get("attempt_identity") != request.attempt_identity:
        raise RelayError("CONSUMPTION_MARKER_MISMATCH")
    if payload.get("relay_workflow_sha") != _workflow_sha(values):
        raise RelayError("CONSUMPTION_MARKER_MISMATCH")


def validate_request(
    values: Mapping[str, str],
    *,
    api: GitHubRelayAPI,
    event: Mapping[str, object] | None = None,
) -> ValidatedRequest:
    request = _event_request(values, _load_event(values) if event is None else event)
    _revalidate_current_issue(api, request)
    return request


def consume_and_dispatch(
    values: Mapping[str, str],
    *,
    api: GitHubRelayAPI,
    event: Mapping[str, object] | None = None,
    progress: ExecutionProgress | None = None,
) -> tuple[ValidatedRequest, int, DispatchOutcome]:
    execution = ExecutionProgress() if progress is None else progress
    request = validate_request(values, api=api, event=event)
    execution.request = request

    _revalidate_tag(api, request)
    comments = api.list_issue_comments(request.issue_number)
    if _matching_markers(comments, request):
        raise RelayError("REQUEST_ALREADY_CONSUMED")

    marker_body = _marker_body(request, values)
    created = api.create_consumption_comment(request.issue_number, marker_body)
    created_id = _positive_int(created.get("id"), "CONSUMPTION_MARKER_ACK_INVALID")
    created_user = created.get("user")
    if (
        not isinstance(created_user, Mapping)
        or created_user.get("login") != BOT_LOGIN
        or created.get("body") != marker_body
    ):
        raise RelayError("CONSUMPTION_MARKER_ACK_INVALID")
    execution.marker_id = created_id

    comments = api.list_issue_comments(request.issue_number)
    matches = _matching_markers(comments, request)
    if len(matches) != 1 or matches[0][0] != created_id:
        raise RelayError("CONSUMPTION_MARKER_REREAD_INVALID")
    _validate_marker_payload(
        matches[0][1],
        request=request,
        expected_body=marker_body,
        values=values,
    )

    _revalidate_current_issue(api, request)
    _revalidate_tag(api, request)

    outcome = api.dispatch_current_observation(
        ref=request.ref,
        certificate_b64=request.certificate_b64,
    )
    return request, created_id, outcome


def _safe_execution_payload(
    *,
    values: Mapping[str, str],
    request: ValidatedRequest | None,
    marker_id: int | None,
    outcome: DispatchOutcome,
    reason_code: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "contract": REQUEST_CONTRACT,
        "fixed_repository": FIXED_REPOSITORY,
        "fixed_workflow": FIXED_WORKFLOW,
        "fixed_operation": FIXED_OPERATION,
        "fixed_method": FIXED_METHOD,
        "automatic_retry": False,
        "fallback_transport": False,
        "max_dispatch_mutation_requests": 1,
        **outcome.safe_payload(),
    }
    workflow_sha = values.get("GITHUB_WORKFLOW_SHA", "")
    if SHA40.fullmatch(workflow_sha) is not None:
        payload["relay_workflow_sha"] = workflow_sha
    if request is not None:
        payload.update(
            {
                "attempt_identity": request.attempt_identity,
                "request_issue_id": request.issue_id,
                "request_body_sha256": request.body_sha256,
                "validated_ref": request.ref,
            }
        )
    if marker_id is not None:
        payload["consumption_comment_id"] = marker_id
    if reason_code is not None:
        payload["reason_code"] = reason_code
    return payload


def _write_summary(values: Mapping[str, str], payload: Mapping[str, object]) -> bool:
    path = values.get("GITHUB_STEP_SUMMARY")
    if not path:
        return False
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("### Current observation dispatch relay\n\n```json\n")
            handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            handle.write("\n```\n")
    except OSError:
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in (["validate"], ["consume-and-dispatch"]):
        print(json.dumps({"status": "BLOCKED", "reason_code": "RELAY_ARGUMENT_INVALID"}))
        return 2

    values = os.environ
    progress = ExecutionProgress()
    try:
        api = GitHubRelayAPI(values.get("GITHUB_TOKEN", ""))
        if arguments == ["validate"]:
            progress.request = validate_request(values, api=api)
            payload = _safe_execution_payload(
                values=values,
                request=progress.request,
                marker_id=None,
                outcome=DispatchOutcome("NOT_SENT"),
            )
            print(json.dumps({"status": "VALIDATED", **payload}, sort_keys=True))
            return 0

        request, marker_id, outcome = consume_and_dispatch(
            values,
            api=api,
            progress=progress,
        )
        payload = _safe_execution_payload(
            values=values,
            request=request,
            marker_id=marker_id,
            outcome=outcome,
        )
        summary_written = _write_summary(values, payload)
        if not summary_written:
            print(
                json.dumps(
                    {
                        "status": "AUDIT_SUMMARY_WRITE_FAILED",
                        "audit_summary_written": False,
                        **payload,
                    },
                    sort_keys=True,
                )
            )
            return 2

        status = {
            "NOT_SENT": "DISPATCH_NOT_SENT",
            "ACCEPTED": "DISPATCH_ACCEPTED",
            "SENT_OR_ACCEPTANCE_UNKNOWN": "DISPATCH_TERMINAL_UNKNOWN",
        }.get(outcome.outcome, "DISPATCH_OUTCOME_INVALID")
        print(
            json.dumps(
                {
                    "status": status,
                    "audit_summary_written": True,
                    **payload,
                },
                sort_keys=True,
            )
        )
        return 0 if outcome.outcome == "ACCEPTED" else 2
    except RelayError as exc:
        payload = _safe_execution_payload(
            values=values,
            request=progress.request,
            marker_id=progress.marker_id,
            outcome=DispatchOutcome("NOT_SENT"),
            reason_code=str(exc).split(":", 1)[0],
        )
        summary_written = False
        if arguments == ["consume-and-dispatch"]:
            summary_written = _write_summary(values, payload)
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "audit_summary_written": summary_written,
                    **payload,
                },
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
