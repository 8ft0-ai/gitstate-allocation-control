from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from .parser import PREFIX, RequestError, malformed_descriptor, parse_request
from .policy import AuthorisationError, authorise


class DiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    comment_id: int
    disposition: str
    reason_code: str | None
    payload_hash: str
    request_id: str
    principal: str | None


@dataclass(frozen=True)
class CanonicalSource:
    comment_id: int
    exact_body_sha256: str


def reconcile_canonical_sources(canonical_sources: Iterable[CanonicalSource], current_comments: Iterable[dict[str, Any]]) -> dict[int, str]:
    """Report post-ingress mutation without changing the canonical result."""
    import hashlib

    current = {comment["id"]: comment for comment in current_comments}
    findings: dict[int, str] = {}
    for source in canonical_sources:
        comment = current.get(source.comment_id)
        if comment is None:
            findings[source.comment_id] = "SOURCE_COMMENT_DELETED"
            continue
        body = comment.get("body")
        digest = "" if not isinstance(body, str) else hashlib.sha256(body.encode("utf-8")).hexdigest()
        if digest != source.exact_body_sha256:
            findings[source.comment_id] = "SOURCE_COMMENT_EDITED"
    return findings


def paginate_comments(fetch_page: Callable[[int, int], tuple[list[dict[str, Any]], bool]], per_page: int = 100) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    seen_pages: set[int] = set()
    seen_ids: set[int] = set()
    page = 1
    last_id = -1
    while True:
        if page in seen_pages:
            raise DiscoveryError("REPEATED_CURSOR")
        seen_pages.add(page)
        batch, has_next = fetch_page(page, per_page)
        if not isinstance(batch, list):
            raise DiscoveryError("INCOMPLETE_PAGE")
        for comment in batch:
            comment_id = comment.get("id")
            if not isinstance(comment_id, int):
                raise DiscoveryError("INVALID_COMMENT_ID")
            if comment_id in seen_ids:
                raise DiscoveryError("REPEATED_COMMENT")
            if comment_id <= last_id:
                raise DiscoveryError("DECREASING_COMMENT_ID")
            seen_ids.add(comment_id)
            last_id = comment_id
            comments.append(comment)
        if has_next:
            if not batch:
                raise DiscoveryError("AMBIGUOUS_TERMINATION")
            page += 1
            continue
        if len(batch) == per_page:
            probe, probe_has_next = fetch_page(page + 1, per_page)
            if probe or probe_has_next:
                raise DiscoveryError("MISSING_NEXT_CURSOR")
        break
    return comments


def classify(comment: dict[str, Any], repository: str, policy: dict[str, Any]) -> Candidate | None:
    body_text = comment.get("body")
    if not isinstance(body_text, str):
        return None
    body = body_text.encode("utf-8", "strict")
    if not body.startswith(PREFIX):
        return None
    comment_id = comment["id"]
    if comment.get("updated_at") != comment.get("created_at"):
        return Candidate(comment_id, "REJECTED", "SOURCE_COMMENT_EDITED_BEFORE_INGRESS", "", f"edited:{repository}:{comment_id}", None)
    try:
        parsed = parse_request(body)
    except RequestError as exc:
        invalid = malformed_descriptor(body, repository, comment_id, exc)
        return Candidate(comment_id, "REJECTED", invalid.reason_code, invalid.payload_hash, invalid.request_id, None)
    try:
        principal = authorise(comment, parsed, policy)
    except AuthorisationError as exc:
        return Candidate(comment_id, "REJECTED", exc.code, parsed.payload_hash, parsed.payload["request_id"], None)
    return Candidate(comment_id, "READY_FOR_LIVE_CHECK", None, parsed.payload_hash, parsed.payload["request_id"], principal.encode())


def discover_candidates(
    comments: Iterable[dict[str, Any]],
    repository: str,
    policy: dict[str, Any],
    processed_comment_ids: set[int],
) -> list[Candidate]:
    """Return every protocol candidate not already represented by canonical state.

    Workstream A deliberately returns the complete numeric-order candidate set.
    A later canonical state-aware stage supplies processed_comment_ids and selects
    the oldest remaining valid request; the credential-free discovery layer must
    not invent processed state or starve later retained comments.
    """
    candidates = [
        candidate
        for comment in comments
        if comment["id"] not in processed_comment_ids
        if (candidate := classify(comment, repository, policy)) is not None
    ]
    return sorted(candidates, key=lambda item: item.comment_id)


def oldest_unprocessed(comments: Iterable[dict[str, Any]], repository: str, policy: dict[str, Any], processed_comment_ids: set[int]) -> Candidate | None:
    candidates = discover_candidates(comments, repository, policy, processed_comment_ids)
    return candidates[0] if candidates else None
