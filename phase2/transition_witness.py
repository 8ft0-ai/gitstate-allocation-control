from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from . import operator_manifest_v1 as _v1


TRANSITION_WITNESS_CONTRACT = "gitstate-v3-architecture-completion/v1"
TRANSITION_WITNESS_RESERVED_PREFIX = "/gitstate-v3-architecture-completion-v1"
TRANSITION_WITNESS_PREFIX = TRANSITION_WITNESS_RESERVED_PREFIX + " "
TRANSITION_WITNESS_FIELDS = frozenset(
    {
        "contract",
        "witness_id",
        "governing_issue",
        "operation",
        "proposal",
        "manifest",
        "preflight_evidence",
        "preflight_disposition",
        "run_attempt",
        "capability_mode",
        "manifest_approval",
        "architecture_completion",
        "workstream_e_authorised",
    }
)
MANIFEST_BINDING_FIELDS = frozenset({"comment_id", "sha256"})
APPROVAL_BINDING_FIELDS = frozenset({"record_id", "comment_id", "body_sha256"})
ARCHITECTURE_COMPLETION_FIELDS = frozenset(
    {"issue_number", "comment_id", "body_sha256", "disposition"}
)


class TransitionWitnessError(RuntimeError):
    pass


@dataclass(frozen=True)
class TransitionWitness:
    payload: Mapping[str, Any]
    comment_id: int
    body_sha256: str
    owner: str
    created_at: str

    @property
    def witness_id(self) -> str:
        return str(self.payload["witness_id"])

    @property
    def proposal(self) -> _v1.CommentBinding:
        value = self.payload["proposal"]
        return _v1.CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))

    @property
    def manifest_comment_id(self) -> int:
        return int(self.payload["manifest"]["comment_id"])

    @property
    def manifest_sha256(self) -> str:
        return str(self.payload["manifest"]["sha256"])

    @property
    def preflight_evidence(self) -> _v1.CommentBinding:
        value = self.payload["preflight_evidence"]
        return _v1.CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))

    @property
    def approval_record_id(self) -> str:
        return str(self.payload["manifest_approval"]["record_id"])

    @property
    def approval(self) -> _v1.CommentBinding:
        value = self.payload["manifest_approval"]
        return _v1.CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))

    @property
    def architecture_completion(self) -> _v1.CommentBinding:
        value = self.payload["architecture_completion"]
        return _v1.CommentBinding(int(value["comment_id"]), str(value["body_sha256"]))


def _fail(reason: str) -> None:
    raise TransitionWitnessError(reason)


def _comment_binding(value: Any, reason: str):
    try:
        return _v1._require_comment_binding(value, reason)
    except _v1.OperatorContractError as exc:
        raise TransitionWitnessError(reason) from exc


def parse_transition_witness(
    comment: Mapping[str, Any],
    *,
    expected_owner: str,
    expected_issue: int,
    expected_operation: str | None = None,
    expected_architecture_issue: int = 40,
    expected_body_sha256: str | None = None,
) -> TransitionWitness | None:
    body = comment.get("body")
    if not isinstance(body, str):
        _fail("TRANSITION_WITNESS_COMMENT_INVALID")
    if not body.startswith(TRANSITION_WITNESS_RESERVED_PREFIX):
        return None
    if not body.startswith(TRANSITION_WITNESS_PREFIX) or "\n" in body:
        _fail("TRANSITION_WITNESS_RESERVED_RECORD_INVALID")

    try:
        comment_id = _v1._require_int(
            comment.get("id"), "TRANSITION_WITNESS_COMMENT_INVALID"
        )
        user = comment.get("user")
        if not isinstance(user, Mapping) or user.get("login") != expected_owner:
            _fail("TRANSITION_WITNESS_WRONG_OWNER")
        created = comment.get("created_at")
        updated = comment.get("updated_at")
        _v1._parse_time(created, "TRANSITION_WITNESS_TIME_INVALID")
        _v1._parse_time(updated, "TRANSITION_WITNESS_TIME_INVALID")
        if created != updated:
            _fail("TRANSITION_WITNESS_SOURCE_EDITED")

        body_sha256 = _v1.sha256_text(body)
        if expected_body_sha256 is not None:
            _v1._require_hex(
                expected_body_sha256,
                _v1.SHA256,
                "TRANSITION_WITNESS_EXPECTED_DIGEST_INVALID",
            )
            if body_sha256 != expected_body_sha256:
                _fail("TRANSITION_WITNESS_BODY_DIGEST_MISMATCH")

        value = _v1._strict_json(
            body[len(TRANSITION_WITNESS_PREFIX) :],
            "TRANSITION_WITNESS_JSON_INVALID",
        )
        _v1._require_exact_keys(
            value, TRANSITION_WITNESS_FIELDS, "TRANSITION_WITNESS_SCHEMA_MISMATCH"
        )
        if value.get("contract") != TRANSITION_WITNESS_CONTRACT:
            _fail("TRANSITION_WITNESS_CONTRACT_MISMATCH")
        _v1._require_hex(
            value.get("witness_id"),
            _v1.OPAQUE_ID,
            "TRANSITION_WITNESS_ID_INVALID",
        )
        if value.get("governing_issue") != expected_issue:
            _fail("TRANSITION_WITNESS_ISSUE_MISMATCH")
        operation = _v1._require_string(
            value.get("operation"), "TRANSITION_WITNESS_OPERATION_INVALID"
        )
        if expected_operation is not None and operation != expected_operation:
            _fail("TRANSITION_WITNESS_OPERATION_MISMATCH")

        _comment_binding(value.get("proposal"), "TRANSITION_WITNESS_PROPOSAL_INVALID")

        manifest = value.get("manifest")
        if not isinstance(manifest, dict):
            _fail("TRANSITION_WITNESS_MANIFEST_INVALID")
        _v1._require_exact_keys(
            manifest, MANIFEST_BINDING_FIELDS, "TRANSITION_WITNESS_MANIFEST_INVALID"
        )
        _v1._require_int(
            manifest.get("comment_id"), "TRANSITION_WITNESS_MANIFEST_INVALID"
        )
        _v1._require_hex(
            manifest.get("sha256"),
            _v1.SHA256,
            "TRANSITION_WITNESS_MANIFEST_INVALID",
        )

        _comment_binding(
            value.get("preflight_evidence"),
            "TRANSITION_WITNESS_PREFLIGHT_INVALID",
        )
        if value.get("preflight_disposition") != "PASS":
            _fail("TRANSITION_WITNESS_PREFLIGHT_NOT_PASS")
        if value.get("run_attempt") != 1:
            _fail("TRANSITION_WITNESS_ATTEMPT_INVALID")
        if value.get("capability_mode") != "capability-denied":
            _fail("TRANSITION_WITNESS_CAPABILITY_MODE_INVALID")

        approval = value.get("manifest_approval")
        if not isinstance(approval, dict):
            _fail("TRANSITION_WITNESS_APPROVAL_INVALID")
        _v1._require_exact_keys(
            approval,
            APPROVAL_BINDING_FIELDS,
            "TRANSITION_WITNESS_APPROVAL_INVALID",
        )
        _v1._require_hex(
            approval.get("record_id"),
            _v1.OPAQUE_ID,
            "TRANSITION_WITNESS_APPROVAL_INVALID",
        )
        _v1._require_int(
            approval.get("comment_id"), "TRANSITION_WITNESS_APPROVAL_INVALID"
        )
        _v1._require_hex(
            approval.get("body_sha256"),
            _v1.SHA256,
            "TRANSITION_WITNESS_APPROVAL_INVALID",
        )

        completion = value.get("architecture_completion")
        if not isinstance(completion, dict):
            _fail("TRANSITION_WITNESS_COMPLETION_INVALID")
        _v1._require_exact_keys(
            completion,
            ARCHITECTURE_COMPLETION_FIELDS,
            "TRANSITION_WITNESS_COMPLETION_INVALID",
        )
        if completion.get("issue_number") != expected_architecture_issue:
            _fail("TRANSITION_WITNESS_ARCHITECTURE_ISSUE_MISMATCH")
        _v1._require_int(
            completion.get("comment_id"), "TRANSITION_WITNESS_COMPLETION_INVALID"
        )
        _v1._require_hex(
            completion.get("body_sha256"),
            _v1.SHA256,
            "TRANSITION_WITNESS_COMPLETION_INVALID",
        )
        if completion.get("disposition") != "COMPLETE":
            _fail("TRANSITION_WITNESS_ARCHITECTURE_NOT_COMPLETE")

        _v1._require_bool(
            value.get("workstream_e_authorised"),
            False,
            "WORKSTREAM_E_NOT_AUTHORISED",
        )
    except TransitionWitnessError:
        raise
    except _v1.OperatorContractError as exc:
        raise TransitionWitnessError(str(exc)) from exc

    return TransitionWitness(
        _v1._freeze(value),
        int(comment_id),
        body_sha256,
        expected_owner,
        str(created),
    )
