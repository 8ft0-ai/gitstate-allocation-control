from datetime import datetime, timezone
from types import SimpleNamespace
import unittest

from phase2.operator_manifest import canonical_json
from phase2.successor_capsule import (
    SuccessorCapsuleError,
    require_current_manifest_approval_attestation,
)
from phase2.successor_contract import (
    APPROVAL_ATTESTATION_V2_CONTRACT,
    APPROVAL_ATTESTATION_V2_PREFIX,
    APPROVAL_ATTESTATION_V2_RESERVED_PREFIX,
    SuccessorContractError,
    parse_manifest_approval_attestation,
)


MANIFEST_SHA = "a" * 64
OTHER_MANIFEST_SHA = "b" * 64
MANIFEST_COMMENT_ID = 9001
AUTHORITY_A = "1" * 32
AUTHORITY_B = "2" * 32
APPROVAL_A = "3" * 32
APPROVAL_B = "4" * 32
ATTESTATION_A = "5" * 32
ATTESTATION_B = "6" * 32


class CommentAPI:
    def __init__(self, comments):
        self.comments = list(comments)

    def get(self, path):
        if "/issues/" not in path or "/comments" not in path:
            raise AssertionError(path)
        return list(self.comments)


def exact_binding(record_id, body_sha256, manifest_comment_id, manifest_sha256):
    return {
        "record_id": record_id,
        "body_sha256": body_sha256,
        "manifest_comment_id": manifest_comment_id,
        "manifest_sha256": manifest_sha256,
    }


def payload(
    *,
    attestation_id,
    authority_id=AUTHORITY_A,
    authority_digest="c" * 64,
    approval_id=APPROVAL_A,
    approval_digest="d" * 64,
    manifest_comment_id=MANIFEST_COMMENT_ID,
    manifest_sha256=MANIFEST_SHA,
):
    return {
        "contract": APPROVAL_ATTESTATION_V2_CONTRACT,
        "attestation_id": attestation_id,
        "manifest_comment_id": manifest_comment_id,
        "manifest_sha256": manifest_sha256,
        "authority": exact_binding(
            authority_id,
            authority_digest,
            manifest_comment_id,
            manifest_sha256,
        ),
        "approval": exact_binding(
            approval_id,
            approval_digest,
            manifest_comment_id,
            manifest_sha256,
        ),
        "disposition": "approved",
        "execution_authorised": True,
        "single_use": True,
        "workstream_e_authorised": False,
    }


def comment(comment_id, value):
    body = APPROVAL_ATTESTATION_V2_PREFIX + canonical_json(value)
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": "8ft0-ai"},
        "created_at": "2026-09-12T00:01:00Z",
        "updated_at": "2026-09-12T00:01:00Z",
    }


def capsule_for(selected):
    return SimpleNamespace(
        manifest_approval={
            "attestation_id": selected.attestation_id,
            "attestation_body_sha256": selected.body_sha256,
        },
        manifest_sha256=MANIFEST_SHA,
        authority={
            "record_id": AUTHORITY_A,
            "body_sha256": "c" * 64,
        },
        created_at=datetime(2026, 9, 12, 0, 2, tzinfo=timezone.utc),
    )


class SuccessorManifestV2RemediationTests(unittest.TestCase):
    def test_reserved_v2_namespace_fails_closed(self):
        invalid_bodies = (
            APPROVAL_ATTESTATION_V2_RESERVED_PREFIX,
            APPROVAL_ATTESTATION_V2_RESERVED_PREFIX + "x",
            APPROVAL_ATTESTATION_V2_RESERVED_PREFIX + "\t{}",
            APPROVAL_ATTESTATION_V2_PREFIX + "{}\n",
        )
        for body in invalid_bodies:
            with self.subTest(body=body):
                candidate = {
                    "id": 501,
                    "body": body,
                    "user": {"login": "8ft0-ai"},
                    "created_at": "2026-09-12T00:01:00Z",
                    "updated_at": "2026-09-12T00:01:00Z",
                }
                with self.assertRaisesRegex(
                    SuccessorContractError,
                    "SUCCESSOR_APPROVAL_ATTESTATION_RESERVED_RECORD_INVALID",
                ):
                    parse_manifest_approval_attestation(candidate)

    def test_unrelated_comment_is_ignored(self):
        candidate = {
            "id": 501,
            "body": "ordinary operator note",
            "user": {"login": "8ft0-ai"},
            "created_at": "2026-09-12T00:01:00Z",
            "updated_at": "2026-09-12T00:01:00Z",
        }
        self.assertIsNone(parse_manifest_approval_attestation(candidate))

    def test_single_exact_v2_attestation_remains_usable(self):
        first_comment = comment(501, payload(attestation_id=ATTESTATION_A))
        selected = parse_manifest_approval_attestation(first_comment)
        observed = require_current_manifest_approval_attestation(
            CommentAPI([first_comment]),
            capsule_for(selected),
        )
        self.assertEqual(observed.attestation_id, ATTESTATION_A)
        self.assertEqual(observed.body_sha256, selected.body_sha256)

    def test_same_exact_manifest_with_different_authority_is_ambiguous(self):
        first_comment = comment(501, payload(attestation_id=ATTESTATION_A))
        second_comment = comment(
            502,
            payload(
                attestation_id=ATTESTATION_B,
                authority_id=AUTHORITY_B,
                authority_digest="e" * 64,
            ),
        )
        selected = parse_manifest_approval_attestation(first_comment)
        with self.assertRaisesRegex(
            SuccessorCapsuleError,
            "SUCCESSOR_APPROVAL_ATTESTATION_AMBIGUOUS",
        ):
            require_current_manifest_approval_attestation(
                CommentAPI([first_comment, second_comment]),
                capsule_for(selected),
            )

    def test_same_exact_manifest_with_different_authority_and_approval_is_ambiguous(self):
        first_comment = comment(501, payload(attestation_id=ATTESTATION_A))
        second_comment = comment(
            502,
            payload(
                attestation_id=ATTESTATION_B,
                authority_id=AUTHORITY_B,
                authority_digest="e" * 64,
                approval_id=APPROVAL_B,
                approval_digest="f" * 64,
            ),
        )
        selected = parse_manifest_approval_attestation(first_comment)
        with self.assertRaisesRegex(
            SuccessorCapsuleError,
            "SUCCESSOR_APPROVAL_ATTESTATION_AMBIGUOUS",
        ):
            require_current_manifest_approval_attestation(
                CommentAPI([first_comment, second_comment]),
                capsule_for(selected),
            )

    def test_duplicate_authority_tuple_under_new_attestation_is_ambiguous(self):
        first_comment = comment(501, payload(attestation_id=ATTESTATION_A))
        second_comment = comment(502, payload(attestation_id=ATTESTATION_B))
        selected = parse_manifest_approval_attestation(first_comment)
        with self.assertRaisesRegex(
            SuccessorCapsuleError,
            "SUCCESSOR_APPROVAL_ATTESTATION_AMBIGUOUS",
        ):
            require_current_manifest_approval_attestation(
                CommentAPI([first_comment, second_comment]),
                capsule_for(selected),
            )

    def test_different_manifest_comment_id_is_not_a_competitor(self):
        first_comment = comment(501, payload(attestation_id=ATTESTATION_A))
        second_comment = comment(
            502,
            payload(
                attestation_id=ATTESTATION_B,
                authority_id=AUTHORITY_B,
                authority_digest="e" * 64,
                manifest_comment_id=MANIFEST_COMMENT_ID + 1,
            ),
        )
        selected = parse_manifest_approval_attestation(first_comment)
        observed = require_current_manifest_approval_attestation(
            CommentAPI([first_comment, second_comment]),
            capsule_for(selected),
        )
        self.assertEqual(observed.attestation_id, ATTESTATION_A)

    def test_different_manifest_digest_is_not_a_competitor(self):
        first_comment = comment(501, payload(attestation_id=ATTESTATION_A))
        second_comment = comment(
            502,
            payload(
                attestation_id=ATTESTATION_B,
                authority_id=AUTHORITY_B,
                authority_digest="e" * 64,
                manifest_sha256=OTHER_MANIFEST_SHA,
            ),
        )
        selected = parse_manifest_approval_attestation(first_comment)
        observed = require_current_manifest_approval_attestation(
            CommentAPI([first_comment, second_comment]),
            capsule_for(selected),
        )
        self.assertEqual(observed.attestation_id, ATTESTATION_A)


if __name__ == "__main__":
    unittest.main()
