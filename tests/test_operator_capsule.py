import unittest
from datetime import datetime, timezone

from phase2.operator_capsule import (
    CAPSULE_CONTRACT,
    CAPSULE_FIELDS,
    CAPSULE_PREFIX,
    GOVERNANCE_CONTRACT,
    OPERATOR_ISSUE_NUMBER,
    PREFLIGHT_PROFILE,
    PROTOCOL_AUTHORITY_SHA,
    STATE_BASELINE_SHA,
    OperatorCapsuleError,
    canonical_json,
    consume_capsule,
    discover_capsule,
    parse_capsule_comment,
)


CONTROL_SHA = "a" * 40
NOW = datetime(2026, 8, 18, 12, 10, tzinfo=timezone.utc)


def payload(**changes):
    value = {
        "contract": CAPSULE_CONTRACT,
        "capsule_id": "1" * 32,
        "governance_contract": GOVERNANCE_CONTRACT,
        "governance_record_id": "2" * 32,
        "review_record_id": "3" * 32,
        "review_record_sha256": "4" * 64,
        "authority_record_id": "5" * 32,
        "authority_record_sha256": "6" * 64,
        "operation": PREFLIGHT_PROFILE,
        "expected_control_sha": CONTROL_SHA,
        "expected_protocol_sha": PROTOCOL_AUTHORITY_SHA,
        "expected_state_baseline": STATE_BASELINE_SHA,
        "created_at": "2026-08-18T12:00:00Z",
        "expires_at": "2026-08-18T12:30:00Z",
        "single_use": True,
        "workstream_e_authorised": False,
    }
    value.update(changes)
    return value


def comment(comment_id=101, *, value=None, login="8ft0-ai", edited=False):
    body = CAPSULE_PREFIX + canonical_json(value or payload())
    return {
        "id": comment_id,
        "body": body,
        "user": {"login": login},
        "created_at": "2026-08-18T12:01:00Z",
        "updated_at": "2026-08-18T12:02:00Z" if edited else "2026-08-18T12:01:00Z",
    }


class FakeIssueAPI:
    def __init__(self, comments):
        self.comments = list(comments)
        self.posts = []

    def get(self, path):
        self.assert_operator_path(path)
        page = int(path.split("page=")[-1])
        return list(self.comments) if page == 1 else []

    def post(self, path, body):
        self.assert_operator_path(path)
        self.posts.append(body["body"])
        return {"id": 9000 + len(self.posts)}

    @staticmethod
    def assert_operator_path(path):
        if f"/issues/{OPERATOR_ISSUE_NUMBER}/comments" not in path:
            raise AssertionError(path)


class OperatorCapsuleTests(unittest.TestCase):
    def test_schema_is_opaque_and_contains_no_direct_private_locator_fields(self):
        self.assertEqual(set(payload()), set(CAPSULE_FIELDS))
        prohibited = {
            "governing_repository",
            "governing_issue",
            "review_comment_id",
            "authority_comment_id",
            "private_url",
        }
        self.assertFalse(prohibited & CAPSULE_FIELDS)
        parsed = parse_capsule_comment(
            comment(),
            now=NOW,
            expected_control_sha=CONTROL_SHA,
            expected_profile=PREFLIGHT_PROFILE,
        )
        self.assertEqual(parsed.payload["expected_protocol_sha"], PROTOCOL_AUTHORITY_SHA)

    def test_edited_wrong_owner_stale_expired_and_workstream_e_capsules_fail(self):
        cases = [
            (comment(edited=True), "CAPSULE_SOURCE_EDITED"),
            (comment(login="other"), "CAPSULE_WRONG_OWNER"),
            (
                comment(value=payload(expected_control_sha="b" * 40)),
                "CAPSULE_STALE_CONTROL_SHA",
            ),
            (
                comment(value=payload(expected_protocol_sha="b" * 40)),
                "CAPSULE_STALE_PROTOCOL_SHA",
            ),
            (
                comment(value=payload(workstream_e_authorised=True)),
                "WORKSTREAM_E_NOT_AUTHORISED",
            ),
        ]
        for value, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(OperatorCapsuleError, reason):
                    parse_capsule_comment(
                        value,
                        now=NOW,
                        expected_control_sha=CONTROL_SHA,
                        expected_profile=PREFLIGHT_PROFILE,
                    )

        with self.assertRaisesRegex(OperatorCapsuleError, "CAPSULE_EXPIRED"):
            parse_capsule_comment(
                comment(value=payload(expires_at="2026-08-18T12:05:00Z")),
                now=NOW,
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
            )

    def test_unknown_duplicate_and_noncanonical_json_fail_closed(self):
        extra = payload(extra="no")
        with self.assertRaisesRegex(OperatorCapsuleError, "CAPSULE_SCHEMA_MISMATCH"):
            parse_capsule_comment(
                comment(value=extra),
                now=NOW,
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
            )

        duplicate = comment()
        duplicate["body"] = CAPSULE_PREFIX + '{"contract":"gitstate-operator/v1","contract":"duplicate"}'
        with self.assertRaisesRegex(OperatorCapsuleError, "DUPLICATE_JSON_KEY"):
            parse_capsule_comment(
                duplicate,
                now=NOW,
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
            )

        noncanonical = comment()
        noncanonical["body"] = CAPSULE_PREFIX + canonical_json(payload()).replace(",", ", ", 1)
        with self.assertRaisesRegex(OperatorCapsuleError, "CAPSULE_NONCANONICAL_JSON"):
            parse_capsule_comment(
                noncanonical,
                now=NOW,
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
            )

    def test_discovery_requires_exactly_one_unconsumed_valid_capsule(self):
        api = FakeIssueAPI([comment(), comment(102, login="other")])
        discovered = discover_capsule(
            api,
            expected_control_sha=CONTROL_SHA,
            expected_profile=PREFLIGHT_PROFILE,
            run_attempt=1,
            now=NOW,
        )
        self.assertEqual(discovered.comment_id, 101)

        with self.assertRaisesRegex(OperatorCapsuleError, "AMBIGUOUS_OPERATOR_CAPSULE"):
            discover_capsule(
                FakeIssueAPI([comment(), comment(102, value=payload(capsule_id="7" * 32))]),
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
                run_attempt=1,
                now=NOW,
            )

        with self.assertRaisesRegex(OperatorCapsuleError, "OPERATOR_RERUN_FORBIDDEN"):
            discover_capsule(
                api,
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
                run_attempt=2,
                now=NOW,
            )

    def test_consumption_rechecks_identity_and_posts_one_immutable_binding(self):
        api = FakeIssueAPI([comment()])
        discovered = discover_capsule(
            api,
            expected_control_sha=CONTROL_SHA,
            expected_profile=PREFLIGHT_PROFILE,
            run_attempt=1,
            now=NOW,
        )
        capsule, consumption, digest = consume_capsule(
            api,
            expected_control_sha=CONTROL_SHA,
            expected_profile=PREFLIGHT_PROFILE,
            expected_capsule_id=discovered.capsule_id,
            expected_comment_id=discovered.comment_id,
            expected_body_sha256=discovered.body_sha256,
            run_id=12345,
            run_attempt=1,
            now=NOW,
        )
        self.assertEqual(capsule.comment_id, 101)
        self.assertEqual(consumption["capsule_body_sha256"], discovered.body_sha256)
        self.assertEqual(consumption["run_id"], 12345)
        self.assertEqual(consumption["run_attempt"], 1)
        self.assertEqual(consumption["trusted_sha"], CONTROL_SHA)
        self.assertFalse(consumption["workstream_e_authorised"])
        self.assertEqual(len(digest), 64)
        self.assertEqual(len(api.posts), 1)

        with self.assertRaisesRegex(OperatorCapsuleError, "CAPSULE_CHANGED_BEFORE_CONSUMPTION"):
            consume_capsule(
                FakeIssueAPI([comment()]),
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
                expected_capsule_id=discovered.capsule_id,
                expected_comment_id=discovered.comment_id,
                expected_body_sha256="f" * 64,
                run_id=12345,
                run_attempt=1,
                now=NOW,
            )

    def test_valid_consumption_makes_capsule_non_replayable(self):
        source = comment()
        parsed = parse_capsule_comment(
            source,
            now=NOW,
            expected_control_sha=CONTROL_SHA,
            expected_profile=PREFLIGHT_PROFILE,
        )
        consumed = {
            "id": 500,
            "body": "/gitstate-consumption-v1 "
            + canonical_json(
                {
                    "contract": "gitstate-consumption/v1",
                    "capsule_id": parsed.capsule_id,
                    "capsule_comment_id": parsed.comment_id,
                    "capsule_body_sha256": parsed.body_sha256,
                    "run_id": 12345,
                    "run_attempt": 1,
                    "trusted_sha": CONTROL_SHA,
                    "operation": PREFLIGHT_PROFILE,
                    "consumed_at": "2026-08-18T12:05:00Z",
                    "workstream_e_authorised": False,
                }
            ),
            "user": {"login": "github-actions[bot]"},
            "created_at": "2026-08-18T12:05:00Z",
            "updated_at": "2026-08-18T12:05:00Z",
        }
        with self.assertRaisesRegex(OperatorCapsuleError, "NO_ELIGIBLE_OPERATOR_CAPSULE"):
            discover_capsule(
                FakeIssueAPI([source, consumed]),
                expected_control_sha=CONTROL_SHA,
                expected_profile=PREFLIGHT_PROFILE,
                run_attempt=1,
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
