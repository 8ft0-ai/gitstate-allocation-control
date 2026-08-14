import hashlib
import json
import unittest

from phase2.discovery import (
    CanonicalSource,
    DiscoveryError,
    discover_candidates,
    oldest_unprocessed,
    paginate_comments,
    reconcile_canonical_sources,
)
from phase2.parser import PREFIX


def page_fetch(pages, links):
    return lambda page, per_page: (pages.get(page, []), links.get(page, False))


def request(comment_id):
    payload = {
        "agent_id": "agent://human/human/session/01",
        "capabilities": [],
        "protocol": "beads-allocation/v0.2",
        "request_id": f"01K{comment_id:023d}"[-26:],
        "task_types": [],
        "type": "ALLOCATE_NEXT",
    }
    return {
        "id": comment_id,
        "body": (PREFIX + json.dumps(payload, separators=(",", ":")).encode()).decode(),
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "user": {"id": 1, "login": "human", "type": "User"},
    }


def policy():
    return {
        "version": 1,
        "operators": [],
        "principals": [
            {
                "actor_login": "human",
                "actor_type": "User",
                "agent_prefixes": ["agent://human/human/session/"],
            }
        ],
        "github_apps": [],
    }


class DiscoveryTests(unittest.TestCase):
    def test_multi_page_ordering(self):
        pages = {1: [{"id": i} for i in range(1, 101)], 2: [{"id": 101}, {"id": 102}]}
        self.assertEqual([item["id"] for item in paginate_comments(page_fetch(pages, {1: True}))], list(range(1, 103)))

    def test_pagination_fails_closed(self):
        cases = [
            ({1: [{"id": 2}, {"id": 1}]}, {}, "DECREASING_COMMENT_ID"),
            ({1: [{"id": 1}], 2: [{"id": 1}]}, {1: True}, "REPEATED_COMMENT"),
            ({1: []}, {1: True}, "AMBIGUOUS_TERMINATION"),
            ({1: [{"id": i} for i in range(1, 101)], 2: [{"id": 101}]}, {}, "MISSING_NEXT_CURSOR"),
        ]
        for pages, links, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(DiscoveryError) as error:
                    paginate_comments(page_fetch(pages, links))
                self.assertEqual(str(error.exception), reason)

    def test_complete_candidate_set_prevents_starvation(self):
        comments = [request(30), request(31), request(32)]
        first = discover_candidates(comments, "example/control", policy(), set())
        retry = discover_candidates(comments, "example/control", policy(), set())
        self.assertEqual([item.comment_id for item in first], [30, 31, 32])
        self.assertEqual([item.comment_id for item in retry], [30, 31, 32])
        self.assertEqual(oldest_unprocessed(comments, "example/control", policy(), set()).comment_id, 30)
        self.assertEqual(
            [item.comment_id for item in discover_candidates(comments, "example/control", policy(), {30})],
            [31, 32],
        )

    def test_edit_before_ingress(self):
        comment = request(40)
        comment["updated_at"] = "2026-01-01T00:00:01Z"
        result = oldest_unprocessed([comment], "example/control", {"version": 1, "operators": [], "principals": [], "github_apps": []}, set())
        self.assertEqual(result.reason_code, "SOURCE_COMMENT_EDITED_BEFORE_INGRESS")

    def test_post_ingress_edit_and_deletion_do_not_replace_canonical_source(self):
        original = request(50)
        source = CanonicalSource(50, hashlib.sha256(original["body"].encode()).hexdigest())
        edited = dict(original, body=original["body"] + " ")
        self.assertEqual(reconcile_canonical_sources([source], [edited]), {50: "SOURCE_COMMENT_EDITED"})
        self.assertEqual(reconcile_canonical_sources([source], []), {50: "SOURCE_COMMENT_DELETED"})


if __name__ == "__main__":
    unittest.main()
