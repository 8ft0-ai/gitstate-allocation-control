import json
import unittest

from phase2.parser import PREFIX, parse_request
from phase2.policy import AuthorisationError, authorise

RID = "01K00000000000000000000000"


def parsed(agent_id):
    value = {"agent_id": agent_id, "capabilities": [], "protocol": "beads-allocation/v0.2", "request_id": RID, "task_types": [], "type": "ALLOCATE_NEXT"}
    return parse_request(PREFIX + json.dumps(value, separators=(",", ":")).encode())


def policy():
    return {
        "version": 1,
        "operators": ["owner"],
        "principals": [{"actor_login": "human", "actor_type": "User", "agent_prefixes": ["agent://human/human/session/"]}],
        "github_apps": [{"actor_login": "synthetic-agent[bot]", "actor_id": 101, "actor_type": "Bot", "app_id": 202, "app_slug": "synthetic-agent", "installation_id": 303, "agent_prefix": "agent://github-app/synthetic-agent/303/session/"}],
    }


def bot_comment(**changes):
    value = {"user": {"id": 101, "login": "synthetic-agent[bot]", "type": "Bot"}, "performed_via_github_app": {"id": 202, "slug": "synthetic-agent"}}
    value.update(changes)
    return value


class PolicyTests(unittest.TestCase):
    def test_human_namespace(self):
        comment = {"user": {"id": 1, "login": "human", "type": "User"}}
        self.assertEqual(authorise(comment, parsed("agent://human/human/session/01"), policy()).actor_login, "human")
        with self.assertRaises(AuthorisationError):
            authorise(comment, parsed("agent://human/other/session/01"), policy())

    def test_operator_namespace(self):
        comment = {"user": {"id": 2, "login": "owner", "type": "User"}}
        self.assertEqual(authorise(comment, parsed("agent://operator/owner/session/recovery"), policy()).actor_login, "owner")

    def test_app_origin_complete_evidence(self):
        principal = authorise(bot_comment(), parsed("agent://github-app/synthetic-agent/303/session/01"), policy())
        self.assertEqual((principal.app_id, principal.installation_id), (202, 303))

    def test_app_origin_negative_fixtures(self):
        cases = [
            {"user": {"id": 101, "login": "synthetic-agent[bot]", "type": "Bot"}},
            bot_comment(performed_via_github_app={"id": 999, "slug": "synthetic-agent"}),
            bot_comment(performed_via_github_app={"id": 202, "slug": "wrong"}),
            bot_comment(user={"id": 999, "login": "synthetic-agent[bot]", "type": "Bot"}),
            bot_comment(user={"id": 101, "login": "wrong[bot]", "type": "Bot"}),
        ]
        for comment in cases:
            with self.subTest(comment=comment):
                with self.assertRaises(AuthorisationError):
                    authorise(comment, parsed("agent://github-app/synthetic-agent/303/session/01"), policy())

    def test_event_installation_is_not_sender_evidence(self):
        comment = bot_comment(installation={"id": 999999})
        self.assertEqual(authorise(comment, parsed("agent://github-app/synthetic-agent/303/session/01"), policy()).installation_id, 303)


if __name__ == "__main__":
    unittest.main()

