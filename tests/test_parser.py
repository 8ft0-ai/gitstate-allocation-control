import hashlib
import json
import unittest

from phase2.parser import PREFIX, RequestError, malformed_descriptor, parse_request

RID = "01K00000000000000000000000"
AID = "01K00000000000000000000001"
AGENT = "agent://human/8ft0-ai/session/01"


def body(payload):
    return PREFIX + json.dumps(payload, separators=(",", ":")).encode()


def allocate_next(**changes):
    value = {
        "agent_id": AGENT,
        "capabilities": [],
        "max_priority": 4,
        "protocol": "beads-allocation/v0.2",
        "request_id": RID,
        "task_types": ["task"],
        "type": "ALLOCATE_NEXT",
    }
    value.update(changes)
    return value


class ParserTests(unittest.TestCase):
    def test_exact_valid_envelopes(self):
        payloads = [
            allocate_next(),
            {
                "protocol": "beads-allocation/v0.2",
                "type": "ALLOCATE_TASK",
                "request_id": RID,
                "agent_id": AGENT,
                "task_id": "task-01",
            },
            {
                "protocol": "beads-allocation/v0.2",
                "type": "RELEASE",
                "request_id": RID,
                "agent_id": AGENT,
                "allocation_id": AID,
                "reason": "synthetic release",
            },
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                parsed = parse_request(body(payload))
                self.assertEqual(parsed.payload, payload)
                self.assertEqual(len(parsed.payload_hash), 64)

    def test_payload_hash_excludes_request_id(self):
        self.assertEqual(
            parse_request(body(allocate_next(request_id=RID))).payload_hash,
            parse_request(body(allocate_next(request_id=AID))).payload_hash,
        )

    def test_rejects_invalid_input(self):
        valid = body(allocate_next())
        cases = [
            (b"discussion", "UNRELATED_COMMENT"),
            (PREFIX + b'{"protocol":"beads-allocation/v0.2","protocol":"beads-allocation/v0.2"}', "DUPLICATE_KEY"),
            (body(allocate_next(extra=True)), "UNKNOWN_FIELD"),
            (body(allocate_next(max_priority=1.5)), "NON_INTEGER_NUMBER"),
            (body(allocate_next(max_priority=True)), "INVALID_FIELD"),
            (body(allocate_next(capabilities=["z", "a"])), "ARRAY_NOT_SORTED_UNIQUE"),
            (body(allocate_next(capabilities=["a", "a"])), "ARRAY_NOT_SORTED_UNIQUE"),
            (body(allocate_next(capabilities=[f"x{i}" for i in range(21)])), "INVALID_ARRAY"),
            (body(allocate_next(request_id="not-a-ulid")), "INVALID_FIELD"),
            (valid + b"\n", "MULTILINE_BODY"),
            (PREFIX + b" " + valid[len(PREFIX):], "INVALID_TRANSPORT"),
            (valid + b" ", "INVALID_TRANSPORT"),
            (valid + b"\t", "INVALID_TRANSPORT"),
            (PREFIX + b"\xff", "INVALID_TRANSPORT"),
            (
                PREFIX
                + b'{"protocol":"beads-allocation/v0.2","type":"RELEASE","request_id":"'
                + RID.encode()
                + b'","agent_id":"'
                + AGENT.encode()
                + b'","allocation_id":"'
                + AID.encode()
                + b'","reason":"\\ud800"}',
                "INVALID_UNICODE",
            ),
            (valid + b" " * 4097, "BODY_TOO_LARGE"),
        ]
        for raw, code in cases:
            with self.subTest(code=code, raw=raw[:80]):
                with self.assertRaises(RequestError) as error:
                    parse_request(raw)
                self.assertEqual(error.exception.code, code)

    def test_invalid_utf8_inside_exact_object_envelope(self):
        raw = PREFIX + b'{"protocol":"beads-allocation/v0.2","x":"\xff"}'
        with self.assertRaises(RequestError) as error:
            parse_request(raw)
        self.assertEqual(error.exception.code, "INVALID_UTF8")

    def test_malformed_descriptor_uses_exact_received_bytes(self):
        raw = PREFIX + b"not-json"
        descriptor = malformed_descriptor(raw, "example/control", 42, RequestError("INVALID_JSON"))
        self.assertEqual(descriptor.request_id, "invalid:example/control:42")
        self.assertEqual(descriptor.payload_hash, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
