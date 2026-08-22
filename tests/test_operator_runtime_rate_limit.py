import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import phase2.operator_runtime as operator_runtime
from phase2.github_api import GitHubAPIError


class OperatorRuntimeRateLimitTests(unittest.TestCase):
    def _run_live_failure(self, error: GitHubAPIError) -> tuple[int, str, dict[str, object]]:
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["operator_runtime.py", "live"]),
            patch.object(operator_runtime, "execute_live", side_effect=error),
            redirect_stdout(output),
        ):
            status = operator_runtime.main()
        raw = output.getvalue()
        return status, raw, json.loads(raw)

    def test_protected_operator_entrypoint_emits_safe_secondary_rate_limit_diagnostic(self):
        status, raw, payload = self._run_live_failure(
            GitHubAPIError(
                403,
                "SECRET_RAW_BODY token=SECRET_TOKEN",
                retry_after="17",
                rate_limit_remaining="42",
                rate_limited=True,
            )
        )
        self.assertEqual(status, 1)
        self.assertEqual(payload["reason_code"], "GITHUB_RATE_LIMITED")
        self.assertEqual(payload["http_status"], 403)
        self.assertTrue(payload["rate_limited"])
        self.assertEqual(payload["retry_after"], "17")
        self.assertEqual(payload["rate_limit_remaining"], "42")
        self.assertFalse(payload["credential_material_emitted"])
        self.assertFalse(payload["workstream_e_authorised"])
        self.assertNotIn("SECRET_RAW_BODY", raw)
        self.assertNotIn("SECRET_TOKEN", raw)

    def test_protected_operator_entrypoint_keeps_permission_403_distinct(self):
        status, raw, payload = self._run_live_failure(
            GitHubAPIError(
                403,
                "Resource not accessible by integration SECRET_RAW_BODY",
                rate_limited=False,
            )
        )
        self.assertEqual(status, 1)
        self.assertEqual(payload["reason_code"], "GITHUB_API_FORBIDDEN")
        self.assertEqual(payload["http_status"], 403)
        self.assertFalse(payload["rate_limited"])
        self.assertNotIn("SECRET_RAW_BODY", raw)

    def test_protected_operator_entrypoint_propagates_429_rate_limit_metadata(self):
        status, raw, payload = self._run_live_failure(
            GitHubAPIError(
                429,
                "SECRET_RAW_BODY",
                retry_after="9",
                rate_limit_remaining="0",
                rate_limit_reset="1234567890",
                rate_limited=True,
            )
        )
        self.assertEqual(status, 1)
        self.assertEqual(payload["reason_code"], "GITHUB_RATE_LIMITED")
        self.assertEqual(payload["http_status"], 429)
        self.assertTrue(payload["rate_limited"])
        self.assertEqual(payload["retry_after"], "9")
        self.assertEqual(payload["rate_limit_remaining"], "0")
        self.assertEqual(payload["rate_limit_reset"], "1234567890")
        self.assertNotIn("SECRET_RAW_BODY", raw)


if __name__ == "__main__":
    unittest.main()
