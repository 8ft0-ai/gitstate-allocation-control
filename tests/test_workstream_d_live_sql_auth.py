import sys
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import phase2.workstream_d_live as live


class WorkstreamDSqlServerAuthRegressionTests(unittest.TestCase):
    def test_fixture_sql_server_receives_existing_state_git_auth_environment(self):
        pymysql = types.ModuleType("pymysql")
        pymysql.MySQLError = RuntimeError  # type: ignore[attr-defined]
        auth_env = {
            "GIT_ASKPASS": "/tmp/workstream-d-state-askpass",
            "GIT_TERMINAL_PROMPT": "0",
            "PHASE2_STATE_TOKEN": "fixture-state-token",
        }

        with TemporaryDirectory() as directory:
            database = Path(directory) / "canonical"
            database.mkdir()
            with patch.dict(sys.modules, {"pymysql": pymysql}):
                with patch.object(
                    live.ManagedDoltConnection, "_connect", return_value=object()
                ):
                    with patch.object(live.subprocess, "Popen", return_value=object()) as popen:
                        connection = live.ManagedDoltConnection(
                            database, "dolt", auth_env
                        )

            command = popen.call_args.args[0]
            spawned_env = popen.call_args.kwargs["env"]
            self.assertEqual(command[0:2], ["dolt", "sql-server"])
            self.assertEqual(spawned_env, auth_env)
            self.assertIsNot(spawned_env, auth_env)
            self.assertNotIn("fixture-state-token", " ".join(command))
            connection.log.close()

    def test_fixture_bootstrap_passes_same_state_git_environment_to_sql_server(self):
        source = __import__("inspect").getsource(live.bootstrap_fixture_repository)
        self.assertIn(
            "ManagedDoltConnection(database, dolt_bin, env)", source
        )
        self.assertIn("env=_state_git_env", __import__("inspect").getsource(live.assert_uninitialised_state))


if __name__ == "__main__":
    unittest.main()
