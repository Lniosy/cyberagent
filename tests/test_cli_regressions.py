from __future__ import annotations

import unittest
from unittest.mock import patch

from click.testing import CliRunner

from jianlai import cli


class CliRegressionTests(unittest.TestCase):
    def test_main_without_args_shows_help(self):
        runner = CliRunner()
        result = runner.invoke(cli.main, [])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage:", result.output)
        self.assertIn("jianlai <目标描述>", result.output)

    def test_natural_language_target_is_forwarded(self):
        captured: dict[str, object] = {}

        async def fake_run(description: str, max_turns: int, max_time: int, resume: bool):
            captured["description"] = description
            captured["max_turns"] = max_turns
            captured["max_time"] = max_time
            captured["resume"] = resume

        runner = CliRunner()
        with patch.object(cli, "_run_natural_language", fake_run):
            result = runner.invoke(cli.main, ["scan localhost:3000"])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(
            captured,
            {
                "description": "scan localhost:3000",
                "max_turns": 15,
                "max_time": 600,
                "resume": False,
            },
        )

    def test_agent_subcommand_is_not_swallowed(self):
        captured: dict[str, object] = {}

        async def fake_run_agent(domain: str, max_turns: int, max_time: int, local: bool,
                                 extra_ports: list[int], resume: bool):
            captured["domain"] = domain
            captured["max_turns"] = max_turns
            captured["max_time"] = max_time
            captured["local"] = local
            captured["extra_ports"] = extra_ports
            captured["resume"] = resume

        runner = CliRunner()
        with patch.object(cli, "_run_agent", fake_run_agent):
            result = runner.invoke(cli.main, ["agent", "localhost", "--local"])

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(
            captured,
            {
                "domain": "localhost",
                "max_turns": 15,
                "max_time": 600,
                "local": True,
                "extra_ports": [],
                "resume": False,
            },
        )

    def test_build_local_target_hint_handles_empty_ports(self):
        hint = cli._build_local_target_hint("localhost", [])

        self.assertIn("未指定端口", hint)
        self.assertIn("localhost", hint)


if __name__ == "__main__":
    unittest.main()
