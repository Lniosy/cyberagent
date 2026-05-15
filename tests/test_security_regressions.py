from __future__ import annotations

import asyncio
import unittest
from pathlib import Path

from cyberagent.core.crawler import WebCrawler
from cyberagent.core.findings_pool import FindingsPool
from cyberagent.core.security_tools import register_all_tools
from cyberagent.core.shell_executor import run_command
from cyberagent.core.tools import create_default_registry


class SecurityRegressionTests(unittest.TestCase):
    def test_run_command_blocks_shell_control_tokens(self):
        result = asyncio.run(run_command("echo ok | cat", timeout=5))

        self.assertFalse(result.success)
        self.assertEqual(result.returncode, -1)
        self.assertIn("shell 控制符", result.stderr)

    def test_restricted_tool_is_blocked(self):
        registry = create_default_registry()
        register_all_tools(registry, FindingsPool(), target="example.com")

        result = asyncio.run(registry.execute("test_rce", {"url": "http://example.com/?q=1"}))

        self.assertTrue(result.is_error)
        self.assertTrue(result.metadata.get("blocked"))
        self.assertIn("被安全策略拦截", result.content)

    def test_crawler_does_not_allow_shell_injection(self):
        tmp_dir = Path(self.id().replace(".", "_"))
        tmp_dir.mkdir(exist_ok=True)
        marker = tmp_dir / "owned.txt"
        malicious_url = f"http://127.0.0.1/'; printf owned >{marker} #'"

        try:
            asyncio.run(WebCrawler(max_pages=1, max_depth=0).crawl(malicious_url))
            self.assertFalse(marker.exists())
        finally:
            if marker.exists():
                marker.unlink()
            tmp_dir.rmdir()


if __name__ == "__main__":
    unittest.main()
