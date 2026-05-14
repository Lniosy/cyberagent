"""异步 Shell 命令执行器，用于调用外部安全工具"""
from __future__ import annotations

import asyncio
import logging
import shlex
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ShellResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def lines(self) -> list[str]:
        return [l for l in self.stdout.strip().splitlines() if l.strip()]


async def run_command(
    cmd: str | list[str],
    timeout: int = 120,
    cwd: str | None = None,
) -> ShellResult:
    """执行单个命令，返回结果"""
    if isinstance(cmd, list):
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
    else:
        cmd_str = cmd

    logger.info("执行命令: %s (timeout=%ds)", cmd_str, timeout)

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")
            return ShellResult(
                command=cmd_str,
                returncode=proc.returncode or 0,
                stdout=stdout,
                stderr=stderr,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ShellResult(
                command=cmd_str,
                returncode=-1,
                stdout="",
                stderr=f"命令超时 ({timeout}s)",
                timed_out=True,
            )
    except Exception as e:
        return ShellResult(
            command=cmd_str,
            returncode=-1,
            stdout="",
            stderr=str(e),
        )


async def run_commands(
    cmds: list[str | list[str]],
    timeout: int = 120,
    max_concurrent: int = 5,
) -> list[ShellResult]:
    """并发执行多个命令"""
    sem = asyncio.Semaphore(max_concurrent)

    async def _run(cmd):
        async with sem:
            return await run_command(cmd, timeout=timeout)

    return await asyncio.gather(*[_run(c) for c in cmds])


def check_tool_exists(tool_name: str) -> bool:
    """检查外部工具是否已安装"""
    import shutil
    return shutil.which(tool_name) is not None


# Go 安全工具目录（优先于 PATH 中的同名 Python 工具）
_GO_TOOLS = {"httpx", "subfinder", "nuclei", "katana", "gau", "unfurl", "assetfinder"}


def resolve_tool(tool_name: str) -> str:
    """解析工具的实际路径，Go 安全工具优先于 PATH 中的同名 Python 工具"""
    import os
    import shutil

    if tool_name in _GO_TOOLS:
        go_bin = os.path.expanduser("~/go/bin")
        go_path = os.path.join(go_bin, tool_name)
        if os.path.isfile(go_path) and os.access(go_path, os.X_OK):
            return go_path

    found = shutil.which(tool_name)
    return found or tool_name
