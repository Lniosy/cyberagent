"""异步 Shell 命令执行器，用于调用外部安全工具

使用进程组管理防止僵尸进程（start_new_session + killpg）
集成安全检查，在命令执行前拦截危险操作
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shlex
import signal
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---- 命令级安全拦截 ----
_BLOCKED_COMMANDS = re.compile(
    r'\b(rm\s+-rf|mkfs|dd\s+if=|format\s+[a-z]:|shutdown|reboot|halt|poweroff|init\s+0)\b',
    re.IGNORECASE,
)
# 拦截所有危险 shell 元字符组合（不限于 rm，包括 curl/wget/python/bash/nc 等）
_BLOCKED_SHELL_INJECTION = re.compile(
    r'(?:;\s*|\|\s*|`\s*|\$\()\s*(?:curl|wget|python|bash|sh|nc|ncat|socat|'
    r'rm|chmod|chown|kill|pkill|killall|nohup|setsid)\b',
    re.IGNORECASE,
)


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
    """执行单个命令，返回结果。使用进程组管理防止僵尸进程。"""
    if isinstance(cmd, list):
        cmd_str = " ".join(shlex.quote(c) for c in cmd)
    else:
        cmd_str = cmd

    logger.info("执行命令: %s (timeout=%ds)", cmd_str, timeout)

    # 安全检查：拦截危险命令
    if _BLOCKED_COMMANDS.search(cmd_str) or _BLOCKED_SHELL_INJECTION.search(cmd_str):
        logger.error("[SAFETY] 拦截危险命令: %s", cmd_str)
        return ShellResult(
            command=cmd_str, returncode=-1, stdout="",
            stderr="[SAFETY BLOCKED] 命令包含危险操作，已被安全策略拦截",
        )

    # 安全检查：超时上限保护
    if timeout > 300:
        logger.warning("[SAFETY] 超时 %ds 超过上限，强制设为 300s", timeout)
        timeout = 300

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            start_new_session=True,  # 创建新进程组，方便整体终止
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
            # 终止整个进程组（包括孙进程）
            _kill_process_group(proc)
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


def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """终止进程组中的所有进程"""
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, OSError):
        # 进程已退出
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def run_commands(
    cmds: list[str | list[str]],
    timeout: int = 120,
    max_concurrent: int = 5,
) -> list[ShellResult]:
    """并发执行多个命令（集成速率限制）"""
    limiter = get_rate_limiter()
    sem = asyncio.Semaphore(min(max_concurrent, limiter.max_concurrent))

    async def _run(cmd):
        if not limiter.check():
            return ShellResult(
                command=str(cmd), returncode=-1, stdout="",
                stderr="[SAFETY] 请求速率超过限制",
            )
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
    import shutil

    if tool_name in _GO_TOOLS:
        go_bin = os.path.expanduser("~/go/bin")
        go_path = os.path.join(go_bin, tool_name)
        if os.path.isfile(go_path) and os.access(go_path, os.X_OK):
            return go_path

    found = shutil.which(tool_name)
    return found or tool_name


# ---- HTTP 请求级安全拦截 ----

# 允许的 curl HTTP 方法
_ALLOWED_CURL_METHODS = {"-G", "--get"}  # GET（默认）
_CONTROLLED_METHODS = {"POST", "PUT", "PATCH"}  # 受控允许（用于认证测试）
_BLOCKED_METHODS = {"DELETE", "TRACE"}  # 严格禁止

# 请求速率限制器
class RateLimiter:
    """全局请求速率限制"""
    def __init__(self, max_total: int = 2000, max_concurrent: int = 10):
        self.max_total = max_total
        self.max_concurrent = max_concurrent
        self._count = 0
        self._semaphore = asyncio.Semaphore(max_concurrent)

    @property
    def count(self) -> int:
        return self._count

    def check(self) -> bool:
        self._count += 1
        if self._count > self.max_total:
            logger.error("[SAFETY] 请求总数 %d 超过限制 %d", self._count, self.max_total)
            return False
        return True

    async def acquire(self):
        await self._semaphore.acquire()

    def release(self):
        self._semaphore.release()


_global_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter()
    return _global_limiter


async def safe_curl(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str = "",
    timeout: int = 10,
    follow_redirects: bool = True,
) -> ShellResult:
    """安全的 curl 封装 — 内置方法检查、速率限制、超时保护"""
    limiter = get_rate_limiter()

    # 1. 速率限制
    if not limiter.check():
        return ShellResult(
            command="BLOCKED", returncode=-1, stdout="",
            stderr="[SAFETY] 请求总数超过限制",
        )

    # 2. HTTP 方法检查
    method = method.upper()
    if method in _BLOCKED_METHODS:
        logger.error("[SAFETY] 拦截 %s 请求: %s", method, url)
        return ShellResult(
            command="BLOCKED", returncode=-1, stdout="",
            stderr=f"[SAFETY] HTTP {method} 方法被禁止",
        )

    # 3. 构建 curl 命令
    parts = ["curl", "-s", "-m", str(min(timeout, 30))]
    if method != "GET":
        parts.extend(["-X", method])
    if follow_redirects:
        parts.append("-L")
    if headers:
        for k, v in headers.items():
            parts.extend(["-H", f"{k}: {v}"])
    if data:
        parts.extend(["-d", data])
    parts.append(url)

    # 4. 并发限制
    await limiter.acquire()
    try:
        return await run_command(parts, timeout=timeout + 5)
    finally:
        limiter.release()
