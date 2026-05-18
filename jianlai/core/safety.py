"""全局安全约束 — 所有 Agent 必须遵守的安全红线

这些约束不可绕过、不可覆盖、不可关闭。
违反这些约束的操作会被阻止并记录。
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ============================================================
# 安全红线（Safety Red Lines）
# ============================================================

# 1. 禁止对目标执行任何增删改操作
#    - 只允许 GET/HEAD/OPTIONS 等只读请求
#    - POST/PUT/PATCH/DELETE 只允许登录/认证测试，且 payload 不含恶意数据
ALLOWED_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

# 2. 禁止 DDoS / 资源耗尽攻击
#    - 单目标并发请求上限
MAX_CONCURRENT_REQUESTS_PER_TARGET = 10
#    - 单次扫描最大请求总数
MAX_TOTAL_REQUESTS = 2000
#    - 单请求最大超时
MAX_REQUEST_TIMEOUT = 30  # seconds

# 3. 禁止数据窃取
#    - 只读取响应特征（状态码、响应头、错误信息）
#    - 不提取/存储/传输用户敏感数据（密码、token、个人信息）

# 4. 禁止执行未经安全审核的代码
#    - PoC 必须通过静态安全审核才能执行
#    - 禁止 eval() / exec() / os.system() / subprocess(shell=True)

# 5. 禁止越界测试
#    - 只测试授权范围内的目标
#    - 遵守 SRC 规则（不测 DoS、社工、物理攻击）

# 6. 所有操作必须可审计
#    - 每个请求必须有日志记录
#    - 发现的漏洞必须存入数据库
#    - 操作历史不可篡改


class SafetyChecker:
    """安全检查器 — 在操作执行前验证是否违反安全红线"""

    def __init__(self):
        self._request_count = 0
        self._blocked_count = 0

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def blocked_count(self) -> int:
        return self._blocked_count

    def check_http_method(self, method: str, url: str) -> bool:
        """检查 HTTP 方法是否允许"""
        method = method.upper().strip()
        if method in ALLOWED_HTTP_METHODS:
            return True

        # POST/PUT 允许用于登录测试，但需要安全检查
        if method in ("POST", "PUT", "PATCH"):
            logger.debug("[safety] 允许 %s %s (登录/认证测试)", method, url)
            return True

        # DELETE 严格禁止
        if method == "DELETE":
            logger.warning("[safety] 拦截 DELETE 请求: %s", url)
            self._blocked_count += 1
            return False

        return True

    def check_payload_safety(self, payload: str) -> tuple[bool, str]:
        """检查 payload 是否包含危险操作"""
        if not payload:
            return True, ""

        # 检查 SQL 破坏性操作
        destructive_sql = [
            r'\bDROP\s+(TABLE|DATABASE)\b',
            r'\bDELETE\s+FROM\b(?!\s+.*WHERE)',
            r'\bTRUNCATE\b',
            r'\bUPDATE\s+.*SET\b(?!\s+.*WHERE)',
        ]
        for pattern in destructive_sql:
            if re.search(pattern, payload, re.IGNORECASE):
                msg = f"payload 包含破坏性 SQL: {pattern}"
                logger.warning("[safety] 拦截: %s", msg)
                self._blocked_count += 1
                return False, msg

        # 检查命令注入（实际执行）
        cmd_injection = [
            r';\s*(rm|mkfs|dd|format)\b',
            r'\|\s*(rm|mkfs|dd|format)\b',
            r'`rm|mkfs|dd|format`',
        ]
        for pattern in cmd_injection:
            if re.search(pattern, payload, re.IGNORECASE):
                msg = f"payload 包含破坏性命令: {pattern}"
                logger.warning("[safety] 拦截: %s", msg)
                self._blocked_count += 1
                return False, msg

        return True, ""

    def check_request_rate(self) -> bool:
        """检查请求速率是否超过限制"""
        self._request_count += 1
        if self._request_count > MAX_TOTAL_REQUESTS:
            logger.warning("[safety] 请求总数超过限制 (%d > %d)",
                           self._request_count, MAX_TOTAL_REQUESTS)
            self._blocked_count += 1
            return False
        return True

    def check_target_scope(self, target: str, allowed_domains: list[str]) -> bool:
        """检查目标是否在授权范围内"""
        if not allowed_domains:
            return True  # 未设置范围限制

        target_lower = target.lower()
        for domain in allowed_domains:
            if target_lower.endswith(domain.lower()) or target_lower == domain.lower():
                return True

        logger.warning("[safety] 目标 %s 不在授权范围内: %s", target, allowed_domains)
        self._blocked_count += 1
        return False

    def check_code_safety(self, code: str) -> tuple[bool, list[str]]:
        """检查代码是否包含危险操作（用于 PoC 审核）"""
        from jianlai.agents.vuln_intel import ALL_DANGEROUS_PATTERNS

        issues = []
        for pattern in ALL_DANGEROUS_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                issues.append(f"危险模式: {pattern[:50]}")

        if issues:
            self._blocked_count += 1
            return False, issues
        return True, []

    def stats(self) -> dict[str, Any]:
        """返回安全检查统计"""
        return {
            "total_requests": self._request_count,
            "blocked_requests": self._blocked_count,
            "block_rate": f"{self._blocked_count / max(self._request_count, 1) * 100:.1f}%",
        }


# 全局安全检查器实例
_global_checker: SafetyChecker | None = None


def get_safety_checker() -> SafetyChecker:
    """获取全局安全检查器"""
    global _global_checker
    if _global_checker is None:
        _global_checker = SafetyChecker()
    return _global_checker
