"""共享发现池 — 模块间实时共享发现信息

所有扫描模块的发现实时写入 pool，后续模块可查询利用。
例如：SQLi 模块发现参数 "id" 存在注入 → XSS 模块优先测试该参数。
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SharedFinding:
    """共享发现条目"""
    source: str             # 来源模块名
    vuln_type: str          # sqli / xss / ssrf / idor / ...
    target_url: str
    parameter: str = ""
    detail: str = ""
    severity: str = "info"
    confidence: str = "possible"
    payload: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


class FindingsPool:
    """共享发现池 — 线程安全的发现集合

    使用场景：
    - SQLi 发现注入点 → 写入 pool
    - XSS 查询 pool 获取已确认的注入参数 → 优先测试
    - IDOR 查询 pool 获取已发现的 API 端点 → 针对性测试
    """

    def __init__(self):
        self._findings: list[SharedFinding] = []
        self._injection_points: dict[str, list[str]] = {}  # url → [params]

    def add(self, finding: SharedFinding) -> None:
        """添加发现"""
        self._findings.append(finding)

        # 维护注入点索引
        if finding.vuln_type in ("sqli", "xss", "ssti", "nosqli", "cmd_injection"):
            url = finding.target_url
            if url not in self._injection_points:
                self._injection_points[url] = []
            if finding.parameter and finding.parameter not in self._injection_points[url]:
                self._injection_points[url].append(finding.parameter)
                logger.info("[pool] 新注入点: %s @ %s", finding.parameter, url)

    def get_injection_points(self, url: str) -> list[str]:
        """获取指定 URL 已确认的注入参数"""
        return self._injection_points.get(url, [])

    def get_all_injection_points(self) -> dict[str, list[str]]:
        """获取所有注入点"""
        return dict(self._injection_points)

    def query(
        self,
        vuln_type: str | None = None,
        target_url: str | None = None,
        source: str | None = None,
        min_severity: str | None = None,
    ) -> list[SharedFinding]:
        """查询发现"""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        min_sev = severity_order.get(min_severity or "info", 0)

        results = []
        for f in self._findings:
            if vuln_type and f.vuln_type != vuln_type:
                continue
            if target_url and f.target_url != target_url:
                continue
            if source and f.source != source:
                continue
            if severity_order.get(f.severity, 0) < min_sev:
                continue
            results.append(f)

        return results

    def get_api_endpoints(self) -> list[str]:
        """获取所有已发现的 API 端点"""
        endpoints = set()
        for f in self._findings:
            if f.vuln_type in ("idor", "api_endpoint", "graphql"):
                if f.target_url:
                    endpoints.add(f.target_url)
        return list(endpoints)

    def get_confirmed_vulns(self) -> list[SharedFinding]:
        """获取所有已确认的漏洞"""
        return [f for f in self._findings if f.confidence == "confirmed"]

    def summary(self) -> dict[str, Any]:
        """返回发现池统计"""
        by_type: dict[str, int] = {}
        for f in self._findings:
            by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

        return {
            "total_findings": len(self._findings),
            "injection_points": len(self._injection_points),
            "by_type": by_type,
            "confirmed": len(self.get_confirmed_vulns()),
        }

    def to_context_string(self) -> str:
        """导出为字符串，供 LLM 上下文使用"""
        if not self._findings:
            return "暂无发现。"

        parts = [f"已发现 {len(self._findings)} 个问题："]

        # 注入点
        if self._injection_points:
            parts.append("\n## 已确认的注入点：")
            for url, params in self._injection_points.items():
                parts.append(f"  - {url}: 参数 {', '.join(params)}")

        # 高危漏洞
        high_vulns = self.get_confirmed_vulns()
        if high_vulns:
            parts.append("\n## 已确认漏洞：")
            for f in high_vulns[:10]:
                parts.append(f"  - [{f.severity}] {f.vuln_type}: {f.detail[:60]}")

        return "\n".join(parts)
