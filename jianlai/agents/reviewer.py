"""Reviewer Agent — 独立审查，裁判与运动员分离

设计思想（借鉴 Helio + Claude Code /goal）：
- Scanner 负责"干活"（发现漏洞）
- Reviewer 负责"验收"（独立验证每个发现）
- 两个角色不共享上下文惯性，避免"自说自话"
- Reviewer 可以质疑、反驳、推翻 Scanner 的结论

审查流程：
1. 接收 Scanner 的 findings
2. 对每个 finding 独立复现验证
3. 标记 verdict: confirmed / false_positive / needs_review
4. 生成审查报告（含反驳证据）
"""
from __future__ import annotations

MANIFEST = {
    "name": "reviewer",
    "display_name": "审查 Agent",
    "description": "独立验证漏洞发现，裁判与运动员分离，支持辩论机制",
    "category": "review",
    "phase": 2.5,
    "input_requires": [],
    "output_provides": ["review_results"],
}

import json
import logging
import re
from typing import Any

from jianlai.agents.base import BaseAgent
from jianlai.core.shell_executor import run_command
from jianlai.core.tools import ToolResult

logger = logging.getLogger(__name__)

REVIEW_SYSTEM_PROMPT = """你是一个独立的安全审查专家。你的职责是验证其他 Agent 发现的漏洞是否真实。

## 你的原则
1. **怀疑一切**：不要轻信 Scanner 的结论，每个发现都需要独立验证
2. **寻找反证**：主动寻找"这不是漏洞"的证据
3. **保守判断**：宁可标记为 needs_review 也不要误判为 confirmed
4. **独立复现**：用自己的方式重新测试，不要复制 Scanner 的方法

## 判定标准
- **confirmed**：有明确证据证明漏洞存在（如 SQL 错误信息、敏感数据泄露、权限绕过成功）
- **false_positive**：有明确证据证明这不是漏洞（如 SPA catch-all、正常错误页面、预期行为）
- **needs_review**：无法确定，需要人工审查

## 输出 JSON：
{
  "verdict": "confirmed|false_positive|needs_review",
  "confidence": 0.0-1.0,
  "evidence_for": "支持漏洞存在的证据",
  "evidence_against": "反对漏洞存在的证据",
  "reproduction_steps": ["独立复现步骤"],
  "reasoning": "判定推理过程"
}"""


class ReviewerAgent(BaseAgent):
    """独立审查 Agent — 验证 Scanner 的发现"""

    name = "reviewer"

    def __init__(self, ctx, scan_findings: list[dict[str, Any]] | None = None):
        super().__init__(ctx)
        self.scan_findings = scan_findings or []

    async def execute(self) -> dict[str, Any]:
        if not self.scan_findings:
            logger.info("[reviewer] 无待审查的发现")
            return {"verdicts": [], "summary": "无待审查的发现"}

        logger.info("[reviewer] 开始审查 %d 个发现", len(self.scan_findings))

        verdicts: list[dict[str, Any]] = []

        for i, finding in enumerate(self.scan_findings):
            logger.info("[reviewer] 审查 %d/%d: %s", i + 1, len(self.scan_findings),
                        finding.get("title", ""))

            # 1. 独立复现验证
            reproduction = await self._reproduce(finding)

            # 2. LLM 独立判定
            verdict = await self._judge(finding, reproduction)
            verdict["original_finding"] = finding
            verdict["reproduction"] = reproduction
            verdicts.append(verdict)

            # 3. 记录到数据库
            status = verdict.get("verdict", "needs_review")
            self.ctx.db.insert_finding(
                self.ctx.target_id,
                category=f"review_{finding.get('vuln_type', 'unknown')}",
                title=f"[{status.upper()}] {finding.get('title', '')}",
                detail=verdict.get("reasoning", ""),
                severity=finding.get("severity", "info"),
                evidence=json.dumps({
                    "for": verdict.get("evidence_for", ""),
                    "against": verdict.get("evidence_against", ""),
                    "confidence": verdict.get("confidence", 0),
                }, ensure_ascii=False),
            )

        # 统计
        confirmed = sum(1 for v in verdicts if v.get("verdict") == "confirmed")
        false_pos = sum(1 for v in verdicts if v.get("verdict") == "false_positive")
        needs_review = sum(1 for v in verdicts if v.get("verdict") == "needs_review")

        summary = {
            "total_reviewed": len(verdicts),
            "confirmed": confirmed,
            "false_positive": false_pos,
            "needs_review": needs_review,
            "accuracy": f"{confirmed}/{len(verdicts)}" if verdicts else "N/A",
        }

        logger.info("[reviewer] 审查完成: %d 确认, %d 误报, %d 待审",
                     confirmed, false_pos, needs_review)

        return {"verdicts": verdicts, "summary": summary}

    async def _reproduce(self, finding: dict[str, Any]) -> dict[str, Any]:
        """独立复现漏洞"""
        vuln_type = finding.get("vuln_type", "")
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        poc = finding.get("poc", "")

        result = {
            "method": "independent",
            "success": False,
            "evidence": "",
        }

        if not url:
            return result

        # 根据漏洞类型选择验证方法
        if vuln_type == "sqli":
            result = await self._verify_sqli(url, param, payload)
        elif vuln_type == "xss":
            result = await self._verify_xss(url, param, payload)
        elif vuln_type == "idor":
            result = await self._verify_idor(url, finding)
        elif vuln_type == "cors":
            result = await self._verify_cors(url)
        elif vuln_type == "graphql":
            result = await self._verify_graphql(url)
        elif vuln_type in ("header", "missing_header"):
            result = await self._verify_headers(url)
        else:
            # 通用验证：用 PoC 重放
            if poc:
                r = await run_command(f"curl -sL -m 10 '{poc}'", timeout=15)
                result = {
                    "method": "poc_replay",
                    "success": r.success and len(r.stdout) > 50,
                    "evidence": r.stdout[:300],
                }

        return result

    async def _verify_sqli(self, url: str, param: str, payload: str) -> dict[str, Any]:
        """独立验证 SQL 注入"""
        # 方法1：用不同的 payload 确认（不是复制 Scanner 的 payload）
        from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return {"method": "sqli_verify", "success": False, "evidence": "无参数"}

        test_param = param if param in params else list(params.keys())[0]

        # Boolean-based 独立验证
        true_params = {k: v[0] for k, v in params.items()}
        true_params[test_param] = "1 AND 1=1"
        true_url = urlunparse(parsed._replace(query=urlencode(true_params)))

        false_params = {k: v[0] for k, v in params.items()}
        false_params[test_param] = "1 AND 1=2"
        false_url = urlunparse(parsed._replace(query=urlencode(false_params)))

        r_true = await run_command(f"curl -sL -m 10 '{true_url}'", timeout=15)
        r_false = await run_command(f"curl -sL -m 10 '{false_url}'", timeout=15)

        if r_true.success and r_false.success:
            len_diff = abs(len(r_true.stdout) - len(r_false.stdout))
            if len_diff > 100:
                return {
                    "method": "boolean_independent",
                    "success": True,
                    "evidence": f"TRUE 响应 {len(r_true.stdout)}B vs FALSE 响应 {len(r_false.stdout)}B，差异 {len_diff}B",
                }

        # Error-based 独立验证
        error_params = {k: v[0] for k, v in params.items()}
        error_params[test_param] = "'"
        error_url = urlunparse(parsed._replace(query=urlencode(error_params)))
        r_err = await run_command(f"curl -sL -m 10 '{error_url}'", timeout=15)

        sql_errors = re.compile(
            r"(?i)(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLSTATE|"
            r"You have an error in your SQL syntax)",
        )
        if r_err.success and sql_errors.search(r_err.stdout):
            return {
                "method": "error_independent",
                "success": True,
                "evidence": sql_errors.search(r_err.stdout).group()[:100],
            }

        return {"method": "sqli_verify", "success": False, "evidence": "无法独立确认 SQL 注入"}

    async def _verify_xss(self, url: str, param: str, payload: str) -> dict[str, Any]:
        """独立验证 XSS — 用不同的 marker"""
        from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return {"method": "xss_verify", "success": False, "evidence": "无参数"}

        # 用完全不同的 marker 独立验证
        marker = "REVIEW_XSS_98765"
        test_param = param if param in params else list(params.keys())[0]
        test_payload = f"<script>{marker}</script>"

        test_params = {k: v[0] for k, v in params.items()}
        test_params[test_param] = test_payload
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
        if r.success and marker in r.stdout:
            return {
                "method": "xss_independent_marker",
                "success": True,
                "evidence": f"独立 marker '{marker}' 在响应中被反射",
            }

        return {"method": "xss_verify", "success": False, "evidence": "独立 marker 未被反射"}

    async def _verify_idor(self, url: str, finding: dict) -> dict[str, Any]:
        """独立验证 IDOR"""
        base = url.rstrip("/")
        # 用完全不同的 ID 组合验证
        r1 = await run_command(f"curl -sL -m 10 '{base}/1'", timeout=15)
        r3 = await run_command(f"curl -sL -m 10 '{base}/999'", timeout=15)

        if r1.success and r3.success:
            # 如果 ID=999 也返回有效数据，可能确实存在 IDOR
            if len(r3.stdout) > 50 and "<!doctype html>" not in r3.stdout.lower()[:200]:
                return {
                    "method": "idor_independent",
                    "success": True,
                    "evidence": f"ID=1 ({len(r1.stdout)}B) 和 ID=999 ({len(r3.stdout)}B) 都返回有效数据",
                }
            # 如果 ID=999 返回 404/空，可能是正常行为
            if len(r3.stdout) < 50 or "not found" in r3.stdout.lower() or "404" in r3.stdout:
                return {
                    "method": "idor_independent",
                    "success": False,
                    "evidence": f"ID=999 返回 404/空响应，可能存在访问控制",
                }

        return {"method": "idor_verify", "success": False, "evidence": "无法独立确认 IDOR"}

    async def _verify_cors(self, url: str) -> dict[str, Any]:
        """独立验证 CORS"""
        evil = "https://review-evil-test.com"
        r = await run_command(f"curl -sI -m 5 -H 'Origin: {evil}' '{url}'", timeout=10)
        if r.success:
            acao = re.search(r'(?i)^access-control-allow-origin:\s*(.+)', r.stdout, re.MULTILINE)
            if acao and acao.group(1).strip() == evil:
                return {
                    "method": "cors_independent",
                    "success": True,
                    "evidence": f"独立 Origin '{evil}' 被反射",
                }
        return {"method": "cors_verify", "success": False, "evidence": "CORS 配置正常"}

    async def _verify_graphql(self, url: str) -> dict[str, Any]:
        """独立验证 GraphQL 内省"""
        query = '{"query":"{ __schema { queryType { name } } }"}'
        r = await run_command(
            f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d '{query}' '{url}'",
            timeout=15,
        )
        if r.success and "queryType" in r.stdout:
            return {
                "method": "graphql_independent",
                "success": True,
                "evidence": "内省查询返回 queryType 定义",
            }
        return {"method": "graphql_verify", "success": False, "evidence": "内省查询被拒绝"}

    async def _verify_headers(self, url: str) -> dict[str, Any]:
        """独立验证安全头"""
        r = await run_command(f"curl -sI -m 5 '{url}'", timeout=10)
        if not r.success:
            return {"method": "header_verify", "success": False, "evidence": "获取响应头失败"}

        headers = r.stdout.lower()
        missing = []
        for header in ["strict-transport-security", "content-security-policy", "x-frame-options"]:
            if header not in headers:
                missing.append(header)

        if missing:
            return {
                "method": "header_independent",
                "success": True,
                "evidence": f"确认缺失: {', '.join(missing)}",
            }
        return {"method": "header_verify", "success": False, "evidence": "安全头配置完整"}

    async def _judge(self, finding: dict, reproduction: dict) -> dict[str, Any]:
        """LLM 独立判定"""
        prompt = (
            f"请独立判定以下漏洞发现是否真实存在：\n\n"
            f"## Scanner 的发现\n"
            f"- 漏洞类型: {finding.get('vuln_type', '')}\n"
            f"- 标题: {finding.get('title', '')}\n"
            f"- URL: {finding.get('url', '')}\n"
            f"- 参数: {finding.get('parameter', '')}\n"
            f"- Payload: {finding.get('payload', '')}\n"
            f"- Scanner 声称的证据: {finding.get('evidence', '')}\n"
            f"- 置信度: {finding.get('confidence', '')}\n\n"
            f"## 我的独立验证结果\n"
            f"- 验证方法: {reproduction.get('method', '')}\n"
            f"- 验证成功: {reproduction.get('success', False)}\n"
            f"- 验证证据: {reproduction.get('evidence', '')}\n\n"
            f"请综合判断并返回 JSON。"
        )

        try:
            return await self.ctx.llm.chat_json_pro(prompt, REVIEW_SYSTEM_PROMPT)
        except Exception:
            # LLM 失败时基于复现结果判定
            if reproduction.get("success"):
                return {
                    "verdict": "confirmed",
                    "confidence": 0.7,
                    "evidence_for": reproduction.get("evidence", ""),
                    "evidence_against": "",
                    "reasoning": "独立复现成功（LLM 判定失败，基于复现结果）",
                }
            return {
                "verdict": "needs_review",
                "confidence": 0.3,
                "evidence_for": "",
                "evidence_against": reproduction.get("evidence", ""),
                "reasoning": "独立复现失败，无法确认（LLM 判定失败）",
            }
# Auto-discovery reference
AGENT_CLASS = ReviewerAgent
