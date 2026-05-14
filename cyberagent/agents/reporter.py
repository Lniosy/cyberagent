"""报告 Agent — 自动生成 SRC 格式漏洞报告"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberagent.agents.base import BaseAgent
from cyberagent.core.config import PROJECT_ROOT

logger = logging.getLogger(__name__)

REPORT_SYSTEM_PROMPT = """你是一名专业的安全研究员，负责撰写高质量的 SRC 漏洞报告。

报告要求：
1. 标题精准、专业，体现漏洞类型和影响范围
2. 描述清晰，非技术人员也能理解风险
3. 复现步骤详细、可操作，每一步都要写清楚
4. PoC（概念验证）代码或请求要完整可用
5. 影响分析要具体，量化潜在损失
6. 修复建议要可行，给出具体代码或配置示例

输出严格的 JSON 格式：
{
  "title": "漏洞标题",
  "severity": "critical/high/medium/low",
  "cvss_score": 7.5,
  "vuln_type": "漏洞类型",
  "affected_component": "受影响组件",
  "description": "漏洞描述",
  "steps_to_reproduce": ["步骤1", "步骤2", ...],
  "poc": "PoC代码或HTTP请求",
  "impact": "影响分析",
  "remediation": "修复建议",
  "references": ["相关参考链接"]
}"""


class ReportAgent(BaseAgent):
    """报告 Agent：生成 SRC 格式漏洞报告"""

    name = "reporter"

    def __init__(self, ctx, recon_results: dict | None = None, scan_results: dict | None = None):
        super().__init__(ctx)
        self.recon = recon_results or {}
        self.scan = scan_results or {}

    async def execute(self) -> dict[str, Any]:
        findings = self.scan.get("findings", [])
        if not findings:
            logger.warning("[reporter] 没有漏洞发现，生成侦察报告")
            return await self._generate_recon_report()

        # 为每个漏洞生成详细报告
        reports: list[dict[str, Any]] = []
        for i, finding in enumerate(findings):
            logger.info("[reporter] 生成报告 %d/%d: %s", i + 1, len(findings), finding.get("title", ""))
            report = await self._generate_vuln_report(finding)
            reports.append(report)

        # 生成总结报告
        summary = await self._generate_summary_report(reports)

        # 保存报告
        output_dir = PROJECT_ROOT / "output" / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        domain = self.ctx.target_domain.replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Markdown 格式
        md_path = output_dir / f"{domain}_{timestamp}.md"
        md_content = self._render_markdown(reports, summary)
        md_path.write_text(md_content, encoding="utf-8")

        # HTML 格式
        html_path = output_dir / f"{domain}_{timestamp}.html"
        html_content = self._render_html(reports, summary)
        html_path.write_text(html_content, encoding="utf-8")

        # JSON 格式
        json_path = output_dir / f"{domain}_{timestamp}.json"
        json_data = {"summary": summary, "reports": reports, "generated_at": datetime.now().isoformat()}
        json_path.write_text(json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8")

        logger.info("[reporter] 报告已生成: %s", output_dir)

        return {
            "reports": reports,
            "summary": summary,
            "output_dir": str(output_dir),
            "files": {
                "markdown": str(md_path),
                "html": str(html_path),
                "json": str(json_path),
            },
        }

    async def _generate_vuln_report(self, finding: dict) -> dict[str, Any]:
        """为单个漏洞生成详细报告"""
        context = {
            "target": self.ctx.target_domain,
            "finding": finding,
            "recon_context": {
                "tech_stack": self.recon.get("analysis", {}).get("tech_stack", []),
                "open_ports": self.recon.get("stages", {}).get("port_scan", {}).get("open_ports", []),
            },
        }

        prompt = (
            "基于以下漏洞发现，撰写一份专业的 SRC 漏洞报告。\n\n"
            f"{json.dumps(context, ensure_ascii=False, indent=2)}\n\n"
            "请根据漏洞类型和上下文，生成完整的报告内容。"
            "复现步骤要具体到 HTTP 请求级别。"
            "PoC 要包含完整的 curl 命令或 HTTP 请求。"
        )

        try:
            report = await self.ctx.llm.chat_json_pro(prompt, REPORT_SYSTEM_PROMPT)
            # 合并原始 finding 数据
            report["_raw_finding"] = finding
            return report
        except Exception as e:
            logger.error("[reporter] LLM 报告生成失败: %s", e)
            return self._fallback_report(finding)

    async def _generate_summary_report(self, reports: list[dict]) -> dict[str, Any]:
        """生成总结报告"""
        summary_data = {
            "target": self.ctx.target_domain,
            "total_findings": len(reports),
            "severity_counts": {},
            "findings_overview": [],
        }

        for r in reports:
            sev = r.get("severity", "unknown")
            summary_data["severity_counts"][sev] = summary_data["severity_counts"].get(sev, 0) + 1
            summary_data["findings_overview"].append({
                "title": r.get("title", ""),
                "severity": sev,
                "type": r.get("vuln_type", ""),
            })

        prompt = (
            "基于以下漏洞扫描结果，生成一份安全评估总结报告。\n\n"
            f"{json.dumps(summary_data, ensure_ascii=False, indent=2)}\n\n"
            "返回JSON格式:\n"
            '{"executive_summary": "执行摘要", "risk_rating": "critical/high/medium/low", '
            '"total_findings": 数字, "key_risks": ["关键风险1", "关键风险2"], '
            '"priority_actions": ["优先行动1", "优先行动2"], '
            '"testing_scope": "测试范围说明", "testing_methodology": "测试方法说明"}'
        )

        try:
            return await self.ctx.llm.chat_json_pro(
                prompt,
                system_prompt="你是一名安全团队负责人，负责撰写安全评估总结。只返回JSON。",
            )
        except Exception:
            return {
                "executive_summary": f"对 {self.ctx.target_domain} 的安全评估发现 {len(reports)} 个漏洞",
                "risk_rating": "high",
                "total_findings": len(reports),
                "key_risks": [r.get("title", "") for r in reports[:3]],
                "priority_actions": ["立即修复高危漏洞", "加强访问控制"],
            }

    async def _generate_recon_report(self) -> dict[str, Any]:
        """仅有侦察结果时生成信息收集报告"""
        analysis = self.recon.get("analysis", {})
        summary = {
            "executive_summary": f"对 {self.ctx.target_domain} 的侦察发现以下信息",
            "risk_rating": "info",
            "total_findings": 0,
            "tech_stack": analysis.get("tech_stack", []),
            "attack_surface": analysis.get("attack_surface", []),
            "suggested_next_steps": analysis.get("suggested_next_steps", []),
        }

        output_dir = PROJECT_ROOT / "output" / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        domain = self.ctx.target_domain.replace(".", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        json_path = output_dir / f"recon_{domain}_{timestamp}.json"
        json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        return {"summary": summary, "files": {"json": str(json_path)}}

    @staticmethod
    def _fallback_report(finding: dict) -> dict[str, Any]:
        """LLM 失败时的降级报告"""
        return {
            "title": finding.get("title", "未命名漏洞"),
            "severity": finding.get("severity", "medium"),
            "vuln_type": finding.get("vuln_type", "unknown"),
            "description": finding.get("evidence", ""),
            "steps_to_reproduce": [
                f"访问 {finding.get('url', '')}",
                f"参数: {finding.get('parameter', '')}",
                f"Payload: {finding.get('payload', '')}",
            ],
            "poc": finding.get("poc", finding.get("payload", "")),
            "impact": "需要进一步评估",
            "remediation": "请参考 OWASP 相关指南",
            "references": [],
            "_raw_finding": finding,
        }

    # ---- Markdown 渲染 ----

    def _render_markdown(self, reports: list[dict], summary: dict) -> str:
        """渲染 Markdown 格式报告"""
        lines = []
        domain = self.ctx.target_domain
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines.append(f"# 安全评估报告: {domain}")
        lines.append(f"\n> 生成时间: {now}")
        lines.append(f"> 工具: CyberAgent v0.1.0")
        lines.append("")

        # 执行摘要
        lines.append("## 执行摘要")
        lines.append("")
        lines.append(summary.get("executive_summary", ""))
        lines.append("")
        lines.append(f"**整体风险评级: {summary.get('risk_rating', 'unknown').upper()}**")
        lines.append(f"**发现漏洞数: {summary.get('total_findings', len(reports))}**")
        lines.append("")

        # 漏洞统计
        sev_counts = summary.get("severity_counts", {})
        if not sev_counts:
            for r in reports:
                sev = r.get("severity", "unknown")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

        if sev_counts:
            lines.append("| 严重性 | 数量 |")
            lines.append("|--------|------|")
            for sev in ["critical", "high", "medium", "low"]:
                if sev in sev_counts:
                    lines.append(f"| {sev.upper()} | {sev_counts[sev]} |")
            lines.append("")

        # 关键风险
        key_risks = summary.get("key_risks", [])
        if key_risks:
            lines.append("### 关键风险")
            lines.append("")
            for risk in key_risks:
                lines.append(f"- {risk}")
            lines.append("")

        # 优先行动
        priority = summary.get("priority_actions", [])
        if priority:
            lines.append("### 优先行动")
            lines.append("")
            for i, action in enumerate(priority, 1):
                lines.append(f"{i}. {action}")
            lines.append("")

        # 各漏洞详细报告
        lines.append("---")
        lines.append("")
        lines.append("## 漏洞详情")
        lines.append("")

        for i, report in enumerate(reports, 1):
            sev = report.get("severity", "unknown")
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(sev, "⚪")

            lines.append(f"### {i}. {sev_emoji} [{sev.upper()}] {report.get('title', '未命名')}")
            lines.append("")

            lines.append(f"- **漏洞类型:** {report.get('vuln_type', '-')}")
            lines.append(f"- **CVSS 评分:** {report.get('cvss_score', '-')}")
            lines.append(f"- **受影响组件:** {report.get('affected_component', '-')}")
            lines.append("")

            lines.append("#### 描述")
            lines.append("")
            lines.append(report.get("description", "—"))
            lines.append("")

            # 复现步骤
            steps = report.get("steps_to_reproduce", [])
            if steps:
                lines.append("#### 复现步骤")
                lines.append("")
                for j, step in enumerate(steps, 1):
                    lines.append(f"{j}. {step}")
                lines.append("")

            # PoC
            poc = report.get("poc", "")
            if poc:
                lines.append("#### PoC（概念验证）")
                lines.append("")
                lines.append("```")
                lines.append(poc)
                lines.append("```")
                lines.append("")

            # 影响
            impact = report.get("impact", "")
            if impact:
                lines.append("#### 影响分析")
                lines.append("")
                lines.append(impact)
                lines.append("")

            # 修复建议
            remediation = report.get("remediation", "")
            if remediation:
                lines.append("#### 修复建议")
                lines.append("")
                lines.append(remediation)
                lines.append("")

            # 参考
            refs = report.get("references", [])
            if refs:
                lines.append("#### 参考")
                lines.append("")
                for ref in refs:
                    lines.append(f"- {ref}")
                lines.append("")

            lines.append("---")
            lines.append("")

        # 测试说明
        lines.append("## 测试说明")
        lines.append("")
        lines.append(f"- **测试范围:** {summary.get('testing_scope', domain)}")
        lines.append(f"- **测试方法:** {summary.get('testing_methodology', '自动化扫描 + LLM 分析')}")
        lines.append(f"- **测试时间:** {now}")
        lines.append("")
        lines.append("---")
        lines.append("*本报告由 CyberAgent 自动生成*")

        return "\n".join(lines)

    # ---- HTML 渲染 ----

    def _render_html(self, reports: list[dict], summary: dict) -> str:
        """渲染 HTML 格式报告"""
        domain = self.ctx.target_domain
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        severity_colors = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280",
        }

        findings_html = ""
        for i, report in enumerate(reports, 1):
            sev = report.get("severity", "unknown")
            color = severity_colors.get(sev, "#6b7280")

            steps_html = ""
            for j, step in enumerate(report.get("steps_to_reproduce", []), 1):
                steps_html += f"<li>{step}</li>"

            poc = report.get("poc", "")
            poc_html = f'<pre><code>{poc}</code></pre>' if poc else ""

            refs_html = ""
            for ref in report.get("references", []):
                refs_html += f'<li><a href="{ref}">{ref}</a></li>'

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 16px; margin: 16px 0; background: #f9fafb;">
                <h3>{i}. <span style="color: {color};">[{sev.upper()}]</span> {report.get('title', '')}</h3>
                <table>
                    <tr><td><b>漏洞类型</b></td><td>{report.get('vuln_type', '-')}</td></tr>
                    <tr><td><b>CVSS 评分</b></td><td>{report.get('cvss_score', '-')}</td></tr>
                    <tr><td><b>受影响组件</b></td><td>{report.get('affected_component', '-')}</td></tr>
                </table>
                <h4>描述</h4>
                <p>{report.get('description', '—')}</p>
                {'<h4>复现步骤</h4><ol>' + steps_html + '</ol>' if steps_html else ''}
                {'<h4>PoC</h4>' + poc_html if poc_html else ''}
                {'<h4>影响分析</h4><p>' + report.get('impact', '') + '</p>' if report.get('impact') else ''}
                {'<h4>修复建议</h4><p>' + report.get('remediation', '') + '</p>' if report.get('remediation') else ''}
                {'<h4>参考</h4><ul>' + refs_html + '</ul>' if refs_html else ''}
            </div>"""

        sev_counts = {}
        for r in reports:
            sev = r.get("severity", "unknown")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        stats_html = ""
        for sev in ["critical", "high", "medium", "low"]:
            if sev in sev_counts:
                color = severity_colors.get(sev, "#6b7280")
                stats_html += f'<span style="background:{color};color:white;padding:4px 12px;border-radius:4px;margin:4px;">{sev.upper()}: {sev_counts[sev]}</span> '

        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>安全评估报告 - {domain}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; color: #1f2937; line-height: 1.6; }}
h1 {{ color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
h2 {{ color: #374151; margin-top: 32px; }}
h3 {{ color: #4b5563; }}
table {{ border-collapse: collapse; width: 100%; margin: 8px 0; }}
td, th {{ border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }}
th {{ background: #f3f4f6; }}
pre {{ background: #1f2937; color: #f9fafb; padding: 16px; border-radius: 8px; overflow-x: auto; }}
code {{ font-family: 'SF Mono', 'Fira Code', monospace; }}
.risk-badge {{ display: inline-block; padding: 4px 16px; border-radius: 4px; color: white; font-weight: bold; }}
</style>
</head>
<body>
<h1>安全评估报告: {domain}</h1>
<p><b>生成时间:</b> {now} | <b>工具:</b> CyberAgent v0.1.0</p>

<h2>执行摘要</h2>
<p>{summary.get('executive_summary', '')}</p>
<p><span class="risk-badge" style="background:{severity_colors.get(summary.get('risk_rating','info'),'#6b7280')}">{summary.get('risk_rating','unknown').upper()}</span></p>
<p>发现漏洞数: <b>{summary.get('total_findings', len(reports))}</b></p>
<p>{stats_html}</p>

<h2>漏洞详情</h2>
{findings_html}

<hr>
<p style="color:#9ca3af;font-size:14px;">本报告由 CyberAgent 自动生成</p>
</body>
</html>"""
