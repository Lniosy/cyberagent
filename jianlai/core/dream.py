"""Dream 复盘机制 — 借鉴 Helio 的"AI 深夜复盘"

扫描完成后，Agent 回顾整个过程，识别：
- 哪些 payload 有效 / 无效
- 哪些策略成功 / 失败
- 哪些步骤可以优化
- 更新知识库行为规范

每次复盘生成 changelog，可审阅、可回滚。
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jianlai.core.config import PROJECT_ROOT
from jianlai.core.knowledge import KnowledgeBase, KnowledgeEntry

logger = logging.getLogger(__name__)

DREAM_PROMPT = """你是一个安全测试复盘专家。回顾以下扫描过程，提取经验教训。

## 目标
{domain}

## 扫描统计
- 轮次: {turns}
- 耗时: {elapsed}s
- LLM 调用: {llm_calls} 次
- 成本: ${cost}

## 工具调用记录
{tool_history}

## 漏洞发现
{findings}

## 失败的工具调用
{failures}

## Reviewer 审查结果
{review_results}

请分析并返回 JSON：
{{
  "effective_payloads": [
    {{"vuln_type": "...", "payload": "...", "why_effective": "..."}}
  ],
  "ineffective_payloads": [
    {{"vuln_type": "...", "payload": "...", "why_failed": "..."}}
  ],
  "strategy_insights": [
    {{"observation": "...", "recommendation": "..."}}
  ],
  "tool_issues": [
    {{"tool": "...", "issue": "...", "fix": "..."}}
  ],
  "false_positives_found": [
    {{"vuln_type": "...", "reason": "..."}}
  ],
  "missed_opportunities": [
    {{"area": "...", "what_should_have_tested": "..."}}
  ],
  "overall_assessment": "整体评估",
  "improvement_priority": ["最重要的改进点"]
}}"""


@dataclass
class DreamResult:
    """复盘结果"""
    domain: str
    timestamp: str
    reflections: dict[str, Any]
    knowledge_updates: int
    changelog: list[str]


class DreamEngine:
    """Dream 复盘引擎"""

    def __init__(self, knowledge: KnowledgeBase, llm=None):
        self.knowledge = knowledge
        self.llm = llm
        self._changelog_dir = PROJECT_ROOT / "data" / "dream_changelogs"
        self._changelog_dir.mkdir(parents=True, exist_ok=True)

    async def reflect(
        self,
        domain: str,
        session_stats: dict[str, Any],
        tool_history: list[dict],
        findings: list[dict],
        review_results: dict | None = None,
    ) -> DreamResult:
        """执行复盘"""
        logger.info("[dream] 开始复盘: %s", domain)

        # 分离成功和失败的工具调用
        successes = [t for t in tool_history if not t.get("error")]
        failures = [t for t in tool_history if t.get("error")]

        prompt = DREAM_PROMPT.format(
            domain=domain,
            turns=session_stats.get("turns", 0),
            elapsed=session_stats.get("elapsed", 0),
            llm_calls=session_stats.get("llm_stats", {}).get("total", {}).get("calls", 0),
            cost=session_stats.get("llm_stats", {}).get("total", {}).get("cost_usd", 0),
            tool_history=json.dumps(tool_history[:30], ensure_ascii=False, default=str)[:2000],
            findings=json.dumps(findings[:20], ensure_ascii=False, default=str)[:2000],
            failures=json.dumps(failures[:10], ensure_ascii=False, default=str)[:500],
            review_results=json.dumps(review_results or {}, ensure_ascii=False, default=str)[:500],
        )

        reflections = {}
        changelog: list[str] = []
        knowledge_updates = 0

        try:
            reflections = await self.llm.chat_json_pro(
                prompt,
                system_prompt="你是安全测试复盘专家。分析扫描过程，提取经验教训。只返回JSON。",
            )
        except Exception as e:
            logger.warning("[dream] LLM 复盘失败: %s", e)
            reflections = {"overall_assessment": "LLM 复盘失败"}

        # 将复盘结果存入知识库
        knowledge_updates += await self._store_effective_payloads(domain, reflections)
        knowledge_updates += await self._store_ineffective_payloads(domain, reflections)
        knowledge_updates += await self._store_strategy_insights(domain, reflections)
        knowledge_updates += await self._store_false_positives(domain, reflections)

        # 生成 changelog
        changelog = self._generate_changelog(reflections, knowledge_updates)

        # 保存 changelog 到文件
        self._save_changelog(domain, changelog, reflections)

        result = DreamResult(
            domain=domain,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            reflections=reflections,
            knowledge_updates=knowledge_updates,
            changelog=changelog,
        )

        logger.info("[dream] 复盘完成: %d 条知识更新, %d 条 changelog",
                     knowledge_updates, len(changelog))
        return result

    async def _store_effective_payloads(self, domain: str, reflections: dict) -> int:
        """存储有效的 payload"""
        count = 0
        for item in reflections.get("effective_payloads", []):
            self.knowledge.store(KnowledgeEntry(
                category="payload_pattern",
                vuln_type=item.get("vuln_type", ""),
                content={
                    "payload": item.get("payload", ""),
                    "why_effective": item.get("why_effective", ""),
                    "effective": True,
                },
                source_domain=domain,
                success_count=1,
                confidence=0.8,
            ))
            count += 1
        return count

    async def _store_ineffective_payloads(self, domain: str, reflections: dict) -> int:
        """存储无效的 payload（避免重复）"""
        count = 0
        for item in reflections.get("ineffective_payloads", []):
            self.knowledge.store(KnowledgeEntry(
                category="failure_record",
                vuln_type=item.get("vuln_type", ""),
                content={
                    "payload": item.get("payload", ""),
                    "reason": item.get("why_failed", ""),
                    "target_tech": domain,
                },
                source_domain=domain,
                fail_count=1,
                confidence=0.7,
            ))
            count += 1
        return count

    async def _store_strategy_insights(self, domain: str, reflections: dict) -> int:
        """存储策略洞察"""
        count = 0
        for item in reflections.get("strategy_insights", []):
            self.knowledge.store(KnowledgeEntry(
                category="target_pattern",
                content={
                    "observation": item.get("observation", ""),
                    "recommendation": item.get("recommendation", ""),
                },
                source_domain=domain,
                confidence=0.6,
            ))
            count += 1
        return count

    async def _store_false_positives(self, domain: str, reflections: dict) -> int:
        """存储误报模式（避免重复误报）"""
        count = 0
        for item in reflections.get("false_positives_found", []):
            self.knowledge.store(KnowledgeEntry(
                category="vuln_signature",
                vuln_type=item.get("vuln_type", ""),
                content={
                    "pattern": "false_positive",
                    "reason": item.get("reason", ""),
                    "target": domain,
                },
                source_domain=domain,
                confidence=0.9,
            ))
            count += 1
        return count

    def _generate_changelog(self, reflections: dict, knowledge_updates: int) -> list[str]:
        """生成 changelog"""
        lines = []

        if reflections.get("overall_assessment"):
            lines.append(f"## 整体评估\n{reflections['overall_assessment']}")

        if reflections.get("effective_payloads"):
            lines.append(f"\n## 有效 payload ({len(reflections['effective_payloads'])} 条)")
            for p in reflections["effective_payloads"]:
                lines.append(f"  + [{p.get('vuln_type')}] {p.get('payload', '')[:50]}")

        if reflections.get("ineffective_payloads"):
            lines.append(f"\n## 无效 payload ({len(reflections['ineffective_payloads'])} 条)")
            for p in reflections["ineffective_payloads"]:
                lines.append(f"  - [{p.get('vuln_type')}] {p.get('payload', '')[:50]}")

        if reflections.get("improvement_priority"):
            lines.append("\n## 改进优先级")
            for i, p in enumerate(reflections["improvement_priority"], 1):
                lines.append(f"  {i}. {p}")

        lines.append(f"\n知识库更新: {knowledge_updates} 条")
        return lines

    def _save_changelog(self, domain: str, changelog: list[str], reflections: dict):
        """保存 changelog 到文件"""
        ts = time.strftime("%Y%m%d_%H%M%S")
        safe_domain = domain.replace(".", "_").replace(":", "_")
        path = self._changelog_dir / f"{safe_domain}_{ts}.md"

        content = f"# Dream Changelog: {domain}\n"
        content += f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        content += "\n".join(changelog)
        content += f"\n\n---\n\n## 原始数据\n```json\n{json.dumps(reflections, ensure_ascii=False, indent=2)}\n```"

        path.write_text(content, encoding="utf-8")
        logger.info("[dream] changelog 已保存: %s", path)
