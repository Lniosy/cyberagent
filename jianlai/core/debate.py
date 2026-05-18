"""Agent 争论机制 — 交叉校验，避免"自说自话"

设计思想（借鉴 Helio 的"AI 吵架"）：
- Scanner 发现漏洞 → Reviewer 独立验证 → 有分歧时进入辩论
- 辩论不是为了吵架，是为了通过不同视角碰撞出真相
- 最终由 LLM 作为仲裁者做出最终判定

辩论流程：
1. Scanner 提出发现（claim）
2. Reviewer 提出质疑（challenge）
3. Scanner 反驳或承认（response）
4. 仲裁者做出最终判定（verdict）

终止条件：
- 双方达成共识
- 达到最大轮次（3轮）
- 仲裁者已有足够信息判定
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

ARBITRATOR_PROMPT = """你是一个安全漏洞仲裁专家。以下是 Scanner 和 Reviewer 关于一个潜在漏洞的辩论。

## Scanner 的立场（发现漏洞）
{scanner_claim}

## Reviewer 的立场（质疑漏洞）
{reviewer_challenge}

## Scanner 的反驳
{scanner_response}

## Reviewer 的再质疑
{reviewer_rebuttal}

请综合双方论点，做出最终判定。返回 JSON：
{{
  "final_verdict": "confirmed|false_positive|needs_review",
  "confidence": 0.0-1.0,
  "reasoning": "判定理由（综合双方论点）",
  "scanner_was_right": true/false,
  "reviewer_was_right": true/false,
  "key_evidence": "决定性的证据",
  "lesson_learned": "从这次辩论中学到什么"
}}"""


@dataclass
class DebateEntry:
    """辩论条目"""
    role: str  # scanner / reviewer / arbitrator
    claim: str
    evidence: str = ""
    timestamp: float = 0.0


@dataclass
class DebateResult:
    """辩论结果"""
    finding_title: str
    entries: list[DebateEntry]
    final_verdict: str
    confidence: float
    reasoning: str
    rounds: int


class DebateEngine:
    """辩论引擎 — 协调 Scanner 和 Reviewer 之间的争论"""

    def __init__(self, llm=None, max_rounds: int = 3):
        self.llm = llm
        self.max_rounds = max_rounds

    async def debate(
        self,
        finding: dict[str, Any],
        review_verdict: dict[str, Any],
    ) -> DebateResult:
        """对一个有分歧的 finding 进行辩论

        触发条件：Reviewer 的 verdict 与 Scanner 的 confidence 不一致
        - Scanner 说 confirmed，Reviewer 说 false_positive
        - Scanner 说 high confidence，Reviewer 说 needs_review
        """
        entries: list[DebateEntry] = []
        title = finding.get("title", "未知漏洞")

        # Round 1: Scanner 提出 claim
        scanner_claim = (
            f"我发现了一个 {finding.get('vuln_type', '')} 漏洞：\n"
            f"- 标题: {finding.get('title', '')}\n"
            f"- URL: {finding.get('url', '')}\n"
            f"- 参数: {finding.get('parameter', '')}\n"
            f"- Payload: {finding.get('payload', '')}\n"
            f"- 证据: {finding.get('evidence', '')}\n"
            f"- 置信度: {finding.get('confidence', '')}"
        )
        entries.append(DebateEntry(role="scanner", claim=scanner_claim))

        # Round 1: Reviewer 提出 challenge
        reviewer_challenge = (
            f"我质疑这个发现：\n"
            f"- 判定: {review_verdict.get('verdict', '')}\n"
            f"- 置信度: {review_verdict.get('confidence', 0)}\n"
            f"- 支持证据: {review_verdict.get('evidence_for', '')}\n"
            f"- 反对证据: {review_verdict.get('evidence_against', '')}\n"
            f"- 推理: {review_verdict.get('reasoning', '')}"
        )
        entries.append(DebateEntry(role="reviewer", claim=reviewer_challenge))

        # 如果分歧不大，直接仲裁
        scanner_conf = self._parse_confidence(finding.get("confidence", "possible"))
        reviewer_conf = review_verdict.get("confidence", 0.5)
        if abs(scanner_conf - reviewer_conf) < 0.3:
            # 分歧不大，直接仲裁
            return await self._arbitrate(title, entries)

        # Round 2: Scanner 反驳
        scanner_response = await self._generate_scanner_response(finding, review_verdict)
        entries.append(DebateEntry(role="scanner", claim=scanner_response))

        # Round 2: Reviewer 再质疑
        reviewer_rebuttal = await self._generate_reviewer_rebuttal(finding, review_verdict, scanner_response)
        entries.append(DebateEntry(role="reviewer", claim=reviewer_rebuttal))

        # 仲裁
        return await self._arbitrate(title, entries)

    async def _generate_scanner_response(self, finding: dict, review: dict) -> str:
        """Scanner 针对 Reviewer 的质疑进行反驳"""
        prompt = (
            f"Reviewer 质疑了你发现的 {finding.get('vuln_type', '')} 漏洞。\n\n"
            f"你的发现: {json.dumps(finding, ensure_ascii=False, default=str)[:500]}\n\n"
            f"Reviewer 的质疑: {json.dumps(review, ensure_ascii=False, default=str)[:500]}\n\n"
            f"请用 2-3 句话反驳 Reviewer 的质疑，或承认自己可能误判。"
        )
        try:
            return await self.llm.chat_flash(prompt, system_prompt="你是 Scanner Agent，为你的发现辩护。简洁有力。")
        except Exception:
            return f"我坚持我的发现。证据: {finding.get('evidence', '无')}"

    async def _generate_reviewer_rebuttal(self, finding: dict, review: dict, scanner_response: str) -> str:
        """Reviewer 针对 Scanner 的反驳进行再质疑"""
        prompt = (
            f"Scanner 反驳了你的质疑：\n{scanner_response}\n\n"
            f"原始发现: {finding.get('title', '')}\n"
            f"你的判定: {review.get('verdict', '')}\n\n"
            f"请用 2-3 句话回应。如果你被说服了，承认；如果坚持，给出更强的反证。"
        )
        try:
            return await self.llm.chat_flash(prompt, system_prompt="你是 Reviewer Agent，坚持独立验证。简洁有力。")
        except Exception:
            return f"我坚持我的判定。反对证据: {review.get('evidence_against', '无')}"

    async def _arbitrate(self, title: str, entries: list[DebateEntry]) -> DebateResult:
        """仲裁者做出最终判定"""
        scanner_text = "\n".join(f"[Scanner] {e.claim}" for e in entries if e.role == "scanner")
        reviewer_text = "\n".join(f"[Reviewer] {e.claim}" for e in entries if e.role == "reviewer")

        prompt = ARBITRATOR_PROMPT.format(
            scanner_claim=scanner_text[:1000],
            reviewer_challenge=reviewer_text[:500],
            scanner_response=scanner_text[-500:] if len(scanner_text) > 500 else "",
            reviewer_rebuttal=reviewer_text[-500:] if len(reviewer_text) > 500 else "",
        )

        try:
            verdict = await self.llm.chat_json_pro(
                prompt,
                system_prompt="你是安全漏洞仲裁专家。综合双方论点，做出公正判定。只返回JSON。",
            )
        except Exception:
            # 仲裁失败，默认 needs_review
            verdict = {
                "final_verdict": "needs_review",
                "confidence": 0.3,
                "reasoning": "仲裁失败，无法判定",
            }

        return DebateResult(
            finding_title=title,
            entries=entries,
            final_verdict=verdict.get("final_verdict", "needs_review"),
            confidence=verdict.get("confidence", 0.5),
            reasoning=verdict.get("reasoning", ""),
            rounds=len([e for e in entries if e.role == "scanner"]),
        )

    @staticmethod
    def _parse_confidence(confidence: str | float) -> float:
        """解析置信度"""
        if isinstance(confidence, (int, float)):
            return float(confidence)
        mapping = {"confirmed": 0.9, "probable": 0.7, "possible": 0.5, "info": 0.3}
        return mapping.get(str(confidence).lower(), 0.5)
