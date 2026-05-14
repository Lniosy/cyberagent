"""上下文压缩 — 对齐 pi 的 compaction 机制

核心设计（参考 pi packages/coding-agent/src/core/compaction/compaction.ts）：
- token 估算：chars / 2（中英混合）
- 触发条件：context_tokens > context_window - reserve_tokens
- 切割点算法：从最新消息向前遍历，合法切割点在 user/assistant 边界
- 压缩摘要：6 维度（Goal/Constraints/Progress/Key Decisions/Next Steps/Critical Context）
- 增量更新：已有摘要时合并，不从头生成
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from cyberagent.core.llm_client import LLMClient

logger = logging.getLogger(__name__)

# DeepSeek V4 Pro 配置
CONTEXT_WINDOW = 128_000       # 128K token
RESERVE_TOKENS = 16_384        # 保留给输出
KEEP_RECENT_TOKENS = 20_000    # 保留最近的消息

COMPACTION_THRESHOLD = CONTEXT_WINDOW - RESERVE_TOKENS  # 112K

SUMMARIZE_PROMPT = """你是一个安全测试 Agent 的上下文压缩器。请将以下会话历史压缩为结构化摘要。

保留以下 6 个维度的信息：
1. **Goal**: 测试目标和范围
2. **Constraints**: 安全红线、SRC 规则、技术约束
3. **Progress**: 已完成/进行中/被阻塞的任务
4. **Key Decisions**: 已做的策略决策及理由
5. **Next Steps**: 下一步计划
6. **Critical Context**: 已发现的漏洞、关键URL、有效payload、技术栈信息

注意：
- 保留所有具体的漏洞发现（URL、参数、payload、证据）
- 保留所有 API 端点信息
- 保留技术栈识别结果
- 丢弃重复的中间步骤和调试信息
- 用简洁的要点列表格式

输出格式：纯文本（不是JSON），每个维度用 ## 标题。"""

UPDATE_PROMPT = """你是一个安全测试 Agent 的上下文压缩器。已有一个历史摘要，请将新的会话内容合并到摘要中。

要求：
- 保留历史摘要中的所有有效信息
- 追加新的进展和发现
- 更新进度状态
- 合并重复信息
- 保持 6 维度结构"""


@dataclass
class CompactionSettings:
    """压缩配置（对齐 pi CompactionSettings）"""
    enabled: bool = True
    context_window: int = CONTEXT_WINDOW
    reserve_tokens: int = RESERVE_TOKENS
    keep_recent_tokens: int = KEEP_RECENT_TOKENS


class ContextCompressor:
    """上下文压缩器"""

    def __init__(self, llm: LLMClient, settings: CompactionSettings | None = None):
        self.llm = llm
        self.settings = settings or CompactionSettings()
        self._last_summary: str = ""

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """估算 token 数（中英混合：1 token ≈ 2 字符）"""
        return max(len(text) // 2, 1)

    def should_compact(self, messages: list[dict[str, str]]) -> bool:
        """检查是否需要压缩（对齐 pi shouldCompact）"""
        if not self.settings.enabled:
            return False

        total_tokens = sum(
            self.estimate_tokens(m.get("content", ""))
            for m in messages
        )

        threshold = self.settings.context_window - self.settings.reserve_tokens
        if total_tokens > threshold:
            logger.info("[compaction] 需要压缩: %d tokens > %d threshold",
                        total_tokens, threshold)
            return True
        return False

    def find_cut_point(self, messages: list[dict[str, str]]) -> int:
        """找到切割点（对齐 pi findCutPoint）

        从最新消息向前遍历，累加 token，当累积超过 keep_recent_tokens
        时找到最近的合法切割点。合法切割点在 user/assistant/system 消息处，
        永不切断 tool 消息。
        """
        keep_tokens = self.settings.keep_recent_tokens
        accumulated = 0

        # 从后向前遍历
        for i in range(len(messages) - 1, -1, -1):
            content = messages[i].get("content", "")
            accumulated += self.estimate_tokens(content)

            role = messages[i].get("role", "")

            # 超过 keep_recent_tokens 且在合法切割点
            if accumulated >= keep_tokens and role in ("user", "assistant", "system"):
                # 确保不会在 tool result 中间切割
                # 检查下一条消息是否是 tool（如果是，跳过）
                if i + 1 < len(messages) and messages[i + 1].get("role") == "tool":
                    continue
                return i

        # 找不到切割点，保留全部
        return 0

    async def compact(
        self,
        messages: list[dict[str, str]],
        target: str = "",
    ) -> list[dict[str, str]]:
        """执行压缩（对齐 pi generateSummary + incremental update）

        返回压缩后的消息列表。
        """
        if not self.should_compact(messages):
            return messages

        cut_point = self.find_cut_point(messages)
        if cut_point == 0:
            logger.info("[compaction] 无需压缩（未找到合法切割点）")
            return messages

        # 分割消息
        old_messages = messages[:cut_point]
        recent_messages = messages[cut_point:]

        logger.info("[compaction] 压缩: 丢弃 %d 条消息, 保留最近 %d 条",
                     len(old_messages), len(recent_messages))

        # 生成摘要
        old_text = self._messages_to_text(old_messages)

        if self._last_summary:
            # 增量更新（对齐 pi UPDATE_SUMMARIZATION_PROMPT）
            prompt = (
                f"{UPDATE_PROMPT}\n\n"
                f"## 历史摘要\n{self._last_summary}\n\n"
                f"## 新的会话内容\n{old_text}\n\n"
                f"## 目标\n{target}\n\n"
                f"请输出合并后的完整摘要。"
            )
        else:
            # 首次压缩
            prompt = (
                f"{SUMMARIZE_PROMPT}\n\n"
                f"## 目标\n{target}\n\n"
                f"## 会话历史\n{old_text}"
            )

        try:
            summary = await self.llm.chat_flash(prompt)
            self._last_summary = summary

            # 构建压缩后的消息列表
            compacted = [
                {"role": "system", "content": f"[上下文压缩摘要]\n\n{summary}"},
                *recent_messages,
            ]

            logger.info("[compaction] 压缩完成: %d → %d 条消息",
                         len(messages), len(compacted))
            return compacted

        except Exception as e:
            logger.error("[compaction] 压缩失败: %s，保留原消息", e)
            return messages

    @staticmethod
    def _messages_to_text(messages: list[dict[str, str]]) -> str:
        """将消息列表转为纯文本"""
        parts = []
        for m in messages:
            role = m.get("role", "unknown")
            content = m.get("content", "")
            if content:
                # 截断过长内容
                if len(content) > 500:
                    content = content[:500] + "..."
                parts.append(f"[{role}]: {content}")
        return "\n".join(parts)
