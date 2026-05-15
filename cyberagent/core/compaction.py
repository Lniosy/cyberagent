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

        从最新消息向前遍历，累加 token。记录最近的合法切割点候选，
        当累积超过 keep_recent_tokens 时返回该候选。

        合法切割点规则：
        - 只在 user/assistant/system 消息处切割
        - 永不切断 tool 消息
        - 永不切断 assistant(tool_calls) → tool(result) 对
        - 永不切断连续的 tool 结果消息组
        """
        keep_tokens = self.settings.keep_recent_tokens
        accumulated = 0
        last_valid_cut: int | None = None

        for i in range(len(messages) - 1, -1, -1):
            content = messages[i].get("content", "")
            accumulated += self.estimate_tokens(content)

            role = messages[i].get("role", "")

            if role in ("user", "system"):
                # user/system 消息始终是合法切割点
                last_valid_cut = i

            elif role == "assistant":
                # assistant 消息：检查是否有 tool_calls
                has_tool_calls = bool(messages[i].get("tool_calls"))
                if has_tool_calls:
                    # 有 tool_calls，不是合法切割点（后面必须跟 tool 结果）
                    pass
                elif i + 1 < len(messages) and messages[i + 1].get("role") == "tool":
                    # 下一条是 tool（属于前一个 assistant 的 tool_calls），不是切割点
                    pass
                else:
                    # 普通 assistant 消息，合法切割点
                    last_valid_cut = i

            # role == "tool" 时不做任何操作（不是合法切割点）

            # 累积超过阈值且有合法候选
            if accumulated >= keep_tokens and last_valid_cut is not None:
                return last_valid_cut

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

        # 清理孤立的 tool 消息（DeepSeek 要求 tool 消息必须紧跟 assistant tool_calls）
        recent_messages = self._clean_orphaned_tools(recent_messages)

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
    def _clean_orphaned_tools(messages: list[dict[str, str]]) -> list[dict[str, str]]:
        """清理孤立的 tool 消息。

        DeepSeek 要求 role='tool' 的消息必须紧跟在包含 tool_calls 的
        assistant 消息之后。如果压缩切断了 assistant+tool_calls，对应的
        tool 结果消息就变成孤立的，必须移除。
        """
        cleaned = []
        pending_tool_count = 0  # 待消费的 tool 结果数量

        for msg in messages:
            role = msg.get("role", "")

            if role == "assistant":
                cleaned.append(msg)
                # 计算 tool_calls 数量
                tool_calls = msg.get("tool_calls", [])
                pending_tool_count = len(tool_calls) if tool_calls else 0

            elif role == "tool":
                if pending_tool_count > 0:
                    # 有待消费的 tool 结果，保留
                    cleaned.append(msg)
                    pending_tool_count -= 1
                else:
                    # 孤立的 tool 消息，跳过
                    logger.debug("[compaction] 移除孤立 tool 消息: %s",
                                 msg.get("content", "")[:50])

            else:
                cleaned.append(msg)
                pending_tool_count = 0

        return cleaned

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
