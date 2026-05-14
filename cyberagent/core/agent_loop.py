"""自主 Agent 循环 — ReAct 模式，对齐 pi 的 runLoop

核心设计（参考 pi packages/agent/src/agent-loop.ts）：
- 双层 while 循环：外层处理 follow-up，内层处理 tool call + steering
- LLM 自主决定调用哪个工具（不是固定流程）
- 工具结果反馈到 context，影响下一轮决策
- 错误恢复：错误编码进 context，LLM 自主决定下一步
- 终止条件：任务完成 / max_turns / abort
- Steering 队列：用户可实时注入指令

无人值守模式：
- Agent 持续运行直到 LLM 判断任务完成
- 遇到错误不放弃，将错误信息反馈给 LLM
- LLM 自主决定重试、换策略、跳过或降级
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from cyberagent.core.llm_client import LLMClient
from cyberagent.core.session import SessionManager
from cyberagent.core.compaction import ContextCompressor
from cyberagent.core.tools import ToolRegistry, ToolResult
from cyberagent.core.safety import get_safety_checker

logger = logging.getLogger(__name__)

# 系统 prompt — 定义 Agent 的身份和行为
AGENT_SYSTEM_PROMPT = """你是一个专业的网络安全自动化 Agent，负责对目标进行全面的安全评估。

## 你的能力
你有以下工具可用（通过 function calling 调用）：
- 侦察工具：子域名枚举、端口扫描、HTTP探测、JS分析、WAF检测
- 漏洞扫描：SQL注入、XSS、SSRF、IDOR、GraphQL、JWT、SSTI等18种检测
- 情报工具：CVE查询、GitHub PoC搜索
- 分析工具：LLM深度分析、动态payload生成
- 报告工具：生成漏洞报告

## 行为规则
1. **自主决策**：根据当前信息决定下一步行动，不要等待用户指令
2. **不放弃任务**：遇到错误时分析原因，尝试其他方法，不要停下来
3. **安全红线**：
   - 禁止对目标执行增删改操作
   - 禁止 DDoS 或资源耗尽
   - 只使用 GET/HEAD/OPTIONS 和受控的 POST
   - PoC 必须经过安全审核
4. **效率优先**：先做高价值的测试，避免重复工作
5. **完成标准**：当所有可行的测试都已完成，生成报告后调用 complete_task

## 工作流程
1. 先侦察（了解目标）
2. 根据侦察结果选择最有价值的测试
3. 并行执行多个独立测试
4. 分析结果，决定下一步
5. 重复 2-4 直到测试充分
6. 生成最终报告
7. 调用 complete_task 结束

## 重要
- 每次回复时，说明你的思考过程和下一步计划
- 如果某个测试失败，说明原因并尝试替代方案
- 优先测试高危漏洞（SQLi、RCE、IDOR）
- 生成的 payload 必须是安全的（只读探测，不执行破坏操作）"""


@dataclass
class AgentLoopConfig:
    """Agent 循环配置"""
    max_turns: int = 50            # 最大轮次（防无限循环）
    max_time: int = 1800           # 最大运行时间（30分钟）
    auto_mode: bool = True         # 无人值守模式（无 steering 时继续运行）
    compaction_enabled: bool = True  # 是否启用上下文压缩


class AgentLoop:
    """自主 Agent 循环

    对齐 pi 的 runLoop() 设计：
    - 双层 while（外层 follow-up，内层 tool call + steering）
    - LLM 自主决策 + 工具执行 + 结果反馈
    - 错误恢复 + 终止条件 + Steering
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: ToolRegistry,
        session: SessionManager,
        compressor: ContextCompressor | None = None,
        config: AgentLoopConfig | None = None,
    ):
        self.llm = llm
        self.tools = tools
        self.session = session
        self.compressor = compressor
        self.config = config or AgentLoopConfig()

        self._steering_queue: asyncio.Queue[str] = asyncio.Queue()
        self._followup_queue: asyncio.Queue[str] = asyncio.Queue()
        self._turn_count: int = 0
        self._start_time: float = 0
        self._abort: bool = False
        self._task_complete: bool = False

    # ---- 公共接口 ----

    async def run(self, target: str, initial_context: str = "") -> dict[str, Any]:
        """启动 Agent 循环（对齐 pi runLoop）

        Args:
            target: 测试目标（域名或URL）
            initial_context: 初始上下文（侦察结果等）

        Returns:
            最终结果（包含 findings、report、stats）
        """
        self._start_time = time.time()
        self._turn_count = 0

        # 注入系统 prompt
        self.session.append(
            role="system",
            content=AGENT_SYSTEM_PROMPT,
            metadata={"type": "system_prompt"},
        )

        # 注入初始任务
        task_prompt = f"请对目标 {target} 进行全面的安全评估。"
        if initial_context:
            task_prompt += f"\n\n以下是已有的侦察结果：\n{initial_context}"
        task_prompt += "\n\n请开始自主执行安全测试。"

        self.session.append(role="user", content=task_prompt)

        logger.info("[loop] Agent 循环启动 — 目标: %s, 最大轮次: %d", target, self.config.max_turns)

        # ---- 主循环（对齐 pi 双层 while）----
        while not self._should_stop():
            # 外层：检查 follow-up 消息
            follow_ups = await self._drain_followups()
            for msg in follow_ups:
                self.session.append(role="user", content=msg)

            # 内层：tool call 循环
            has_more_tools = True
            while has_more_tools and not self._should_stop():
                # 1. 注入 steering 消息
                await self._inject_steering()

                # 2. 构建 LLM 上下文
                messages = await self._build_messages()

                # 3. 调用 LLM
                try:
                    response = await self._call_llm(messages)
                except Exception as e:
                    # 错误编码进 context（对齐 pi handleRunFailure）
                    error_msg = f"LLM 调用失败: {str(e)}。请分析原因并尝试其他方法。"
                    self.session.append(role="assistant", content=error_msg)
                    logger.error("[loop] LLM 调用失败: %s", e)
                    has_more_tools = False
                    continue

                # 4. 解析响应
                text, tool_calls = self._parse_response(response)

                # 5. 记录 assistant 响应
                if text:
                    self.session.append(role="assistant", content=text)
                    logger.info("[loop] Turn %d: %s", self._turn_count, text[:100])

                # 6. 检查是否完成
                if self._task_complete:
                    logger.info("[loop] 任务完成！")
                    break

                # 7. 执行工具调用
                if tool_calls:
                    await self._execute_tool_calls(tool_calls)
                else:
                    # 无工具调用，本轮结束
                    has_more_tools = False

                self._turn_count += 1

            # 内层结束，检查是否需要继续
            if self._task_complete:
                break

        # ---- 循环结束 ----
        elapsed = time.time() - self._start_time
        self.session.force_flush()

        stats = {
            "turns": self._turn_count,
            "elapsed": round(elapsed, 1),
            "task_complete": self._task_complete,
            "aborted": self._abort,
            "session": self.session.summary(),
            "llm_stats": self.llm.stats.summary(),
        }

        logger.info("[loop] Agent 循环结束 — %d 轮, %.1fs, 完成=%s",
                     self._turn_count, elapsed, self._task_complete)

        return stats

    def steer(self, message: str):
        """注入 steering 消息（用户实时指令）"""
        self._steering_queue.put_nowait(message)
        logger.info("[loop] Steering 注入: %s", message[:50])

    def follow_up(self, message: str):
        """注入 follow-up 消息（Agent 停止后继续）"""
        self._followup_queue.put_nowait(message)

    def abort(self):
        """中断 Agent"""
        self._abort = True
        logger.info("[loop] 收到中断信号")

    # ---- 内部方法 ----

    def _should_stop(self) -> bool:
        """检查终止条件（对齐 pi shouldStopAfterTurn）"""
        if self._abort:
            return True
        if self._task_complete:
            return True
        if self._turn_count >= self.config.max_turns:
            logger.warning("[loop] 达到最大轮次 %d", self.config.max_turns)
            return True
        if time.time() - self._start_time > self.config.max_time:
            logger.warning("[loop] 达到最大运行时间 %ds", self.config.max_time)
            return True
        return False

    async def _inject_steering(self):
        """注入 steering 消息到 session（对齐 pi steering 注入时机）"""
        while not self._steering_queue.empty():
            try:
                msg = self._steering_queue.get_nowait()
                self.session.append(
                    role="user",
                    content=f"[用户指令] {msg}",
                    metadata={"type": "steering"},
                )
            except asyncio.QueueEmpty:
                break

    async def _drain_followups(self) -> list[str]:
        """排空 follow-up 队列"""
        messages = []
        while not self._followup_queue.empty():
            try:
                messages.append(self._followup_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return messages

    async def _build_messages(self) -> list[dict[str, str]]:
        """构建 LLM 消息列表（含工具定义 + 上下文压缩）"""
        messages = self.session.build_context()

        # 上下文压缩检查
        if self.compressor and self.config.compaction_enabled:
            target = self.session.get_entries_by_role("system")
            target_name = target[0].metadata.get("target", "") if target else ""
            messages = await self.compressor.compact(messages, target=target_name)

        return messages

    async def _call_llm(self, messages: list[dict[str, str]]) -> str:
        """调用 LLM（带工具定义和 prompt cache）"""
        # 构建带工具定义的请求
        tool_schemas = self.tools.get_schemas_for_llm()

        # DeepSeek 兼容 OpenAI 格式
        response = await self.llm.chat_with_tools(
            messages=messages,
            tools=tool_schemas if tool_schemas else None,
        )

        return response

    def _parse_response(self, response: str) -> tuple[str, list[dict[str, Any]]]:
        """解析 LLM 响应，提取文本和工具调用

        DeepSeek 的 function calling 返回格式：
        {"role": "assistant", "content": "...", "tool_calls": [...]}
        """
        text = ""
        tool_calls = []

        try:
            # 尝试解析 JSON 响应
            data = json.loads(response) if response.strip().startswith("{") else {}
            text = data.get("content", response)
            tool_calls = data.get("tool_calls", [])
        except json.JSONDecodeError:
            text = response

        return text, tool_calls

    async def _execute_tool_calls(self, tool_calls: list[dict[str, Any]]):
        """执行工具调用（对齐 pi tool execution）"""
        # 转换为 (name, args) 列表
        calls = []
        for tc in tool_calls:
            func = tc.get("function", {})
            name = func.get("name", "")
            args_str = func.get("arguments", "{}")
            try:
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
            except json.JSONDecodeError:
                args = {}
            if name:
                calls.append((name, args))

        if not calls:
            return

        # 批量执行（根据 executionMode 自动决定并行/串行）
        results = await self.tools.execute_batch(calls)

        # 记录结果到 session
        for (name, args), result in zip(calls, results):
            self.session.append(
                role="tool",
                content=result.content,
                tool_name=name,
                tool_args=args,
                tool_result=result.to_dict(),
                is_error=result.is_error,
            )

            # 检查是否需要终止
            if result.terminate:
                self._task_complete = True
                break

        # 检查 complete_task 调用
        for name, _ in calls:
            if name == "complete_task":
                self._task_complete = True
                break
