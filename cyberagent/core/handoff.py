"""Agent 间 Handoff 交接机制 — 对齐 pi 的 handoff 设计

核心概念：
- Coordinator（总控 Agent）：接收任务，分配给专业 Agent
- Specialist（专业 Agent）：专注特定领域，完成后交还控制权
- Handoff 传递：消息 + 上下文 + 共享发现池

通信流程：
  用户 → Coordinator → handoff(ReconAgent) → 返回结果
                    → handoff(ScannerAgent) → 返回结果
                    → handoff(ReporterAgent) → 返回报告

每个 Agent 有独立的：
- ReAct 循环（AgentLoop）
- 工具集（ToolRegistry 子集）
- 上下文（但共享 FindingsPool）

Handoff 消息格式：
{
    "from": "coordinator",
    "to": "scanner",
    "message": "目标已侦察完成，请执行漏洞扫描",
    "context": { ... },  // 传递的上下文数据
    "findings_pool": { ... }  // 共享发现池快照
}
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class HandoffMessage:
    """Handoff 交接消息"""
    from_agent: str
    to_agent: str
    message: str
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_agent,
            "to": self.to_agent,
            "message": self.message,
            "context": self.context,
            "timestamp": self.timestamp,
        }


@dataclass
class HandoffResult:
    """Handoff 返回结果"""
    from_agent: str
    to_agent: str
    success: bool
    result: dict[str, Any]
    findings_summary: str = ""
    elapsed: float = 0.0


class HandoffManager:
    """Handoff 管理器 — 注册和调度多个专业 Agent"""

    def __init__(self):
        self._agents: dict[str, Any] = {}  # name → AgentLoop
        self._agent_tools: dict[str, list[str]] = {}  # name → [tool_names]
        self._history: list[HandoffMessage] = []

    def register_agent(self, name: str, agent_loop: Any, tool_names: list[str]) -> None:
        """注册一个专业 Agent"""
        self._agents[name] = agent_loop
        self._agent_tools[name] = tool_names
        logger.info("[handoff] 注册 Agent: %s (工具: %s)", name, ", ".join(tool_names))

    async def handoff(
        self,
        from_agent: str,
        to_agent: str,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> HandoffResult:
        """执行 Handoff 交接

        将控制权交给目标 Agent，等待其完成后返回结果。
        """
        if to_agent not in self._agents:
            return HandoffResult(
                from_agent=from_agent,
                to_agent=to_agent,
                success=False,
                result={"error": f"Agent {to_agent} 未注册"},
            )

        handoff_msg = HandoffMessage(
            from_agent=from_agent,
            to_agent=to_agent,
            message=message,
            context=context or {},
        )
        self._history.append(handoff_msg)

        logger.info("[handoff] %s → %s: %s", from_agent, to_agent, message[:50])

        target_agent = self._agents[to_agent]
        start_time = time.time()

        try:
            # 启动目标 Agent 的 ReAct 循环（超时保护 10 分钟）
            result = await asyncio.wait_for(
                target_agent.run(
                    target=context.get("target", ""),
                    initial_context=message,
                ),
                timeout=600,
            )

            elapsed = time.time() - start_time
            return HandoffResult(
                from_agent=from_agent,
                to_agent=to_agent,
                success=True,
                result=result,
                elapsed=elapsed,
            )

        except Exception as e:
            elapsed = time.time() - start_time
            logger.error("[handoff] %s 执行失败: %s", to_agent, e)
            return HandoffResult(
                from_agent=from_agent,
                to_agent=to_agent,
                success=False,
                result={"error": str(e)},
                elapsed=elapsed,
            )

    def get_agent_names(self) -> list[str]:
        """获取所有已注册的 Agent 名称"""
        return list(self._agents.keys())

    def get_agent_tools(self, name: str) -> list[str]:
        """获取指定 Agent 的工具列表"""
        return self._agent_tools.get(name, [])

    def get_history(self) -> list[dict[str, Any]]:
        """获取 Handoff 历史"""
        return [m.to_dict() for m in self._history]

    def build_agent_descriptions(self) -> str:
        """构建 Agent 描述（供 Coordinator LLM 使用）"""
        parts = ["你可以将任务交接给以下专业 Agent：\n"]
        for name, tools in self._agent_tools.items():
            parts.append(f"- **{name}**: 工具 [{', '.join(tools)}]")
        parts.append("\n使用 handoff_to_agent 工具交接任务。")
        return "\n".join(parts)


def create_coordinator_tools(handoff_mgr: HandoffManager):
    """为 Coordinator 创建 handoff 工具"""
    from cyberagent.core.tools import ToolDefinition, ToolResult

    tools = []

    # 为每个已注册的 Agent 创建一个 handoff 工具
    for agent_name in handoff_mgr.get_agent_names():
        tools.append(ToolDefinition(
            name=f"handoff_to_{agent_name}",
            description=f"将任务交接给 {agent_name}。传递消息和上下文，等待其完成后返回结果。",
            parameters={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": f"交给 {agent_name} 的任务描述和指令",
                    },
                    "target": {
                        "type": "string",
                        "description": "目标域名或URL",
                    },
                    "context": {
                        "type": "object",
                        "description": "额外上下文数据（可选）",
                    },
                },
                "required": ["message", "target"],
            },
            execution_mode="sequential",  # handoff 必须串行
            safety_level="read_only",
            category="handoff",
            execute=lambda message, target, context=None, _name=agent_name: _do_handoff(
                handoff_mgr, _name, message, target, context or {},
            ),
        ))

    return tools


async def _do_handoff(
    mgr: HandoffManager,
    agent_name: str,
    message: str,
    target: str,
    context: dict[str, Any],
) -> ToolResult:
    """执行 handoff 并返回结果"""
    context["target"] = target
    result = await mgr.handoff(
        from_agent="coordinator",
        to_agent=agent_name,
        message=message,
        context=context,
    )

    if result.success:
        summary = json.dumps(result.result, ensure_ascii=False, default=str)[:500]
        return ToolResult(
            content=f"[{agent_name}] 任务完成 (耗时 {result.elapsed:.1f}s):\n{summary}",
        )
    else:
        return ToolResult(
            content=f"[{agent_name}] 任务失败: {result.result.get('error', '未知错误')}",
            is_error=True,
        )
