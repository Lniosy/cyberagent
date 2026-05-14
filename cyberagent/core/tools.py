"""工具注册系统 — 对齐 pi 的 AgentTool 设计

核心设计（参考 pi packages/agent/src/types.ts）：
- 工具定义为 JSON Schema（name/description/parameters）
- beforeToolCall/afterToolCall 钩子管道
- executionMode: sequential / parallel
- safety_level: read_only / controlled / restricted
- 工具结果包含 terminate 标志（控制循环终止）
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """工具执行结果（对齐 pi ToolResultMessage）"""
    content: str
    is_error: bool = False
    terminate: bool = False       # 是否终止 Agent 循环
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "is_error": self.is_error,
            "terminate": self.terminate,
            "metadata": self.metadata,
        }


@dataclass
class ToolDefinition:
    """工具定义（对齐 pi AgentTool）"""
    name: str
    description: str
    parameters: dict[str, Any]    # JSON Schema
    execution_mode: str = "parallel"  # parallel / sequential
    safety_level: str = "read_only"   # read_only / controlled / restricted
    category: str = ""                # recon / scan / intel / report
    execute: Callable[..., Awaitable[ToolResult]] | None = None


# 钩子函数类型
ToolHook = Callable[[ToolDefinition, dict[str, Any]], Awaitable[dict[str, Any] | None]]


class ToolRegistry:
    """工具注册中心

    管理所有可用工具，提供钩子管道（对齐 pi 的 beforeToolCall/afterToolCall）。
    """

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._before_hooks: list[ToolHook] = []
        self._after_hooks: list[ToolHook] = []

    # ---- 注册 ----

    def register(self, tool: ToolDefinition) -> None:
        """注册工具"""
        self._tools[tool.name] = tool
        logger.debug("[tools] 注册工具: %s (%s)", tool.name, tool.category)

    def register_before_hook(self, hook: ToolHook) -> None:
        """注册 beforeToolCall 钩子"""
        self._before_hooks.append(hook)

    def register_after_hook(self, hook: ToolHook) -> None:
        """注册 afterToolCall 钩子"""
        self._after_hooks.append(hook)

    # ---- 查询 ----

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def get_all(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def get_by_category(self, category: str) -> list[ToolDefinition]:
        return [t for t in self._tools.values() if t.category == category]

    def get_schemas_for_llm(self) -> list[dict[str, Any]]:
        """生成 LLM function calling 格式的工具定义"""
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            }
            for t in self._tools.values()
        ]

    # ---- 执行 ----

    async def execute(
        self,
        tool_name: str,
        args: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> ToolResult:
        """执行工具（含钩子管道）

        流程：prepare → beforeToolCall → execute → afterToolCall → return
        """
        tool = self._tools.get(tool_name)
        if not tool:
            return ToolResult(
                content=f"未知工具: {tool_name}",
                is_error=True,
            )

        if not tool.execute:
            return ToolResult(
                content=f"工具 {tool_name} 未实现 execute 方法",
                is_error=True,
            )

        ctx = context or {}
        start_time = time.time()

        # beforeToolCall 钩子（可拦截、可修改参数）
        for hook in self._before_hooks:
            try:
                modified = await hook(tool, args)
                if modified is not None:
                    args.update(modified)
            except Exception as e:
                logger.warning("[tools] beforeHook 异常: %s", e)

        # 执行
        try:
            result = await tool.execute(**args)
            elapsed = time.time() - start_time
            result.metadata["elapsed"] = round(elapsed, 2)
            result.metadata["tool"] = tool_name
        except Exception as e:
            elapsed = time.time() - start_time
            result = ToolResult(
                content=f"工具 {tool_name} 执行异常: {str(e)}",
                is_error=True,
                metadata={"elapsed": round(elapsed, 2), "tool": tool_name},
            )

        # afterToolCall 钩子（可修改结果）
        for hook in self._after_hooks:
            try:
                modified = await hook(tool, result.to_dict())
                if modified:
                    if "content" in modified:
                        result.content = modified["content"]
                    if "is_error" in modified:
                        result.is_error = modified["is_error"]
                    if "terminate" in modified:
                        result.terminate = modified["terminate"]
            except Exception as e:
                logger.warning("[tools] afterHook 异常: %s", e)

        return result

    # ---- 批量执行 ----

    async def execute_batch(
        self,
        calls: list[tuple[str, dict[str, Any]]],
        context: dict[str, Any] | None = None,
    ) -> list[ToolResult]:
        """批量执行工具（根据 executionMode 决定并行/串行）

        对齐 pi 的 parallel/sequential 决策逻辑。
        """
        import asyncio

        # 检查是否有 sequential 工具
        has_sequential = any(
            self._tools.get(name, ToolDefinition(name="", description="", parameters={})).execution_mode == "sequential"
            for name, _ in calls
        )

        if has_sequential:
            # 串行执行
            results = []
            for name, args in calls:
                result = await self.execute(name, args, context)
                results.append(result)
                if result.terminate:
                    break
            return results
        else:
            # 并行执行
            return await asyncio.gather(
                *[self.execute(name, args, context) for name, args in calls]
            )


# ---- 内置钩子 ----

async def safety_hook(tool: ToolDefinition, args: dict[str, Any]) -> dict[str, Any] | None:
    """安全检查钩子 — 在工具执行前检查安全性"""
    if tool.safety_level == "restricted":
        logger.warning("[safety] 受限工具 %s 被调用，参数: %s", tool.name, args)
    return None


async def logging_hook(tool: ToolDefinition, result: dict[str, Any]) -> dict[str, Any] | None:
    """日志钩子 — 在工具执行后记录结果"""
    status = "ERROR" if result.get("is_error") else "OK"
    elapsed = result.get("metadata", {}).get("elapsed", 0)
    logger.info("[audit] %s %s — %.1fs", tool.name, status, elapsed)
    return None


def create_default_registry() -> ToolRegistry:
    """创建默认工具注册中心（含安全钩子）"""
    registry = ToolRegistry()
    registry.register_before_hook(safety_hook)
    registry.register_after_hook(logging_hook)
    return registry
