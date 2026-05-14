"""Agent 基类，定义通用执行流程和钩子系统

设计参考 pi (earendil-works/pi) 的事件驱动架构：
- before_run / after_run 生命周期钩子
- on_finding 发现漏洞时回调
- on_error 错误处理钩子
- 中间件模式支持无侵入扩展
"""
from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from cyberagent.core.database import Database
from cyberagent.core.llm_client import LLMClient

logger = logging.getLogger(__name__)


@dataclass
class AgentContext:
    """Agent 执行上下文，贯穿整个任务生命周期"""
    target_domain: str
    target_id: int
    db: Database
    llm: LLMClient
    metadata: dict[str, Any] = field(default_factory=dict)


# 钩子函数类型
HookFn = Callable[["BaseAgent", dict[str, Any]], Awaitable[dict[str, Any] | None]]


class BaseAgent(abc.ABC):
    """所有 Agent 的基类，支持钩子系统"""

    name: str = "base"

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx
        self.start_time: float = 0
        self.results: dict[str, Any] = {}
        self._hooks: dict[str, list[HookFn]] = {
            "before_run": [],
            "after_run": [],
            "on_finding": [],
            "on_error": [],
        }

    # ---- 钩子注册 ----

    def on(self, event: str, hook: HookFn) -> None:
        """注册钩子。支持的事件: before_run, after_run, on_finding, on_error"""
        if event not in self._hooks:
            raise ValueError(f"未知事件: {event}，支持: {list(self._hooks.keys())}")
        self._hooks[event].append(hook)

    def add_plugin(self, plugin: "AgentPlugin") -> None:
        """注册插件（批量注册多个钩子）"""
        plugin.install(self)

    async def _emit(self, event: str, data: dict[str, Any]) -> dict[str, Any]:
        """触发事件，执行所有注册的钩子"""
        for hook in self._hooks.get(event, []):
            try:
                result = await hook(self, data)
                if result is not None:
                    data.update(result)
            except Exception as e:
                logger.warning("[%s] 钩子 %s.%s 异常: %s", self.name, event, hook.__name__, e)
        return data

    # ---- 执行流程 ----

    async def run(self) -> dict[str, Any]:
        """统一执行入口，支持生命周期钩子"""
        self.start_time = time.time()
        logger.info("[%s] 开始执行 — 目标: %s", self.name, self.ctx.target_domain)

        # before_run 钩子
        await self._emit("before_run", {"agent": self.name, "target": self.ctx.target_domain})

        try:
            self.results = await self.execute()
            elapsed = time.time() - self.start_time
            logger.info("[%s] 执行完成 — 耗时: %.1fs", self.name, elapsed)
            self.results["_elapsed"] = round(elapsed, 1)

            # after_run 钩子
            await self._emit("after_run", {
                "agent": self.name,
                "elapsed": elapsed,
                "results": self.results,
            })

            return self.results
        except Exception as e:
            logger.error("[%s] 执行失败: %s", self.name, e, exc_info=True)
            # on_error 钩子
            await self._emit("on_error", {"agent": self.name, "error": str(e)})
            raise

    async def emit_finding(self, finding_data: dict[str, Any]) -> None:
        """通知发现漏洞，触发 on_finding 钩子"""
        await self._emit("on_finding", {
            "agent": self.name,
            "target": self.ctx.target_domain,
            "finding": finding_data,
        })

    @abc.abstractmethod
    async def execute(self) -> dict[str, Any]:
        """子类实现具体的执行逻辑"""
        ...

    async def analyze_with_llm(self, data: dict[str, Any], prompt_template: str = "") -> dict[str, Any]:
        """使用 LLM 分析结果数据"""
        import json
        data_str = json.dumps(data, ensure_ascii=False, indent=2, default=str)
        if not prompt_template:
            prompt_template = (
                f"以下是针对目标 {self.ctx.target_domain} 的侦察数据:\n\n"
                f"{data_str}\n\n"
                "请分析这些数据，识别潜在的安全问题和攻击面，并建议下一步操作。"
            )
        else:
            prompt_template = prompt_template.format(data=data_str, domain=self.ctx.target_domain)

        return await self.ctx.llm.chat_json_pro(prompt_template)


class AgentPlugin:
    """插件基类 — 批量注册多个钩子，实现无侵入扩展"""

    def install(self, agent: BaseAgent) -> None:
        """子类实现，通过 agent.on() 注册钩子"""
        raise NotImplementedError


# ---- 内置插件 ----

class LoggingPlugin(AgentPlugin):
    """日志插件 — 记录每个发现的漏洞"""

    def install(self, agent: BaseAgent) -> None:
        agent.on("on_finding", self._log_finding)

    @staticmethod
    async def _log_finding(agent: BaseAgent, data: dict[str, Any]) -> None:
        finding = data.get("finding", {})
        logger.warning(
            "[%s] 发现漏洞: [%s] %s — %s",
            agent.name,
            finding.get("severity", "?"),
            finding.get("title", "?"),
            finding.get("url", "?"),
        )


class TimingPlugin(AgentPlugin):
    """计时插件 — 记录各阶段耗时"""

    def __init__(self):
        self._stages: dict[str, float] = {}

    def install(self, agent: BaseAgent) -> None:
        agent.on("before_run", self._start_timer)
        agent.on("after_run", self._end_timer)

    async def _start_timer(self, agent: BaseAgent, data: dict[str, Any]) -> None:
        self._stages[agent.name] = time.time()

    async def _end_timer(self, agent: BaseAgent, data: dict[str, Any]) -> None:
        elapsed = data.get("elapsed", 0)
        logger.info("[timing] %s 耗时: %.1fs", agent.name, elapsed)
