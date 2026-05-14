"""Agent 基类，定义通用执行流程"""
from __future__ import annotations

import abc
import logging
import time
from dataclasses import dataclass, field
from typing import Any

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


class BaseAgent(abc.ABC):
    """所有 Agent 的基类"""

    name: str = "base"

    def __init__(self, ctx: AgentContext):
        self.ctx = ctx
        self.start_time: float = 0
        self.results: dict[str, Any] = {}

    async def run(self) -> dict[str, Any]:
        """统一执行入口"""
        self.start_time = time.time()
        logger.info("[%s] 开始执行 — 目标: %s", self.name, self.ctx.target_domain)

        try:
            self.results = await self.execute()
            elapsed = time.time() - self.start_time
            logger.info("[%s] 执行完成 — 耗时: %.1fs", self.name, elapsed)
            self.results["_elapsed"] = round(elapsed, 1)
            return self.results
        except Exception as e:
            logger.error("[%s] 执行失败: %s", self.name, e, exc_info=True)
            raise

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
