"""Agent Registry — 配置驱动的 Agent 管理

借鉴 Helio 的"招募"模式：
- 每个 Agent 自描述（manifest = JD）
- Registry 自动发现和管理 Agent
- Orchestrator 根据任务自动编排
- 通过配置文件增减 Agent，不改代码

使用方式：
  registry = AgentRegistry()
  registry.discover()          # 自动发现所有 Agent
  registry.load_config("agents.yaml")  # 加载配置
  orchestrator = Orchestrator(registry, llm, db)
  await orchestrator.run(target="example.com")
"""
from __future__ import annotations

import importlib
import json
import logging
import pkgutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Awaitable, Type

import yaml

from jianlai.core.config import PROJECT_ROOT

logger = logging.getLogger(__name__)


@dataclass
class AgentManifest:
    """Agent 自描述清单（= Helio 的 JD / 岗位说明书）"""
    name: str                           # 唯一标识
    display_name: str                   # 显示名称
    description: str                    # 职责描述
    category: str                       # recon / scan / review / report / intel
    phase: int                          # 执行阶段（越小越先执行）
    input_requires: list[str] = field(default_factory=list)   # 依赖的输入
    output_provides: list[str] = field(default_factory=list)  # 提供的输出
    enabled: bool = True                # 是否启用
    priority: int = 0                   # 优先级（同 phase 内排序）
    timeout: int = 600                  # 超时（秒）
    config: dict[str, Any] = field(default_factory=dict)  # Agent 专属配置


@dataclass
class AgentRegistration:
    """注册条目"""
    manifest: AgentManifest
    agent_class: type | None = None
    factory: Callable | None = None  # 动态创建函数


class AgentRegistry:
    """Agent 注册中心 — 自动发现、管理、创建 Agent"""

    def __init__(self):
        self._registrations: dict[str, AgentRegistration] = {}

    def register(self, manifest: AgentManifest, agent_class: type | None = None,
                 factory: Callable | None = None):
        """注册一个 Agent"""
        self._registrations[manifest.name] = AgentRegistration(
            manifest=manifest,
            agent_class=agent_class,
            factory=factory,
        )
        logger.debug("[registry] 注册 Agent: %s (%s)", manifest.name, manifest.category)

    def discover(self):
        """自动发现 jianlai.agents 包下的所有 Agent"""
        import jianlai.agents as agents_pkg

        for importer, modname, ispkg in pkgutil.iter_modules(agents_pkg.__path__):
            if modname.startswith("_"):
                continue
            try:
                module = importlib.import_module(f"jianlai.agents.{modname}")
                # 查找有 MANIFEST 属性的模块
                manifest_data = getattr(module, "MANIFEST", None)
                agent_class = getattr(module, "AGENT_CLASS", None)

                if manifest_data:
                    manifest = AgentManifest(**manifest_data)
                    self.register(manifest, agent_class=agent_class)
                    logger.info("[registry] 发现 Agent: %s", manifest.name)
            except Exception as e:
                logger.warning("[registry] 加载模块 %s 失败: %s", modname, e)

    def load_config(self, config_path: str | Path | None = None):
        """从 YAML 配置文件加载 Agent 配置"""
        if config_path is None:
            config_path = PROJECT_ROOT / "configs" / "agents.yaml"

        path = Path(config_path)
        if not path.exists():
            logger.info("[registry] 配置文件不存在: %s，使用默认配置", path)
            return

        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        for agent_config in config.get("agents", []):
            name = agent_config.get("name")
            if name in self._registrations:
                reg = self._registrations[name]
                # 覆盖配置
                if "enabled" in agent_config:
                    reg.manifest.enabled = agent_config["enabled"]
                if "phase" in agent_config:
                    reg.manifest.phase = agent_config["phase"]
                if "priority" in agent_config:
                    reg.manifest.priority = agent_config["priority"]
                if "timeout" in agent_config:
                    reg.manifest.timeout = agent_config["timeout"]
                if "config" in agent_config:
                    reg.manifest.config.update(agent_config["config"])
                logger.info("[registry] 配置更新: %s (enabled=%s, phase=%d)",
                            name, reg.manifest.enabled, reg.manifest.phase)

    def get_enabled_agents(self) -> list[AgentRegistration]:
        """获取所有启用的 Agent，按 phase + priority 排序"""
        enabled = [r for r in self._registrations.values() if r.manifest.enabled]
        return sorted(enabled, key=lambda r: (r.manifest.phase, r.manifest.priority))

    def get(self, name: str) -> AgentRegistration | None:
        return self._registrations.get(name)

    def list_all(self) -> list[dict[str, Any]]:
        """列出所有注册的 Agent"""
        return [
            {
                "name": r.manifest.name,
                "display_name": r.manifest.display_name,
                "category": r.manifest.category,
                "phase": r.manifest.phase,
                "enabled": r.manifest.enabled,
                "description": r.manifest.description,
            }
            for r in self._registrations.values()
        ]


class Orchestrator:
    """编排器 — 根据注册的 Agent 自动构建执行管道

    替代 cli.py 中硬编码的 Phase 1→2→3 管道。
    自动按 phase 排序，处理依赖关系，传递上下文。
    """

    def __init__(self, registry: AgentRegistry, llm_factory: Callable, db: Any,
                 knowledge: Any = None, skill_loader: Any = None):
        self.registry = registry
        self.llm_factory = llm_factory  # 创建独立 LLM 的工厂函数
        self.db = db
        self.knowledge = knowledge
        self.skill_loader = skill_loader
        self._shared_context: dict[str, Any] = {}  # Agent 间共享的上下文

    async def run(self, target: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        """执行完整的 Agent 管道"""
        from rich.console import Console
        console = Console()

        agents = self.registry.get_enabled_agents()
        if not agents:
            console.print("[red]没有启用的 Agent[/red]")
            return {}

        console.print(f"[bold]编排器启动[/bold] — {len(agents)} 个 Agent，目标: {target}")

        results: dict[str, Any] = {"target": target, "agents": {}, "total_elapsed": 0}
        start_time = time.time()

        for reg in agents:
            manifest = reg.manifest
            console.print(f"\n[bold cyan]═══ [{manifest.phase}] {manifest.display_name} ═══[/bold cyan]")

            # 检查依赖
            if not self._check_dependencies(manifest):
                console.print(f"[yellow]跳过 {manifest.name}（依赖未满足）[/yellow]")
                continue

            # 创建独立 LLM
            agent_llm = self.llm_factory()

            # 创建 Agent 实例
            agent = self._create_agent(reg, target, agent_llm, config)
            if agent is None:
                console.print(f"[yellow]无法创建 {manifest.name}[/yellow]")
                continue

            # 执行
            try:
                import asyncio
                agent_result = await asyncio.wait_for(
                    agent.run(),
                    timeout=manifest.timeout,
                )
                results["agents"][manifest.name] = agent_result

                # 更新共享上下文
                self._update_shared_context(manifest, agent_result)

                console.print(f"[green]{manifest.display_name} 完成[/green]")

            except asyncio.TimeoutError:
                console.print(f"[red]{manifest.display_name} 超时 ({manifest.timeout}s)[/red]")
                results["agents"][manifest.name] = {"error": "timeout"}
            except Exception as e:
                console.print(f"[red]{manifest.display_name} 异常: {e}[/red]")
                results["agents"][manifest.name] = {"error": str(e)}

        results["total_elapsed"] = round(time.time() - start_time, 1)

        # 最终总结
        console.print(f"\n[bold green]管道完成[/bold green] — {results['total_elapsed']}s, "
                       f"{len(results['agents'])} 个 Agent")

        return results

    def _check_dependencies(self, manifest: AgentManifest) -> bool:
        """检查 Agent 的输入依赖是否满足"""
        for dep in manifest.input_requires:
            if dep not in self._shared_context:
                return False
        return True

    def _create_agent(self, reg: AgentRegistration, target: str, llm: Any,
                      config: dict[str, Any] | None) -> Any:
        """创建 Agent 实例"""
        from jianlai.agents.base import AgentContext

        ctx = AgentContext(
            target_domain=target,
            target_id=self._shared_context.get("target_id", 0),
            db=self.db,
            llm=llm,
            metadata=manifest_config(reg.manifest, config),
        )

        if reg.factory:
            return reg.factory(ctx, self._shared_context)

        if reg.agent_class:
            # 智能参数注入
            import inspect
            sig = inspect.signature(reg.agent_class.__init__)
            kwargs = {"ctx": ctx}

            # 根据参数名自动注入共享上下文
            for param_name in sig.parameters:
                if param_name == "self":
                    continue
                if param_name == "recon_results" and "recon_results" in self._shared_context:
                    kwargs["recon_results"] = self._shared_context["recon_results"]
                elif param_name == "scan_results" and "scan_results" in self._shared_context:
                    kwargs["scan_results"] = self._shared_context["scan_results"]
                elif param_name == "scan_findings" and "scan_findings" in self._shared_context:
                    kwargs["scan_findings"] = self._shared_context["scan_findings"]

            return reg.agent_class(**kwargs)

        return None

    def _update_shared_context(self, manifest: AgentManifest, result: dict[str, Any]):
        """更新共享上下文（Agent 间信息传递）"""
        # 按 output_provides 更新
        for key in manifest.output_provides:
            if key in result:
                self._shared_context[key] = result[key]

        # 特殊处理
        if manifest.category == "recon":
            self._shared_context["recon_results"] = result
        elif manifest.category == "scan":
            self._shared_context["scan_results"] = result
            self._shared_context["scan_findings"] = result.get("findings", [])
        elif manifest.category == "review":
            self._shared_context["review_results"] = result
        elif manifest.category == "report":
            self._shared_context["report_results"] = result


def manifest_config(manifest: AgentManifest, override: dict | None) -> dict:
    """合并 manifest 配置和运行时覆盖"""
    config = dict(manifest.config)
    if override:
        config.update(override)
    return config
