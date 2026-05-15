"""Coordinator Agent — 总指挥，借鉴 Helio 的 HR + PM 角色

核心职责（对齐 Helio 的组织模型）：
1. HR 功能：分析目标 → 决定需要哪些 Agent → "招募"团队
2. PM 功能：拆解任务 → 分配工作 → 管理进度 → 处理冲突
3. 通信中心：Agent 间双向讨论频道
4. 活动面板：实时展示每个 Agent 的状态

与 Orchestrator 的区别：
- Orchestrator：按固定 phase 顺序执行（无智能）
- Coordinator：LLM 驱动的智能调度（动态决定下一步）
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from cyberagent.core.llm_client import LLMClient

logger = logging.getLogger(__name__)

COORDINATOR_PROMPT = """你是 CyberAgent 的总指挥（Coordinator），负责协调一个安全测试团队。

## 你的团队
你有以下专业 Agent 可以调度：
{agent_descriptions}

## 你的职责
1. **分析目标**：理解目标是什么类型的应用，有哪些攻击面
2. **招募团队**：决定需要哪些 Agent，按什么顺序执行
3. **分配任务**：给每个 Agent 明确的任务描述
4. **管理进度**：跟踪每个 Agent 的状态，处理异常
5. **决策调整**：根据中间结果调整策略（如发现新端点就追加测试）
6. **汇总报告**：所有 Agent 完成后，汇总结果

## 决策规则
1. 先侦察，再测试，最后报告（基本顺序）
2. 根据侦察结果动态选择测试模块（不是全部都要跑）
3. 发现高危漏洞时可以追加针对性测试
4. 一个 Agent 失败不影响其他 Agent
5. 不要重复已经完成的工作

## 输出格式
每次决策返回 JSON：
{{
  "thinking": "你的思考过程",
  "action": "recruit|dispatch|adjust|summarize|complete",
  "agents": [
    {{"name": "agent_name", "task": "具体任务描述", "priority": "high/medium/low"}}
  ],
  "message_to_team": "给团队的消息"
}}"""


@dataclass
class AgentStatus:
    """Agent 状态"""
    name: str
    status: str = "idle"  # idle / running / completed / failed
    current_task: str = ""
    findings_count: int = 0
    start_time: float = 0
    elapsed: float = 0
    error: str = ""


@dataclass
class ChannelMessage:
    """频道消息"""
    sender: str
    content: str
    timestamp: float = field(default_factory=time.time)
    msg_type: str = "info"  # info / question / answer / alert / finding


class CommunicationChannel:
    """Agent 间双向通信频道（借鉴 Helio 的频道机制）"""

    def __init__(self):
        self._messages: list[ChannelMessage] = []
        self._subscribers: dict[str, asyncio.Queue] = {}  # agent_name → queue

    def subscribe(self, agent_name: str) -> asyncio.Queue:
        """订阅频道"""
        if agent_name not in self._subscribers:
            self._subscribers[agent_name] = asyncio.Queue()
        return self._subscribers[agent_name]

    def unsubscribe(self, agent_name: str):
        """取消订阅"""
        self._subscribers.pop(agent_name, None)

    async def broadcast(self, sender: str, content: str, msg_type: str = "info"):
        """广播消息给所有订阅者"""
        msg = ChannelMessage(sender=sender, content=content, msg_type=msg_type)
        self._messages.append(msg)
        logger.info("[channel] %s [%s]: %s", sender, msg_type, content[:80])

        for name, queue in self._subscribers.items():
            if name != sender:
                await queue.put(msg)

    async def send_to(self, sender: str, recipient: str, content: str, msg_type: str = "info"):
        """定向发送消息"""
        msg = ChannelMessage(sender=sender, content=content, msg_type=msg_type)
        self._messages.append(msg)
        logger.info("[channel] %s → %s [%s]: %s", sender, recipient, msg_type, content[:80])

        if recipient in self._subscribers:
            await self._subscribers[recipient].put(msg)

    def get_history(self, limit: int = 50) -> list[dict]:
        """获取频道历史"""
        return [
            {"sender": m.sender, "content": m.content, "type": m.msg_type,
             "time": m.timestamp}
            for m in self._messages[-limit:]
        ]

    @property
    def message_count(self) -> int:
        return len(self._messages)


class ActivityPanel:
    """活动面板（借鉴 Helio 的 Activity Panel）"""

    def __init__(self):
        self._statuses: dict[str, AgentStatus] = {}

    def register(self, agent_name: str):
        self._statuses[agent_name] = AgentStatus(name=agent_name)

    def update(self, agent_name: str, **kwargs):
        if agent_name in self._statuses:
            status = self._statuses[agent_name]
            for k, v in kwargs.items():
                if hasattr(status, k):
                    setattr(status, k, v)

    def start(self, agent_name: str, task: str = ""):
        self.update(agent_name, status="running", current_task=task, start_time=time.time())

    def complete(self, agent_name: str, findings_count: int = 0):
        status = self._statuses.get(agent_name)
        if status:
            elapsed = time.time() - status.start_time if status.start_time else 0
            self.update(agent_name, status="completed", findings_count=findings_count, elapsed=elapsed)

    def fail(self, agent_name: str, error: str = ""):
        self.update(agent_name, status="failed", error=error)

    def get_all(self) -> list[dict]:
        """获取所有 Agent 状态"""
        return [
            {
                "name": s.name,
                "status": s.status,
                "task": s.current_task,
                "findings": s.findings_count,
                "elapsed": round(s.elapsed, 1),
                "error": s.error,
            }
            for s in self._statuses.values()
        ]

    def summary(self) -> str:
        """生成状态摘要"""
        running = [s for s in self._statuses.values() if s.status == "running"]
        completed = [s for s in self._statuses.values() if s.status == "completed"]
        failed = [s for s in self._statuses.values() if s.status == "failed"]
        total_findings = sum(s.findings_count for s in self._statuses.values())

        return (
            f"运行中: {len(running)} | 完成: {len(completed)} | "
            f"失败: {len(failed)} | 总发现: {total_findings}"
        )

    def display(self) -> str:
        """生成 Rich 可渲染的状态表格"""
        lines = ["┌─────────────┬──────────┬────────┬──────────┬─────────────────────┐"]
        lines.append("│ Agent       │ 状态     │ 发现   │ 耗时     │ 当前任务             │")
        lines.append("├─────────────┼──────────┼────────┼──────────┼─────────────────────┤")

        status_icons = {"idle": "⏸", "running": "🔄", "completed": "✅", "failed": "❌"}
        for s in self._statuses.values():
            icon = status_icons.get(s.status, "?")
            elapsed = f"{s.elapsed:.0f}s" if s.elapsed else "—"
            task = (s.current_task or "—")[:20]
            lines.append(f"│ {s.name:<11} │ {icon} {s.status:<6} │ {s.findings_count:<6} │ {elapsed:<8} │ {task:<19} │")

        lines.append("└─────────────┴──────────┴────────┴──────────┴─────────────────────┘")
        return "\n".join(lines)


class CoordinatorAgent:
    """Coordinator Agent — 总指挥

    对齐 Helio 的 HR Manager + PM 角色：
    - 接收用户目标
    - 分析需要哪些 Agent
    - 动态调度 Agent
    - 管理进度和冲突
    - 汇总结果
    """

    def __init__(self, llm: LLMClient, registry: Any, channel: CommunicationChannel | None = None):
        self.llm = llm
        self.registry = registry
        self.channel = channel or CommunicationChannel()
        self.activity = ActivityPanel()
        self._team_decisions: list[dict] = []
        self._shared_context: dict[str, Any] = {}

    async def run(self, target: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        """运行 Coordinator — 支持并行专项测试"""
        from rich.console import Console
        console = Console()

        console.print(f"\n[bold cyan]═══ Coordinator Agent 启动 ═══[/bold cyan]")
        console.print(f"目标: [bold]{target}[/bold]")

        results: dict[str, Any] = {"target": target, "agents": {}, "total_elapsed": 0}
        start_time = time.time()

        # Phase 1: 侦察（必须先执行）
        console.print(f"\n[bold]═══ Phase 1: 侦察 ═══[/bold]")
        self.activity.register("recon")
        self.activity.start("recon", f"侦察 {target}")
        await self.channel.broadcast("coordinator", f"派发侦察任务: {target}")

        recon_result = await self._dispatch_agent("recon", target, f"侦察 {target}", config)
        results["agents"]["recon"] = recon_result

        if "error" in recon_result:
            self.activity.fail("recon", recon_result["error"])
            console.print(f"[red]侦察失败: {recon_result['error']}[/red]")
        else:
            self.activity.complete("recon", recon_result.get("total_findings", 0))
            console.print(f"[green]侦察完成[/green]")

        # Phase 2: PM 分析侦察结果，拆分为并行专项任务
        console.print(f"\n[bold]═══ Phase 2: 并行专项测试 ═══[/bold]")
        specialist_tasks = await self._pm_plan_parallel(target, recon_result, config)

        if specialist_tasks:
            console.print(f"[bold]PM 拆分 {len(specialist_tasks)} 个专项任务:[/bold]")
            for t in specialist_tasks:
                console.print(f"  🔍 {t['name']}: {t['task']}")

            # 并行执行专项 Agent
            parallel_results = await self._run_parallel(specialist_tasks, target, config, console)
            results["agents"].update(parallel_results)

        # Phase 3: PM 分析并行结果，决定是否追加测试
        adjustment = await self._pm_post_parallel(target, results)
        if adjustment:
            console.print(f"\n[yellow]PM 追加测试: {adjustment.get('reason', '')}[/yellow]")
            for extra in adjustment.get("extra_agents", []):
                self.activity.register(extra["name"])
                self.activity.start(extra["name"], extra["task"])
                extra_result = await self._dispatch_agent(extra["name"], target, extra["task"], config)
                results["agents"][extra["name"]] = extra_result
                if "error" not in extra_result:
                    self.activity.complete(extra["name"], extra_result.get("total_findings", 0))

        # Phase 4: 审查 + 报告
        console.print(f"\n[bold]═══ Phase 3: 审查与报告 ═══[/bold]")
        for phase_name, agent_name in [("独立审查", "reviewer"), ("生成报告", "reporter")]:
            reg = self.registry.get(agent_name)
            if not reg or not reg.agent_class:
                continue
            self.activity.register(agent_name)
            self.activity.start(agent_name, phase_name)
            await self.channel.broadcast("coordinator", f"派发 {phase_name}")

            phase_result = await self._dispatch_agent(agent_name, target, phase_name, config)
            results["agents"][agent_name] = phase_result

            if "error" in phase_result:
                self.activity.fail(agent_name, phase_result["error"])
            else:
                self.activity.complete(agent_name, phase_result.get("total_findings", 0))

        results["total_elapsed"] = round(time.time() - start_time, 1)

        # 汇总
        console.print(f"\n{self.activity.display()}")
        total_findings = sum(
            r.get("total_findings", 0) for r in results["agents"].values() if isinstance(r, dict)
        )
        console.print(f"\n[bold green]Coordinator 完成[/bold green] — "
                       f"{results['total_elapsed']}s | "
                       f"{len(results['agents'])} 个 Agent | "
                       f"{total_findings} 个发现 | "
                       f"频道消息: {self.channel.message_count}")

        return results

    async def _hr_analyze(self, target: str) -> list[dict[str, str]]:
        """HR: 分析目标，决定需要哪些 Agent"""
        # 获取可用 Agent 描述
        agent_list = self.registry.list_all()
        agent_descriptions = "\n".join(
            f"- {a['name']} ({a['category']}): {a['description']}"
            for a in agent_list
        )

        prompt = (
            f"目标: {target}\n\n"
            f"可用 Agent:\n{agent_descriptions}\n\n"
            f"请分析这个目标，决定需要招募哪些 Agent，按执行顺序排列。\n"
            f"每个 Agent 给出具体的任务描述。\n"
            f"返回 JSON 数组: [{{\"name\": \"agent_name\", \"task\": \"具体任务\"}}]"
        )

        try:
            result = await self.llm.chat_json_pro(
                prompt,
                system_prompt="你是安全测试团队的 HR Manager。根据目标特点选择合适的 Agent。只返回JSON数组。",
            )
            if isinstance(result, list):
                # 注册活动面板
                for a in result:
                    self.activity.register(a["name"])
                return result
        except Exception as e:
            logger.warning("[coordinator] HR 分析失败: %s", e)

        # 默认招募顺序
        default_plan = [
            {"name": "recon", "task": f"对 {target} 进行全面侦察"},
            {"name": "scanner", "task": "基于侦察结果进行漏洞扫描"},
            {"name": "reporter", "task": "生成漏洞报告"},
        ]
        for a in default_plan:
            self.activity.register(a["name"])
        return default_plan

    async def _dispatch_agent(self, agent_name: str, target: str, task: str,
                               config: dict | None) -> dict[str, Any]:
        """调度执行一个 Agent"""
        import asyncio

        reg = self.registry.get(agent_name)
        if not reg or not reg.agent_class:
            return {"error": f"Agent {agent_name} 未注册"}

        # 创建独立 LLM
        agent_llm = LLMClient()

        # 创建 AgentContext
        from cyberagent.agents.base import AgentContext
        from cyberagent.core.database import Database

        # 使用共享上下文中的 db
        db = self._shared_context.get("db")
        if not db:
            db = Database()
            db.connect()
            self._shared_context["db"] = db

        target_id = db.get_or_create_target(target)
        ctx = AgentContext(
            target_domain=target,
            target_id=target_id,
            db=db,
            llm=agent_llm,
            metadata=config or {},
        )

        # 智能参数注入
        import inspect
        sig = inspect.signature(reg.agent_class.__init__)
        kwargs = {"ctx": ctx}
        for param_name in sig.parameters:
            if param_name == "self":
                continue
            if param_name == "recon_results" and "recon_results" in self._shared_context:
                kwargs["recon_results"] = self._shared_context["recon_results"]
            elif param_name == "scan_results" and "scan_results" in self._shared_context:
                kwargs["scan_results"] = self._shared_context["scan_results"]
            elif param_name == "scan_findings" and "scan_findings" in self._shared_context:
                kwargs["scan_findings"] = self._shared_context["scan_findings"]

        agent = reg.agent_class(**kwargs)

        # 执行
        try:
            timeout = reg.manifest.timeout
            result = await asyncio.wait_for(agent.run(), timeout=timeout)

            # 更新共享上下文
            for key in reg.manifest.output_provides:
                if key in result:
                    self._shared_context[key] = result[key]
            if reg.manifest.category == "recon":
                self._shared_context["recon_results"] = result
            elif reg.manifest.category == "scan":
                self._shared_context["scan_results"] = result
                self._shared_context["scan_findings"] = result.get("findings", [])

            return result

        except asyncio.TimeoutError:
            return {"error": f"超时 ({timeout}s)"}
        except Exception as e:
            logger.error("[coordinator] %s 异常: %s", agent_name, e, exc_info=True)
            return {"error": str(e)}

    async def _pm_adjust(self, target: str, agent_name: str, agent_result: dict,
                          all_results: dict) -> dict | None:
        """PM: 根据中间结果调整策略"""
        # 如果侦察发现了 GraphQL 端点，追加 GraphQL 测试
        if agent_name == "recon" and "recon_results" in self._shared_context:
            recon = self._shared_context["recon_results"]
            api_endpoints = []
            for stage_data in recon.get("stages", {}).values():
                if isinstance(stage_data, list):
                    for item in stage_data:
                        if isinstance(item, dict) and "endpoint" in str(item):
                            api_endpoints.append(str(item))

            # 检查是否有 GraphQL
            has_graphql = any("graphql" in str(ep).lower() for ep in api_endpoints)
            if has_graphql and "scanner" not in all_results.get("agents", {}):
                return {
                    "reason": "发现 GraphQL 端点，优先测试",
                    "extra_agents": [
                        {"name": "scanner", "task": "重点测试 GraphQL 注入和 IDOR"},
                    ],
                }

        # 如果扫描发现了高危漏洞，追加 Reviewer
        if agent_name == "scanner":
            findings = agent_result.get("findings", [])
            high_findings = [f for f in findings if f.get("severity") in ("critical", "high")]
            if high_findings and "reviewer" not in all_results.get("agents", {}):
                return {
                    "reason": f"发现 {len(high_findings)} 个高危漏洞，追加独立审查",
                    "extra_agents": [
                        {"name": "reviewer", "task": f"独立验证 {len(high_findings)} 个高危漏洞"},
                    ],
                }

        return None

    async def _pm_plan_parallel(self, target: str, recon_result: dict,
                                 config: dict | None) -> list[dict[str, str]]:
        """PM: 分析侦察结果，拆分为可并行执行的专项任务"""
        if "error" in recon_result:
            return [{"name": "scanner", "task": f"对 {target} 进行全面漏洞扫描"}]

        # 提取攻击面信息
        attack_surface = []
        stages = recon_result.get("stages", {})

        # API 端点
        api_endpoints = []
        for stage_data in stages.values():
            if isinstance(stage_data, dict):
                for item in stage_data.get("targets", []):
                    if isinstance(item, dict) and item.get("url"):
                        api_endpoints.append(item["url"])
            elif isinstance(stage_data, list):
                for item in stage_data:
                    if isinstance(item, dict):
                        for v in item.values():
                            if isinstance(v, str) and "api" in v.lower():
                                api_endpoints.append(v)

        # 技术栈
        tech_stack = []
        analysis = recon_result.get("analysis", {})
        for tech in analysis.get("tech_stack", []):
            if isinstance(tech, dict):
                tech_stack.append(tech.get("name", ""))
            elif isinstance(tech, str):
                tech_stack.append(tech)

        # LLM 决定如何拆分
        prompt = (
            f"侦察结果摘要：\n"
            f"- 目标: {target}\n"
            f"- API 端点: {api_endpoints[:10]}\n"
            f"- 技术栈: {tech_stack}\n"
            f"- 攻击面: {[a.get('type', '') for a in analysis.get('attack_surface', [])]}\n\n"
            f"请将漏洞测试拆分为可并行执行的专项任务。每个任务针对一个独立的攻击面。\n"
            f"返回 JSON 数组: [{{\"name\": \"scanner\", \"task\": \"具体任务描述\"}}]\n"
            f"注意：name 必须是已注册的 Agent 名称（scanner/reviewer）。"
            f"如果攻击面足够多，可以创建多个 scanner 实例（用不同 task 描述区分）。"
        )

        try:
            result = await self.llm.chat_json_pro(
                prompt,
                system_prompt=(
                    "你是安全测试 PM。将漏洞测试拆分为可并行执行的独立任务。"
                    "每个任务应针对不同的攻击面，互不干扰。只返回JSON数组。"
                ),
            )
            if isinstance(result, list) and result:
                for t in result:
                    self.activity.register(t.get("name", "scanner"))
                return result
        except Exception as e:
            logger.warning("[coordinator] PM 并行规划失败: %s", e)

        # 默认：一个 scanner 测试所有
        return [{"name": "scanner", "task": f"对 {target} 进行全面漏洞扫描"}]

    async def _run_parallel(self, tasks: list[dict], target: str,
                             config: dict | None, console: Any) -> dict[str, Any]:
        """并行执行多个专项 Agent"""
        import asyncio

        console.print(f"\n[bold]🚀 并行启动 {len(tasks)} 个专项 Agent...[/bold]")

        async def _run_one(task_plan: dict) -> tuple[str, dict]:
            name = task_plan["name"]
            task_desc = task_plan["task"]
            self.activity.start(name, task_desc)
            await self.channel.broadcast("coordinator", f"派发: {name} — {task_desc}")

            result = await self._dispatch_agent(name, target, task_desc, config)

            if "error" in result:
                self.activity.fail(name, result["error"])
            else:
                self.activity.complete(name, result.get("total_findings", 0))

            return name, result

        # 并行执行
        results_list = await asyncio.gather(
            *[_run_one(t) for t in tasks],
            return_exceptions=True,
        )

        # 收集结果
        all_results = {}
        for item in results_list:
            if isinstance(item, Exception):
                logger.error("[coordinator] 并行任务异常: %s", item)
                continue
            name, result = item
            # 多个同名 agent 结果合并
            if name in all_results:
                existing = all_results[name]
                if isinstance(existing, dict) and isinstance(result, dict):
                    existing_findings = existing.get("findings", [])
                    new_findings = result.get("findings", [])
                    existing["findings"] = existing_findings + new_findings
                    existing["total_findings"] = len(existing["findings"])
            else:
                all_results[name] = result

        # 打印并行结果摘要
        for name, result in all_results.items():
            if "error" in result:
                console.print(f"  ❌ {name}: {result['error']}")
            else:
                console.print(f"  ✅ {name}: {result.get('total_findings', 0)} 个发现")

        return all_results

    async def _pm_post_parallel(self, target: str, results: dict) -> dict | None:
        """PM: 并行测试后分析结果，决定是否追加测试"""
        all_findings = []
        for agent_name, agent_result in results.get("agents", {}).items():
            if isinstance(agent_result, dict):
                all_findings.extend(agent_result.get("findings", []))

        if not all_findings:
            return None

        # 检查是否有需要追加审查的高危漏洞
        high_findings = [f for f in all_findings if f.get("severity") in ("critical", "high")]
        if high_findings and "reviewer" not in results.get("agents", {}):
            return {
                "reason": f"发现 {len(high_findings)} 个高危漏洞，追加独立审查",
                "extra_agents": [
                    {"name": "reviewer", "task": f"独立验证 {len(high_findings)} 个高危漏洞"},
                ],
            }

        return None
