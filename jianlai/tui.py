"""剑来 (Jianlai) TUI — 交互式终端界面

类似 Claude Code 的体验：
- 直接启动 jianlai 进入交互模式
- 输入框发送自然语言指令
- 实时显示 Agent 出剑
- 支持历史记录、多行输入
- Ctrl+C 退出
"""
from __future__ import annotations

import asyncio
import sys
import os
import json

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.table import Table
from rich.markdown import Markdown

from jianlai.branding import boot, QUOTE, QUOTE_FROM

console = Console()


def _format_progress_event(event: dict) -> str | None:
    """把 AgentLoop 进度事件格式化为 TUI 可读日志。"""
    name = event.get("event")
    turn = event.get("turn", 0)
    elapsed = event.get("elapsed", 0)

    if name == "start":
        return f"[bold green][start] 开始[/bold green] 目标={event.get('target')} 最大轮次={event.get('max_turns')}"
    if name == "llm_start":
        return f"[cyan][llm] 第 {turn + 1} 轮[/cyan] 正在请求 LLM... 消息={event.get('message_count')}"
    if name == "llm_done":
        return f"[cyan][llm] 响应完成[/cyan] 工具调用={event.get('tool_count')} 耗时={elapsed}s"
    if name == "assistant" and event.get("text"):
        text = str(event.get("text", "")).replace("\n", " ")
        return f"[dim]思路[/dim] {text[:220]}"
    if name == "tools_start":
        tools = ", ".join(event.get("tools", []))
        return f"[yellow][tools] 准备执行[/yellow] {tools}"
    if name == "tool_start":
        args = event.get("args", {})
        arg_text = json.dumps(args, ensure_ascii=False)
        return f"[yellow][tool ->][/yellow] {event.get('tool')} {arg_text[:180]}"
    if name == "tool_done":
        status = "[red]失败[/red]" if event.get("is_error") else "[green]完成[/green]"
        summary = str(event.get("summary", "")).replace("\n", " ")
        elapsed_part = f" {event.get('elapsed')}s" if event.get("elapsed") is not None else ""
        return f"[yellow][tool <-][/yellow] {event.get('tool')} {status}{elapsed_part} [dim]{summary[:220]}[/dim]"
    if name == "error":
        return f"[bold red][error] 错误[/bold red] {event.get('message')}"
    if name == "done":
        stats = event.get("stats", {})
        return f"[bold green][done] 完成[/bold green] 轮次={stats.get('turns')} 耗时={stats.get('elapsed')}s"
    return None

WELCOME = """[bold red]剑来 (Jianlai)[/bold red] — AI 驱动的自主漏洞挖掘 Agent

[italic yellow]"我有一剑，可破万法"[/italic yellow] [dim]——《剑来》[/dim]

[dim]描述你想测的目标，剑修自会出鞘。[/dim]

[bold]示例指令：[/bold]
  • 测试 localhost:8765 上的 Pikachu 靶场
  • scan example.com for vulnerabilities
  • 帮我看看 192.168.1.100:8080 有什么安全问题

[bold]内置命令：[/bold]
  • /help    查看帮助
  • /status  查看知识库和系统状态
  • /skills  查看可用招式（Skill）
  • /agent <目标>   独行模式（单 Agent 自主循环）
  • /team  <目标>   结阵模式（Coordinator 调度群剑）
  • /auto  <目标>   章法模式（侦察→出剑→复盘）
  • exit / quit / q  入鞘退出
"""


def _no_anim() -> bool:
    return not sys.stdout.isatty() or os.environ.get("JIANLAI_NO_ANIM") == "1"


def run_tui():
    """启动 TUI 交互模式"""
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.styles import Style
    except ImportError:
        console.print("[yellow]需要安装 prompt_toolkit：pip install prompt_toolkit[/yellow]")
        sys.exit(1)

    # 样式
    style = Style.from_dict({
        "prompt": "bold red",
        "input": "white",
    })

    # 历史记录
    history_path = os.path.expanduser("~/.jianlai_history")
    session = PromptSession(
        history=FileHistory(history_path),
        auto_suggest=AutoSuggestFromHistory(),
        style=style,
    )

    # 出剑动画 + 欢迎面板
    boot(console, mode="交互 · 候命", fast=_no_anim())
    console.print(Panel(WELCOME, border_style="bright_red", title="[bold]候命[/bold]"))

    while True:
        try:
            user_input = session.prompt(
                [("class:prompt", "剑来 ▸ ")],
                style=style,
            ).strip()

            if not user_input:
                continue

            # 内置命令
            if user_input.lower() in ("exit", "quit", "q"):
                console.print("[dim]剑入鞘。江湖再见。[/dim]")
                break

            if user_input == "/help":
                _show_help()
                continue

            if user_input == "/status":
                _show_status()
                continue

            if user_input == "/skills":
                _show_skills()
                continue

            if user_input.startswith("/agent "):
                target = user_input[7:].strip()
                asyncio.run(_run_agent_mode(target))
                continue

            if user_input.startswith("/team "):
                target = user_input[6:].strip()
                asyncio.run(_run_team_mode(target))
                continue

            if user_input.startswith("/auto "):
                target = user_input[6:].strip()
                asyncio.run(_run_auto_mode(target))
                continue

            # 默认：自然语言模式
            asyncio.run(_run_natural(user_input))

        except KeyboardInterrupt:
            console.print("\n[dim]Ctrl+C — 收剑。再按 Ctrl+D 或输入 exit 离开。[/dim]")
            continue
        except EOFError:
            console.print("\n[dim]剑入鞘。江湖再见。[/dim]")
            break


def _show_help():
    """显示帮助"""
    table = Table(title="剑来 · 招式表", show_header=True, header_style="bold red")
    table.add_column("命令", style="green")
    table.add_column("说明")
    table.add_row("<目标描述>", "自然语言模式 — 描述目标，Agent 自主出剑（推荐）")
    table.add_row("/agent <目标>", "独行 — 单 Agent 自主 ReAct 循环")
    table.add_row("/team <目标>", "结阵 — Coordinator 调度群剑齐发")
    table.add_row("/auto <目标>", "章法 — 侦察 → 出剑 → 复盘 固定流水")
    table.add_row("/status", "查看知识库和系统状态")
    table.add_row("/skills", "查看可用招式（Skill）列表")
    table.add_row("/help", "显示帮助")
    table.add_row("exit / quit / q", "入鞘退出")
    console.print(table)


def _show_status():
    """显示系统状态"""
    from jianlai.core.config import get_settings
    from jianlai.core.knowledge import KnowledgeBase
    from jianlai.core.skill_loader import SkillLoader

    settings = get_settings()
    knowledge = KnowledgeBase()
    knowledge.connect()
    kb_stats = knowledge.get_stats()
    knowledge.close()

    skill_loader = SkillLoader()

    table = Table(title="剑来 · 状态", show_header=True, header_style="bold red")
    table.add_column("项目", style="green")
    table.add_column("值")
    table.add_row("DeepSeek API", "已配置" if settings.deepseek_api_key else "未配置")
    table.add_row("Pro 模型", settings.deepseek_pro_model)
    table.add_row("Flash 模型", settings.deepseek_flash_model)
    table.add_row("知识库", f"{kb_stats['total']} 条经验")
    table.add_row("Skill 库", f"{len(skill_loader.available_skills)} 个 skill")
    table.add_row("数据库", str(settings.db_full_path))
    console.print(table)

    if kb_stats.get("by_vuln_type"):
        console.print("\n[bold]知识库分布:[/bold]")
        for vuln_type, count in kb_stats["by_vuln_type"].items():
            console.print(f"  {vuln_type}: {count} 条")


def _show_skills():
    """显示可用 Skill"""
    from jianlai.core.skill_loader import SkillLoader
    loader = SkillLoader()
    table = Table(title=f"招式 · Skill ({len(loader.available_skills)})", show_header=True, header_style="bold red")
    table.add_column("Skill", style="green")
    table.add_column("描述")
    for name in sorted(loader.available_skills):
        content = loader.load_skill(name)
        first_line = content.split("\n")[0][:60] if content else ""
        table.add_row(name, first_line)
    console.print(table)


async def _run_natural(description: str):
    """自然语言模式"""
    from jianlai.cli import _parse_target
    from jianlai.core.llm_client import LLMClient

    console.print(f"\n[bold cyan]目标:[/bold cyan] {description}")

    llm = LLMClient()
    target_info = await _parse_target(llm, description)
    domain = target_info["domain"]
    local = target_info.get("local", False)
    extra_ports = target_info.get("ports", [])

    console.print(f"[green]解析:[/green] {domain} | 本地={local} | 端口={extra_ports}")
    console.print()

    # 复用 agent 模式
    await _run_agent_mode_internal(domain, local, extra_ports)


async def _run_agent_mode(target: str):
    """自主 Agent 模式"""
    import re
    local = "localhost" in target or "127.0.0.1" in target
    ports = [int(p) for p in re.findall(r':(\d+)', target)]
    domain = target.split(":")[0].strip()
    await _run_agent_mode_internal(domain, local, ports)


async def _run_agent_mode_internal(domain: str, local: bool, extra_ports: list[int]):
    """内部 Agent 执行"""
    from jianlai.core.agent_loop import AgentLoop, AgentLoopConfig
    from jianlai.core.session import SessionManager
    from jianlai.core.compaction import ContextCompressor
    from jianlai.core.tools import create_default_registry
    from jianlai.core.security_tools import register_all_tools
    from jianlai.core.findings_pool import FindingsPool
    from jianlai.core.skill_loader import SkillLoader
    from jianlai.core.knowledge import KnowledgeBase
    from jianlai.core.config import get_settings

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        return

    pool = FindingsPool()
    registry = create_default_registry()
    llm = __import__("jianlai.core.llm_client", fromlist=["LLMClient"]).LLMClient()
    register_all_tools(registry, pool, llm=llm, target=domain)
    skill_loader = SkillLoader()
    knowledge = KnowledgeBase()
    knowledge.connect()
    session = SessionManager.create(domain)
    config = AgentLoopConfig(max_turns=15, max_time=600, auto_mode=True)
    compressor = ContextCompressor(llm)

    def progress(event: dict):
        line = _format_progress_event(event)
        if line:
            console.print(line)

    loop = AgentLoop(
        llm=llm, tools=registry, session=session,
        compressor=compressor, config=config,
        skill_loader=skill_loader, knowledge=knowledge,
        progress_callback=progress,
    )

    initial_ctx = f"目标: {domain}\n"
    if local and extra_ports:
        initial_ctx += f"本地模式，已知端口: {extra_ports}\n请直接使用 http://{domain}:{extra_ports[0]} 作为探测目标。\n"
    initial_ctx += f"已注册 {len(registry.get_all())} 个安全工具。\n{pool.to_context_string()}"

    try:
        stats = await loop.run(target=domain, initial_context=initial_ctx)
    except KeyboardInterrupt:
        loop.abort()
        session.force_flush()
        stats = {"aborted": True}

    kb = knowledge.get_stats()
    console.print(Panel(
        f"轮次: {stats.get('turns', 0)} | 耗时: {stats.get('elapsed', 0)}s | 完成: {stats.get('task_complete', False)}\n"
        f"发现: {pool.summary()}\nLLM: {llm.stats.summary()['total']}\n"
        f"知识库: {kb['total']} 条 (新增 {stats.get('knowledge_extracted', 0)})",
        title="[bold green]完成[/bold green]",
    ))
    knowledge.close()


async def _run_team_mode(target: str):
    """团队模式"""
    import re
    local = "localhost" in target or "127.0.0.1" in target
    ports = [int(p) for p in re.findall(r':(\d+)', target)]
    domain = target.split(":")[0].strip()

    from jianlai.core.agent_registry import AgentRegistry
    from jianlai.agents.coordinator import CoordinatorAgent, CommunicationChannel
    from jianlai.core.llm_client import LLMClient

    registry = AgentRegistry()
    registry.discover()
    registry.load_config()
    llm = LLMClient()
    channel = CommunicationChannel()
    coordinator = CoordinatorAgent(llm=llm, registry=registry, channel=channel)
    config = {"local_mode": local, "extra_ports": ports}

    try:
        results = await coordinator.run(target=domain, config=config)
    except KeyboardInterrupt:
        results = {}

    console.print("\n" + coordinator.activity.display())


async def _run_auto_mode(target: str):
    """固定流水线模式"""
    from jianlai.cli import _run_auto
    import re
    local = "localhost" in target or "127.0.0.1" in target
    ports = [int(p) for p in re.findall(r':(\d+)', target)]
    domain = target.split(":")[0].strip()
    await _run_auto(domain, local=local, extra_ports=ports)
