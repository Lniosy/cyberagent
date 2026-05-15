"""CyberAgent TUI — 交互式终端界面

类似 Claude Code 的体验：
- 直接启动 cyberagent 进入交互模式
- 输入框发送自然语言指令
- 实时显示 Agent 输出
- 支持历史记录、多行输入
- Ctrl+C 退出
"""
from __future__ import annotations

import asyncio
import sys
import os

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.table import Table
from rich.markdown import Markdown

console = Console()

WELCOME = """[bold cyan]CyberAgent[/bold cyan] — AI驱动的自动化漏洞挖掘

[dim]输入目标描述开始安全测试，Agent 团队自主完成一切。[/dim]

[bold]示例指令：[/bold]
  • 测试 localhost:8765 上的 Pikachu 靶场
  • scan example.com for vulnerabilities
  • 帮我看看 192.168.1.100:8080 有什么安全问题
  • /help   查看帮助
  • /status 查看知识库状态
  • /skills 查看可用技能
  • exit    退出
"""


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
        "prompt": "bold cyan",
        "input": "white",
    })

    # 历史记录
    history_path = os.path.expanduser("~/.cyberagent_history")
    session = PromptSession(
        history=FileHistory(history_path),
        auto_suggest=AutoSuggestFromHistory(),
        style=style,
    )

    console.print(Panel(WELCOME, border_style="cyan"))

    while True:
        try:
            user_input = session.prompt(
                [("class:prompt", "cyberagent > ")],
                style=style,
            ).strip()

            if not user_input:
                continue

            # 内置命令
            if user_input.lower() in ("exit", "quit", "q"):
                console.print("[dim]再见！[/dim]")
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
            console.print("\n[dim]Ctrl+C 退出。再按一次退出。[/dim]")
            continue
        except EOFError:
            console.print("\n[dim]再见！[/dim]")
            break


def _show_help():
    """显示帮助"""
    table = Table(title="CyberAgent 命令", show_header=True, header_style="bold cyan")
    table.add_column("命令", style="green")
    table.add_column("说明")
    table.add_row("<目标描述>", "自然语言模式，Agent 自主完成（推荐）")
    table.add_row("/agent <目标>", "自主 Agent 模式（ReAct 循环）")
    table.add_row("/team <目标>", "团队模式（Coordinator 调度）")
    table.add_row("/auto <目标>", "固定流水线模式")
    table.add_row("/status", "查看知识库和系统状态")
    table.add_row("/skills", "查看可用 Skill 列表")
    table.add_row("/help", "显示帮助")
    table.add_row("exit / quit", "退出")
    console.print(table)


def _show_status():
    """显示系统状态"""
    from cyberagent.core.config import get_settings
    from cyberagent.core.knowledge import KnowledgeBase
    from cyberagent.core.skill_loader import SkillLoader

    settings = get_settings()
    knowledge = KnowledgeBase()
    knowledge.connect()
    kb_stats = knowledge.get_stats()
    knowledge.close()

    skill_loader = SkillLoader()

    table = Table(title="系统状态", show_header=True, header_style="bold cyan")
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
    from cyberagent.core.skill_loader import SkillLoader
    loader = SkillLoader()
    table = Table(title=f"可用 Skill ({len(loader.available_skills)})", show_header=True, header_style="bold cyan")
    table.add_column("Skill", style="green")
    table.add_column("描述")
    for name in sorted(loader.available_skills):
        content = loader.load_skill(name)
        first_line = content.split("\n")[0][:60] if content else ""
        table.add_row(name, first_line)
    console.print(table)


async def _run_natural(description: str):
    """自然语言模式"""
    from cyberagent.cli import _parse_target
    from cyberagent.core.llm_client import LLMClient

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
    from cyberagent.core.agent_loop import AgentLoop, AgentLoopConfig
    from cyberagent.core.session import SessionManager
    from cyberagent.core.compaction import ContextCompressor
    from cyberagent.core.tools import create_default_registry
    from cyberagent.core.security_tools import register_all_tools
    from cyberagent.core.findings_pool import FindingsPool
    from cyberagent.core.skill_loader import SkillLoader
    from cyberagent.core.knowledge import KnowledgeBase
    from cyberagent.core.config import get_settings

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        return

    pool = FindingsPool()
    registry = create_default_registry()
    llm = __import__("cyberagent.core.llm_client", fromlist=["LLMClient"]).LLMClient()
    register_all_tools(registry, pool, llm=llm, target=domain)
    skill_loader = SkillLoader()
    knowledge = KnowledgeBase()
    knowledge.connect()
    session = SessionManager.create(domain)
    config = AgentLoopConfig(max_turns=15, max_time=600, auto_mode=True)
    compressor = ContextCompressor(llm)

    loop = AgentLoop(
        llm=llm, tools=registry, session=session,
        compressor=compressor, config=config,
        skill_loader=skill_loader, knowledge=knowledge,
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

    from cyberagent.core.agent_registry import AgentRegistry
    from cyberagent.agents.coordinator import CoordinatorAgent, CommunicationChannel
    from cyberagent.core.llm_client import LLMClient

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
    from cyberagent.cli import _run_auto
    import re
    local = "localhost" in target or "127.0.0.1" in target
    ports = [int(p) for p in re.findall(r':(\d+)', target)]
    domain = target.split(":")[0].strip()
    await _run_auto(domain, local=local, extra_ports=ports)
