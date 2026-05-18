"""剑来 (Jianlai) CLI — 自然语言驱动的安全测试入口

用户只需描述目标，Agent 自主出剑。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from jianlai.branding import boot, render_banner, BRAND_NAME_CN, BRAND_NAME_EN, QUOTE
from jianlai.core.config import get_settings, PROJECT_ROOT
from jianlai.core.database import Database
from jianlai.core.llm_client import LLMClient
from jianlai.agents.base import AgentContext
from jianlai.agents.recon import ReconAgent
from jianlai.agents.scanner import ScannerAgent
from jianlai.agents.reporter import ReportAgent
from jianlai.agents.vuln_intel import VulnIntelAgent
from jianlai.agents.reviewer import ReviewerAgent

console = Console()


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


class NaturalLanguageGroup(click.Group):
    """优先识别已注册子命令，否则回退到自然语言模式。"""

    def invoke(self, ctx):
        if ctx._protected_args and not self.chain:
            args = [*ctx._protected_args, *ctx.args]
            if args and args[0] not in self.commands:
                ctx.args = args
                ctx._protected_args = []
                ctx.invoked_subcommand = None
                with ctx:
                    return click.Command.invoke(self, ctx)
        return super().invoke(ctx)


# ============================================================
# 自然语言入口 — 用户描述目标，Agent 自主完成
# ============================================================

@click.group(
    cls=NaturalLanguageGroup,
    invoke_without_command=True,
    context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
)
@click.pass_context
@click.option("--max-turns", default=15, help="最大轮次")
@click.option("--max-time", default=600, help="最大运行时间（秒）")
@click.option("--resume", is_flag=True, help="断点续扫")
def main(ctx, max_turns: int, max_time: int, resume: bool):
    """剑来 (Jianlai) — AI 驱动的自主漏洞挖掘 Agent

    用法：
      jianlai                     # 显示帮助
      jianlai <目标描述>           # 自然语言模式（出剑）
      jianlai agent <目标>         # 自主 Agent 模式（独行）
      jianlai team <目标>          # 团队协作模式（结阵）
      jianlai auto <目标>          # 固定流水线模式（章法）
      jianlai recon/scan/report    # 分步执行（拆招）
    """
    if ctx.invoked_subcommand is not None:
        return
    target = " ".join(ctx.args).strip() or None
    if target is None:
        console.print(render_banner(subtitle="[ 候命 ]"))
        click.echo(ctx.get_help())
        return

    setup_logging()
    asyncio.run(_run_natural_language(target, max_turns, max_time, resume))


def _no_anim() -> bool:
    """非交互终端或显式关闭动画时跳过出鞘动画。"""
    return not sys.stdout.isatty() or os.environ.get("JIANLAI_NO_ANIM") == "1"


async def _run_natural_language(description: str, max_turns: int, max_time: int, resume: bool):
    """自然语言模式 — Agent 自主解析目标并执行"""
    from jianlai.core.agent_loop import AgentLoop, AgentLoopConfig
    from jianlai.core.session import SessionManager
    from jianlai.core.compaction import ContextCompressor
    from jianlai.core.tools import create_default_registry
    from jianlai.core.security_tools import register_all_tools
    from jianlai.core.findings_pool import FindingsPool
    from jianlai.core.skill_loader import SkillLoader
    from jianlai.core.knowledge import KnowledgeBase

    boot(console, mode="自然语言 · 出剑", fast=_no_anim())
    console.print(Panel(
        f"目标: [bold]{description}[/bold]",
        title="[bold red]剑指[/bold red]",
        border_style="red",
    ))

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        sys.exit(1)

    # LLM 解析目标
    llm = LLMClient()
    target_info = await _parse_target(llm, description)
    domain = target_info["domain"]
    local = target_info.get("local", False)
    extra_ports = target_info.get("ports", [])

    console.print(f"[green]解析结果:[/green] 目标={domain}, 本地模式={local}, 端口={extra_ports}")

    # 初始化组件
    pool = FindingsPool()
    registry = create_default_registry()
    register_all_tools(registry, pool, llm=llm, target=domain)
    skill_loader = SkillLoader()
    knowledge = KnowledgeBase()
    knowledge.connect()

    session = SessionManager.create(domain) if not resume else (
        SessionManager.continue_recent(domain) or SessionManager.create(domain)
    )

    config = AgentLoopConfig(max_turns=max_turns, max_time=max_time, auto_mode=True)
    compressor = ContextCompressor(llm)

    loop = AgentLoop(
        llm=llm,
        tools=registry,
        session=session,
        compressor=compressor,
        config=config,
        skill_loader=skill_loader,
        knowledge=knowledge,
    )

    # 构建初始上下文
    initial_ctx = f"目标: {domain}\n"
    if local:
        initial_ctx += f"本地模式，已知端口: {extra_ports}\n"
        initial_ctx += _build_local_target_hint(domain, extra_ports)
    initial_ctx += f"已注册 {len(registry.get_all())} 个安全工具。\n"
    initial_ctx += f"Skill 知识库: {len(skill_loader.available_skills)} 个可用。\n"
    initial_ctx += pool.to_context_string()

    try:
        stats = await loop.run(target=domain, initial_context=initial_ctx)
    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断[/yellow]")
        loop.abort()
        session.force_flush()
        stats = {"aborted": True}

    # 输出结果
    kb_final = knowledge.get_stats()
    console.print(Panel(
        f"轮次: {stats.get('turns', 0)} | "
        f"耗时: {stats.get('elapsed', 0)}s | "
        f"完成: {stats.get('task_complete', False)}\n"
        f"发现: {pool.summary()}\n"
        f"LLM: {llm.stats.summary()['total']}\n"
        f"知识库: {kb_final['total']} 条经验 (新增 {stats.get('knowledge_extracted', 0)} 条)",
        title="[bold green]入鞘[/bold green]",
        border_style="green",
    ))

    knowledge.close()


async def _parse_target(llm: LLMClient, description: str) -> dict:
    """用 LLM 解析用户自然语言描述，提取目标信息"""
    prompt = f"""从以下描述中提取安全测试目标信息：

"{description}"

返回 JSON：
{{
  "domain": "目标域名或IP",
  "local": true/false,
  "ports": [端口列表],
  "scan_type": "full/web/api/recon-only",
  "notes": "其他注意事项"
}}"""

    try:
        result = await llm.chat_json_pro(
            prompt,
            system_prompt="你是目标解析器。从用户描述中提取安全测试目标信息。只返回JSON。",
        )
        return result
    except Exception:
        # 降级：直接解析
        desc = description.lower().strip()
        local = "localhost" in desc or "127.0.0.1" in desc or "本地" in desc
        ports = []
        import re
        port_matches = re.findall(r'[:\s](\d{2,5})', desc)
        ports = [int(p) for p in port_matches]
        domain = re.sub(r'https?://', '', desc.split()[0] if desc.split() else desc)
        domain = domain.split(':')[0].split('/')[0].strip()
        return {"domain": domain or "localhost", "local": local, "ports": ports}


def _build_local_target_hint(domain: str, ports: list[int]) -> str:
    """构建本地目标提示，避免未传端口时访问空列表。"""
    if ports:
        return f"请直接使用 http://{domain}:{ports[0]} 作为探测目标。\n"
    return f"未指定端口，请先探测 {domain} 上开放的本地服务端口，再继续访问验证。\n"


# ============================================================
# 传统命令 — 保留向后兼容
# ============================================================

@main.command()
@click.argument("domain")
@click.option("--max-turns", default=15, help="最大轮次")
@click.option("--max-time", default=600, help="最大运行时间")
@click.option("--local", is_flag=True, help="本地目标模式")
@click.option("--port", "-p", multiple=True, type=int, help="额外端口")
@click.option("--resume", is_flag=True, help="断点续扫")
def agent(domain: str, max_turns: int, max_time: int, local: bool,
          port: tuple[int, ...], resume: bool):
    """自主 Agent 模式：LLM 自主决策，无人值守"""
    setup_logging()
    asyncio.run(_run_agent(domain, max_turns, max_time, local, list(port), resume))


@main.command()
@click.argument("domain")
@click.option("--local", is_flag=True, help="本地目标模式")
@click.option("--port", "-p", multiple=True, type=int, help="额外端口")
def team(domain: str, local: bool, port: tuple[int, ...]):
    """团队模式：Coordinator 动态调度所有 Agent"""
    setup_logging()
    asyncio.run(_run_team(domain, local, list(port)))


@main.command()
@click.argument("domain")
@click.option("--local", is_flag=True, help="本地目标模式")
@click.option("--port", "-p", multiple=True, type=int, help="额外端口")
@click.option("--skip-recon", is_flag=True, help="跳过侦察")
@click.option("--skip-scan", is_flag=True, help="跳过扫描")
@click.option("--skip-report", is_flag=True, help="跳过报告")
def auto(domain: str, local: bool, port: tuple[int, ...],
         skip_recon: bool, skip_scan: bool, skip_report: bool):
    """固定流水线：侦察 → 扫描 → 报告"""
    setup_logging()
    asyncio.run(_run_auto(domain, local=local, extra_ports=list(port),
                          skip_recon=skip_recon, skip_scan=skip_scan, skip_report=skip_report))


@main.command()
@click.argument("domain")
@click.option("--output", "-o", type=click.Path(), help="输出路径")
@click.option("--local", is_flag=True, help="本地模式")
@click.option("--port", "-p", multiple=True, type=int, help="额外端口")
def recon(domain: str, output: str | None, local: bool, port: tuple[int, ...]):
    """侦察扫描"""
    setup_logging()
    asyncio.run(_run_recon(domain, output, local=local, extra_ports=list(port)))


@main.command()
@click.argument("domain")
@click.option("--recon-file", "-r", type=click.Path(exists=True), help="侦察结果文件")
@click.option("--output", "-o", type=click.Path(), help="输出路径")
@click.option("--local", is_flag=True, help="本地模式")
def scan(domain: str, recon_file: str | None, output: str | None, local: bool):
    """漏洞扫描"""
    setup_logging()
    asyncio.run(_run_scan(domain, recon_file, output, local=local))


@main.command()
@click.argument("domain")
@click.option("--recon-file", "-r", type=click.Path(exists=True), help="侦察结果文件")
@click.option("--scan-file", "-s", type=click.Path(exists=True), help="扫描结果文件")
def report(domain: str, recon_file: str | None, scan_file: str | None):
    """生成报告"""
    setup_logging()
    asyncio.run(_run_report(domain, recon_file, scan_file))


@main.command()
def db_status():
    """查看数据库状态"""
    setup_logging()
    db = Database()
    db.connect()
    targets = db._ensure_conn().execute("SELECT * FROM targets ORDER BY id DESC LIMIT 10").fetchall()
    if not targets:
        console.print("[yellow]无目标记录[/yellow]")
        return
    for t in targets:
        console.print(Panel(f"[bold]{t['domain']}[/bold] — {t['status']} — {t['created_at']}"))
        subs = db.get_subdomains(t["id"])
        ports = db.get_ports(t["id"])
        findings = db.get_findings(t["id"])
        console.print(f"  子域名: {len(subs)} | 端口: {len(ports)} | 发现: {len(findings)}")
        for f in findings[:5]:
            s = {"high": "red", "medium": "yellow", "low": "blue"}.get(f["severity"], "white")
            console.print(f"    [{s}][{f['severity'].upper()}][/{s}] {f['title']}")
    db.close()


# ============================================================
# 以下为 _run_agent / _run_team / _run_auto / _run_recon / _run_scan / _run_report 的实现
# （与之前版本相同，此处省略重复代码，保留函数签名）
# ============================================================

async def _run_agent(domain: str, max_turns: int, max_time: int,
                     local: bool, extra_ports: list[int], resume: bool):
    """自主 Agent 运行"""
    from jianlai.core.agent_loop import AgentLoop, AgentLoopConfig
    from jianlai.core.session import SessionManager
    from jianlai.core.compaction import ContextCompressor
    from jianlai.core.tools import create_default_registry
    from jianlai.core.security_tools import register_all_tools
    from jianlai.core.findings_pool import FindingsPool
    from jianlai.core.skill_loader import SkillLoader
    from jianlai.core.knowledge import KnowledgeBase

    domain = domain.lower().strip()
    boot(console, mode="独行 · 自主 Agent", fast=_no_anim())
    console.print(Panel(
        f"目标: [bold]{domain}[/bold]\n最大轮次: {max_turns} | 最大时间: {max_time}s",
        title="[bold red]剑指[/bold red]",
        border_style="red",
    ))

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        sys.exit(1)

    llm = LLMClient()
    pool = FindingsPool()
    registry = create_default_registry()
    register_all_tools(registry, pool, llm=llm, target=domain)
    skill_loader = SkillLoader()
    knowledge = KnowledgeBase()
    knowledge.connect()
    console.print(f"[green]Skill: {len(skill_loader.available_skills)} | 知识库: {knowledge.get_stats()['total']} 条[/green]")

    if resume:
        session = SessionManager.continue_recent(domain)
        if not session:
            session = SessionManager.create(domain)
    else:
        session = SessionManager.create(domain)

    config = AgentLoopConfig(max_turns=max_turns, max_time=max_time, auto_mode=True)
    compressor = ContextCompressor(llm)

    loop = AgentLoop(
        llm=llm, tools=registry, session=session,
        compressor=compressor, config=config,
        skill_loader=skill_loader, knowledge=knowledge,
    )

    initial_ctx = f"目标: {domain}\n"
    if local:
        initial_ctx += f"本地模式，已知端口: {extra_ports}\n{_build_local_target_hint(domain, extra_ports)}"
    initial_ctx += f"已注册 {len(registry.get_all())} 个安全工具。\n{pool.to_context_string()}"

    try:
        stats = await loop.run(target=domain, initial_context=initial_ctx)
    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断[/yellow]")
        loop.abort()
        session.force_flush()
        stats = {"aborted": True}

    kb = knowledge.get_stats()
    console.print(Panel(
        f"轮次: {stats.get('turns', 0)} | 耗时: {stats.get('elapsed', 0)}s | 完成: {stats.get('task_complete', False)}\n"
        f"发现: {pool.summary()}\nLLM: {llm.stats.summary()['total']}\n"
        f"知识库: {kb['total']} 条 (新增 {stats.get('knowledge_extracted', 0)})",
        title="[bold green]入鞘 · Agent 运行结束[/bold green]",
    ))
    knowledge.close()


async def _run_team(domain: str, local: bool = False, extra_ports: list[int] | None = None):
    """Coordinator 团队模式"""
    from jianlai.core.agent_registry import AgentRegistry
    from jianlai.agents.coordinator import CoordinatorAgent, CommunicationChannel

    domain = domain.lower().strip()
    boot(console, mode="结阵 · 群剑齐发", fast=_no_anim())
    console.print(Panel(f"目标: [bold]{domain}[/bold]", title="[bold red]剑指[/bold red]", border_style="red"))

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        sys.exit(1)

    registry = AgentRegistry()
    registry.discover()
    registry.load_config()
    console.print(f"[green]发现 {len(registry.list_all())} 个 Agent[/green]")

    llm = LLMClient()
    channel = CommunicationChannel()
    coordinator = CoordinatorAgent(llm=llm, registry=registry, channel=channel)

    config = {"local_mode": local, "extra_ports": extra_ports or []}
    try:
        results = await coordinator.run(target=domain, config=config)
    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断[/yellow]")
        results = {}

    console.print("\n" + coordinator.activity.display())
    cost = llm.stats.summary()
    console.print(Panel(
        f"Agent: {len(results.get('agents', {}))} | 耗时: {results.get('total_elapsed', 0)}s | 消息: {channel.message_count}\n"
        f"LLM: {cost['total']['calls']} 次 | Token: {cost['total']['tokens']:,} | 成本: ${cost['total']['cost_usd']:.4f}",
        title="[bold green]入鞘 · 群剑收势[/bold green]",
    ))


async def _run_auto(domain: str, local: bool = False, extra_ports: list[int] | None = None,
                    skip_recon: bool = False, skip_scan: bool = False, skip_report: bool = False):
    """固定流水线"""
    from jianlai.core.knowledge import KnowledgeBase
    from jianlai.core.dream import DreamEngine

    domain = domain.lower().strip()
    boot(console, mode="章法 · 三段流水", fast=_no_anim())
    console.print(Panel(f"目标: [bold]{domain}[/bold]", title="[bold red]剑指[/bold red]", border_style="red"))

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        sys.exit(1)

    db = Database()
    db.connect()
    llm = LLMClient()
    out_dir = PROJECT_ROOT / "output"
    out_dir.mkdir(exist_ok=True)
    domain_key = domain.replace(".", "_")

    try:
        target_id = db.get_or_create_target(domain)
        recon_results: dict = {}
        scan_results: dict = {}
        review_results: dict = {}

        # Phase 1: 侦察
        if not skip_recon:
            console.print("\n[bold cyan]═══ Phase 1: 侦察 ═══[/bold cyan]")
            ctx = AgentContext(target_domain=domain, target_id=target_id, db=db, llm=llm,
                              metadata={"local_mode": local, "extra_ports": extra_ports or []})
            agent = ReconAgent(ctx)
            recon_results = await agent.run()
            recon_path = out_dir / f"recon_{domain_key}.json"
            with open(recon_path, "w", encoding="utf-8") as f:
                json.dump(recon_results, f, ensure_ascii=False, indent=2, default=str)
            console.print(f"[green]侦察结果: {recon_path}[/green]")
        else:
            recon_path = out_dir / f"recon_{domain_key}.json"
            if recon_path.exists():
                with open(recon_path, "r", encoding="utf-8") as f:
                    recon_results = json.load(f)

        # Phase 2: 扫描
        if not skip_scan:
            console.print("\n[bold red]═══ Phase 2: 漏洞扫描 ═══[/bold red]")
            ctx = AgentContext(target_domain=domain, target_id=target_id, db=db, llm=llm,
                              metadata={"local_mode": local})
            agent = ScannerAgent(ctx, recon_results=recon_results)
            scan_results = await agent.run()
            scan_path = out_dir / f"scan_{domain_key}.json"
            with open(scan_path, "w", encoding="utf-8") as f:
                json.dump(scan_results, f, ensure_ascii=False, indent=2, default=str)
            console.print(f"[green]扫描结果: {scan_path}[/green]")
            total = scan_results.get("total_findings", 0)
            console.print(f"[bold red]发现 {total} 个漏洞[/bold red]" if total else "[green]未发现漏洞[/green]")

            # Phase 2.5: 审查
            if scan_results.get("findings"):
                console.print("\n[bold cyan]═══ Phase 2.5: 独立审查 ═══[/bold cyan]")
                reviewer_llm = LLMClient()
                ctx = AgentContext(target_domain=domain, target_id=target_id, db=db, llm=reviewer_llm)
                minimal = [{"vuln_type": f.get("vuln_type"), "title": f.get("title"), "url": f.get("url"),
                            "parameter": f.get("parameter"), "payload": f.get("payload"),
                            "evidence": f.get("evidence", "")[:200], "severity": f.get("severity"),
                            "confidence": f.get("confidence")} for f in scan_results["findings"]]
                reviewer = ReviewerAgent(ctx, scan_findings=minimal)
                review_results = await reviewer.run()
                s = review_results.get("summary", {})
                console.print(f"审查: {s.get('confirmed', 0)} 确认 | {s.get('false_positive', 0)} 误报 | {s.get('needs_review', 0)} 待审")

        # Phase 3: 报告
        if not skip_report:
            console.print("\n[bold magenta]═══ Phase 3: 生成报告 ═══[/bold magenta]")
            ctx = AgentContext(target_domain=domain, target_id=target_id, db=db, llm=llm)
            agent = ReportAgent(ctx, recon_results=recon_results, scan_results=scan_results)
            report_results = await agent.run()
            for fmt, path in report_results.get("files", {}).items():
                console.print(f"  {fmt}: {path}")

        # Phase 3.5: Dream 复盘
        if scan_results.get("findings"):
            console.print("\n[bold blue]═══ Phase 3.5: Dream 复盘 ═══[/bold blue]")
            knowledge = KnowledgeBase()
            knowledge.connect()
            dream_llm = LLMClient()
            dream = DreamEngine(knowledge=knowledge, llm=dream_llm)
            try:
                dream_result = await dream.reflect(
                    domain=domain,
                    session_stats={"turns": 0, "elapsed": 0, "llm_stats": llm.stats.summary()},
                    tool_history=[], findings=scan_results.get("findings", []),
                    review_results=review_results if review_results else None,
                )
                console.print(f"  知识更新: {dream_result.knowledge_updates} 条")
            except Exception as e:
                console.print(f"[yellow]复盘异常: {e}[/yellow]")
            finally:
                knowledge.close()

    except KeyboardInterrupt:
        console.print("\n[yellow]用户中断[/yellow]")
    finally:
        db.close()

    cost = llm.stats.summary()
    console.print(Panel(
        f"LLM: {cost['total']['calls']} 次 | Token: {cost['total']['tokens']:,} | 成本: ${cost['total']['cost_usd']:.4f}",
        title="[bold green]入鞘 · 章法已毕[/bold green]",
    ))


async def _run_recon(domain: str, output: str | None, local: bool = False, extra_ports: list[int] | None = None):
    """侦察"""
    domain = domain.lower().strip()
    boot(console, mode="拆招 · 侦察", fast=_no_anim())
    console.print(Panel(f"目标: [bold]{domain}[/bold]", title="[bold cyan]望气 · Recon[/bold cyan]", border_style="cyan"))

    db = Database()
    db.connect()
    llm = LLMClient()
    target_id = db.get_or_create_target(domain)
    ctx = AgentContext(target_domain=domain, target_id=target_id, db=db, llm=llm,
                      metadata={"local_mode": local, "extra_ports": extra_ports or []})
    agent = ReconAgent(ctx)
    try:
        results = await agent.run()
    finally:
        db.close()

    out_dir = PROJECT_ROOT / "output"
    out_dir.mkdir(exist_ok=True)
    out_path = Path(output) if output else out_dir / f"recon_{domain.replace('.', '_')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    console.print(f"[green]结果: {out_path}[/green]")


async def _run_scan(domain: str, recon_file: str | None, output: str | None, local: bool = False):
    """扫描"""
    domain = domain.lower().strip()
    boot(console, mode="拆招 · 扫描", fast=_no_anim())
    console.print(Panel(f"目标: [bold]{domain}[/bold]", title="[bold red]出剑 · Scan[/bold red]", border_style="red"))

    settings = get_settings()
    recon_results = {}
    if recon_file:
        with open(recon_file, "r", encoding="utf-8") as f:
            recon_results = json.load(f)
    else:
        default = PROJECT_ROOT / "output" / f"recon_{domain.replace('.', '_')}.json"
        if default.exists():
            with open(default, "r", encoding="utf-8") as f:
                recon_results = json.load(f)

    db = Database()
    db.connect()
    llm = LLMClient()
    target_id = db.get_or_create_target(domain)
    ctx = AgentContext(target_domain=domain, target_id=target_id, db=db, llm=llm,
                      metadata={"local_mode": local})
    agent = ScannerAgent(ctx, recon_results=recon_results)
    try:
        results = await agent.run()
    finally:
        db.close()

    out_dir = PROJECT_ROOT / "output"
    out_dir.mkdir(exist_ok=True)
    out_path = Path(output) if output else out_dir / f"scan_{domain.replace('.', '_')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    console.print(f"[green]结果: {out_path}[/green]")

    total = results.get("total_findings", 0)
    console.print(f"[bold red]发现 {total} 个漏洞[/bold red]" if total else "[green]未发现漏洞[/green]")


async def _run_report(domain: str, recon_file: str | None, scan_file: str | None):
    """报告"""
    domain = domain.lower().strip()
    boot(console, mode="拆招 · 报告", fast=_no_anim())
    console.print(Panel(f"目标: [bold]{domain}[/bold]", title="[bold magenta]复盘 · Report[/bold magenta]", border_style="magenta"))

    recon_results = {}
    scan_results = {}
    out_dir = PROJECT_ROOT / "output"
    domain_key = domain.replace(".", "_")

    if recon_file:
        with open(recon_file, "r", encoding="utf-8") as f:
            recon_results = json.load(f)
    else:
        p = out_dir / f"recon_{domain_key}.json"
        if p.exists():
            recon_results = json.loads(p.read_text())

    if scan_file:
        with open(scan_file, "r", encoding="utf-8") as f:
            scan_results = json.load(f)
    else:
        p = out_dir / f"scan_{domain_key}.json"
        if p.exists():
            scan_results = json.loads(p.read_text())

    if not scan_results and not recon_results:
        console.print("[yellow]未找到结果，请先运行 recon 和 scan[/yellow]")
        return

    db = Database()
    db.connect()
    llm = LLMClient()
    target_id = db.get_or_create_target(domain)
    ctx = AgentContext(target_domain=domain, target_id=target_id, db=db, llm=llm)
    agent = ReportAgent(ctx, recon_results=recon_results, scan_results=scan_results)
    try:
        results = await agent.run()
    finally:
        db.close()

    for fmt, path in results.get("files", {}).items():
        console.print(f"  {fmt}: {path}")


if __name__ == "__main__":
    main()
