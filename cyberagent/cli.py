"""CyberAgent CLI 入口"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from cyberagent.core.config import get_settings, PROJECT_ROOT
from cyberagent.core.database import Database
from cyberagent.core.llm_client import LLMClient
from cyberagent.agents.base import AgentContext
from cyberagent.agents.recon import ReconAgent
from cyberagent.agents.scanner import ScannerAgent
from cyberagent.agents.reporter import ReportAgent

console = Console()


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
def main():
    """CyberAgent — AI驱动的自动化漏洞挖掘工具"""
    pass


@main.command()
@click.argument("domain")
@click.option("--output", "-o", type=click.Path(), help="结果输出路径 (JSON)")
@click.option("--local", is_flag=True, help="本地目标模式（跳过子域名枚举，直接探测目标）")
@click.option("--port", "-p", multiple=True, type=int, help="要额外探测的端口")
def recon(domain: str, output: str | None, local: bool, port: tuple[int, ...]):
    """对目标域名执行侦察扫描"""
    setup_logging()
    asyncio.run(_run_recon(domain, output, local=local, extra_ports=list(port)))


async def _run_recon(domain: str, output: str | None, local: bool = False, extra_ports: list[int] | None = None):
    """异步执行侦察流程"""
    domain = domain.lower().strip()
    mode_label = "本地模式" if local else "域名模式"
    console.print(Panel(
        f"[bold cyan]CyberAgent Recon[/bold cyan] ({mode_label})\n目标: [bold]{domain}[/bold]",
        title="开始侦察",
    ))

    # 初始化组件
    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY，请在 .env 文件中配置[/bold red]")
        sys.exit(1)

    db = Database()
    db.connect()
    llm = LLMClient()

    target_id = db.get_or_create_target(domain)
    db.update_target_status(target_id, "scanning")

    ctx = AgentContext(
        target_domain=domain,
        target_id=target_id,
        db=db,
        llm=llm,
        metadata={"local_mode": local, "extra_ports": extra_ports or []},
    )

    agent = ReconAgent(ctx)

    try:
        results = await agent.run()
    finally:
        db.close()

    # 输出结果
    _print_results(results, domain)

    # 保存到文件
    if output:
        out_path = Path(output)
    else:
        out_dir = PROJECT_ROOT / "output"
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / f"recon_{domain.replace('.', '_')}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    console.print(f"\n[green]结果已保存到: {out_path}[/green]")


def _print_results(results: dict, domain: str):
    """美化输出侦察结果"""
    stages = results.get("stages", {})

    # 子域名统计
    sub_data = stages.get("subdomain_enum", {})
    console.print(f"\n[bold]1. 子域名枚举[/bold] — 发现 {sub_data.get('count', 0)} 个")

    # HTTP 存活
    http_data = stages.get("http_probe", {})
    console.print(f"[bold]2. HTTP 探测[/bold] — {http_data.get('alive_count', 0)} 个存活")

    if http_data.get("targets"):
        table = Table(title="活跃目标")
        table.add_column("URL", style="cyan")
        table.add_column("状态码", style="green")
        table.add_column("标题")
        table.add_column("技术栈")
        for t in http_data["targets"][:20]:
            table.add_row(
                t.get("url", ""),
                str(t.get("status", "")),
                (t.get("title", "") or "")[:40],
                ", ".join(t.get("tech", [])[:5]),
            )
        console.print(table)

    # 端口
    port_data = stages.get("port_scan", {})
    ports = port_data.get("open_ports", [])
    console.print(f"[bold]3. 端口扫描[/bold] — 发现 {len(ports)} 个开放端口")
    if ports:
        table = Table(title="开放端口")
        table.add_column("主机")
        table.add_column("端口", style="yellow")
        table.add_column("服务")
        table.add_column("版本")
        for p in ports[:30]:
            table.add_row(
                p.get("host", ""),
                str(p.get("port", "")),
                p.get("service", ""),
                p.get("version", ""),
            )
        console.print(table)

    # 信息泄露
    leaks = stages.get("info_leaks", [])
    console.print(f"[bold]4. 信息泄露[/bold] — 发现 {len(leaks)} 个")
    for leak in leaks[:10]:
        severity_color = "red" if leak.get("status") == 200 else "yellow"
        console.print(f"  [{severity_color}]{leak.get('path', '')}[/{severity_color}] — {leak.get('url', '')}")

    # JS 分析
    js_data = stages.get("js_analysis", [])
    console.print(f"[bold]5. JS 分析[/bold] — 发现 {len(js_data)} 个")

    # WAF
    waf = stages.get("waf_detection", {})
    if waf.get("detected"):
        console.print(f"[bold red]6. WAF 检测[/bold red] — 检测到: {waf.get('waf_name', '未知')}")
    else:
        console.print("[bold green]6. WAF 检测[/bold green] — 未检测到 WAF")

    # LLM 分析
    analysis = results.get("analysis", {})
    if analysis:
        console.print(Panel(
            analysis.get("summary", "无摘要"),
            title="[bold magenta]LLM 分析摘要[/bold magenta]",
        ))

        # 技术栈识别
        tech_stack = analysis.get("tech_stack", [])
        if tech_stack:
            table = Table(title="识别的技术栈")
            table.add_column("技术", style="cyan")
            table.add_column("版本")
            table.add_column("已知CVE", style="red")
            for t in tech_stack:
                cves = ", ".join(t.get("cve_list", [])) or "—"
                table.add_row(t.get("name", ""), t.get("version", "未知"), cves)
            console.print(table)

        # 攻击面分析
        attack_surface = analysis.get("attack_surface", [])
        if attack_surface:
            table = Table(title="攻击面分析")
            table.add_column("类型", style="yellow")
            table.add_column("详情")
            table.add_column("风险", style="red")
            for item in attack_surface:
                risk = item.get("risk", "info")
                risk_style = {"high": "bold red", "medium": "yellow", "low": "blue"}.get(risk, "white")
                table.add_row(
                    item.get("type", ""),
                    (item.get("detail", "") or "")[:60],
                    f"[{risk_style}]{risk}[/{risk_style}]",
                )
            console.print(table)

        # 建议的下一步
        if analysis.get("suggested_next_steps"):
            tree = Tree("[bold]建议的下一步[/bold]")
            for step in analysis["suggested_next_steps"]:
                tree.add(step)
            console.print(tree)

    elapsed = results.get("_elapsed", 0)
    console.print(f"\n[bold green]侦察完成[/bold green] — 耗时 {elapsed}s")


@main.command()
@click.argument("domain")
@click.option("--recon-file", "-r", type=click.Path(exists=True), help="侦察结果JSON文件路径")
@click.option("--output", "-o", type=click.Path(), help="结果输出路径 (JSON)")
@click.option("--local", is_flag=True, help="本地目标模式")
def scan(domain: str, recon_file: str | None, output: str | None, local: bool):
    """对目标执行漏洞扫描（需先运行recon或提供recon结果文件）"""
    setup_logging()
    asyncio.run(_run_scan(domain, recon_file, output, local=local))


async def _run_scan(domain: str, recon_file: str | None, output: str | None, local: bool = False):
    """异步执行漏洞扫描"""
    domain = domain.lower().strip()
    console.print(Panel(
        f"[bold red]CyberAgent Scanner[/bold red]\n目标: [bold]{domain}[/bold]",
        title="漏洞扫描",
    ))

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        sys.exit(1)

    # 加载侦察结果
    recon_results = {}
    if recon_file:
        with open(recon_file, "r", encoding="utf-8") as f:
            recon_results = json.load(f)
        console.print(f"[green]已加载侦察结果: {recon_file}[/green]")
    else:
        # 尝试从默认路径加载
        default_path = PROJECT_ROOT / "output" / f"recon_{domain.replace('.', '_')}.json"
        if default_path.exists():
            with open(default_path, "r", encoding="utf-8") as f:
                recon_results = json.load(f)
            console.print(f"[green]已加载侦察结果: {default_path}[/green]")
        else:
            console.print("[yellow]未找到侦察结果，将直接扫描目标[/yellow]")
            recon_results = {
                "stages": {
                    "http_probe": {"targets": [{"url": f"http://{domain}:3000" if local else f"http://{domain}"}]},
                    "port_scan": {"open_ports": [{"host": domain, "port": 3000}] if local else []},
                    "js_analysis": [],
                },
                "analysis": {},
            }

    db = Database()
    db.connect()
    llm = LLMClient()
    target_id = db.get_or_create_target(domain)
    db.update_target_status(target_id, "scanning")

    ctx = AgentContext(
        target_domain=domain, target_id=target_id, db=db, llm=llm,
        metadata={"local_mode": local},
    )

    agent = ScannerAgent(ctx, recon_results=recon_results)
    try:
        results = await agent.run()
    finally:
        db.close()

    _print_scan_results(results)

    if output:
        out_path = Path(output)
    else:
        out_dir = PROJECT_ROOT / "output"
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / f"scan_{domain.replace('.', '_')}.json"

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
    console.print(f"\n[green]结果已保存到: {out_path}[/green]")


def _print_scan_results(results: dict):
    """美化输出扫描结果"""
    findings = results.get("findings", [])
    total = results.get("total_findings", 0)

    console.print(f"\n[bold]扫描完成[/bold] — 发现 [bold red]{total}[/bold red] 个漏洞\n")

    if not findings:
        console.print("[green]未发现漏洞[/green]")
        return

    table = Table(title="漏洞发现")
    table.add_column("类型", style="cyan")
    table.add_column("标题")
    table.add_column("URL", style="blue")
    table.add_column("参数")
    table.add_column("严重性", style="red")
    table.add_column("置信度")

    for f in findings:
        sev = f.get("severity", "info")
        sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
        conf = f.get("confidence", "")
        conf_style = {"confirmed": "bold green", "probable": "green", "possible": "yellow"}.get(conf, "white")

        table.add_row(
            f.get("vuln_type", ""),
            (f.get("title", "") or "")[:40],
            (f.get("url", "") or "")[:40],
            f.get("parameter", ""),
            f"[{sev_style}]{sev}[/{sev_style}]",
            f"[{conf_style}]{conf}[/{conf_style}]",
        )

    console.print(table)

    # 打印 PoC
    for f in findings:
        if f.get("poc"):
            console.print(f"\n[bold yellow]PoC — {f['title']}[/bold yellow]")
            console.print(f"  {f['poc']}")

    # LLM 分析
    analysis = results.get("analysis", {})
    if analysis:
        console.print(Panel(
            analysis.get("summary", ""),
            title=f"[bold magenta]风险评估: {analysis.get('risk_level', 'unknown').upper()}[/bold magenta]",
        ))
        if analysis.get("remediation"):
            tree = Tree("[bold]修复建议[/bold]")
            for r in analysis["remediation"]:
                tree.add(r)
            console.print(tree)


@main.command()
@click.argument("domain")
@click.option("--recon-file", "-r", type=click.Path(exists=True), help="侦察结果JSON文件")
@click.option("--scan-file", "-s", type=click.Path(exists=True), help="扫描结果JSON文件")
def report(domain: str, recon_file: str | None, scan_file: str | None):
    """生成 SRC 格式漏洞报告"""
    setup_logging()
    asyncio.run(_run_report(domain, recon_file, scan_file))


async def _run_report(domain: str, recon_file: str | None, scan_file: str | None):
    """异步生成报告"""
    domain = domain.lower().strip()
    console.print(Panel(
        f"[bold magenta]CyberAgent Reporter[/bold magenta]\n目标: [bold]{domain}[/bold]",
        title="生成报告",
    ))

    settings = get_settings()
    if not settings.deepseek_api_key:
        console.print("[bold red]错误: 未设置 DEEPSEEK_API_KEY[/bold red]")
        sys.exit(1)

    # 加载侦察结果
    recon_results = {}
    if recon_file:
        with open(recon_file, "r", encoding="utf-8") as f:
            recon_results = json.load(f)
    else:
        default_path = PROJECT_ROOT / "output" / f"recon_{domain.replace('.', '_')}.json"
        if default_path.exists():
            with open(default_path, "r", encoding="utf-8") as f:
                recon_results = json.load(f)

    # 加载扫描结果
    scan_results = {}
    if scan_file:
        with open(scan_file, "r", encoding="utf-8") as f:
            scan_results = json.load(f)
    else:
        default_path = PROJECT_ROOT / "output" / f"scan_{domain.replace('.', '_')}.json"
        if default_path.exists():
            with open(default_path, "r", encoding="utf-8") as f:
                scan_results = json.load(f)

    if not scan_results and not recon_results:
        console.print("[yellow]未找到侦察或扫描结果，请先运行 recon 和 scan 命令[/yellow]")
        return

    db = Database()
    db.connect()
    llm = LLMClient()
    target_id = db.get_or_create_target(domain)

    ctx = AgentContext(
        target_domain=domain, target_id=target_id, db=db, llm=llm,
    )

    agent = ReportAgent(ctx, recon_results=recon_results, scan_results=scan_results)
    try:
        results = await agent.run()
    finally:
        db.close()

    # 展示结果
    reports = results.get("reports", [])
    summary = results.get("summary", {})
    files = results.get("files", {})

    console.print(f"\n[bold]报告生成完成[/bold] — {len(reports)} 个漏洞报告\n")

    if summary:
        risk = summary.get("risk_rating", "unknown")
        risk_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(risk, "white")
        console.print(Panel(
            summary.get("executive_summary", ""),
            title=f"[{risk_style}]风险评级: {risk.upper()}[/{risk_style}]",
        ))

    if files:
        console.print("[bold]输出文件:[/bold]")
        for fmt, path in files.items():
            console.print(f"  {fmt}: {path}")

    if reports:
        table = Table(title="漏洞报告列表")
        table.add_column("#", style="dim")
        table.add_column("标题")
        table.add_column("类型")
        table.add_column("严重性", style="red")
        for i, r in enumerate(reports, 1):
            sev = r.get("severity", "")
            sev_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "blue"}.get(sev, "white")
            table.add_row(str(i), r.get("title", ""), r.get("vuln_type", ""), f"[{sev_style}]{sev}[/{sev_style}]")
        console.print(table)


@main.command()
def db_status():
    """查看数据库中的目标和发现"""
    setup_logging()
    db = Database()
    db.connect()

    targets = db._ensure_conn().execute("SELECT * FROM targets ORDER BY id DESC LIMIT 10").fetchall()
    if not targets:
        console.print("[yellow]数据库中没有目标记录[/yellow]")
        return

    for t in targets:
        console.print(Panel(f"[bold]{t['domain']}[/bold] — 状态: {t['status']} — 创建: {t['created_at']}"))
        subs = db.get_subdomains(t["id"])
        ports = db.get_ports(t["id"])
        findings = db.get_findings(t["id"])

        console.print(f"  子域名: {len(subs)} | 端口: {len(ports)} | 发现: {len(findings)}")
        for f in findings[:5]:
            severity_style = {"high": "red", "medium": "yellow", "low": "blue"}.get(f["severity"], "white")
            console.print(f"    [{severity_style}][{f['severity'].upper()}][/{severity_style}] {f['title']}")

    db.close()


if __name__ == "__main__":
    main()
