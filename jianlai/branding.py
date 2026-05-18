"""剑来 (Jianlai) — 品牌资产与启动动画

名字取自烽火戏诸侯长篇玄幻小说《剑来》。
主角陈平安自骊珠洞天的窑工出身，一步一步走上剑道，
"我有一剑，可破万法"。

这套漏洞挖掘 Agent 借此意：
  · 剑修出剑，agent 出招
  · 一剑破万法，一念破万防
  · 不退、不让、不畏难
"""
from __future__ import annotations

import time
from typing import Iterator

from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.text import Text


BRAND_NAME_CN = "剑来"
BRAND_NAME_EN = "JIANLAI"
BRAND_PINYIN = "Jiànlái"
VERSION = "0.1.0"
TAGLINE = "AI 驱动 · 自主漏洞挖掘 Agent"
QUOTE = "我有一剑，可破万法"
QUOTE_FROM = "——《剑来》"


# 大字 logo（FIGlet "ANSI Shadow" 风格的 JIANLAI）
LOGO_ASCII = r"""     ██╗██╗ █████╗ ███╗   ██╗██╗      █████╗ ██╗
     ██║██║██╔══██╗████╗  ██║██║     ██╔══██╗██║
     ██║██║███████║██╔██╗ ██║██║     ███████║██║
██   ██║██║██╔══██║██║╚██╗██║██║     ██╔══██║██║
╚█████╔╝██║██║  ██║██║ ╚████║███████╗██║  ██║██║
 ╚════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝"""


# 剑的 ASCII —— 横置长剑，剑尖向右
SWORD_FULL = r"""    ╓──╖                                                          ╱▔▔▔╲
    ║  ╙────────────────────────────────────────────────────────╮ ╱ ▔▔▔╲
   ═╫══════════════════════════════════════════════════════════════════╪═══◆
    ║  ╓────────────────────────────────────────────────────────╯ ╲ ▁▁▁╱
    ╙──╜                                                          ╲▁▁▁╱"""


def _sword_frame(extend: int) -> str:
    """根据出鞘进度返回某一帧的剑。extend ∈ [0, 60]。"""
    blade = "═" * max(extend, 0)
    hilt = "╓──╖"
    pommel = "◆" if extend >= 50 else ""
    if extend == 0:
        return f"    {hilt}\n    ║\n   ═╫\n    ║\n    ╙──╜"
    return (
        f"    {hilt}\n"
        f"    ║  ╙{'─' * max(extend - 2, 0)}\n"
        f"   ═╫{blade}{pommel}\n"
        f"    ║  ╓{'─' * max(extend - 2, 0)}\n"
        f"    ╙──╜"
    )


def _banner_panel(extend: int = 60, *, subtitle: str | None = None) -> Panel:
    sword = Text(_sword_frame(extend), style="bold bright_white")
    title = Text()
    title.append("    " + BRAND_NAME_CN + "    ", style="bold bright_red")
    title.append("·  ", style="dim")
    title.append(BRAND_NAME_EN, style="bold bright_cyan")
    title.append(f"  v{VERSION}", style="dim cyan")

    quote = Text()
    quote.append('"', style="dim")
    quote.append(QUOTE, style="italic yellow")
    quote.append('"  ', style="dim")
    quote.append(QUOTE_FROM, style="dim italic")

    body = Group(
        Align.center(sword),
        Text(""),
        Align.center(title),
        Align.center(Text(TAGLINE, style="dim cyan")),
        Text(""),
        Align.center(quote),
    )
    return Panel(
        body,
        border_style="bright_red" if extend >= 50 else "bright_black",
        padding=(1, 2),
        subtitle=subtitle,
        subtitle_align="right",
    )


def render_banner(subtitle: str | None = None) -> Panel:
    """静态 banner —— 用于不便动画的环境。"""
    return _banner_panel(60, subtitle=subtitle)


def animate_banner(console: Console, *, subtitle: str | None = None, fast: bool = False) -> None:
    """出鞘动画 —— 剑从鞘中拉出，最后亮出 banner。

    fast=True 时跳过动画（CI/非 TTY 环境用静态 banner）。
    """
    if fast or not console.is_terminal:
        console.print(render_banner(subtitle=subtitle))
        return

    frames = [0, 6, 14, 24, 36, 48, 58, 60]
    refresh = 30
    delay = 0.06
    with Live(
        _banner_panel(0, subtitle=subtitle),
        console=console,
        refresh_per_second=refresh,
        transient=False,
    ) as live:
        for f in frames:
            live.update(_banner_panel(f, subtitle=subtitle))
            time.sleep(delay)


def boot(console: Console, *, mode: str | None = None, fast: bool = False) -> None:
    """一键启动 banner —— CLI / TUI 入口处统一调用。"""
    subtitle = f"[ {mode} ]" if mode else None
    animate_banner(console, subtitle=subtitle, fast=fast)


__all__ = [
    "BRAND_NAME_CN",
    "BRAND_NAME_EN",
    "VERSION",
    "TAGLINE",
    "QUOTE",
    "QUOTE_FROM",
    "render_banner",
    "animate_banner",
    "boot",
]
