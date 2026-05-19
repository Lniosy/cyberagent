# 剑来 · Jianlai

> **"我有一剑，可破万法。"**
> ——《剑来》· 烽火戏诸侯

AI 驱动的自主漏洞挖掘 Agent，面向 SRC 赏金计划。

[English](README_en.md)

## 名字的来处

「剑来」二字取自烽火戏诸侯的长篇玄幻小说《剑来》。

主角 **陈平安** 自骊珠洞天的穷苦窑工出身，一步步走上剑道——
从最初连一把像样的剑都没有，到背三尺青锋、问剑天下；
"宁姚一剑撼山岳，陈平安一剑破万法"。

小说里有几句话，恰好可以做这个项目的注脚：

- **"我有一剑，可破万法"** —— 一把好剑、一次精准出剑，胜过千百回试探。
- **"莫向外求"** —— 漏洞从来不在远方，在每一个被忽视的参数、每一行被默认信任的代码里。
- **"事不可为时，则不为；事可为时，则全力以赴"** —— Agent 学会取舍、知所进退。
- **"宁姚那一剑，从不畏死。"** —— 出剑当如剑修，遇险不退，遇 WAF 不绕。

借此意：**剑修出剑，agent 出招；一剑破万法，一念破万防。**

整套 CLI 的语义也按这套世界观重新做了：

| 概念 | 含义 |
|------|------|
| **出剑** | 启动一次漏洞挖掘 |
| **入鞘** | 一次任务结束、收剑复盘 |
| **独行** | 单 Agent 自主 ReAct 循环（`agent` 模式）|
| **结阵** | Coordinator 调度群剑齐发（`team` 模式）|
| **章法** | 固定流水线：望气 → 出剑 → 复盘（`auto` 模式）|
| **拆招** | 分步执行（recon / scan / report）|
| **招式** | Skill 知识库（102 个 SKILL.md）|
| **复盘** | Dream 反思机制，落到知识库 |

## 项目进度

| 阶段 | 模块 | 状态 | 说明 |
|------|------|------|------|
| Phase 1 | 核心框架 | OK | LLM 客户端、Shell 执行器、数据库、配置系统、钩子系统 |
| Phase 1 | 望气 (Recon) Agent | OK | 子域名枚举、HTTP 指纹、端口扫描、信息泄露、JS 分析、WAF 检测 |
| Phase 2 | 出剑 (Scanner) Agent | OK | 23 个安全工具：SQLi/XSS/SSRF/IDOR/GraphQL/JWT/CORS/SSTI/NoSQL/XXE/RCE/LFI/暴力破解/表单测试 |
| Phase 2 | 复盘 (Report) Agent | OK | LLM 生成 SRC 格式报告（Markdown/HTML/JSON），含 PoC 和修复建议 |
| Phase 2 | Docker 部署 | OK | Dockerfile + docker-compose + 靶场环境 |
| Phase 3 | 编排器 | OK | `auto`（章法）+ `agent`（独行）+ `team`（结阵）|
| Phase 3 | 总指挥 Coordinator | OK | HR 分析 + PM 调度 + 并行专项测试 + 动态调整 |
| Phase 3 | 知识积累闭环 | OK | Dream 复盘 + 知识库持久化 + 策略迭代 |
| Phase 3 | 独立审查 Reviewer | OK | 审查 Agent + 辩论机制（裁判分离，借鉴 Helio）|
| Phase 3 | 配置驱动 | OK | Agent 自发现 + agents.yaml + Orchestrator |
| Phase 3 | 上下文管理 | OK | JSONL 会话持久化 + 上下文压缩 + Prompt Cache |
| Phase 4 | 真实 SRC 实战 | TODO | 对接公开 SRC 项目进行实战测试 |
| Phase 4 | Web UI | TODO | 可视化 Dashboard，任务管理，报告查看 |

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                       剑来 CLI（4 种出剑方式）                    │
│   章法（auto）  独行（agent）  结阵（team）  拆招（recon/scan/...） │
└────────┬────────────────────┬─────────────────────┬─────────────┘
         │                    │                     │
  ┌──────▼──────┐   ┌────────▼────────┐   ┌───────▼───────┐
  │ Coordinator │   │   Agent Loop    │   │   Pipeline    │
  │  （剑阵）    │   │   （独剑）       │   │   （章法）     │
  │  HR + PM    │   │   ReAct 循环    │   │  望气→出剑→复盘 │
  └──────┬──────┘   └───────┬─────────┘   └───────┬───────┘
         └──────────────────┼─────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
   ┌─────▼─────┐    ┌──────▼──────┐    ┌──────▼──────┐
   │ 望气 Agent │    │ 出剑 Agent  │    │ 复盘 Agent  │
   │ 6 个子任务 │    │ 23 个安全工具│    │ 3 种格式输出 │
   └───────────┘    └─────────────┘    └─────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼────┐ ┌─────▼────┐
        │ 审查 Agent│ │ 情报Agent│ │ Dream    │
        │ 独立验证  │ │ CVE/PoC │ │ 复盘+知识 │
        │ + 辩论    │ │ 搜索    │ │ 库持久化 │
        └──────────┘ └─────────┘ └──────────┘
```

## 23 个安全工具

| 类别 | 工具 | 说明 |
|------|------|------|
| 望气 | subdomain_enum, port_scan, http_probe, api_enum, js_analyze, web_crawl | 6 个 |
| 出剑 | test_sqli, test_xss, test_idor, test_graphql, test_cors, test_headers, form_test, test_rce, test_lfi, test_bruteforce, test_deserialization | 11 个 |
| 情报 | cve_query, poc_search | 2 个 |
| 拆解 | analyze_findings, get_findings_summary, load_skill | 3 个 |
| 复盘 | generate_report, complete_task | 2 个 |

## 4 种运行模式

```bash
# 章法（固定流水线，简单可靠）
jianlai auto example.com

# 独行（LLM 自主决策，ReAct 模式）
jianlai agent example.com

# 结阵（Coordinator 调度，并行专项测试）
jianlai team example.com

# 拆招（手动控制每一步）
jianlai recon example.com
jianlai scan example.com
jianlai report example.com

# 自然语言模式（直接描述，agent 自主出剑）
jianlai "测试 localhost:8765 上的 Pikachu 靶场"
```

## 快速开始

### 环境要求

- Python 3.12+
- DeepSeek API Key

### 安全工具（可选）

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
brew install nmap  # macOS
```

### 一行安装（推荐）

安装器会把项目安装到用户目录，创建独立 Python 3.12 venv，生成全局 `jianlai` 命令，并创建用户级配置文件 `~/.jianlai/.env`。

Windows PowerShell：

```powershell
irm https://raw.githubusercontent.com/Lniosy/jianlai/master/scripts/install.ps1 | iex
```

Linux / macOS / WSL：

```bash
curl -fsSL https://raw.githubusercontent.com/Lniosy/jianlai/master/scripts/install.sh | bash
```

安装后编辑配置，填入 DeepSeek API Key：

```powershell
# Windows
notepad "$HOME\.jianlai\.env"
```

```bash
# Linux / macOS / WSL
${EDITOR:-nano} ~/.jianlai/.env
```

然后打开一个新终端，在任意目录运行：

```bash
jianlai
```

> 如果仓库地址或分支不同，可以先设置 `JIANLAI_REPO_URL` / `JIANLAI_BRANCH` 再运行安装器。

### 源码开发安装

```bash
git clone https://github.com/Lniosy/jianlai.git
cd jianlai
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# 编辑 .env，填入 DeepSeek API Key
git clone --depth 1 https://github.com/yaklang/hack-skills.git references/hack-skills
```

### 启动 TUI

安装后直接输入项目命令即可进入交互式终端：

```bash
jianlai
```

也可以使用显式 TUI 命令启动：

```bash
jianlai tui
jianlai-tui
```

这里参考的是 Hermes 的启动体验：直接输入主命令进入 TUI。项目名称和命令仍然统一使用 `jianlai`。

### Docker

```bash
docker compose build
docker compose run recon example.com
```

### 启动动画

CLI 启动时会播放一段"出鞘"动画（横剑从鞘中拉出，最后亮出 `剑来 · JIANLAI` 标识）。
非 TTY 环境（CI、管道、日志重定向）会自动退回静态 banner，无需关心。

也可以手动关闭：

```bash
JIANLAI_NO_ANIM=1 jianlai auto example.com
```

## 技术栈

| 组件 | 技术 |
|------|------|
| LLM 核心 | DeepSeek V4 Pro（推理）+ Flash（轻量）|
| 语言 | Python 3.12+ |
| Agent 框架 | 自研（asyncio + LLM ReAct 驱动）|
| 知识库 | hack-skills（102 个 SKILL.md 按需加载）|
| 安全工具 | subfinder, httpx, nuclei, nmap |
| 数据库 | SQLite |
| CLI | Click + Rich + prompt_toolkit |
| 部署 | Docker + docker-compose |

## 靶场验证

| 靶场 | 工具检出 | LLM 分析 | 耗时 | 成本 |
|------|---------|---------|------|------|
| OWASP Juice Shop | 14 IDOR + 6 安全头 | 10+ 漏洞 | 6 轮 / 181s | $0.011 |
| Pikachu | 9 (5 安全头 + 3 IDOR + 1 信息) | 10+ 漏洞 | 10 轮 / 484s | $0.022 |

## 致谢

- **《剑来》/ 烽火戏诸侯** —— 项目名与精神来源
- [**pi**](https://github.com/earendil-works/pi) —— AI Agent 框架架构和多智能体编排设计
- [**hack-skills**](https://github.com/yaklang/hack-skills) —— 安全测试知识库（102 个 SKILL.md）
- [ProjectDiscovery](https://github.com/projectdiscovery) —— subfinder, httpx, nuclei
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) —— 靶场环境
- [Pikachu](https://github.com/zhuifengshaonianhanlu/pikachu) —— 靶场环境

## 免责声明

> **本工具仅限授权安全测试和教育研究用途，严禁任何未授权使用。**
> **使用者需遵守当地法律法规，对使用本工具造成的任何后果自行负责。**

详见 [README_en.md](README_en.md) 中的完整免责声明（含国际法律条款）。
