# CyberAgent

AI 驱动的自动化漏洞挖掘 Agent，面向 SRC 赏金计划。

[English](README_en.md)

## 项目进度

| 阶段 | 模块 | 状态 | 说明 |
|------|------|------|------|
| Phase 1 | 核心框架 | ✅ | LLM客户端、Shell执行器、数据库、配置系统、钩子系统 |
| Phase 1 | 侦察 Agent | ✅ | 子域名枚举、HTTP指纹、端口扫描、信息泄露、JS分析、WAF检测 |
| Phase 2 | 扫描 Agent | ✅ | 23个安全工具：SQLi/XSS/SSRF/IDOR/GraphQL/JWT/CORS/SSTI/NoSQL/XXE/RCE/LFI/暴力破解/表单测试等 |
| Phase 2 | 报告 Agent | ✅ | LLM生成SRC格式报告（Markdown/HTML/JSON），含PoC和修复建议 |
| Phase 2 | Docker 部署 | ✅ | Dockerfile + docker-compose + 靶场环境 |
| Phase 3 | 编排器 | ✅ | `auto`固定流水线 + `agent`自主循环 + `team`团队协作 |
| Phase 3 | Coordinator Agent | ✅ | 总指挥：HR分析 + PM调度 + 并行专项测试 + 动态调整 |
| Phase 3 | 知识积累闭环 | ✅ | Dream复盘 + 知识库持久化 + 策略迭代 |
| Phase 3 | 独立审查 | ✅ | Reviewer Agent + 辩论机制（裁判分离，借鉴Helio） |
| Phase 3 | 配置驱动 | ✅ | Agent自发现 + agents.yaml + Orchestrator |
| Phase 3 | 上下文管理 | ✅ | JSONL会话持久化 + 上下文压缩 + Prompt Cache |
| Phase 4 | 真实SRC实战 | 🔲 | 对接公开SRC项目进行实战测试 |
| Phase 4 | Web UI | 🔲 | 可视化Dashboard，任务管理，报告查看 |

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│                    CyberAgent CLI（4种模式）                      │
│  auto（固定流水线）/ agent（自主循环）/ team（团队协作）/ 分步执行  │
└────────┬────────────────────┬─────────────────────┬─────────────┘
         │                    │                     │
  ┌──────▼──────┐   ┌────────▼────────┐   ┌───────▼───────┐
  │ Coordinator │   │   Agent Loop    │   │   Pipeline    │
  │  （总指挥）  │   │  （自主循环）    │   │ （固定流水线） │
  │  HR + PM    │   │  ReAct 模式     │   │  Phase 1→2→3  │
  │  并行调度    │   │  工具自选       │   │               │
  └──────┬──────┘   └───────┬─────────┘   └───────┬───────┘
         │                  │                     │
         └──────────────────┼─────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
   ┌─────▼─────┐    ┌──────▼──────┐   ┌──────▼──────┐
   │ 侦察Agent  │    │  扫描Agent   │   │  报告Agent  │
   │ 6个子任务  │    │ 23个安全工具 │   │ 3种格式输出 │
   └───────────┘    └─────────────┘   └─────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼────┐ ┌────▼────┐
        │ 审查Agent │ │ 情报Agent│ │ Dream   │
        │ 独立验证  │ │ CVE/PoC │ │ 复盘    │
        │ + 辩论    │ │ 搜索    │ │ + 知识库│
        └──────────┘ └─────────┘ └─────────┘
```

## 23 个安全工具

| 类别 | 工具 | 说明 |
|------|------|------|
| 侦察 | subdomain_enum, port_scan, http_probe, api_enum, js_analyze, web_crawl | 6个 |
| 扫描 | test_sqli, test_xss, test_idor, test_graphql, test_cors, test_headers, form_test, test_rce, test_lfi, test_bruteforce, test_deserialization | 11个 |
| 情报 | cve_query, poc_search | 2个 |
| 分析 | analyze_findings, get_findings_summary, load_skill | 3个 |
| 报告 | generate_report, complete_task | 2个 |

## 4 种运行模式

```bash
# 1. 固定流水线（简单可靠）
cyberagent auto example.com

# 2. 自主循环（LLM 自主决策，ReAct 模式）
cyberagent agent example.com

# 3. 团队协作（Coordinator 调度，并行专项测试）
cyberagent team example.com

# 4. 分步执行（手动控制每一步）
cyberagent recon example.com
cyberagent scan example.com
cyberagent report example.com
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

### 安装

```bash
git clone https://github.com/Lniosy/cyberagent.git
cd cyberagent
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# 编辑 .env，填入 DeepSeek API Key
```

### Docker

```bash
docker compose build
docker compose run recon example.com
```

## 技术栈

| 组件 | 技术 |
|------|------|
| LLM 核心 | DeepSeek V4 Pro (推理) + Flash (轻量) |
| 语言 | Python 3.12+ |
| Agent 框架 | 自研（asyncio + LLM ReAct 驱动） |
| 知识库 | hack-skills (102个SKILL.md按需加载) |
| 安全工具 | subfinder, httpx, nuclei, nmap |
| 数据库 | SQLite |
| CLI | Click + Rich |
| 部署 | Docker + docker-compose |

## 靶场验证

| 靶场 | 工具检出 | LLM 分析 | 耗时 | 成本 |
|------|---------|---------|------|------|
| OWASP Juice Shop | 14 IDOR + 6 安全头 | 10+ 漏洞 | 6轮/181s | $0.011 |
| Pikachu | 9 (5安全头+3IDOR+1信息) | 10+ 漏洞 | 10轮/484s | $0.022 |

## 致谢

- [**pi**](https://github.com/earendil-works/pi) — AI Agent 框架架构和多智能体编排设计
- [**hack-skills**](https://github.com/yaklang/hack-skills) — 安全测试知识库（102个SKILL.md）
- [ProjectDiscovery](https://github.com/projectdiscovery) — subfinder, httpx, nuclei
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — 靶场环境
- [Pikachu](https://github.com/zhuifengshaonianhanlu/pikachu) — 靶场环境

## 免责声明

> **本工具仅限授权安全测试和教育研究用途，严禁任何未授权使用。**
> **使用者需遵守当地法律法规，对使用本工具造成的任何后果自行负责。**

详见 [README_en.md](README_en.md) 中的完整免责声明（含国际法律条款）。
