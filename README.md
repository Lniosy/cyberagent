# CyberAgent

AI 驱动的自动化漏洞挖掘 Agent，面向 SRC 赏金计划。

[English](README_en.md)

## 项目计划与进度

| 阶段 | 模块 | 状态 | 说明 |
|------|------|------|------|
| Phase 1 | 核心框架 | ✅ 完成 | LLM客户端、Shell执行器、数据库、配置系统 |
| Phase 1 | 侦察 Agent | ✅ 完成 | 子域名枚举、HTTP指纹、端口扫描、信息泄露、JS分析、WAF检测 |
| Phase 2 | 扫描 Agent | ✅ 完成 | 23个工具：SQLi/XSS/SSRF/IDOR/GraphQL/JWT/CORS/SSTI/NoSQL/XXE/RCE/LFI/暴力破解/表单测试等 |
| Phase 2 | 报告 Agent | ✅ 完成 | LLM生成SRC格式报告（Markdown/HTML/JSON），含PoC和修复建议 |
| Phase 2 | Docker 部署 | ✅ 完成 | Dockerfile + docker-compose + 靶场环境 |
| Phase 3 | 编排器 | ✅ 完成 | `auto`固定流水线 + `agent`自主循环 + `team`团队协作 |
| Phase 3 | Coordinator Agent | ✅ 完成 | 总指挥：HR分析 + PM调度 + 并行专项测试 |
| Phase 3 | 知识积累闭环 | ✅ 完成 | Dream复盘 + 知识库持久化 + 策略迭代 |
| Phase 3 | 独立审查 | ✅ 完成 | Reviewer Agent + 辩论机制（裁判分离） |
| Phase 4 | 真实SRC实战 | 🔲 计划中 | 对接公开SRC项目进行实战测试 |
| Phase 4 | Web UI | 🔲 计划中 | 可视化Dashboard，任务管理，报告查看 |

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│              CyberAgent CLI（4种运行模式）                    │
│   auto（固定流水线）/ agent（自主循环）/ team（团队协作）      │
└───────┬──────────────┬──────────────┬───────────────────────┘
        │              │              │
 ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼───────┐
 │  侦察Agent   │ │  扫描Agent  │ │  报告Agent  │
 │  (Recon)     │ │  (Scanner) │ │  (Reporter) │
 └─────────────┘ └────────────┘ └────────────┘
 ├─ 子域名枚举    ├─ 23个安全工具  ├─ Markdown/HTML/JSON
 ├─ HTTP指纹      ├─ Web爬虫+表单  ├─ PoC代码生成
 ├─ 端口扫描      ├─ SQLi/XSS     ├─ CVSS评分
 ├─ 信息泄露      ├─ SSRF/IDOR    ├─ 修复建议
 ├─ JS分析        ├─ GraphQL/JWT   └─ 风险评估
 ├─ WAF检测       ├─ RCE/LFI
 └─ LLM分析       ├─ 暴力破解
                   └─ CORS/安全头
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

### 使用

```bash
# 一键全自动（推荐）
cyberagent auto example.com

# 自主 Agent 模式（LLM 自主决策）
cyberagent agent example.com

# 团队模式（Coordinator 调度，支持并行专项测试）
cyberagent team example.com

# 分步执行
cyberagent recon example.com
cyberagent scan example.com
cyberagent report example.com

# 本地靶场
cyberagent agent localhost --local -p 3000
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

- [**pi**](https://github.com/earendil-works/pi) — AI Agent 框架架构和多智能体编排
- [**hack-skills**](https://github.com/yaklang/hack-skills) — 安全测试知识库
- [ProjectDiscovery](https://github.com/projectdiscovery) — subfinder, httpx, nuclei
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — 靶场环境

## 免责声明

> **本工具仅限授权安全测试和教育研究用途，严禁任何未授权使用。**

详见 [README_en.md](README_en.md) 中的完整免责声明（含国际法律条款）。
