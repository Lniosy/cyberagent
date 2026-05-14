# CyberAgent

AI 驱动的自动化漏洞挖掘 Agent，面向 SRC 赏金计划。

## 项目计划与进度

| 阶段 | 模块 | 状态 | 说明 |
|------|------|------|------|
| Phase 1 | 核心框架 | ✅ 完成 | LLM客户端、Shell执行器、数据库、配置系统 |
| Phase 1 | 侦察 Agent | ✅ 完成 | 子域名枚举、HTTP指纹、端口扫描、信息泄露、JS分析、WAF检测 |
| Phase 2 | 扫描 Agent | ✅ 完成 | SQLi/XSS/SSRF/IDOR/Open Redirect/目录遍历/命令注入 + Nuclei |
| Phase 2 | 报告 Agent | ✅ 完成 | LLM生成SRC格式报告（Markdown/HTML/JSON），含PoC和修复建议 |
| Phase 2 | Docker 部署 | ✅ 完成 | Dockerfile + docker-compose + 靶场环境 |
| Phase 3 | 编排器 | ✅ 完成 | `cyberagent auto` 一键全自动流水线 |
| Phase 3 | 增强扫描 | 🔲 计划中 | GraphQL注入、JWT攻击、CORS检测、安全头审计 |
| Phase 3 | 真实SRC实战 | 🔲 计划中 | 对接公开SRC项目进行实战测试 |
| Phase 4 | Web UI | 🔲 计划中 | 可视化Dashboard，任务管理，报告查看 |

## 架构

```
┌─────────────────────────────────────────────────────────────┐
│                      CyberAgent CLI                         │
│              recon / scan / report / db-status               │
└───────┬──────────────┬──────────────┬───────────────────────┘
        │              │              │
 ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼───────┐
 │  侦察Agent   │ │  扫描Agent  │ │  报告Agent  │
 │  (Recon)     │ │  (Scanner) │ │  (Reporter) │
 └─────────────┘ └────────────┘ └────────────┘
 ├─ 子域名枚举    ├─ API端点枚举   ├─ 漏洞报告生成
 ├─ HTTP指纹      ├─ SQL注入       ├─ Markdown/HTML/JSON
 ├─ 端口扫描      ├─ XSS          ├─ PoC代码生成
 ├─ 信息泄露      ├─ SSRF         ├─ 修复建议
 ├─ JS分析        ├─ IDOR         ├─ CVSS评分
 ├─ WAF检测       ├─ Open Redirect └─ 风险评估
 └─ LLM分析       ├─ 目录遍历
                   ├─ 命令注入
                   ├─ Nuclei扫描
                   └─ LLM策略规划
```

## 快速开始

### 环境要求

- Python 3.12+
- DeepSeek API Key

### 安全工具（可选，增强扫描能力）

```bash
# Go 安全工具
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 系统工具
brew install nmap  # macOS
```

### 安装

```bash
git clone https://github.com/Lniosy/cyberagent.git
cd cyberagent
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 配置

```bash
cp .env.example .env
# 编辑 .env，填入 DeepSeek API Key
```

### 使用

```bash
# 一键全自动（推荐）
cyberagent auto example.com
cyberagent auto localhost --local -p 3000  # 本地靶场

# 分步执行
cyberagent recon example.com              # 1. 侦察
cyberagent scan example.com               # 2. 扫描
cyberagent report example.com             # 3. 生成报告

# 控制选项
cyberagent auto target.com --skip-recon   # 跳过侦察（使用已有结果）
cyberagent auto target.com --skip-scan    # 跳过扫描
cyberagent auto target.com --skip-report  # 跳过报告

# 查看数据库状态
cyberagent db-status
```

### Docker 部署

```bash
# 构建
docker compose build

# 运行侦察
docker compose run recon example.com

# 本地靶场测试
docker compose -f docker-compose.test.yml up -d juice-shop
cyberagent recon localhost --local -p 3000
cyberagent scan localhost --local
cyberagent report localhost
```

## 项目结构

```
cyberagent/
├── cyberagent/
│   ├── core/
│   │   ├── config.py          # 配置管理 (.env + Pydantic)
│   │   ├── llm_client.py      # DeepSeek API 客户端（Pro/Flash双模型）
│   │   ├── shell_executor.py  # 异步 Shell 命令执行器
│   │   └── database.py        # SQLite 数据库层
│   ├── agents/
│   │   ├── base.py            # Agent 基类（统一执行流程）
│   │   ├── recon.py           # 侦察 Agent（6个子任务）
│   │   ├── scanner.py         # 扫描 Agent（8种漏洞检测）
│   │   └── reporter.py        # 报告 Agent（多格式输出）
│   └── cli.py                 # CLI 入口（recon/scan/report）
├── Dockerfile                 # Docker 镜像（预装安全工具）
├── docker-compose.yml         # 生产部署
├── docker-compose.test.yml    # 靶场测试环境
├── pyproject.toml
└── README.md
```

## 技术栈

| 组件 | 技术 |
|------|------|
| LLM 核心 | DeepSeek V4 Pro (推理) + Flash (轻量) |
| 语言 | Python 3.12+ |
| Agent 框架 | 自研（asyncio + LLM ReAct 驱动） |
| 安全工具 | subfinder, httpx, nuclei, nmap |
| 数据库 | SQLite |
| CLI | Click + Rich |
| 部署 | Docker + docker-compose |

## 漏洞检测能力

| 类型 | 方法 | 置信度 |
|------|------|--------|
| SQL 注入 | Error-based / Boolean-based / Time-based | 确认/可能 |
| XSS | Reflected (URL参数 + 表单) | 确认 |
| SSRF | 内网地址 / 云元数据 / 协议探测 | 可能 |
| IDOR | API ID枚举 + 响应对比 | 确认/可能 |
| Open Redirect | 302 跳转验证 | 确认 |
| 目录遍历 | /etc/passwd 读取 | 确认 |
| 命令注入 | 输出匹配 / 时间延迟 | 确认/可能 |
| 模板扫描 | Nuclei (3000+ 模板) | 可能 |

## 靶场验证

在 OWASP Juice Shop 上的测试结果：

- 侦察阶段：识别出 OWASP Juice Shop、Node.js、API端点、硬编码密码
- 扫描阶段：发现 4 个 IDOR 漏洞（/api/products, /api/users, /api/feedbacks, /api/challenges）
- 报告阶段：自动生成 SRC 格式报告，含 CVSS 评分、PoC、复现步骤、修复建议

## 免责声明

本工具仅供合法安全测试和授权渗透测试使用。使用者需遵守当地法律法规，对使用本工具造成的任何后果自行负责。
