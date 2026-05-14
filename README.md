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
- 扫描阶段：发现 13 个漏洞（4 IDOR + 3 GraphQL + 1 CORS + 5 安全头缺失）
- 报告阶段：自动生成 SRC 格式报告，含 CVSS 评分、PoC、复现步骤、修复建议

## 免责声明

### 使用条件

本工具（CyberAgent）仅限以下合法场景使用：

1. **授权测试** — 在获得目标系统所有者明确书面授权后进行的安全评估
2. **SRC/漏洞赏金** — 参与目标方公开的漏洞赏金计划（Bug Bounty Program），且严格遵守其范围和规则
3. **安全研究** — 在自建环境（如靶场、CTF）中进行的安全技术研究和学习
4. **内部评估** — 对本组织拥有或授权管理的系统进行安全审计

### 严格禁止

- 未经授权对任何系统进行扫描或测试
- 对目标系统造成拒绝服务（DoS）或其他破坏性影响
- 利用发现的漏洞进行数据窃取、篡改或其他恶意行为
- 违反任何适用的法律法规，包括但不限于《网络安全法》《刑法》相关条款

### 责任限制

- 本工具按"现状"提供，不作任何明示或暗示的保证
- 作者不对使用本工具产生的任何直接或间接损失承担责任
- 使用者对自身使用行为承担全部法律责任
- 使用本工具即表示您已阅读、理解并同意本免责声明

### 合规建议

- 测试前确认目标在授权范围内，遵守 SRC 规则（如禁止 DoS、社工等）
- 发现漏洞后通过正规渠道（SRC 平台、厂商安全响应中心）报告
- 不公开披露未修复的漏洞细节，遵守负责任的漏洞披露原则
- 保留测试授权文件和操作记录，以备合规审查

### 法律依据

- 《中华人民共和国网络安全法》
- 《中华人民共和国刑法》第二百八十五条（非法侵入计算机信息系统罪）
- 《网络安全漏洞管理规定》

**使用本工具即表示您已充分理解并同意上述条款。如有疑问，请在使用前咨询法律顾问。**
