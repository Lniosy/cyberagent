# CyberAgent

AI 驱动的自动化漏洞挖掘 Agent，面向 SRC 赏金计划。

## 架构

```
┌─────────────────────────────────────────────────────┐
│                   Orchestrator                       │
│            DeepSeek API 驱动全局决策                  │
└──────────┬──────────────────────────┬───────────────┘
           │                          │
    ┌──────▼──────┐           ┌───────▼───────┐
    │  侦察Agent   │           │   扫描Agent   │
    │  (Recon)     │──────────▶│  (Scanner)    │
    └─────────────┘           └───────────────┘
    ├─ 子域名枚举               ├─ SQL注入检测
    ├─ HTTP指纹识别             ├─ XSS检测
    ├─ 端口扫描                 ├─ SSRF检测
    ├─ 信息泄露检测             ├─ IDOR检测
    ├─ JS分析(端点/密钥)        ├─ Open Redirect
    ├─ WAF检测                  ├─ 目录遍历
    └─ LLM综合分析              ├─ 命令注入
                                ├─ Nuclei模板扫描
                                └─ LLM漏洞分析
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
git clone https://github.com/YOUR_USERNAME/cyberagent.git
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
# 侦察模式
cyberagent recon example.com
cyberagent recon localhost --local -p 3000  # 本地靶场

# 漏洞扫描（需先运行 recon）
cyberagent scan example.com
cyberagent scan localhost --local -r output/recon_localhost.json

# 查看报告
cyberagent report
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
```

## 项目结构

```
cyberagent/
├── cyberagent/
│   ├── core/
│   │   ├── config.py          # 配置管理 (.env + Pydantic)
│   │   ├── llm_client.py      # DeepSeek API 客户端
│   │   ├── shell_executor.py  # 异步 Shell 命令执行器
│   │   └── database.py        # SQLite 数据库层
│   ├── agents/
│   │   ├── base.py            # Agent 基类
│   │   ├── recon.py           # 侦察 Agent
│   │   └── scanner.py         # 扫描 Agent
│   └── cli.py                 # CLI 入口
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

## 技术栈

| 组件 | 技术 |
|------|------|
| LLM 核心 | DeepSeek V4 Pro (推理) + Flash (轻量) |
| 语言 | Python 3.12+ |
| Agent 框架 | 自研（asyncio + LLM 驱动） |
| 安全工具 | subfinder, httpx, nuclei, nmap |
| 数据库 | SQLite |
| CLI | Click + Rich |
| 部署 | Docker + docker-compose |

## 漏洞检测能力

| 类型 | 方法 | 置信度 |
|------|------|--------|
| SQL 注入 | Error-based / Boolean-based / Time-based | 确认/可能 |
| XSS | Reflected (URL参数 + 表单) | 确认 |
| SSRF | 内网地址探测 / 云元数据 | 可能 |
| IDOR | ID 遍历 + 响应对比 | 可能 |
| Open Redirect | 302 跳转验证 | 确认 |
| 目录遍历 | /etc/passwd 读取 | 确认 |
| 命令注入 | 输出匹配 / 时间延迟 | 确认/可能 |
| 模板扫描 | Nuclei (3000+ 模板) | 可能 |

## 免责声明

本工具仅供合法安全测试和授权渗透测试使用。使用者需遵守当地法律法规，对使用本工具造成的任何后果自行负责。
