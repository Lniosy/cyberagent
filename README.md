# CyberAgent

AI-driven automated vulnerability discovery agent for bug bounty programs.

[中文文档](README_zh.md)

## Project Roadmap

| Phase | Module | Status | Description |
|-------|--------|--------|-------------|
| Phase 1 | Core Framework | ✅ Done | LLM client, shell executor, database, config system |
| Phase 1 | Recon Agent | ✅ Done | Subdomain enum, HTTP fingerprint, port scan, info leak, JS analysis, WAF detection |
| Phase 2 | Scanner Agent | ✅ Done | SQLi/XSS/SSRF/IDOR/Redirect/Traversal/CMDi + GraphQL/JWT/CORS/Headers |
| Phase 2 | Report Agent | ✅ Done | LLM-generated SRC reports (Markdown/HTML/JSON) with PoC & remediation |
| Phase 2 | Docker Deploy | ✅ Done | Dockerfile + docker-compose + test lab environment |
| Phase 3 | Orchestrator | ✅ Done | `cyberagent auto` — full pipeline: recon → scan → report |
| Phase 3 | Enhanced Scanning | ✅ Done | GraphQL injection, JWT attacks, CORS, security headers, auth bypass |
| Phase 4 | Real SRC Testing | 🔲 Planned | Test against live bug bounty programs |
| Phase 4 | Web UI Dashboard | 🔲 Planned | Visual dashboard, task management, report viewer |
| Phase 5 | Advanced Modules | 🔲 Planned | XXE, SSTI, deserialization, race conditions, subdomain takeover |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CyberAgent CLI                         │
│              auto / recon / scan / report                    │
└───────┬──────────────┬──────────────┬───────────────────────┘
        │              │              │
 ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼───────┐
 │  Recon Agent │ │ Scan Agent │ │  Reporter  │
 └─────────────┘ └────────────┘ └────────────┘
 ├─ Subdomain      ├─ SQLi          ├─ Markdown/HTML/JSON
 ├─ HTTP Fingerprint├─ XSS          ├─ PoC Generation
 ├─ Port Scan      ├─ SSRF          ├─ CVSS Scoring
 ├─ Info Leak      ├─ IDOR          ├─ Remediation
 ├─ JS Analysis    ├─ Open Redirect ├─ Risk Assessment
 ├─ WAF Detection  ├─ Dir Traversal └─ Executive Summary
 └─ LLM Analysis   ├─ CMD Injection
                    ├─ GraphQL
                    ├─ JWT Attacks
                    ├─ CORS Check
                    ├─ Security Headers
                    └─ Auth Bypass
```

## Quick Start

### Prerequisites

- Python 3.12+
- DeepSeek API Key

### Optional Security Tools

```bash
# Go-based tools (ProjectDiscovery)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# System tools
brew install nmap  # macOS
apt install nmap   # Linux
```

### Installation

```bash
git clone https://github.com/Lniosy/cyberagent.git
cd cyberagent
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Configuration

```bash
cp .env.example .env
# Edit .env and add your DeepSeek API Key
```

### Usage

```bash
# Full automated pipeline (recommended)
cyberagent auto example.com
cyberagent auto localhost --local -p 3000  # local target

# Step-by-step
cyberagent recon example.com              # 1. Reconnaissance
cyberagent scan example.com               # 2. Vulnerability scanning
cyberagent report example.com             # 3. Generate report

# Pipeline control
cyberagent auto target.com --skip-recon   # Skip recon (use existing results)
cyberagent auto target.com --skip-scan    # Skip scanning
cyberagent auto target.com --skip-report  # Skip report generation

# Database status
cyberagent db-status
```

### Docker

```bash
# Build
docker compose build

# Run recon
docker compose run recon example.com

# Local lab testing
docker compose -f docker-compose.test.yml up -d juice-shop
cyberagent auto localhost --local -p 3000
```

## Project Structure

```
cyberagent/
├── cyberagent/
│   ├── core/
│   │   ├── config.py          # Configuration (.env + Pydantic)
│   │   ├── llm_client.py      # DeepSeek API client (Pro/Flash dual model)
│   │   ├── shell_executor.py  # Async shell command executor
│   │   └── database.py        # SQLite database layer
│   ├── agents/
│   │   ├── base.py            # Agent base class (unified execution flow)
│   │   ├── recon.py           # Recon Agent (6 subtasks)
│   │   ├── scanner.py         # Scanner Agent (12 vulnerability modules)
│   │   └── reporter.py        # Report Agent (multi-format output)
│   └── cli.py                 # CLI entry point (auto/recon/scan/report)
├── Dockerfile
├── docker-compose.yml
├── docker-compose.test.yml
├── pyproject.toml
└── README.md
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| LLM Core | DeepSeek V4 Pro (reasoning) + Flash (lightweight) |
| Language | Python 3.12+ |
| Agent Framework | Custom (asyncio + LLM ReAct-driven) |
| Security Tools | subfinder, httpx, nuclei, nmap |
| Database | SQLite |
| CLI | Click + Rich |
| Deployment | Docker + docker-compose |

## Vulnerability Detection

| Type | Method | Confidence |
|------|--------|------------|
| SQL Injection | Error-based / Boolean-based / Time-based | Confirmed/Probable |
| XSS | Reflected (URL params + forms) | Confirmed |
| SSRF | Internal network / Cloud metadata / Protocol probe | Probable |
| IDOR | API ID enumeration + response comparison | Confirmed/Probable |
| Open Redirect | 302 redirect verification | Confirmed |
| Directory Traversal | /etc/passwd read | Confirmed |
| Command Injection | Output matching / Time delay | Confirmed/Probable |
| Template Scan | Nuclei (3000+ templates) | Probable |
| GraphQL | Introspection / Injection / Deep query DoS | Confirmed/Probable |
| JWT | None algorithm / Weak algorithm / Default creds | Confirmed/Probable |
| CORS | Origin reflection / Wildcard / Null origin | Confirmed |
| Security Headers | HSTS / CSP / X-Frame-Options / etc. | Confirmed |

## Lab Validation

Tested against OWASP Juice Shop:

- **Recon**: Identified OWASP Juice Shop, Node.js, API endpoints, hardcoded passwords
- **Scan**: Found 13 vulnerabilities (4 IDOR + 3 GraphQL + 1 CORS + 5 missing headers)
- **Report**: Auto-generated SRC reports with CVSS scores, PoC, reproduction steps, remediation

## Disclaimer

> **This tool is intended for authorized security testing and educational purposes only. Unauthorized use is strictly prohibited and may violate applicable laws.**

### Authorized Use

1. **Authorized Penetration Testing** — With explicit written authorization from the target system owner
2. **Bug Bounty Programs** — Within publicly disclosed program scope and rules
3. **Security Research** — In self-built environments (CTF, DVWA, Juice Shop, HackTheBox)
4. **Internal Auditing** — On systems owned or managed by your organization

### Strictly Prohibited

- Scanning or testing any system without proper authorization
- Causing denial of service (DoS) or destructive impact
- Exploiting vulnerabilities for data theft or malicious activities
- Any violation of applicable laws in your jurisdiction
- Targeting critical infrastructure without explicit authorization
- Selling vulnerabilities to unauthorized parties

### Legal Compliance

Users must comply with all applicable laws, including:

**International**
- **CFAA (US)** — Computer Fraud and Abuse Act, 18 U.S.C. § 1030
- **CMA (UK)** — Computer Misuse Act 1990
- **Budapest Convention (EU)** — Convention on Cybercrime
- **GDPR (EU)** — General Data Protection Regulation

**China**
- 网络安全法 / 刑法§285 / 数据安全法 / 个人信息保护法

**Other**
- Japan — 不正アクセス行為の禁止等に関する法律
- Singapore — Computer Misuse Act (Cap. 50A)
- Australia — Criminal Code Act 1995, Part 10.7
- Germany — StGB § 202a-c
- India — IT Act 2000, Sections 43 & 66
- Brazil — LGPD & Lei de Crimes Informáticos

### Limitation of Liability

- Provided **"AS IS"** without warranty of any kind
- Authors not liable for any direct or indirect damages
- **Users assume full legal responsibility** for their actions
- Use constitutes acceptance of this disclaimer

### Responsible Disclosure

- Report through official channels (SRC, HackerOne, Bugcrowd, vendor PSIRT)
- Do not publicly disclose unpatched vulnerabilities
- Allow reasonable remediation time
- Follow coordinated vulnerability disclosure (CVD) practices

---

**By using this tool, you acknowledge that you have read, understood, and agreed to this disclaimer.**

## Acknowledgments

This project is inspired by and grateful to the following open-source projects:

- [**pi**](https://github.com/earendil-works/pi) by [earendil-works](https://github.com/earendil-works) — AI agent framework architecture and multi-agent orchestration design patterns
- [**hack-skills**](https://github.com/yaklang/hack-skills) by [yaklang](https://github.com/yaklang) — Comprehensive security testing knowledge base with 90+ vulnerability testing techniques and methodologies

We also thank the following tools and communities:

- [ProjectDiscovery](https://github.com/projectdiscovery) — subfinder, httpx, nuclei
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — Intentionally vulnerable test target
- [DeepSeek](https://www.deepseek.com/) — LLM API powering the AI analysis engine
