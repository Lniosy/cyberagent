# CyberAgent

AI-driven automated vulnerability discovery agent for bug bounty programs.

[中文文档](README.md)

## Project Roadmap

| Phase | Module | Status | Description |
|-------|--------|--------|-------------|
| Phase 1 | Core Framework | ✅ | LLM client, shell executor, database, config, hooks |
| Phase 1 | Recon Agent | ✅ | Subdomain enum, HTTP fingerprint, port scan, info leak, JS analysis, WAF detection |
| Phase 2 | Scanner Agent | ✅ | 23 tools: SQLi/XSS/SSRF/IDOR/GraphQL/JWT/CORS/SSTI/NoSQL/XXE/RCE/LFI/BruteForce/FormTest |
| Phase 2 | Report Agent | ✅ | LLM-generated SRC reports (Markdown/HTML/JSON) with PoC & remediation |
| Phase 2 | Docker Deploy | ✅ | Dockerfile + docker-compose + test lab |
| Phase 3 | Orchestrator | ✅ | `auto` pipeline + `agent` ReAct loop + `team` coordination |
| Phase 3 | Coordinator Agent | ✅ | HR analysis + PM scheduling + parallel specialist dispatch |
| Phase 3 | Knowledge Loop | ✅ | Dream reflection + knowledge persistence + strategy iteration |
| Phase 3 | Independent Review | ✅ | Reviewer Agent + debate mechanism (inspired by Helio) |
| Phase 3 | Config-Driven | ✅ | Agent auto-discovery + agents.yaml + Orchestrator |
| Phase 3 | Context Management | ✅ | JSONL session persistence + context compression + prompt cache |
| Phase 4 | Real SRC Testing | 🔲 Planned | Test against live bug bounty programs |
| Phase 4 | Web UI | 🔲 Planned | Visual dashboard, task management, report viewer |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CyberAgent CLI (4 modes)                      │
│  auto (pipeline) / agent (ReAct) / team (coordinator) / step    │
└────────┬────────────────────┬─────────────────────┬─────────────┘
         │                    │                     │
  ┌──────▼──────┐   ┌────────▼────────┐   ┌───────▼───────┐
  │ Coordinator │   │   Agent Loop    │   │   Pipeline    │
  │  (HR + PM)  │   │  (ReAct mode)  │   │ (Phase 1→2→3) │
  │  Parallel   │   │  Tool selection │   │               │
  └──────┬──────┘   └───────┬─────────┘   └───────┬───────┘
         └──────────────────┼─────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
   ┌─────▼─────┐    ┌──────▼──────┐   ┌──────▼──────┐
   │ Recon     │    │  Scanner    │   │  Reporter   │
   │ 6 tasks   │    │ 23 tools   │   │ 3 formats  │
   └───────────┘    └─────────────┘   └─────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼────┐ ┌────▼────┐
        │ Reviewer  │ │ Intel   │ │ Dream   │
        │ Verify +  │ │ CVE/    │ │ Reflect │
        │ Debate    │ │ PoC     │ │ + Learn │
        └──────────┘ └─────────┘ └─────────┘
```

## 23 Security Tools

| Category | Tools | Count |
|----------|-------|-------|
| Recon | subdomain_enum, port_scan, http_probe, api_enum, js_analyze, web_crawl | 6 |
| Scan | test_sqli, test_xss, test_idor, test_graphql, test_cors, test_headers, form_test, test_rce, test_lfi, test_bruteforce, test_deserialization | 11 |
| Intel | cve_query, poc_search | 2 |
| Analysis | analyze_findings, get_findings_summary, load_skill | 3 |
| Report | generate_report, complete_task | 2 |

## 4 Running Modes

```bash
# 1. Fixed pipeline (simple, reliable)
cyberagent auto example.com

# 2. Autonomous agent (LLM decides, ReAct loop)
cyberagent agent example.com

# 3. Team mode (Coordinator dispatches, parallel specialists)
cyberagent team example.com

# 4. Step-by-step (manual control)
cyberagent recon example.com
cyberagent scan example.com
cyberagent report example.com
```

## Quick Start

### Prerequisites

- Python 3.12+
- DeepSeek API Key

### Optional Security Tools

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
brew install nmap  # macOS
```

### Installation

```bash
git clone https://github.com/Lniosy/cyberagent.git
cd cyberagent
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cp .env.example .env
# Edit .env with your DeepSeek API Key
```

### Docker

```bash
docker compose build
docker compose run recon example.com
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| LLM Core | DeepSeek V4 Pro (reasoning) + Flash (lightweight) |
| Language | Python 3.12+ |
| Agent Framework | Custom (asyncio + LLM ReAct-driven) |
| Knowledge Base | hack-skills (102 SKILL.md, on-demand loading) |
| Security Tools | subfinder, httpx, nuclei, nmap |
| Database | SQLite |
| CLI | Click + Rich |
| Deployment | Docker + docker-compose |

## Lab Validation

| Target | Tool Findings | LLM Analysis | Time | Cost |
|--------|--------------|--------------|------|------|
| OWASP Juice Shop | 14 IDOR + 6 headers | 10+ vulns | 6 turns/181s | $0.011 |
| Pikachu | 9 (5 headers + 3 IDOR + 1 info) | 10+ vulns | 10 turns/484s | $0.022 |

## Acknowledgments

- [**pi**](https://github.com/earendil-works/pi) — AI agent framework architecture and multi-agent orchestration design
- [**hack-skills**](https://github.com/yaklang/hack-skills) — Security testing knowledge base (102 SKILL.md)
- [ProjectDiscovery](https://github.com/projectdiscovery) — subfinder, httpx, nuclei
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — Test lab
- [Pikachu](https://github.com/zhuifengshaonianhanlu/pikachu) — Test lab

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
