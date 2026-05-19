# 剑来 · Jianlai-Sec

> **"With one sword, I can break every law."**
> — *Jianlai* by Fenghuo Xizhuhou

An AI-driven autonomous vulnerability discovery agent for bug bounty programs.

> **PyPI / repo name:** `jianlai-sec` (disambiguates from the generic `jianlai`)
> **CLI / Python package:** `jianlai` (short, keeps the original sword name)

[中文文档](README.md)

## About the Name

**Jianlai (剑来)**, literally *"the sword arrives"*, is the title of a wuxia/xianxia novel
by Fenghuo Xizhuhou (烽火戏诸侯). The protagonist Chen Pingan grows from a poor kiln boy
in the Lizhu Cave Heaven into a sword cultivator who "with one sword, breaks every law."

The project borrows the spirit of a sword cultivator:

- **"With one sword, I break every law"** — one precise exploit beats a thousand probes.
- **"Seek nothing outside"** — vulnerabilities aren't far away; they live in every
  ignored parameter and every line of code we silently trust.
- **"When it cannot be done, do not. When it can, give everything."** — agents learn
  when to push and when to fall back.
- **"Ning Yao's sword never fears death."** — meet WAFs head-on, don't tiptoe.

So: *sword cultivator draws sword, agent makes its move; one sword breaks every law,
one thought breaks every defense.*

The CLI vocabulary is re-themed to match:

| Term | Meaning |
|------|---------|
| **出剑 (draw sword)** | Start a vulnerability hunt |
| **入鞘 (sheathe)** | End of task, reflect |
| **独行 (solo)** | Single-agent autonomous ReAct loop (`agent` mode) |
| **结阵 (formation)** | Coordinator-orchestrated multi-agent (`team` mode) |
| **章法 (rite)** | Fixed pipeline: recon → scan → report (`auto` mode) |
| **拆招 (decompose)** | Step-by-step (recon / scan / report) |
| **招式 (technique)** | Skill knowledge base (102 SKILL.md files) |
| **复盘 (post-mortem)** | Dream reflection → persisted knowledge |

## Project Roadmap

| Phase | Module | Status | Description |
|-------|--------|--------|-------------|
| Phase 1 | Core Framework | OK | LLM client, shell executor, database, config, hooks |
| Phase 1 | Recon Agent | OK | Subdomain enum, HTTP fingerprint, port scan, info leak, JS analysis, WAF detection |
| Phase 2 | Scanner Agent | OK | 23 tools: SQLi/XSS/SSRF/IDOR/GraphQL/JWT/CORS/SSTI/NoSQL/XXE/RCE/LFI/BruteForce/FormTest |
| Phase 2 | Report Agent | OK | LLM-generated SRC reports (Markdown/HTML/JSON) with PoC & remediation |
| Phase 2 | Docker Deploy | OK | Dockerfile + docker-compose + test lab |
| Phase 3 | Orchestrator | OK | `auto` pipeline + `agent` ReAct loop + `team` coordination |
| Phase 3 | Coordinator Agent | OK | HR analysis + PM scheduling + parallel specialist dispatch |
| Phase 3 | Knowledge Loop | OK | Dream reflection + knowledge persistence + strategy iteration |
| Phase 3 | Independent Review | OK | Reviewer Agent + debate mechanism (inspired by Helio) |
| Phase 3 | Config-Driven | OK | Agent auto-discovery + agents.yaml + Orchestrator |
| Phase 3 | Context Management | OK | JSONL session persistence + context compression + prompt cache |
| Phase 4 | Real SRC Testing | TODO | Test against live bug bounty programs |
| Phase 4 | Web UI | TODO | Visual dashboard, task management, report viewer |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Jianlai CLI (4 modes)                        │
│   章法 (auto) · 独行 (agent) · 结阵 (team) · 拆招 (recon/scan)    │
└────────┬────────────────────┬─────────────────────┬─────────────┘
         │                    │                     │
  ┌──────▼──────┐   ┌────────▼────────┐   ┌───────▼───────┐
  │ Coordinator │   │   Agent Loop    │   │   Pipeline    │
  │  (formation)│   │   (solo sword)  │   │   (rite)      │
  │  HR + PM    │   │   ReAct loop    │   │ Phase 1→2→3   │
  └──────┬──────┘   └───────┬─────────┘   └───────┬───────┘
         └──────────────────┼─────────────────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
   ┌─────▼─────┐    ┌──────▼──────┐    ┌──────▼──────┐
   │ Recon     │    │  Scanner    │    │  Reporter   │
   │ 6 tasks   │    │ 23 tools    │    │ 3 formats   │
   └───────────┘    └─────────────┘    └─────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼────┐ ┌─────▼────┐
        │ Reviewer │ │ Intel   │ │ Dream    │
        │ Verify + │ │ CVE/PoC │ │ Reflect+ │
        │ Debate   │ │ Search  │ │ Learn    │
        └──────────┘ └─────────┘ └──────────┘
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
# Rite (fixed pipeline, simple and reliable)
jianlai auto example.com

# Solo (LLM-driven ReAct loop)
jianlai agent example.com

# Formation (Coordinator dispatches parallel specialists)
jianlai team example.com

# Decompose (manual step-by-step)
jianlai recon example.com
jianlai scan example.com
jianlai report example.com

# Natural language (just describe the target)
jianlai "scan localhost:8765 for vulnerabilities"
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
git clone https://github.com/Lniosy/jianlai-sec.git
cd jianlai-sec
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

### Boot Animation

The CLI plays a short *"unsheathing"* animation on startup — a horizontal blade
draws out from its scabbard, ending on the `剑来 · JIANLAI` banner.
Non-TTY environments (CI, pipes, redirected logs) fall back to a static banner.

To disable explicitly:

```bash
JIANLAI_NO_ANIM=1 jianlai auto example.com
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
| CLI | Click + Rich + prompt_toolkit |
| Deployment | Docker + docker-compose |

## Lab Validation

| Target | Tool Findings | LLM Analysis | Time | Cost |
|--------|--------------|--------------|------|------|
| OWASP Juice Shop | 14 IDOR + 6 headers | 10+ vulns | 6 turns / 181s | $0.011 |
| Pikachu | 9 (5 headers + 3 IDOR + 1 info) | 10+ vulns | 10 turns / 484s | $0.022 |

## Acknowledgments

- **《剑来》 / Fenghuo Xizhuhou** — project name and spirit
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
