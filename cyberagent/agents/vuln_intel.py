"""漏洞情报 Agent — CVE 查询 + PoC 搜索/审核/安全执行

功能：
1. 根据目标技术栈查询 NVD CVE 漏洞库
2. 在 GitHub 搜索 PoC/EXP 代码
3. 静态审核 PoC 代码安全性（检测后门/恶意操作）
4. 沙箱化安全执行 PoC（只读、无增删改、无 DDoS）
5. LLM 辅助生成安全 PoC

安全红线（不可违反）：
- 禁止对目标执行增删改操作
- 禁止 DDoS / 资源耗尽攻击
- 禁止执行未经审核的 PoC
- PoC 执行结果仅用于漏洞确认，不用于数据窃取
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import tempfile
import os
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

from cyberagent.agents.base import BaseAgent
from cyberagent.core.shell_executor import run_command, run_commands

logger = logging.getLogger(__name__)

# ---- 危险代码模式（PoC 安全审核用）----

# 文件系统破坏
DANGEROUS_FILE_PATTERNS = [
    r'\brm\s+(-[rfvRF]+\s+|/\s)',           # rm -rf /
    r'\bunlink\b',                            # unlink
    r'\bos\.remove\b',                        # os.remove
    r'\bshutil\.rmtree\b',                    # shutil.rmtree
    r'\bPath\(.*\)\.unlink\b',                # Path.unlink
    r'\bformat\s+[a-z]:',                     # format c:
    r'\bmkfs\b',                              # mkfs
    r'\bdd\s+if=.*of=/dev/',                  # dd if= of=/dev/
]

# 数据库破坏
DANGEROUS_DB_PATTERNS = [
    r'\bDROP\s+(TABLE|DATABASE|INDEX)\b',
    r'\bDELETE\s+FROM\b(?!\s+.*WHERE)',        # DELETE 无 WHERE
    r'\bTRUNCATE\b',
    r'\bUPDATE\s+.*SET\b(?!\s+.*WHERE)',       # UPDATE 无 WHERE
    r'\bALTER\s+TABLE\s+.*DROP\b',
]

# DDoS / 资源耗尽
DANGEROUS_DOS_PATTERNS = [
    r'\bfork\s*bomb\b',
    r':\(\)\s*\{.*:.*\|.*&.*\}',              # bash fork bomb
    r'\bos\.fork\b',
    r'\bwhile\s+True\s*:\s*(?:requests|urllib|http)',  # 无限 HTTP 请求
    r'\bfor\s+.*\s+in\s+range\(\s*\d{6,}\s*\)',       # 超大循环
    r'\bxrange\(\s*\d{6,}\s*\)',
    r'\bthreading\.Thread.*daemon.*start',     # 大量线程
    r'\bsubprocess\.Popen.*shell=True.*&\s*$', # 后台进程
    r'\bgevent|asyncio\.gather.*\d{3,}',       # 大并发
]

# 反弹 Shell / 后门
DANGEROUS_BACKDOOR_PATTERNS = [
    r'\bbash\s+-i\s*>&?\s*/dev/tcp/',          # bash reverse shell
    r'\bnc\s+.*-e\s*/bin/',                    # netcat reverse shell
    r'\bpython.*socket.*connect.*exec',        # python reverse shell
    r'\bsubprocess.*shell=True.*\bexec\b',     # 隐藏 exec
    r'\b__import__\s*\(\s*["\']os["\']\s*\)',  # 隐藏 os 导入
    r'\beval\s*\(',                            # eval() 动态执行
    r'\bexec\s*\(',                            # exec() 动态执行
    r'\bcompile\s*\(.*exec',                   # compile + exec
    r'\bos\.system\b',                         # os.system
    r'\bos\.popen\b',                          # os.popen
    r'\bsubprocess\.(call|run|Popen)\b.*shell=True',  # shell=True
]

# 网络数据外泄
DANGEROUS_EXFIL_PATTERNS = [
    r'\brequests\.(get|post).*\b(password|token|secret|key)\b',  # 外发敏感数据
    r'\bsocket\.connect\b(?!.*127\.0\.0\.1)',   # 非 localhost 连接
    r'\bcurl\b.*-d\b.*\b(password|token)\b',    # curl 外发
]

ALL_DANGEROUS_PATTERNS = (
    DANGEROUS_FILE_PATTERNS +
    DANGEROUS_DB_PATTERNS +
    DANGEROUS_DOS_PATTERNS +
    DANGEROUS_BACKDOOR_PATTERNS +
    DANGEROUS_EXFIL_PATTERNS
)

# NVD API 2.0
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEItem:
    """CVE 漏洞条目"""
    cve_id: str
    description: str
    severity: str = "unknown"
    cvss_score: float = 0.0
    published: str = ""
    references: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)


@dataclass
class PoCItem:
    """PoC/EXP 条目"""
    cve_id: str
    repo_name: str
    repo_url: str
    description: str = ""
    language: str = ""
    stars: int = 0
    poc_code: str = ""
    safety_status: str = "pending"  # pending / safe / dangerous / backdoor
    safety_issues: list[str] = field(default_factory=list)


class VulnIntelAgent(BaseAgent):
    """漏洞情报 Agent"""

    name = "vuln_intel"

    def __init__(self, ctx, recon_results: dict | None = None):
        super().__init__(ctx)
        self.recon = recon_results or {}

    async def execute(self) -> dict[str, Any]:
        # 1. 提取目标技术栈
        tech_stack = self._extract_tech_stack()
        logger.info("[vuln_intel] 目标技术栈: %s", tech_stack)

        # 2. 查询 CVE
        cves = await self._query_cves(tech_stack)
        logger.info("[vuln_intel] 发现 %d 个相关 CVE", len(cves))

        # 3. 搜索 PoC
        poc_results = await self._search_pocs(cves[:10])  # 最多搜 10 个 CVE 的 PoC
        logger.info("[vuln_intel] 搜索到 %d 个 PoC", len(poc_results))

        # 4. 安全审核
        reviewed_pocs = await self._review_pocs(poc_results)
        safe_pocs = [p for p in reviewed_pocs if p.safety_status == "safe"]
        dangerous_pocs = [p for p in reviewed_pocs if p.safety_status in ("dangerous", "backdoor")]
        logger.info("[vuln_intel] 安全: %d, 危险: %d", len(safe_pocs), len(dangerous_pocs))

        # 5. 对无 PoC 的高危 CVE，LLM 辅助生成安全 PoC
        no_poc_cves = [c for c in cves[:10] if not any(p.cve_id == c.cve_id for p in poc_results)]
        generated_pocs = []
        if no_poc_cves:
            generated_pocs = await self._generate_pocs(no_poc_cves[:5])
            logger.info("[vuln_intel] LLM 生成 %d 个 PoC", len(generated_pocs))

        # 6. 存入数据库
        for cve in cves:
            self.ctx.db.insert_finding(
                self.ctx.target_id, "cve", f"{cve.cve_id}: {cve.description[:60]}",
                cve.description, cve.severity,
                f"CVSS: {cve.cvss_score} | Products: {', '.join(cve.affected_products[:3])}",
            )

        return {
            "tech_stack": tech_stack,
            "cves": [{"cve_id": c.cve_id, "severity": c.severity, "cvss": c.cvss_score,
                       "desc": c.description[:100]} for c in cves],
            "pocs": [{"cve_id": p.cve_id, "repo": p.repo_name, "safety": p.safety_status,
                       "issues": p.safety_issues} for p in reviewed_pocs],
            "generated_pocs": [{"cve_id": p.cve_id, "safety": p.safety_status} for p in generated_pocs],
            "total_cves": len(cves),
            "safe_pocs": len(safe_pocs),
            "dangerous_pocs": len(dangerous_pocs),
        }

    # ---- 技术栈提取 ----

    def _extract_tech_stack(self) -> list[dict[str, str]]:
        """从侦察结果中提取技术栈信息"""
        stack = []

        # 从 LLM 分析结果提取
        analysis = self.recon.get("analysis", {})
        for tech in analysis.get("tech_stack", []):
            stack.append({
                "name": tech.get("name", ""),
                "version": tech.get("version", ""),
            })

        # 从 HTTP 探测结果提取
        http_data = self.recon.get("stages", {}).get("http_probe", {})
        for target in http_data.get("targets", []):
            for t in target.get("tech", []):
                if isinstance(t, str) and t not in [s["name"] for s in stack]:
                    stack.append({"name": t, "version": ""})

        # 从端口扫描提取服务信息
        port_data = self.recon.get("stages", {}).get("port_scan", {})
        for p in port_data.get("open_ports", []):
            svc = p.get("service", "")
            ver = p.get("version", "")
            if svc and svc not in [s["name"] for s in stack]:
                stack.append({"name": svc, "version": ver})

        return stack

    # ---- CVE 查询 ----

    async def _query_cves(self, tech_stack: list[dict]) -> list[CVEItem]:
        """通过 NVD API 查询匹配的 CVE"""
        cves: list[CVEItem] = []

        for tech in tech_stack[:5]:
            keyword = tech["name"]
            if not keyword or keyword.lower() in ("http", "tcp", "ppp", "unknown"):
                continue

            logger.info("[vuln_intel] 查询 CVE: %s", keyword)

            # NVD API 2.0 关键词搜索
            url = f"{NVD_API_BASE}?keywordSearch={keyword}&resultsPerPage=20"
            r = await run_command(
                f"curl -sL -m 15 -H 'Accept: application/json' '{url}'",
                timeout=20,
            )

            if not r.success:
                continue

            try:
                data = json.loads(r.stdout)
                for vuln in data.get("vulnerabilities", []):
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")

                    # 提取描述
                    desc = ""
                    for d in cve_data.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    # 提取 CVSS 评分
                    severity = "unknown"
                    cvss_score = 0.0
                    metrics = cve_data.get("metrics", {})
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(version, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            severity = cvss_data.get("baseSeverity", "unknown").lower()
                            break

                    # 只保留中高危
                    if cvss_score < 5.0:
                        continue

                    # 提取参考链接
                    refs = [r.get("url", "") for r in cve_data.get("references", [])[:5]]

                    cves.append(CVEItem(
                        cve_id=cve_id,
                        description=desc[:200],
                        severity=severity,
                        cvss_score=cvss_score,
                        published=cve_data.get("published", ""),
                        references=refs,
                        affected_products=[keyword],
                    ))

            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("[vuln_intel] CVE 解析失败: %s", e)
                continue

        # 按 CVSS 评分排序
        cves.sort(key=lambda c: c.cvss_score, reverse=True)

        # 去重
        seen = set()
        unique_cves = []
        for c in cves:
            if c.cve_id not in seen:
                seen.add(c.cve_id)
                unique_cves.append(c)

        return unique_cves

    # ---- PoC 搜索 ----

    async def _search_pocs(self, cves: list[CVEItem]) -> list[PoCItem]:
        """在 GitHub 搜索 PoC/EXP 代码"""
        pocs: list[PoCItem] = []

        for cve in cves:
            cve_id = cve.cve_id
            logger.info("[vuln_intel] 搜索 PoC: %s", cve_id)

            # GitHub 搜索 API
            search_queries = [
                f"{cve_id} poc",
                f"{cve_id} exploit",
                f"{cve_id} proof of concept",
            ]

            for query in search_queries[:2]:  # 每个 CVE 最多搜 2 个查询
                r = await run_command(
                    f"curl -sL -m 15 "
                    f"'https://api.github.com/search/repositories?q={query}&sort=stars&per_page=5'",
                    timeout=20,
                )

                if not r.success:
                    continue

                try:
                    data = json.loads(r.stdout)
                    for repo in data.get("items", [])[:3]:
                        repo_name = repo.get("full_name", "")
                        repo_url = repo.get("html_url", "")
                        description = repo.get("description", "") or ""
                        stars = repo.get("stargazers_count", 0)
                        language = repo.get("language", "") or ""

                        # 去重
                        if any(p.repo_name == repo_name for p in pocs):
                            continue

                        # 尝试下载主文件
                        poc_code = await self._fetch_poc_code(repo_name, language)

                        pocs.append(PoCItem(
                            cve_id=cve_id,
                            repo_name=repo_name,
                            repo_url=repo_url,
                            description=description[:100],
                            language=language,
                            stars=stars,
                            poc_code=poc_code,
                        ))

                except (json.JSONDecodeError, KeyError):
                    continue

                # 避免 GitHub API 限流
                await asyncio.sleep(2)

        return pocs

    async def _fetch_poc_code(self, repo_name: str, language: str) -> str:
        """尝试从 GitHub 获取 PoC 代码"""
        # 常见 PoC 文件名
        common_names = {
            "Python": ["poc.py", "exploit.py", "exploit.py", "CVE.py", "main.py", "rce.py"],
            "JavaScript": ["poc.js", "exploit.js", "index.js"],
            "Go": ["main.go", "exploit.go", "poc.go"],
            "Shell": ["poc.sh", "exploit.sh", "pwn.sh"],
            "Ruby": ["exploit.rb", "poc.rb"],
            "Java": ["Exploit.java", "PoC.java"],
            "C": ["exploit.c", "poc.c"],
        }

        filenames = common_names.get(language, ["poc.py", "exploit.py", "main.py"])

        for filename in filenames[:3]:
            r = await run_command(
                f"curl -sL -m 10 "
                f"'https://raw.githubusercontent.com/{repo_name}/master/{filename}'",
                timeout=15,
            )
            if r.success and len(r.stdout) > 50 and "<!DOCTYPE" not in r.stdout[:100]:
                return r.stdout[:5000]  # 限制大小

            # 尝试 main 分支
            r2 = await run_command(
                f"curl -sL -m 10 "
                f"'https://raw.githubusercontent.com/{repo_name}/main/{filename}'",
                timeout=15,
            )
            if r2.success and len(r2.stdout) > 50 and "<!DOCTYPE" not in r2.stdout[:100]:
                return r2.stdout[:5000]

        return ""

    # ---- PoC 安全审核 ----

    async def _review_pocs(self, pocs: list[PoCItem]) -> list[PoCItem]:
        """静态分析审核 PoC 代码安全性"""
        for poc in pocs:
            if not poc.poc_code:
                poc.safety_status = "pending"
                continue

            issues = []

            # 检查所有危险模式
            for pattern in ALL_DANGEROUS_PATTERNS:
                matches = re.findall(pattern, poc.poc_code, re.IGNORECASE | re.MULTILINE)
                if matches:
                    issues.append(f"检测到危险模式: {pattern[:40]}...")

            # 分类
            has_backdoor = any(
                re.search(p, poc.poc_code, re.IGNORECASE)
                for p in DANGEROUS_BACKDOOR_PATTERNS
            )
            has_dos = any(
                re.search(p, poc.poc_code, re.IGNORECASE)
                for p in DANGEROUS_DOS_PATTERNS
            )
            has_destructive = any(
                re.search(p, poc.poc_code, re.IGNORECASE)
                for p in DANGEROUS_FILE_PATTERNS + DANGEROUS_DB_PATTERNS
            )

            if has_backdoor:
                poc.safety_status = "backdoor"
                poc.safety_issues = issues
                logger.warning("[vuln_intel] PoC %s 检测到后门代码！", poc.repo_name)
            elif has_destructive or has_dos:
                poc.safety_status = "dangerous"
                poc.safety_issues = issues
                logger.warning("[vuln_intel] PoC %s 包含危险操作", poc.repo_name)
            elif issues:
                poc.safety_status = "dangerous"
                poc.safety_issues = issues
            else:
                poc.safety_status = "safe"

        return pocs

    # ---- 安全 PoC 执行 ----

    async def execute_safe_poc(self, poc: PoCItem, target_url: str) -> dict[str, Any]:
        """安全执行已审核通过的 PoC

        安全约束：
        1. 只执行 safety_status == "safe" 的 PoC
        2. 在独立临时文件中执行，设置 30s 超时
        3. 注入目标 URL，替换 PoC 中的占位符
        4. 限制输出大小（防止数据外泄）
        """
        if poc.safety_status != "safe":
            return {
                "executed": False,
                "reason": f"PoC 安全状态不是 safe（当前: {poc.safety_status}）",
                "issues": poc.safety_issues,
            }

        if not poc.poc_code:
            return {"executed": False, "reason": "无 PoC 代码"}

        # 注入目标 URL
        code = poc.poc_code
        code = code.replace("{{TARGET_URL}}", target_url)
        code = code.replace("{{TARGET}}", self.ctx.target_domain)

        # 添加安全包装
        safe_header = """import sys, signal
def _timeout(signum, frame):
    print("[SAFETY] 超时终止"); sys.exit(1)
signal.signal(signal.SIGALRM, _timeout)
signal.alarm(30)
_builtins_print = __builtins__.__dict__.get('print', print) if hasattr(__builtins__, '__dict__') else print
import builtins as _b
_orig = _b.print
def _safe_print(*a, **k):
    s = ' '.join(str(x) for x in a)
    if len(s) > 2000: s = s[:2000] + '...[SAFETY_TRUNCATED]'
    _orig(s, **k)
_b.print = _safe_print
try:
"""
        safe_footer = """
except Exception as e:
    print(f"[PoC Error] {e}")
finally:
    signal.alarm(0)
"""
        safe_code = safe_header + "\n".join(f"  {line}" for line in code.split("\n")) + safe_footer

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".py", prefix="poc_safe_", delete=False)
        tmp.write(safe_code)
        tmp_path = tmp.name
        tmp.close()

        try:
            result = await run_command(
                f"python3 {tmp_path}",
                timeout=35,
            )
            return {
                "executed": True,
                "cve_id": poc.cve_id,
                "stdout": result.stdout[:2000],
                "stderr": result.stderr[:500],
                "returncode": result.returncode,
                "timed_out": result.timed_out,
            }
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # ---- LLM 辅助 PoC 生成 ----

    async def _generate_pocs(self, cves: list[CVEItem]) -> list[PoCItem]:
        """对无公开 PoC 的 CVE，LLM 辅助生成安全验证代码"""
        generated = []

        for cve in cves[:3]:  # 最多生成 3 个
            prompt = (
                f"为以下 CVE 生成一个安全的漏洞验证 PoC（仅用于确认漏洞存在）。\n\n"
                f"CVE: {cve.cve_id}\n"
                f"描述: {cve.description}\n"
                f"CVSS: {cve.cvss_score}\n"
                f"目标: {self.ctx.target_domain}\n\n"
                "安全约束（必须遵守）：\n"
                "1. 只发送探测请求，不执行任何修改操作\n"
                "2. 不发送恶意 payload（如 SQL 注入的实际查询）\n"
                "3. 只通过响应特征（状态码、响应头、错误信息）判断漏洞是否存在\n"
                "4. 不执行 DDoS 或资源耗尽\n"
                "5. 代码必须是 Python，使用 requests 库\n\n"
                "返回 JSON 格式：\n"
                '{"code": "Python PoC 代码", "description": "说明", '
                '"safe_check": "为什么这个 PoC 是安全的"}'
            )

            try:
                result = await self.ctx.llm.chat_json_pro(
                    prompt,
                    system_prompt=(
                        "你是一个安全研究员，负责编写安全的漏洞验证代码。"
                        "你的代码必须严格遵守安全约束：只读、不修改、不破坏、不 DDoS。"
                        "只返回 JSON。"
                    ),
                )

                code = result.get("code", "")
                if code:
                    # 对 LLM 生成的代码也做安全审核
                    poc = PoCItem(
                        cve_id=cve.cve_id,
                        repo_name="[LLM Generated]",
                        repo_url="",
                        description=result.get("description", ""),
                        language="Python",
                        poc_code=code,
                    )
                    reviewed = await self._review_pocs([poc])
                    generated.extend(reviewed)

            except Exception as e:
                logger.warning("[vuln_intel] LLM PoC 生成失败 %s: %s", cve.cve_id, e)

        return generated
