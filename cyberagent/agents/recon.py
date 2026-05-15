"""侦察 Agent — 自动化子域名枚举、端口扫描、指纹识别等"""
from __future__ import annotations

# Agent 自描述清单（= Helio 的 JD）
MANIFEST = {
    "name": "recon",
    "display_name": "侦察 Agent",
    "description": "子域名枚举、端口扫描、HTTP指纹、JS分析、WAF检测、信息泄露",
    "category": "recon",
    "phase": 1,
    "input_requires": [],
    "output_provides": ["recon_results"],
}

import asyncio
import json
import logging
import re
from typing import Any

from cyberagent.agents.base import BaseAgent
from cyberagent.core.shell_executor import check_tool_exists, resolve_tool, run_command, run_commands

logger = logging.getLogger(__name__)


class ReconAgent(BaseAgent):
    """侦察 Agent：目标信息收集和攻击面枚举"""

    name = "recon"

    async def execute(self) -> dict[str, Any]:
        domain = self.ctx.target_domain
        target_id = self.ctx.target_id
        db = self.ctx.db
        local_mode = self.ctx.metadata.get("local_mode", False)
        extra_ports = self.ctx.metadata.get("extra_ports", [])

        results: dict[str, Any] = {"domain": domain, "stages": {}, "local_mode": local_mode}

        if local_mode:
            # 本地模式：跳过子域名枚举，直接探测目标
            subdomains = [domain]
            logger.info("[recon] 本地模式，跳过子域名枚举，直接探测: %s", domain)
            results["stages"]["subdomain_enum"] = {"count": 1, "subdomains": subdomains, "skipped": True}
        else:
            # 1. 子域名枚举
            subdomains = await self._enumerate_subdomains(domain)
            results["stages"]["subdomain_enum"] = {
                "count": len(subdomains),
                "subdomains": subdomains,
            }

        # 2. HTTP 存活探测 + 指纹识别
        alive = await self._probe_http(subdomains)

        # 本地模式回退：如果 httpx 没结果，用 curl 直接探测
        if not alive and local_mode and extra_ports:
            logger.info("[recon] httpx 无结果，使用 curl 回退探测...")
            for p in extra_ports:
                url = f"http://{domain}:{p}"
                r = await run_command(f"curl -sI -m 5 '{url}'", timeout=10)
                if r.success and "HTTP/" in r.stdout:
                    status_match = re.search(r'HTTP/\S+\s+(\d+)', r.stdout)
                    title_match = re.search(r'(?i)X-Recruiting:\s*(.*)', r.stdout)
                    alive.append({
                        "url": url, "host": domain, "port": p,
                        "status": int(status_match.group(1)) if status_match else 0,
                        "title": "", "tech": [], "webserver": "",
                    })
                    db.insert_subdomain(domain, domain, "127.0.0.1")

        results["stages"]["http_probe"] = {
            "alive_count": len(alive),
            "targets": alive,
        }

        # 3. 端口扫描（对主域名和发现的子域名取样）
        scan_targets = self._select_port_scan_targets(domain, subdomains, alive)
        ports = await self._port_scan(scan_targets)
        results["stages"]["port_scan"] = {
            "scanned_hosts": len(scan_targets),
            "open_ports": ports,
        }

        # 4. 信息泄露检测（robots.txt, sitemap.xml, .git, .env 等）
        leaks = await self._check_info_leaks(alive)
        results["stages"]["info_leaks"] = leaks

        # 5. JS 文件分析
        js_findings = await self._analyze_js(alive)
        results["stages"]["js_analysis"] = js_findings

        # 6. WAF 检测
        waf_result = await self._detect_waf(domain)
        results["stages"]["waf_detection"] = waf_result

        # 7. LLM 综合分析
        logger.info("[recon] 正在进行 LLM 综合分析...")
        analysis = await self.analyze_with_llm(results)
        results["analysis"] = analysis

        # 存储分析结果到 findings
        if analysis:
            for item in analysis.get("attack_surface", []):
                db.insert_finding(
                    target_id=target_id,
                    category="attack_surface",
                    title=item.get("type", "未知"),
                    detail=item.get("detail", ""),
                    severity=item.get("risk", "info"),
                )
            for step in analysis.get("suggested_next_steps", []):
                db.insert_finding(
                    target_id=target_id,
                    category="suggestion",
                    title="建议的下一步",
                    detail=step,
                    severity="info",
                )

        db.update_target_status(target_id, "recon_complete")
        return results

    # ---- 子域名枚举 ----

    async def _enumerate_subdomains(self, domain: str) -> list[str]:
        """使用 subfinder 枚举子域名"""
        subs: set[str] = {domain}

        if check_tool_exists("subfinder"):
            subfinder_bin = resolve_tool("subfinder")
            logger.info("[recon] 使用 subfinder 枚举子域名...")
            result = await run_command(
                f"{subfinder_bin} -d {domain} -silent -all",
                timeout=120,
            )
            if result.success:
                for line in result.lines:
                    sub = line.strip().lower()
                    if sub and "." in sub:
                        subs.add(sub)

            self.ctx.db.insert_recon_result(
                self.ctx.target_id, "subdomain", "subfinder",
                result.stdout, {"subdomains": list(subs)},
            )

        # 常见子域名爆破补充
        common_prefixes = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "portal", "app", "blog", "cdn", "docs", "git", "jenkins",
            "jira", "vpn", "mx", "ns1", "ns2", "shop", "m", "mobile",
            "sso", "auth", "console", "dashboard", "status", "ci",
        ]
        # 仅记录潜在子域名，不实际扫描所有（MVP阶段）
        potential = {f"{prefix}.{domain}" for prefix in common_prefixes}
        logger.info("[recon] 潜在子域名候选: %d 个", len(potential))

        # 存入数据库
        sub_list = [{"subdomain": s, "ip": ""} for s in subs]
        self.ctx.db.insert_subdomains(self.ctx.target_id, sub_list)

        return sorted(subs)

    # ---- HTTP 存活探测 ----

    async def _probe_http(self, subdomains: list[str]) -> list[dict[str, Any]]:
        """使用 httpx 探测 HTTP 存活并获取指纹"""
        alive: list[dict[str, Any]] = []

        if not check_tool_exists("httpx"):
            logger.warning("[recon] httpx 未安装，跳过 HTTP 探测")
            return alive

        httpx_bin = resolve_tool("httpx")

        # 构建探测目标列表
        extra_ports = self.ctx.metadata.get("extra_ports", [])
        local_mode = self.ctx.metadata.get("local_mode", False)
        probe_targets: list[str] = []
        for sub in subdomains:
            if extra_ports:
                for p in extra_ports:
                    probe_targets.append(f"http://{sub}:{p}" if local_mode else f"{sub}:{p}")
            else:
                probe_targets.append(sub)

        logger.info("[recon] 使用 httpx 探测 %d 个目标...", len(probe_targets))

        # 写入临时文件（使用唯一文件名避免并发冲突）
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", prefix="cyberagent_", delete=False)
        tmp.write("\n".join(probe_targets))
        tmp_input = tmp.name
        tmp.close()

        result = await run_command(
            f"{httpx_bin} -l {tmp_input} -silent -status-code -title -tech-detect "
            f"-follow-redirects -timeout 10 -json",
            timeout=180,
        )

        if result.success:
            for line in result.lines:
                try:
                    data = json.loads(line)
                    entry = {
                        "url": data.get("url", ""),
                        "host": data.get("host", ""),
                        "status": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "webserver": data.get("webserver", ""),
                        "content_length": data.get("content_length", 0),
                    }
                    alive.append(entry)

                    self.ctx.db.update_subdomain_http(
                        entry["host"],
                        entry["status"],
                        entry["title"],
                        entry["tech"],
                    )
                except json.JSONDecodeError:
                    continue

        self.ctx.db.insert_recon_result(
            self.ctx.target_id, "http_probe", "httpx",
            result.stdout, {"alive": alive},
        )

        return alive

    # ---- 端口扫描 ----

    def _select_port_scan_targets(
        self, domain: str, subdomains: list[str], alive: list[dict]
    ) -> list[str]:
        """选择端口扫描目标：主域名 + 活跃子域名（限制数量）"""
        targets = {domain}
        for item in alive[:20]:  # 最多扫20个
            targets.add(item.get("host", domain))
        return list(targets)

    def _get_nmap_port_args(self) -> str:
        """根据配置生成 nmap 端口参数"""
        extra_ports = self.ctx.metadata.get("extra_ports", [])
        local_mode = self.ctx.metadata.get("local_mode", False)
        if extra_ports:
            ports_str = ",".join(str(p) for p in extra_ports)
            if local_mode:
                return f"-p {ports_str}"
            return f"--top-ports 1000 -p {ports_str}"
        return "--top-ports 1000"

    async def _port_scan(self, hosts: list[str]) -> list[dict[str, Any]]:
        """使用 nmap 进行快速端口扫描，对 Web 端口做 HTTP 二次验证"""
        all_ports: list[dict[str, Any]] = []

        nmap_bin = resolve_tool("nmap")
        if not check_tool_exists("nmap"):
            logger.warning("[recon] nmap 未安装，跳过端口扫描")
            return all_ports

        # 常见 Web 端口，需要额外 HTTP 识别
        web_ports = {80, 443, 8080, 8443, 3000, 3001, 4000, 5000, 5173, 8000, 8001, 8888, 9000, 9090}

        port_args = self._get_nmap_port_args()
        for host in hosts[:5]:
            logger.info("[recon] nmap 扫描: %s", host)
            result = await run_command(
                f"{nmap_bin} -sV -T4 {port_args} -oX - {host}",
                timeout=120,
            )
            if result.success:
                ports = self._parse_nmap_xml(result.stdout)
                for p in ports:
                    p["host"] = host
                    all_ports.append(p)

                # 对 Web 端口做 HTTP 服务识别
                web_ports_found = [p for p in ports if p["port"] in web_ports]
                if web_ports_found:
                    await self._identify_web_services(host, web_ports_found, all_ports)

                for p in all_ports:
                    self.ctx.db.insert_port(
                        self.ctx.target_id, p.get("host", host), p["port"],
                        p.get("protocol", "tcp"),
                        p.get("service", ""),
                        p.get("version", ""),
                    )

        self.ctx.db.insert_recon_result(
            self.ctx.target_id, "port_scan", "nmap",
            "", {"ports": all_ports},
        )
        return all_ports

    async def _identify_web_services(
        self, host: str, web_ports: list[dict], all_ports: list[dict]
    ) -> None:
        """对 Web 端口发送 HTTP 请求，识别实际服务类型"""
        cmds = []
        port_map: list[int] = []
        for p in web_ports:
            port = p["port"]
            scheme = "https" if port in (443, 8443) else "http"
            cmds.append(f"curl -sI -m 5 -k '{scheme}://{host}:{port}'")
            port_map.append(port)

        results = await run_commands(cmds, timeout=10, max_concurrent=5)

        for port_num, r in zip(port_map, results):
            if not r.success:
                continue

            headers = r.stdout
            # 提取 Server 头
            server_match = re.search(r'(?i)^server:\s*(.+)', headers, re.MULTILINE)
            server = server_match.group(1).strip() if server_match else ""

            # 提取 X-Powered-By 头
            powered_match = re.search(r'(?i)^x-powered-by:\s*(.+)', headers, re.MULTILINE)
            powered_by = powered_match.group(1).strip() if powered_match else ""

            # 构建服务描述
            service_parts = []
            if server:
                service_parts.append(server)
            if powered_by:
                service_parts.append(f"({powered_by})")
            service_desc = " ".join(service_parts) if service_parts else ""

            if not service_desc:
                continue

            # 更新 all_ports 中对应端口的服务信息
            for p in all_ports:
                if p["port"] == port_num and p.get("host", host) == host:
                    if not p.get("version") or p["version"] == "":
                        p["version"] = service_desc
                    elif service_desc not in p["version"]:
                        p["version"] = f"{p['version']} {service_desc}"
                    # 修正服务名
                    if p.get("service") in ("ppp", "unknown", ""):
                        if "nginx" in server.lower():
                            p["service"] = "http"
                        elif "apache" in server.lower():
                            p["service"] = "http"
                        else:
                            p["service"] = "http"

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> list[dict[str, Any]]:
        """简单解析 nmap XML 输出"""
        ports = []
        # 使用正则提取，避免引入 lxml 依赖
        port_pattern = re.compile(
            r'<port\s+protocol="(\w+)"\s+portid="(\d+)">'
            r'.*?<state\s+state="(\w+)".*?/>'
            r'(.*?)</port>',
            re.DOTALL,
        )
        service_pattern = re.compile(
            r'<service\s+name="([^"]*)"(?:\s+product="([^"]*)")?'
            r'(?:\s+version="([^"]*)")?',
        )

        for match in port_pattern.finditer(xml_output):
            protocol, portid, state, content = match.groups()
            if state != "open":
                continue
            svc_match = service_pattern.search(content)
            ports.append({
                "port": int(portid),
                "protocol": protocol,
                "service": svc_match.group(1) if svc_match else "",
                "version": " ".join(filter(None, [
                    svc_match.group(2) if svc_match else "",
                    svc_match.group(3) if svc_match else "",
                ])).strip(),
            })
        return ports

    # ---- 信息泄露检测 ----

    async def _check_info_leaks(self, alive: list[dict]) -> list[dict[str, Any]]:
        """检测常见信息泄露路径，带内容验证防误报"""
        leaks: list[dict[str, Any]] = []
        leak_paths = [
            "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env",
            "/.git/config", "/wp-config.php.bak", "/.DS_Store",
            "/server-status", "/server-info", "/.well-known/security.txt",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/phpinfo.php", "/info.php", "/.htaccess",
            "/backup.zip", "/db.sql", "/dump.sql",
        ]

        targets = [item["url"] for item in alive[:5]]
        if not targets:
            return leaks

        # 第一步：先获取一个基线响应（用于识别 SPA catch-all）
        baseline_url = targets[0].rstrip("/")
        baseline_resp = await run_command(
            f"curl -sL -m 5 '{baseline_url}/__definitely_not_exist_12345__' | head -c 1000",
            timeout=10,
        )
        baseline_body = baseline_resp.stdout if baseline_resp.success else ""
        is_spa = "<!doctype html>" in baseline_body.lower()[:100] or "<html" in baseline_body.lower()[:100]
        baseline_len = len(baseline_body.strip())
        logger.info("[recon] SPA 检测: %s (基线响应长度: %d)", "是" if is_spa else "否", baseline_len)

        # 第二步：收集候选 URL
        cmds = []
        for base_url in targets:
            base = base_url.rstrip("/")
            for path in leak_paths:
                url = f"{base}{path}"
                cmds.append(f"curl -s -o /dev/null -w '%{{http_code}} {url}' -m 5 '{url}'")

        logger.info("[recon] 检测 %d 个信息泄露路径...", len(cmds))
        results = await run_commands(cmds, timeout=10, max_concurrent=10)

        # 收集有响应的 URL
        candidate_urls: list[tuple[str, str]] = []  # (url, status_code)
        for r in results:
            if r.success and r.stdout.strip():
                parts = r.stdout.strip().split(" ", 1)
                if len(parts) == 2:
                    code, url = parts
                    code = code.strip("'\" ")
                    if code in ("200", "301", "302", "403"):
                        candidate_urls.append((url, code))

        # 第三步：对所有候选做内容验证
        for url, code in candidate_urls:
            path_part = url.split("//", 1)[-1]
            if "/" in path_part:
                path_part = path_part.split("/", 1)[1]

            # 301/302 跳转需要检查跳转目标
            if code in ("301", "302"):
                redirect_check = await run_command(
                    f"curl -sI -m 5 '{url}' | grep -i '^location:'",
                    timeout=10,
                )
                if redirect_check.success and redirect_check.stdout.strip():
                    redirect_target = redirect_check.stdout.strip().split(":", 1)[1].strip()
                    # 如果跳转到根路径，大概率是 SPA
                    if redirect_target in ("/", "/#/", "/#/login"):
                        continue

            # 200 响应做内容验证
            if code == "200":
                body_check = await run_command(
                    f"curl -sL -m 5 '{url}' | head -c 1500",
                    timeout=10,
                )
                body = body_check.stdout if body_check.success else ""
                body_lower = body.lower()

                # 检查1：如果基线是 SPA，对比响应长度
                if is_spa:
                    # 响应长度与基线接近，说明是 SPA catch-all
                    if abs(len(body.strip()) - baseline_len) < 100:
                        continue

                # 检查2：明确的 HTML 页面（非预期的 HTML 响应）
                is_html = "<!doctype html>" in body_lower[:200] or "<html" in body_lower[:200]
                is_expected_html = path_part in ("phpinfo.php", "info.php", "server-status", "server-info")
                if is_html and not is_expected_html:
                    continue

                # 检查3：空或极短响应
                if len(body.strip()) < 5:
                    continue

                # 检查4：验证内容与路径语义匹配
                if not self._validate_leak_content(path_part, body):
                    continue

            leaks.append({"url": url, "status": int(code), "path": f"/{path_part}"})
            severity = "high" if any(s in path_part for s in [".git", ".env", "backup", "dump", "db.sql", "config"]) else "medium"
            self.ctx.db.insert_finding(
                self.ctx.target_id, "info_leak",
                f"发现可访问路径: /{path_part}",
                f"URL: {url}, 状态码: {code}",
                severity=severity,
            )

        self.ctx.db.insert_recon_result(
            self.ctx.target_id, "info_leaks", "curl",
            "", {"leaks": leaks, "spa_detected": is_spa},
        )
        return leaks

    @staticmethod
    def _validate_leak_content(path: str, body: str) -> bool:
        """验证响应内容是否与路径语义匹配"""
        body_lower = body.lower().strip()

        # robots.txt 应该包含 User-agent 或 Disallow
        if path == "robots.txt":
            return "user-agent" in body_lower or "disallow" in body_lower

        # sitemap.xml 应该包含 urlset 或 sitemapindex
        if path == "sitemap.xml":
            return "urlset" in body_lower or "sitemapindex" in body_lower

        # .git/HEAD 应该包含 ref:
        if path == ".git/HEAD":
            return "ref:" in body_lower

        # .git/config 应该包含 [core] 或 repositoryformatversion
        if path == ".git/config":
            return "[core]" in body_lower or "repositoryformatversion" in body_lower

        # .env 应该包含 KEY=VALUE 格式
        if path == ".env":
            return "=" in body and any(kw in body_lower for kw in ["key", "secret", "password", "database", "db_", "app_"])

        # .DS_Store 是二进制文件
        if path == ".DS_Store":
            return len(body) > 100 and "\x00" in body

        # security.txt 应该包含 Contact 或 Expires
        if "security.txt" in path:
            return "contact" in body_lower or "expires" in body_lower

        # crossdomain.xml 应该包含 cross-domain-policy
        if "crossdomain" in path:
            return "cross-domain-policy" in body_lower

        # 默认：只要内容不是 HTML 且有一定长度就认为有效
        if "<!doctype html>" in body_lower[:100] or "<html" in body_lower[:100]:
            return False
        return len(body_lower) > 20

    # ---- JS 分析 ----

    async def _analyze_js(self, alive: list[dict]) -> list[dict[str, Any]]:
        """分析页面中的 JS 文件，提取 API 端点和敏感信息"""
        findings: list[dict[str, Any]] = []
        seen_endpoints: set[str] = set()
        seen_secrets: set[str] = set()

        # 噪音过滤：排除静态资源路径
        _NOISE_PATTERNS = re.compile(
            r'\.(?:css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(?:\?|$)',
            re.IGNORECASE,
        )

        targets = [item["url"] for item in alive[:3]]
        if not targets:
            return findings

        for url in targets:
            logger.info("[recon] 分析 JS: %s", url)
            result = await run_command(f"curl -sL -m 10 '{url}'", timeout=15)
            if not result.success:
                continue

            html = result.stdout
            from urllib.parse import urlparse
            parsed = urlparse(url)

            # 提取 JS 文件 URL
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)
            for js_url in js_urls[:10]:
                if js_url.startswith("//"):
                    js_url = "https:" + js_url
                elif js_url.startswith("/"):
                    js_url = f"{parsed.scheme}://{parsed.netloc}{js_url}"
                elif not js_url.startswith("http"):
                    base_path = parsed.path.rsplit("/", 1)[0] if "/" in parsed.path else ""
                    js_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/{js_url}"

                js_result = await run_command(f"curl -sL -m 10 '{js_url}'", timeout=15)
                if not js_result.success:
                    continue

                js_content = js_result.stdout

                # 提取 API 端点（多模式）
                api_patterns = [
                    r'["\']/(api|v[0-9]+)/[^"\']{3,}["\']',
                    r'["\']https?://[^"\']*(?:api|graphql)[^"\']*["\']',
                    r'(?:fetch|axios|ajax)\s*\(\s*["\']([^"\']+)["\']',
                    r'["\'](/[a-zA-Z0-9_/-]{4,}(?:\.json|\.xml|\.php|\.asp))["\']',
                    # GraphQL 特征
                    r'(?:query|mutation)\s+[A-Z]\w+\s*[\({]',
                    r'["\'](?:/graphql|/gql|/query)["\']',
                    # RESTful 路径参数
                    r'["\']/(?:rest|api)/[^"\']*(?:\{[^}]+\}|:[a-zA-Z_]+)[^"\']*["\']',
                    # WebSocket
                    r'(?:wss?://)[^"\']+',
                ]

                for pattern in api_patterns:
                    for match in re.findall(pattern, js_content):
                        endpoint = match if isinstance(match, str) else match[-1]
                        endpoint = endpoint.strip("\"' ")
                        if not endpoint or _NOISE_PATTERNS.search(endpoint):
                            continue
                        if endpoint in seen_endpoints:
                            continue
                        seen_endpoints.add(endpoint)

                        endpoint_type = "graphql" if "graphql" in endpoint.lower() or "gql" in endpoint.lower() else \
                                        "websocket" if endpoint.startswith(("ws://", "wss://")) else "api_endpoint"
                        findings.append({
                            "type": endpoint_type,
                            "source": js_url,
                            "value": endpoint,
                        })

                # 检测敏感信息
                sensitive_patterns = [
                    (r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["\']([^"\']{8,})["\']', "api_key"),
                    (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', "password"),
                    (r'(?:AWS|aws)[_-]?(?:ACCESS|access)[_-]?(?:KEY|key)\s*[:=]\s*["\']([^"\']{16,})["\']', "aws_key"),
                    (r'(?:secret|token)\s*[:=]\s*["\']([A-Za-z0-9+/=_-]{16,})["\']', "secret"),
                    (r'(?:private[_-]?key)\s*[:=]\s*["\']([^"\']{16,})["\']', "private_key"),
                    (r'(?:Bearer|Authorization)\s+["\']([A-Za-z0-9._-]{20,})["\']', "auth_token"),
                ]
                for pattern, secret_type in sensitive_patterns:
                    for match in re.findall(pattern, js_content, re.IGNORECASE):
                        match_key = f"{secret_type}:{match[:10]}"
                        if match_key in seen_secrets:
                            continue
                        seen_secrets.add(match_key)

                        findings.append({
                            "type": "sensitive_info",
                            "secret_type": secret_type,
                            "source": js_url,
                            "value": match[:20] + "...",
                        })
                        self.ctx.db.insert_finding(
                            self.ctx.target_id, "info_leak",
                            f"JS中发现敏感信息: {secret_type}",
                            f"来源: {js_url}",
                            severity="high",
                        )

        self.ctx.db.insert_recon_result(
            self.ctx.target_id, "js_analysis", "regex",
            "", {"findings": findings},
        )
        return findings

    # ---- WAF 检测 ----

    async def _detect_waf(self, domain: str) -> dict[str, Any]:
        """简单 WAF 检测"""
        result_info: dict[str, Any] = {"detected": False, "waf_name": ""}

        nmap_bin = resolve_tool("nmap")
        if not check_tool_exists("nmap"):
            return result_info

        logger.info("[recon] WAF 检测: %s", domain)
        result = await run_command(
            f"{nmap_bin} -p 80,443 --script http-waf-detect {domain}",
            timeout=30,
        )

        if result.success:
            if "WAF" in result.stdout or "firewall" in result.stdout.lower():
                result_info["detected"] = True
                # 尝试提取 WAF 名称
                waf_match = re.search(r'(?i)(cloudflare|akamai|incapsula|imperva|mod_security|f5|waf)', result.stdout)
                if waf_match:
                    result_info["waf_name"] = waf_match.group(1)

        self.ctx.db.insert_recon_result(
            self.ctx.target_id, "waf_detection", "nmap",
            result.stdout, result_info,
        )

        if result_info["detected"]:
            self.ctx.db.insert_finding(
                self.ctx.target_id, "waf",
                f"检测到 WAF: {result_info['waf_name'] or '未知'}",
                "目标部署了 WAF，可能影响漏洞利用",
                severity="info",
            )

        return result_info
# Auto-discovery reference
AGENT_CLASS = ReconAgent
