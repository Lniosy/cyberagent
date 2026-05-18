"""Skill Loader — 按需加载 hack-skills 知识库

参考 yaklang/hack-skills 的 SKILL.md 格式：
- 每个漏洞类型一个 SKILL.md 文件
- 结构化知识：payload、场景、绕过技巧、检测方法
- 按需路由：根据目标特征动态选择加载哪些 skill
- 省 token：只加载需要的 skill，不加载全部 102 个

使用场景：
1. LLM 策略规划后，根据选定的漏洞类型加载对应 SKILL.md
2. 侦察结果出来后，根据技术栈匹配相关 skill
3. 工具执行前，将对应 skill 内容注入 LLM 上下文
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# hack-skills 目录路径
SKILLS_DIR = Path(__file__).parent.parent.parent / "references" / "hack-skills" / "skills"

# 漏洞类型 → skill 目录名映射
VULN_SKILL_MAP: dict[str, list[str]] = {
    "sqli": ["sqli-sql-injection"],
    "xss": ["xss-cross-site-scripting"],
    "ssrf": ["ssrf-server-side-request-forgery"],
    "idor": ["idor-broken-object-authorization", "api-authorization-and-bola"],
    "csrf": ["csrf-cross-site-request-forgery"],
    "xxe": ["xxe-xml-external-entity"],
    "ssti": ["ssti-server-side-template-injection"],
    "nosqli": ["nosql-injection"],
    "graphql": ["graphql-and-hidden-parameters"],
    "jwt": ["jwt-oauth-token-attacks"],
    "cors": ["cors-cross-origin-misconfiguration"],
    "upload": ["upload-insecure-files"],
    "cmd_injection": ["cmdi-command-injection"],
    "dir_traversal": ["path-traversal-lfi"],
    "open_redirect": ["open-redirect"],
    "crlf": ["crlf-injection"],
    "race_condition": ["race-condition"],
    "request_smuggling": ["request-smuggling"],
    "prototype_pollution": ["prototype-pollution", "prototype-pollution-advanced"],
    "subdomain_takeover": ["subdomain-takeover"],
    "waf_bypass": ["waf-bypass-techniques"],
    "auth_bypass": ["401-403-bypass-techniques", "authbypass-authentication-flaws"],
    "host_header": ["http-host-header-attacks"],
    "deserialization": ["deserialization-insecure"],
    "cache_poisoning": ["web-cache-deception"],
    "csp_bypass": ["csp-bypass-advanced"],
    "hpp": ["http-parameter-pollution"],
    "recon": ["recon-for-sec", "recon-and-methodology", "api-recon-and-docs"],
    "api_sec": ["api-sec", "api-auth-and-jwt-abuse"],
    "business_logic": ["business-logic-vulnerabilities", "business-logic-vuln"],
}

# 技术栈关键词 → 相关 skill 映射
TECH_SKILL_MAP: dict[str, list[str]] = {
    "node": ["nosql-injection", "prototype-pollution", "jwt-oauth-token-attacks"],
    "express": ["nosql-injection", "prototype-pollution"],
    "angular": ["xss-cross-site-scripting", "csp-bypass-advanced"],
    "react": ["xss-cross-site-scripting"],
    "php": ["sqli-sql-injection", "deserialization-insecure", "type-juggling"],
    "wordpress": ["sqli-sql-injection", "upload-insecure-files", "xss-cross-site-scripting"],
    "django": ["sqli-sql-injection", "idor-broken-object-authorization"],
    "flask": ["ssti-server-side-template-injection", "sqli-sql-injection"],
    "spring": ["ssti-server-side-template-injection", "deserialization-insecure"],
    "java": ["deserialization-insecure", "jndi-injection", "ssti-server-side-template-injection"],
    "tomcat": ["upload-insecure-files", "http-host-header-attacks"],
    "nginx": ["http-host-header-attacks", "request-smuggling"],
    "apache": ["http-host-header-attacks", "path-traversal-lfi"],
    "graphql": ["graphql-and-hidden-parameters"],
    "mongodb": ["nosql-injection"],
    "mysql": ["sqli-sql-injection"],
    "postgresql": ["sqli-sql-injection"],
    "redis": ["ssrf-server-side-request-forgery"],
    "aws": ["ssrf-server-side-request-forgery", "subdomain-takeover"],
    "docker": ["container-escape-techniques"],
    "kubernetes": ["kubernetes-pentesting"],
}


class SkillLoader:
    """Skill 按需加载器"""

    def __init__(self, skills_dir: Path | None = None):
        self._dir = skills_dir or SKILLS_DIR
        self._cache: dict[str, str] = {}  # skill_name → content
        self._index: dict[str, Path] = {}  # skill_name → file path
        self._build_index()

    def _build_index(self) -> None:
        """构建 skill 索引"""
        if not self._dir.exists():
            logger.warning("[skill] hack-skills 目录不存在: %s", self._dir)
            return

        for skill_dir in self._dir.iterdir():
            if not skill_dir.is_dir():
                continue
            skill_md = skill_dir / "SKILL.md"
            if skill_md.exists():
                self._index[skill_dir.name] = skill_md

        logger.info("[skill] 索引 %d 个 skill", len(self._index))

    @property
    def available_skills(self) -> list[str]:
        """返回所有可用的 skill 名称"""
        return list(self._index.keys())

    def load_skill(self, skill_name: str) -> str:
        """加载单个 skill 的内容"""
        if skill_name in self._cache:
            return self._cache[skill_name]

        path = self._index.get(skill_name)
        if not path:
            return ""

        try:
            content = path.read_text(encoding="utf-8")
            # 截断过长的 skill（保留前 3000 字符，约 1500 token）
            if len(content) > 3000:
                content = content[:3000] + "\n\n[... 内容已截断，完整内容请查看 SKILL.md]"
            self._cache[skill_name] = content
            return content
        except Exception as e:
            logger.warning("[skill] 加载失败 %s: %s", skill_name, e)
            return ""

    def load_for_vuln_type(self, vuln_type: str) -> str:
        """根据漏洞类型加载对应 skill"""
        skill_names = VULN_SKILL_MAP.get(vuln_type, [])
        if not skill_names:
            return ""

        parts = []
        for name in skill_names:
            content = self.load_skill(name)
            if content:
                parts.append(f"## {name}\n{content}")

        return "\n\n".join(parts)

    def load_for_tech_stack(self, tech_stack: list[str]) -> str:
        """根据技术栈加载相关 skill"""
        skill_names = set()
        for tech in tech_stack:
            tech_lower = tech.lower()
            for keyword, skills in TECH_SKILL_MAP.items():
                if keyword in tech_lower:
                    skill_names.update(skills)

        if not skill_names:
            return ""

        parts = []
        for name in list(skill_names)[:5]:  # 最多加载 5 个
            content = self.load_skill(name)
            if content:
                parts.append(f"## {name}\n{content}")

        return "\n\n".join(parts)

    def load_for_context(self, context: dict[str, Any]) -> str:
        """根据上下文智能加载 skill（组合策略）

        输入上下文包含：
        - vuln_type: 当前测试的漏洞类型
        - tech_stack: 目标技术栈
        - findings: 已发现的漏洞
        """
        parts = []

        # 1. 按漏洞类型加载
        vuln_type = context.get("vuln_type", "")
        if vuln_type:
            skill_content = self.load_for_vuln_type(vuln_type)
            if skill_content:
                parts.append(skill_content)

        # 2. 按技术栈加载
        tech_stack = context.get("tech_stack", [])
        if tech_stack:
            skill_content = self.load_for_tech_stack(tech_stack)
            if skill_content:
                parts.append(skill_content)

        # 3. 始终加载 recon 技巧
        if not parts:
            skill_content = self.load_for_vuln_type("recon")
            if skill_content:
                parts.append(skill_content)

        return "\n\n---\n\n".join(parts)

    def get_skill_summary(self) -> str:
        """返回 skill 摘要（供 LLM 了解可用 skill）"""
        if not self._index:
            return "无可用 skill。"

        lines = [f"可用 skill ({len(self._index)} 个):"]
        for name in sorted(self._index.keys())[:30]:
            # 读取第一行作为描述
            content = self.load_skill(name)
            first_line = content.split("\n")[0][:60] if content else ""
            lines.append(f"  - {name}: {first_line}")

        if len(self._index) > 30:
            lines.append(f"  ... 还有 {len(self._index) - 30} 个")

        return "\n".join(lines)
