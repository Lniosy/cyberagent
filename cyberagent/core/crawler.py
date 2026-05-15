"""Web 爬虫 + 表单解析

解决核心问题：当前 Agent 只测 URL 参数，不测 HTML 表单。
Pikachu 等传统 Web 应用的漏洞大多藏在 POST 表单中。

功能：
1. 从首页递归爬取所有页面链接
2. 解析 HTML 表单（form + input）
3. 生成可用于漏洞测试的表单数据
4. 发现隐藏路径和参数
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs

from cyberagent.core.shell_executor import run_command

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """表单字段"""
    name: str
    input_type: str = "text"  # text, password, hidden, submit, checkbox, radio, select, textarea
    value: str = ""
    placeholder: str = ""
    required: bool = False


@dataclass
class WebForm:
    """HTML 表单"""
    action: str          # 提交 URL
    method: str = "POST" # GET / POST
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = field(default_factory=list)
    page_url: str = ""   # 表单所在页面


@dataclass
class PageResult:
    """页面爬取结果"""
    url: str
    status: int = 0
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[WebForm] = field(default_factory=list)
    tech_hints: list[str] = field(default_factory=list)


class WebCrawler:
    """Web 爬虫 — 递归发现页面和表单"""

    def __init__(self, max_pages: int = 50, max_depth: int = 3):
        self.max_pages = max_pages
        self.max_depth = max_depth
        self._visited: set[str] = set()
        self._all_pages: list[PageResult] = []
        self._all_forms: list[WebForm] = []

    async def crawl(self, start_url: str) -> dict[str, Any]:
        """从起始 URL 递归爬取"""
        logger.info("[crawler] 开始爬取: %s (max_pages=%d, max_depth=%d)",
                     start_url, self.max_pages, self.max_depth)

        await self._crawl_page(start_url, depth=0)

        logger.info("[crawler] 爬取完成: %d 页面, %d 表单",
                     len(self._all_pages), len(self._all_forms))

        return {
            "pages": [
                {
                    "url": p.url,
                    "status": p.status,
                    "title": p.title,
                    "forms_count": len(p.forms),
                    "links_count": len(p.links),
                }
                for p in self._all_pages
            ],
            "forms": [
                {
                    "action": f.action,
                    "method": f.method,
                    "fields": [{"name": ff.name, "type": ff.input_type, "value": ff.value} for ff in f.fields],
                    "page_url": f.page_url,
                }
                for f in self._all_forms
            ],
            "total_pages": len(self._all_pages),
            "total_forms": len(self._all_forms),
        }

    async def _crawl_page(self, url: str, depth: int):
        """爬取单个页面"""
        if depth > self.max_depth:
            return
        if len(self._all_pages) >= self.max_pages:
            return
        if url in self._visited:
            return

        self._visited.add(url)

        r = await run_command(["curl", "-sL", "-m", "10", url], timeout=15)
        if not r.success:
            return

        html = r.stdout
        if not html or len(html) < 50:
            return

        # 解析页面
        page = PageResult(url=url, status=200)

        # 提取标题
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        page.title = title_match.group(1).strip()[:100] if title_match else ""

        # 提取链接
        links = re.findall(r'href=["\']([^"\']+)["\']', html)
        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc

        for link in links:
            full_url = urljoin(url, link)
            parsed_link = urlparse(full_url)

            # 只爬同域名
            if parsed_link.netloc != base_domain:
                continue
            # 跳过静态资源
            if any(full_url.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf"]):
                continue
            # 跳过锚点
            if full_url.startswith("#"):
                continue

            page.links.append(full_url)

        # 提取表单
        page.forms = self._parse_forms(html, url)
        self._all_forms.extend(page.forms)
        self._all_pages.append(page)

        # 递归爬取链接
        for link in page.links:
            if link not in self._visited:
                await self._crawl_page(link, depth + 1)

    def _parse_forms(self, html: str, page_url: str) -> list[WebForm]:
        """解析 HTML 表单"""
        forms = []

        # 提取所有 <form> 块
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        form_tag_pattern = re.compile(r'<form([^>]*)>', re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            # 解析 form 属性
            tag_match = form_tag_pattern.search(form_html)
            if not tag_match:
                continue

            attrs = tag_match.group(1)
            action = self._extract_attr(attrs, "action") or page_url
            method = self._extract_attr(attrs, "method") or "POST"
            enctype = self._extract_attr(attrs, "enctype") or "application/x-www-form-urlencoded"

            # 解析 action URL
            action_url = urljoin(page_url, action) if action else page_url

            # 解析 input 字段
            fields = []
            input_pattern = re.compile(
                r'<input([^>]*)>|<textarea([^>]*)>.*?</textarea>|<select([^>]*)>.*?</select>',
                re.DOTALL | re.IGNORECASE,
            )

            for input_match in input_pattern.finditer(form_body):
                attrs_str = input_match.group(1) or input_match.group(2) or input_match.group(3) or ""
                name = self._extract_attr(attrs_str, "name")
                if not name:
                    continue

                input_type = self._extract_attr(attrs_str, "type") or "text"
                value = self._extract_attr(attrs_str, "value") or ""
                placeholder = self._extract_attr(attrs_str, "placeholder") or ""
                required = "required" in attrs_str.lower()

                fields.append(FormField(
                    name=name,
                    input_type=input_type,
                    value=value,
                    placeholder=placeholder,
                    required=required,
                ))

            if fields:
                forms.append(WebForm(
                    action=action_url,
                    method=method.upper(),
                    enctype=enctype,
                    fields=fields,
                    page_url=page_url,
                ))

        return forms

    @staticmethod
    def _extract_attr(attrs_str: str, attr_name: str) -> str:
        """从 HTML 属性字符串中提取指定属性值"""
        pattern = re.compile(rf'{attr_name}\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
        match = pattern.search(attrs_str)
        return match.group(1) if match else ""

    def get_testable_forms(self) -> list[WebForm]:
        """获取可测试的表单（排除只有 submit 按钮的表单）"""
        testable = []
        for form in self._all_forms:
            has_input = any(
                f.input_type not in ("submit", "button", "reset", "hidden")
                for f in form.fields
            )
            if has_input:
                testable.append(form)
        return testable
