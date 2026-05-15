"""知识积累与策略迭代系统

让 Agent 从"一次性工具"进化为"经验积累的渗透专家"。

核心闭环：
  扫描 → 提取经验 → 持久化 → 智能匹配 → 优化策略 → 更好的扫描 → 更多经验

知识类型：
1. payload_pattern — 对特定技术栈有效的 payload
2. bypass_technique — 成功的绕过技巧
3. vuln_signature — 漏洞特征模式（响应头、错误信息等）
4. target_pattern — 目标技术栈特征与漏洞关联
5. failure_record — 失败的尝试（避免重复犯错）
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import sqlite3

from cyberagent.core.config import get_settings, PROJECT_ROOT

logger = logging.getLogger(__name__)

KNOWLEDGE_DB = PROJECT_ROOT / "data" / "knowledge.db"

KNOWLEDGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    vuln_type TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL,
    source_domain TEXT NOT NULL DEFAULT '',
    tech_stack TEXT DEFAULT '[]',
    success_count INTEGER DEFAULT 1,
    fail_count INTEGER DEFAULT 0,
    confidence REAL DEFAULT 0.5,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    last_success_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_knowledge_category ON knowledge(category);
CREATE INDEX IF NOT EXISTS idx_knowledge_vuln ON knowledge(vuln_type);
CREATE INDEX IF NOT EXISTS idx_knowledge_domain ON knowledge(source_domain);
"""

# 经验提取 prompt
EXTRACT_PROMPT = """分析以下安全测试结果，提取可复用的安全测试知识。

目标：{domain}
技术栈：{tech_stack}
漏洞发现：{findings}
工具调用记录：{tool_history}

请提取以下类型的知识（返回 JSON 数组）：

1. **payload_pattern** — 哪些 payload 对这类技术栈有效？
   {{"category": "payload_pattern", "vuln_type": "sqli", "content": {{"payload": "...", "context": "...", "effective": true}}}}

2. **bypass_technique** — 发现了什么绕过技巧？
   {{"category": "bypass_technique", "vuln_type": "xss", "content": {{"technique": "...", "target_tech": "...", "detail": "..."}}}}

3. **vuln_signature** — 漏洞有什么可识别的特征？
   {{"category": "vuln_signature", "vuln_type": "idor", "content": {{"sign": "响应长度差异>100B", "context": "REST API ID 参数"}}}}

4. **target_pattern** — 目标有什么特征模式？
   {{"category": "target_pattern", "vuln_type": "", "content": {{"tech": "Express.js", "patterns": ["/api/v1/users/:id"], "common_vulns": ["idor", "nosqli"]}}}}

5. **failure_record** — 哪些尝试失败了？（避免重复）
   {{"category": "failure_record", "vuln_type": "sqli", "content": {{"approach": "...", "reason": "...", "target_tech": "..."}}}}

只返回 JSON 数组，不要其他文字。每个条目 1-3 个即可。"""

# 策略优化 prompt
STRATEGY_PROMPT = """你是一个安全测试策略专家。根据以下历史知识，为当前目标优化攻击策略。

当前目标：{domain}
目标技术栈：{tech_stack}

相关历史知识：
{knowledge_entries}

请基于历史经验，返回优化后的攻击策略（JSON 格式）：
{{
  "priority_tests": ["最应该先测的漏洞类型"],
  "skip_tests": ["可以跳过的（历史证明对这类目标无效）"],
  "payload_overrides": {{"vuln_type": "推荐使用的 payload"}},
  "bypass_hints": ["可用的绕过技巧"],
  "risk_areas": ["根据历史，这类目标最容易出问题的地方"],
  "reasoning": "策略推理过程"
}}

只返回 JSON。"""


@dataclass
class KnowledgeEntry:
    """知识条目"""
    category: str
    vuln_type: str = ""
    content: dict[str, Any] = field(default_factory=dict)
    source_domain: str = ""
    tech_stack: list[str] = field(default_factory=list)
    success_count: int = 1
    fail_count: int = 0
    confidence: float = 0.5


class KnowledgeBase:
    """知识库 — 经验积累与策略迭代"""

    def __init__(self, db_path: Path | None = None):
        self._db_path = db_path or KNOWLEDGE_DB
        self._conn: sqlite3.Connection | None = None

    def connect(self):
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(KNOWLEDGE_SCHEMA)
        logger.info("[knowledge] 知识库已连接: %s", self._db_path)

    def close(self):
        if self._conn:
            self._conn.close()

    def _ensure_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        return self._conn  # type: ignore

    # ---- 存储 ----

    def store(self, entry: KnowledgeEntry) -> int:
        """存储一条知识"""
        conn = self._ensure_conn()

        # 检查是否已有相同知识（去重）
        existing = conn.execute(
            "SELECT id, success_count, fail_count FROM knowledge "
            "WHERE category = ? AND vuln_type = ? AND content = ?",
            (entry.category, entry.vuln_type, json.dumps(entry.content, ensure_ascii=False)),
        ).fetchone()

        if existing:
            # 更新计数
            new_count = existing["success_count"] + entry.success_count
            conn.execute(
                "UPDATE knowledge SET success_count = ?, last_used_at = ?, last_success_at = ? WHERE id = ?",
                (new_count, datetime_str(), datetime_str(), existing["id"]),
            )
            conn.commit()
            return existing["id"]

        cur = conn.execute(
            "INSERT INTO knowledge (category, vuln_type, content, source_domain, tech_stack, "
            "success_count, fail_count, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                entry.category,
                entry.vuln_type,
                json.dumps(entry.content, ensure_ascii=False),
                entry.source_domain,
                json.dumps(entry.tech_stack),
                entry.success_count,
                entry.fail_count,
                entry.confidence,
                datetime_str(),
            ),
        )
        conn.commit()
        return cur.lastrowid  # type: ignore

    def store_batch(self, entries: list[KnowledgeEntry]) -> int:
        """批量存储"""
        count = 0
        for entry in entries:
            self.store(entry)
            count += 1
        return count

    # ---- 查询 ----

    def match_for_target(
        self,
        domain: str = "",
        tech_stack: list[str] | None = None,
        vuln_type: str = "",
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """为新目标匹配相关历史知识

        匹配策略：
        1. 同域名的知识（最高优先）
        2. 相同技术栈的知识
        3. 相同漏洞类型的知识
        4. 按 confidence * success_count 排序
        """
        conn = self._ensure_conn()
        conditions = []
        params: list[Any] = []

        if domain:
            conditions.append("source_domain = ?")
            params.append(domain)

        if tech_stack:
            # 技术栈匹配（JSON LIKE 查询）
            for tech in tech_stack[:3]:
                conditions.append("tech_stack LIKE ?")
                params.append(f"%{tech}%")

        if vuln_type:
            conditions.append("vuln_type = ?")
            params.append(vuln_type)

        where = " OR ".join(conditions) if conditions else "1=1"
        query = (
            f"SELECT * FROM knowledge WHERE {where} "
            f"ORDER BY confidence * success_count DESC LIMIT ?"
        )
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_failure_records(self, vuln_type: str = "", tech: str = "") -> list[dict]:
        """获取失败记录（避免重复犯错）"""
        conn = self._ensure_conn()
        conditions = ["category = 'failure_record'"]
        params: list[Any] = []

        if vuln_type:
            conditions.append("vuln_type = ?")
            params.append(vuln_type)

        where = " AND ".join(conditions)
        rows = conn.execute(
            f"SELECT * FROM knowledge WHERE {where} ORDER BY created_at DESC LIMIT 20",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict[str, Any]:
        """知识库统计"""
        conn = self._ensure_conn()
        total = conn.execute("SELECT COUNT(*) as c FROM knowledge").fetchone()["c"]
        by_cat = conn.execute(
            "SELECT category, COUNT(*) as c FROM knowledge GROUP BY category"
        ).fetchall()
        by_vuln = conn.execute(
            "SELECT vuln_type, COUNT(*) as c FROM knowledge WHERE vuln_type != '' GROUP BY vuln_type ORDER BY c DESC"
        ).fetchall()

        return {
            "total": total,
            "by_category": {r["category"]: r["c"] for r in by_cat},
            "by_vuln_type": {r["vuln_type"]: r["c"] for r in by_vuln},
        }

    # ---- 经验提取 ----

    async def extract_from_scan(
        self,
        llm,
        domain: str,
        tech_stack: list[str],
        findings: list[dict],
        tool_history: list[dict],
    ) -> list[KnowledgeEntry]:
        """从扫描结果中提取可复用知识"""
        findings_str = json.dumps(findings[:20], ensure_ascii=False, default=str)
        history_str = json.dumps(tool_history[:30], ensure_ascii=False, default=str)
        tech_str = ", ".join(tech_stack) if tech_stack else "未知"

        prompt = EXTRACT_PROMPT.format(
            domain=domain,
            tech_stack=tech_str,
            findings=findings_str,
            tool_history=history_str,
        )

        try:
            result = await llm.chat_json_pro(
                prompt,
                system_prompt="你是安全测试知识提取专家。只返回JSON数组，不要其他文字。",
            )

            entries = []
            raw_entries = result if isinstance(result, list) else result.get("knowledge", [])
            for item in raw_entries:
                if not isinstance(item, dict):
                    continue
                entries.append(KnowledgeEntry(
                    category=item.get("category", "unknown"),
                    vuln_type=item.get("vuln_type", ""),
                    content=item.get("content", {}),
                    source_domain=domain,
                    tech_stack=tech_stack,
                    confidence=0.7,
                ))

            # 批量存储
            stored = self.store_batch(entries)
            logger.info("[knowledge] 从 %s 提取 %d 条知识，存储 %d 条", domain, len(entries), stored)
            return entries

        except Exception as e:
            logger.warning("[knowledge] 知识提取失败: %s", e)
            return []

    # ---- 策略迭代 ----

    async def optimize_strategy(
        self,
        llm,
        domain: str,
        tech_stack: list[str],
    ) -> dict[str, Any]:
        """根据历史知识优化攻击策略"""
        # 匹配相关知识
        knowledge = self.match_for_target(
            domain=domain,
            tech_stack=tech_stack,
            limit=15,
        )

        if not knowledge:
            logger.info("[knowledge] 无历史知识，使用默认策略")
            return {}

        # 格式化知识条目
        entries_text = []
        for k in knowledge:
            content = json.loads(k["content"]) if isinstance(k["content"], str) else k["content"]
            entries_text.append(
                f"- [{k['category']}] {k['vuln_type']}: "
                f"{json.dumps(content, ensure_ascii=False)[:150]} "
                f"(成功{k['success_count']}次, 置信度{k['confidence']:.1f})"
            )

        # 获取失败记录
        failures = self.get_failure_records()
        if failures:
            entries_text.append("\n## 失败记录（避免重复）:")
            for f in failures[:5]:
                content = json.loads(f["content"]) if isinstance(f["content"], str) else f["content"]
                entries_text.append(f"- [{f['vuln_type']}] {json.dumps(content, ensure_ascii=False)[:100]}")

        prompt = STRATEGY_PROMPT.format(
            domain=domain,
            tech_stack=", ".join(tech_stack),
            knowledge_entries="\n".join(entries_text),
        )

        try:
            strategy = await llm.chat_json_pro(
                prompt,
                system_prompt="你是安全测试策略专家。基于历史知识优化攻击策略。只返回JSON。",
            )
            logger.info("[knowledge] 策略优化完成: %s", json.dumps(strategy, ensure_ascii=False)[:200])
            return strategy
        except Exception as e:
            logger.warning("[knowledge] 策略优化失败: %s", e)
            return {}

    # ---- 记录失败 ----

    def record_failure(self, vuln_type: str, approach: str, reason: str, tech: str = ""):
        """记录失败尝试"""
        self.store(KnowledgeEntry(
            category="failure_record",
            vuln_type=vuln_type,
            content={"approach": approach, "reason": reason, "target_tech": tech},
            confidence=0.8,
        ))


def datetime_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")
