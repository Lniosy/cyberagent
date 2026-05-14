"""会话持久化 — JSONL 树形存储，对齐 pi 的 SessionManager

核心设计（参考 pi packages/coding-agent/src/core/session-manager.ts）：
- JSONL 追加写入（append-only，永不修改）
- 每条 entry 有 id/parentId 形成树结构
- leafId 指针追踪当前位置
- branch() 回退到历史点，创建新分支
- 断点续扫：重启后自动加载最新 session
"""
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator

from cyberagent.core.config import PROJECT_ROOT

logger = logging.getLogger(__name__)

SESSION_DIR = PROJECT_ROOT / "data" / "sessions"


@dataclass
class SessionEntry:
    """会话条目 — 树形结构中的一个节点"""
    id: str
    parent_id: str | None
    role: str           # system / user / assistant / tool / compaction
    content: str
    tool_name: str | None = None
    tool_args: dict | None = None
    tool_result: dict | None = None
    is_error: bool = False
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, default=str)

    @classmethod
    def from_json(cls, line: str) -> SessionEntry:
        data = json.loads(line)
        return cls(**data)


class SessionManager:
    """会话管理器 — JSONL 树形存储 + leafId 指针

    对齐 pi 的 SessionManager 核心特性：
    1. append-only JSONL 写入
    2. id/parentId 树形结构
    3. leafId 当前位置追踪
    4. branch() 回退到历史点
    5. build_context() 从 leaf 回溯到 root 重建 LLM 消息
    6. continue_recent() 断点续扫
    """

    def __init__(self, session_path: Path | None = None):
        self._path = session_path
        self._entries: list[SessionEntry] = []
        self._by_id: dict[str, SessionEntry] = {}
        self._leaf_id: str | None = None
        self._dirty: list[SessionEntry] = []  # 未写入磁盘的条目

    @property
    def leaf_id(self) -> str | None:
        return self._leaf_id

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    # ---- 创建和加载 ----

    @classmethod
    def create(cls, target: str) -> SessionManager:
        """创建新会话"""
        SESSION_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_")
        path = SESSION_DIR / f"{safe_target}_{timestamp}.jsonl"

        session = cls(session_path=path)
        # 写入 system 条目
        session.append(
            role="system",
            content=f"CyberAgent 会话开始 — 目标: {target}",
            metadata={"target": target},
        )
        logger.info("[session] 创建新会话: %s", path)
        return session

    @classmethod
    def continue_recent(cls, target: str) -> SessionManager | None:
        """断续续扫：加载目标最近的会话（对齐 pi continueRecent）"""
        if not SESSION_DIR.exists():
            return None

        safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_")
        sessions = sorted(
            SESSION_DIR.glob(f"{safe_target}_*.jsonl"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not sessions:
            return None

        path = sessions[0]
        session = cls(session_path=path)
        session._load_from_file()

        if session._entries:
            session._leaf_id = session._entries[-1].id
            logger.info("[session] 恢复会话: %s (%d 条目, leaf=%s)",
                        path, len(session._entries), session._leaf_id[:8])
            return session

        return None

    def _load_from_file(self):
        """从 JSONL 文件加载所有条目"""
        if not self._path or not self._path.exists():
            return

        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = SessionEntry.from_json(line)
                    self._entries.append(entry)
                    self._by_id[entry.id] = entry
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning("[session] 跳过损坏条目: %s", e)

    # ---- 追加条目 ----

    def append(
        self,
        role: str,
        content: str,
        tool_name: str | None = None,
        tool_args: dict | None = None,
        tool_result: dict | None = None,
        is_error: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> SessionEntry:
        """追加一个条目（对齐 pi appendEntry）"""
        entry = SessionEntry(
            id=str(uuid.uuid4()),
            parent_id=self._leaf_id,
            role=role,
            content=content,
            tool_name=tool_name,
            tool_args=tool_args,
            tool_result=tool_result,
            is_error=is_error,
            metadata=metadata or {},
        )

        self._entries.append(entry)
        self._by_id[entry.id] = entry
        self._leaf_id = entry.id
        self._dirty.append(entry)

        # 延迟写入策略（对齐 pi）：assistant 消息到达后才 flush
        if role in ("assistant", "compaction"):
            self._flush()

        return entry

    def _flush(self):
        """将未写入的条目 flush 到磁盘"""
        if not self._dirty or not self._path:
            return

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "a", encoding="utf-8") as f:
            for entry in self._dirty:
                f.write(entry.to_json() + "\n")
        self._dirty.clear()

    def force_flush(self):
        """强制 flush 所有未写入条目"""
        self._flush()

    # ---- 分支回退 ----

    def branch(self, entry_id: str) -> bool:
        """回退到指定 entry，创建新分支（对齐 pi branch()）

        不删除任何 entry，只移动 leafId 指针。
        下一次 append 自然创建新分支。
        """
        if entry_id not in self._by_id:
            logger.error("[session] 分支失败: entry %s 不存在", entry_id)
            return False

        self._leaf_id = entry_id
        logger.info("[session] 分支到: %s", entry_id[:8])
        return True

    # ---- 构建 LLM 上下文 ----

    def build_context(self) -> list[dict[str, str]]:
        """从 leafId 回溯到 root，构建 LLM 消息列表（对齐 pi buildSessionContext）

        从叶节点沿 parentId 链回溯，收集所有消息。
        遇到 compaction 条目时，用其摘要替代更早的历史。
        """
        messages: list[SessionEntry] = []
        seen_compaction = False

        current_id = self._leaf_id
        while current_id and current_id in self._by_id:
            entry = self._by_id[current_id]

            # 遇到 compaction 条目：用摘要替代更早历史
            if entry.role == "compaction":
                messages.append(entry)
                seen_compaction = True
                break

            messages.append(entry)
            current_id = entry.parent_id

        messages.reverse()

        # 转换为 LLM 消息格式
        llm_messages = []
        for entry in messages:
            if entry.role == "system":
                llm_messages.append({"role": "system", "content": entry.content})
            elif entry.role == "user":
                llm_messages.append({"role": "user", "content": entry.content})
            elif entry.role == "assistant":
                msg = {"role": "assistant", "content": entry.content}
                if entry.tool_name:
                    msg["tool_calls"] = [{
                        "id": entry.id,
                        "type": "function",
                        "function": {
                            "name": entry.tool_name,
                            "arguments": json.dumps(entry.tool_args or {}),
                        },
                    }]
                llm_messages.append(msg)
            elif entry.role == "tool":
                llm_messages.append({
                    "role": "tool",
                    "tool_call_id": entry.parent_id or entry.id,
                    "content": json.dumps(entry.tool_result or {"error": entry.content}, ensure_ascii=False),
                })
            elif entry.role == "compaction":
                llm_messages.append({
                    "role": "system",
                    "content": f"[上下文压缩摘要]\n{entry.content}",
                })

        return llm_messages

    # ---- 查询 ----

    def get_entries_by_role(self, role: str) -> list[SessionEntry]:
        """获取指定角色的所有条目（沿当前分支路径）"""
        return [e for e in self._entries if e.role == role]

    def get_tool_results(self) -> list[dict[str, Any]]:
        """获取所有工具执行结果"""
        return [
            {"tool": e.tool_name, "result": e.tool_result, "error": e.is_error}
            for e in self._entries
            if e.role == "tool"
        ]

    def estimate_tokens(self) -> int:
        """估算当前上下文的 token 数"""
        total_chars = sum(len(e.content) for e in self._entries)
        # 粗略估算：1 token ≈ 2 字符（中英混合）
        return total_chars // 2

    def summary(self) -> dict[str, Any]:
        """返回会话统计"""
        return {
            "total_entries": len(self._entries),
            "leaf_id": self._leaf_id,
            "path": str(self._path),
            "estimated_tokens": self.estimate_tokens(),
            "tool_calls": sum(1 for e in self._entries if e.role == "tool"),
        }
