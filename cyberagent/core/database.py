"""SQLite 数据库层，存储侦察结果"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberagent.core.config import get_settings

logger = logging.getLogger(__name__)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL DEFAULT 'pending',
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    subdomain TEXT NOT NULL,
    ip TEXT,
    http_status INTEGER,
    title TEXT,
    tech_stack TEXT DEFAULT '[]',
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    UNIQUE(target_id, subdomain)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT,
    service TEXT,
    version TEXT,
    banner TEXT,
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id),
    UNIQUE(target_id, host, port)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    severity TEXT NOT NULL DEFAULT 'info',
    evidence TEXT,
    raw_data TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS recon_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    stage TEXT NOT NULL,
    tool TEXT NOT NULL,
    raw_output TEXT,
    parsed_data TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
"""


class Database:
    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            db_path = get_settings().db_full_path
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def connect(self):
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA_SQL)
        logger.info("数据库已连接: %s", self.db_path)

    def close(self):
        if self._conn:
            self._conn.close()

    def _ensure_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        return self._conn  # type: ignore

    # ---- Target 管理 ----

    def get_or_create_target(self, domain: str) -> int:
        conn = self._ensure_conn()
        row = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
        if row:
            return row["id"]
        cur = conn.execute("INSERT INTO targets (domain) VALUES (?)", (domain,))
        conn.commit()
        return cur.lastrowid  # type: ignore

    def update_target_status(self, target_id: int, status: str):
        conn = self._ensure_conn()
        conn.execute(
            "UPDATE targets SET status = ? WHERE id = ?", (status, target_id)
        )
        conn.commit()

    # ---- 子域名 ----

    def insert_subdomain(self, target_id: int, subdomain: str, ip: str = ""):
        conn = self._ensure_conn()
        conn.execute(
            "INSERT OR IGNORE INTO subdomains (target_id, subdomain, ip) VALUES (?, ?, ?)",
            (target_id, subdomain, ip),
        )
        conn.commit()

    def insert_subdomains(self, target_id: int, subs: list[dict[str, Any]]):
        conn = self._ensure_conn()
        conn.executemany(
            "INSERT OR IGNORE INTO subdomains (target_id, subdomain, ip) VALUES (?, ?, ?)",
            [(target_id, s.get("subdomain", ""), s.get("ip", "")) for s in subs],
        )
        conn.commit()

    def update_subdomain_http(self, subdomain: str, status: int, title: str, tech: list[str]):
        conn = self._ensure_conn()
        conn.execute(
            "UPDATE subdomains SET http_status = ?, title = ?, tech_stack = ? WHERE subdomain = ?",
            (status, title, json.dumps(tech), subdomain),
        )
        conn.commit()

    def get_subdomains(self, target_id: int) -> list[dict]:
        conn = self._ensure_conn()
        rows = conn.execute(
            "SELECT * FROM subdomains WHERE target_id = ?", (target_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- 端口 ----

    def insert_port(self, target_id: int, host: str, port: int, protocol: str = "tcp",
                    service: str = "", version: str = "", banner: str = ""):
        conn = self._ensure_conn()
        conn.execute(
            """INSERT OR IGNORE INTO ports
               (target_id, host, port, protocol, service, version, banner)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (target_id, host, port, protocol, service, version, banner),
        )
        conn.commit()

    def get_ports(self, target_id: int) -> list[dict]:
        conn = self._ensure_conn()
        rows = conn.execute(
            "SELECT * FROM ports WHERE target_id = ?", (target_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- Findings ----

    def insert_finding(self, target_id: int, category: str, title: str,
                       detail: str = "", severity: str = "info", evidence: str = ""):
        conn = self._ensure_conn()
        conn.execute(
            """INSERT INTO findings (target_id, category, title, detail, severity, evidence)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (target_id, category, title, detail, severity, evidence),
        )
        conn.commit()

    def get_findings(self, target_id: int) -> list[dict]:
        conn = self._ensure_conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE target_id = ?", (target_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- 原始结果 ----

    def insert_recon_result(self, target_id: int, stage: str, tool: str,
                            raw_output: str, parsed_data: Any = None):
        conn = self._ensure_conn()
        conn.execute(
            """INSERT INTO recon_results (target_id, stage, tool, raw_output, parsed_data)
               VALUES (?, ?, ?, ?, ?)""",
            (target_id, stage, tool, raw_output,
             json.dumps(parsed_data, ensure_ascii=False) if parsed_data else None),
        )
        conn.commit()
