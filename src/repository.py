from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS observation_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_no TEXT NOT NULL UNIQUE,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','applied','failed','review')),
                    observations TEXT NOT NULL,
                    result TEXT,
                    error TEXT,
                    actor TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    applied_at TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    reviewed_by TEXT,
                    reviewed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS permits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','invalid','released')),
                    basis_version INTEGER NOT NULL,
                    wind_direction TEXT,
                    fire_line_length REAL,
                    conditions TEXT NOT NULL,
                    issued_by TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    invalidated_at TEXT,
                    reviewed INTEGER NOT NULL DEFAULT 0,
                    reviewed_by TEXT,
                    reviewed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS resource_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    resource TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'assigned'
                        CHECK(status IN ('assigned','released')),
                    updated_at TEXT NOT NULL,
                    UNIQUE(item_id, resource)
                );
                CREATE TABLE IF NOT EXISTS resource_occupations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    resource TEXT NOT NULL,
                    permit_id INTEGER REFERENCES permits(id) ON DELETE SET NULL,
                    status TEXT NOT NULL DEFAULT 'occupied'
                        CHECK(status IN ('occupied','released')),
                    occupied_at TEXT NOT NULL,
                    released_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_occupations_resource_active
                    ON resource_occupations(resource) WHERE status='occupied';
            """)
        self._ensure_columns()

    def _ensure_columns(self) -> None:
        """为旧库补充任务区版本链所需列。"""
        existing = {row[1] for row in self.conn.execute("PRAGMA table_info(items)").fetchall()}
        with self.conn:
            if "wind_direction" not in existing:
                self.conn.execute("ALTER TABLE items ADD COLUMN wind_direction TEXT")
            if "review_pending" not in existing:
                self.conn.execute(
                    "ALTER TABLE items ADD COLUMN review_pending INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # ------------------------------------------------------------------
    # 观测批次（批次存储）
    # ------------------------------------------------------------------
    @staticmethod
    def _batch(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        if data.get("observations"):
            data["observations"] = json.loads(data["observations"])
        if data.get("result"):
            data["result"] = json.loads(data["result"])
        return data

    def history_observations(self, item_id: int) -> List[Dict[str, Any]]:
        """已应用批次中的全部观测，作为在线一侧历史。"""
        with self._lock:
            rows = self.conn.execute(
                "SELECT observations FROM observation_batches "
                "WHERE item_id=? AND status='applied' ORDER BY id",
                (item_id,),
            ).fetchall()
        history: List[Dict[str, Any]] = []
        for row in rows:
            history.extend(json.loads(row["observations"]))
        return history

    def get_batch_by_ticket(self, ticket_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM observation_batches WHERE ticket_no=?", (ticket_no,)
            ).fetchone()
        return self._batch(row) if row else None

    def get_batch(self, batch_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM observation_batches WHERE id=?", (batch_id,)
            ).fetchone()
        return self._batch(row) if row else None

    def create_batch(self, ticket_no: str, item_id: int,
                     observations: List[Dict[str, Any]], actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO observation_batches
                   (ticket_no, item_id, status, observations, actor, created_at, attempts)
                   VALUES(?,?,?,?,?,?,0)""",
                (ticket_no, item_id, "pending", json.dumps(observations, ensure_ascii=False),
                 actor, now),
            )
            batch_id = int(cur.lastrowid)
        return self.get_batch(batch_id)  # type: ignore[return-value]

    def list_batches(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM observation_batches WHERE item_id=? ORDER BY id",
                (item_id,),
            ).fetchall()
        return [self._batch(row) for row in rows]

    def mark_batch_failed(self, batch_id: int, error: str) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE observation_batches SET status='failed', error=?, "
                "attempts=attempts+1 WHERE id=?",
                (error[:500], batch_id),
            )

    def apply_batch_transaction(self, batch_id: int, item_id: int,
                                plan: Dict[str, Any]) -> Dict[str, Any]:
        """整批应用：在一个事务内更新任务区版本、批次结果、许可与占用。

        失败则整批回滚，不留下半条观测。plan 由 Service 依据判定规则生成。
        """
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE items SET wind_direction=?, quantity=COALESCE(?, quantity),
                   review_pending=?, version=version+1, updated_at=? WHERE id=?""",
                (plan.get("wind_direction"), plan.get("fire_line_length"),
                 1 if plan.get("review_pending") else 0, now, item_id),
            )
            self.conn.execute(
                """UPDATE observation_batches SET status=?, result=?, error=NULL,
                   applied_at=?, attempts=attempts+1 WHERE id=?""",
                (plan["batch_status"], json.dumps(plan["result"], ensure_ascii=False),
                 now, batch_id),
            )
            if plan.get("invalidate"):
                self.conn.execute(
                    "UPDATE permits SET status='invalid', invalidated_at=? "
                    "WHERE item_id=? AND status='active'",
                    (now, item_id),
                )
                self.conn.execute(
                    "UPDATE resource_occupations SET status='released', released_at=? "
                    "WHERE item_id=? AND status='occupied'",
                    (now, item_id),
                )
            self._apply_resources(item_id, plan.get("resources", {}),
                                  plan.get("invalidate", False), now)
        return self.get_batch(batch_id)  # type: ignore[return-value]

    def review_batch_transaction(self, batch_id: int, item_id: int,
                                 plan: Dict[str, Any], reviewer: str) -> Dict[str, Any]:
        """复核后按选定值落定合并结果，同样在一个事务内完成。"""
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE items SET wind_direction=?, quantity=COALESCE(?, quantity),
                   review_pending=0, version=version+1, updated_at=? WHERE id=?""",
                (plan.get("wind_direction"), plan.get("fire_line_length"), now, item_id),
            )
            self.conn.execute(
                """UPDATE observation_batches SET status='applied', result=?, error=NULL,
                   applied_at=?, reviewed_by=?, reviewed_at=? WHERE id=?""",
                (json.dumps(plan["result"], ensure_ascii=False), now, reviewer, now, batch_id),
            )
            self.conn.execute(
                "UPDATE permits SET status='invalid', invalidated_at=? "
                "WHERE item_id=? AND status='active'",
                (now, item_id),
            )
            self.conn.execute(
                "UPDATE resource_occupations SET status='released', released_at=? "
                "WHERE item_id=? AND status='occupied'",
                (now, item_id),
            )
            self._apply_resources(item_id, plan.get("resources", {}), True, now)
        return self.get_batch(batch_id)  # type: ignore[return-value]

    def _apply_resources(self, item_id: int, resources: Dict[str, str],
                         invalidated: bool, now: str) -> None:
        """更新资源编入/撤出状态，并联动占用。须在事务内调用。"""
        active = self.conn.execute(
            "SELECT id FROM permits WHERE item_id=? AND status='active' LIMIT 1",
            (item_id,),
        ).fetchone()
        for resource, action in resources.items():
            status = "assigned" if action == "assign" else "released"
            self.conn.execute(
                """INSERT INTO resource_assignments(item_id, resource, status, updated_at)
                   VALUES(?,?,?,?)
                   ON CONFLICT(item_id, resource) DO UPDATE SET status=excluded.status,
                   updated_at=excluded.updated_at""",
                (item_id, resource, status, now),
            )
            if action == "assign" and active is not None and not invalidated:
                self.conn.execute(
                    """INSERT INTO resource_occupations(item_id, resource, permit_id,
                       status, occupied_at)
                       SELECT ?,?,?,?,'occupied'
                       WHERE NOT EXISTS(
                           SELECT 1 FROM resource_occupations
                           WHERE resource=? AND status='occupied')""",
                    (item_id, resource, active["id"], now, resource),
                )
            elif action == "release":
                self.conn.execute(
                    "UPDATE resource_occupations SET status='released', released_at=? "
                    "WHERE item_id=? AND resource=? AND status='occupied'",
                    (now, item_id, resource),
                )

    # ------------------------------------------------------------------
    # 处置许可
    # ------------------------------------------------------------------
    def get_active_permit(self, item_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM permits WHERE item_id=? AND status='active' "
                "ORDER BY id DESC LIMIT 1",
                (item_id,),
            ).fetchone()
        return self._permit(row) if row else None

    def get_permit(self, permit_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM permits WHERE id=?", (permit_id,)).fetchone()
        return self._permit(row) if row else None

    @staticmethod
    def _permit(row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        if data.get("conditions"):
            data["conditions"] = json.loads(data["conditions"])
        return data

    def create_permit(self, item_id: int, basis_version: int, wind_direction: Optional[str],
                      fire_line_length: Optional[float], conditions: Dict[str, Any],
                      actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO permits(item_id, status, basis_version, wind_direction,
                   fire_line_length, conditions, issued_by, issued_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (item_id, "active", basis_version, wind_direction, fire_line_length,
                 json.dumps(conditions, ensure_ascii=False), actor, now),
            )
            permit_id = int(cur.lastrowid)
            assignments = self.conn.execute(
                "SELECT resource FROM resource_assignments "
                "WHERE item_id=? AND status='assigned'",
                (item_id,),
            ).fetchall()
            for row in assignments:
                self.conn.execute(
                    """INSERT INTO resource_occupations(item_id, resource, permit_id,
                       status, occupied_at)
                       SELECT ?,?,?,'occupied',?
                       WHERE NOT EXISTS(
                           SELECT 1 FROM resource_occupations
                           WHERE resource=? AND status='occupied')""",
                    (item_id, row["resource"], permit_id, now, row["resource"]),
                )
        return self.get_permit(permit_id)  # type: ignore[return-value]

    def list_permits(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM permits WHERE item_id=? ORDER BY id DESC", (item_id,)
            ).fetchall()
        return [self._permit(row) for row in rows]

    def release_permit(self, permit_id: int) -> Optional[Dict[str, Any]]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE permits SET status='released' WHERE id=? AND status='active'",
                (permit_id,),
            )
            if cur.rowcount == 0:
                return None
            self.conn.execute(
                "UPDATE resource_occupations SET status='released', released_at=? "
                "WHERE permit_id=? AND status='occupied'",
                (now, permit_id),
            )
        return self.get_permit(permit_id)

    def list_assignments(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT resource, status FROM resource_assignments WHERE item_id=?",
                (item_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_occupations(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT resource, status, permit_id FROM resource_occupations "
                "WHERE item_id=? ORDER BY id",
                (item_id,),
            ).fetchall()
        return [dict(row) for row in rows]
