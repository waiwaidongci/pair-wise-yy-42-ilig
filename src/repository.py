from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (BATCH_STATUSES, ID_PREFIX, STATES, TASK_STATUSES)


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
        batch_statuses = ",".join("'" + s + "'" for s in BATCH_STATUSES)
        task_statuses = ",".join("'" + s + "'" for s in TASK_STATUSES)
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
                CREATE TABLE IF NOT EXISTS zones (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    danger_length REAL NOT NULL,
                    wind TEXT,
                    fireline_length REAL,
                    status TEXT NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active','review','closed')),
                    version INTEGER NOT NULL DEFAULT 1,
                    item_id INTEGER REFERENCES items(id) ON DELETE SET NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS observation_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
                    ticket_no TEXT NOT NULL,
                    field_time TEXT NOT NULL,
                    base_version INTEGER,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ({batch_statuses})),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    result TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    applied_at TEXT,
                    UNIQUE(zone_id, ticket_no)
                );
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL
                        REFERENCES observation_batches(id) ON DELETE CASCADE,
                    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
                    field_time TEXT NOT NULL,
                    kind TEXT NOT NULL CHECK(kind IN ('wind','fireline_length','resource')),
                    value TEXT,
                    task_code TEXT,
                    resource_code TEXT,
                    seq INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS field_conflicts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
                    batch_id INTEGER NOT NULL
                        REFERENCES observation_batches(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL CHECK(kind IN ('wind','fireline_length','resource')),
                    task_code TEXT,
                    base_value TEXT,
                    server_value TEXT,
                    observed_value TEXT,
                    resolution TEXT CHECK(resolution IN ('server','field')),
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','resolved')),
                    resolved_by TEXT,
                    resolved_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS permits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
                    status TEXT NOT NULL
                        CHECK(status IN ('proposed','approved','invalidated')),
                    decision TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    based_on_version INTEGER NOT NULL,
                    based_on_wind TEXT,
                    based_on_length REAL,
                    approved_by TEXT,
                    approved_at TEXT,
                    invalidated_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS resource_tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
                    task_code TEXT NOT NULL,
                    resource_code TEXT NOT NULL,
                    permit_id INTEGER REFERENCES permits(id) ON DELETE SET NULL,
                    batch_id INTEGER REFERENCES observation_batches(id) ON DELETE SET NULL,
                    status TEXT NOT NULL CHECK(status IN ({task_statuses})),
                    created_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_task_live
                    ON resource_tasks(zone_id, task_code) WHERE status!='released';
                CREATE UNIQUE INDEX IF NOT EXISTS ux_resource_active
                    ON resource_tasks(resource_code) WHERE status='active';
                CREATE UNIQUE INDEX IF NOT EXISTS ux_resource_proposed
                    ON resource_tasks(resource_code) WHERE status='proposed';
                CREATE TABLE IF NOT EXISTS zone_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(zone_id, seq)
                );
            """)

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

    def _insert_audit(self, conn, action: str, entity_type: str, entity_id: int,
                      actor: str, detail: dict) -> Dict[str, Any]:
        """在给定连接上追加审计事件（可属于调用方已开启的事务）。"""
        row = conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        event["id"] = int(cur.lastrowid)
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._insert_audit(self.conn, action, entity_type, entity_id,
                                      actor, detail)

    def _append_zone_event(self, conn, zone_id: int, version: int, action: str,
                           actor: str, detail: dict) -> Dict[str, Any]:
        """在任务区版本链上追加一个哈希链接事件。"""
        row = conn.execute(
            "SELECT entry_hash, seq FROM zone_events WHERE zone_id=? ORDER BY seq DESC LIMIT 1",
            (zone_id,),
        ).fetchone()
        if row is None:
            previous, seq = f"GENESIS-ZONE-{zone_id}", 1
        else:
            previous, seq = row["entry_hash"], int(row["seq"]) + 1
        from .audit import calculate_hash
        created_at = utc_now()
        payload = {"action": action, "actor": actor, "detail": detail,
                   "created_at": created_at}
        entry_hash = calculate_hash(previous, payload)
        cur = conn.execute(
            """INSERT INTO zone_events(zone_id, seq, version, action, actor, detail,
               previous_hash, entry_hash, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (zone_id, seq, version, action, actor,
             json.dumps(detail, ensure_ascii=False, sort_keys=True),
             previous, entry_hash, created_at),
        )
        return {"id": int(cur.lastrowid), "zone_id": zone_id, "seq": seq,
                "version": version, "action": action, "actor": actor,
                "detail": detail, "previous_hash": previous, "entry_hash": entry_hash,
                "created_at": created_at}

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

    def verify_zone_chain(self, zone_id: int) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM zone_events WHERE zone_id=? ORDER BY seq", (zone_id,)
            ).fetchall()
        previous = f"GENESIS-ZONE-{zone_id}"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    # ------------------------------------------------------------------
    # 任务区 / 离线观测批次 / 处置许可
    # ------------------------------------------------------------------
    @staticmethod
    def _zone(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_zone(self, name: str, danger_length: float, wind: Optional[str],
                    fireline_length: Optional[float], item_id: Optional[int],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            if item_id is not None:
                if self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone() is None:
                    raise NotFoundError("关联项目不存在")
            cur = self.conn.execute(
                """INSERT INTO zones(name, danger_length, wind, fireline_length, status,
                   version, item_id, created_by, created_at, updated_at)
                   VALUES(?,?,?,?,'active',1,?,?,?,?)""",
                (name, danger_length, wind, fireline_length, item_id, actor, now, now),
            )
            zone_id = int(cur.lastrowid)
            self._append_zone_event(self.conn, zone_id, 1, "zone_created", actor, {
                "name": name, "danger_length": danger_length, "wind": wind,
                "fireline_length": fireline_length, "item_id": item_id,
            })
            self._insert_audit(self.conn, "zone_created", "zone", zone_id, actor, {
                "name": name, "danger_length": danger_length,
            })
        return self.get_zone(zone_id)

    def get_zone(self, zone_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if row is None:
            raise NotFoundError("任务区不存在")
        return self._zone(row)

    def list_zones(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM zones ORDER BY id DESC").fetchall()
        return [self._zone(row) for row in rows]

    def list_zone_events(self, zone_id: int) -> List[Dict[str, Any]]:
        self.get_zone(zone_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM zone_events WHERE zone_id=? ORDER BY seq", (zone_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def merge_snapshots(self, conn, zone_id: int, base_version: int):
        """在调用方事务连接上读取基线与当前版本快照（保证与写入同一事务、同一版本）。"""
        zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
        if zone is None:
            raise NotFoundError("任务区不存在")
        current_version = int(zone["version"])
        if base_version > current_version:
            raise ConflictError(
                f"基线版本{base_version}超前于当前版本{current_version}，无法合并")
        base_snapshot = self.snapshot_at(conn, zone_id, base_version)
        current_snapshot = self.snapshot_at(conn, zone_id, current_version)
        return base_snapshot, current_snapshot, current_version, dict(zone)

    def snapshot_at(self, conn, zone_id: int, version: int) -> Dict[str, Any]:
        """从任务区版本链重建指定版本的状态快照（风向/火线长度/资源任务）。
        链内每个状态变更事件都带应用后的 state_after，故按序回放即可。"""
        if conn.execute("SELECT 1 FROM zones WHERE id=?", (zone_id,)).fetchone() is None:
            raise NotFoundError("任务区不存在")
        wind, length, tasks = None, None, {}
        rows = conn.execute(
            "SELECT action, detail FROM zone_events WHERE zone_id=? AND version<=? ORDER BY seq",
            (zone_id, version),
        ).fetchall()
        for row in rows:
            detail = json.loads(row["detail"])
            if row["action"] == "zone_created":
                wind, length, tasks = detail.get("wind"), detail.get("fireline_length"), {}
            state = detail.get("state_after")
            if state is not None:
                wind = state.get("wind", wind)
                length = state.get("fireline_length", length)
                tasks = dict(state.get("tasks", {}))
        return {"wind": wind, "fireline_length": length, "tasks": tasks}

    def queue_batch(self, zone_id: int, ticket_no: str, field_time: str,
                    base_version: Optional[int], payload: str, actor: str) -> Dict[str, Any]:
        """整批先落库为 queued：之后失败只改状态，观测在应用时同事务写入，
        因此任何失败都不会留下半条观测。"""
        now = utc_now()
        with self._lock, self.conn:
            if self.conn.execute("SELECT 1 FROM zones WHERE id=?", (zone_id,)).fetchone() is None:
                raise NotFoundError("任务区不存在")
            try:
                cur = self.conn.execute(
                    """INSERT INTO observation_batches(zone_id, ticket_no, field_time,
                       base_version, payload, status, attempts, created_by, created_at)
                       VALUES(?,?,?,?,?,'queued',0,?,?)""",
                    (zone_id, ticket_no, field_time, base_version, payload, actor, now),
                )
                batch_id = int(cur.lastrowid)
            except sqlite3.IntegrityError as exc:
                raise ConflictError("现场单号已存在") from exc
        return self.get_batch(zone_id, ticket_no)

    def get_batch(self, zone_id: int, ticket_no: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM observation_batches WHERE zone_id=? AND ticket_no=?",
                (zone_id, ticket_no),
            ).fetchone()
        if row is None:
            raise NotFoundError("观测批次不存在")
        return self._batch(row)

    def get_batch_by_id(self, batch_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM observation_batches WHERE id=?", (batch_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("观测批次不存在")
        return self._batch(row)

    @staticmethod
    def _batch(row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        if item.get("result"):
            item["result"] = json.loads(item["result"])
        if item.get("last_error"):
            item["last_error"] = json.loads(item["last_error"])
        return item

    def list_batches(self, zone_id: int, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self.get_zone(zone_id)
        sql = "SELECT * FROM observation_batches WHERE zone_id=?"
        params: tuple = (zone_id,)
        if status:
            sql += " AND status=?"
            params = (zone_id, status)
        sql += " ORDER BY field_time, id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._batch(row) for row in rows]

    def list_observations(self, zone_id: int, batch_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM observations WHERE zone_id=? AND batch_id=? ORDER BY seq",
                (zone_id, batch_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_batch_failed(self, batch_id: int, error: dict) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE observation_batches SET status='failed', attempts=attempts+1,
                   last_error=? WHERE id=?""",
                (json.dumps(error, ensure_ascii=False), batch_id),
            )

    def pending_batches_ordered(self, zone_id: int) -> List[Dict[str, Any]]:
        """断网恢复：按现场时刻排序取出所有未应用批次（queued 与失败待重试）。"""
        with self._lock:
            rows = self.conn.execute(
                """SELECT * FROM observation_batches WHERE zone_id=? AND status!='applied'
                   ORDER BY field_time, id""",
                (zone_id,),
            ).fetchall()
        return [self._batch(row) for row in rows]

    def active_permit(self, conn, zone_id: int) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM permits WHERE zone_id=? AND status='approved' ORDER BY id DESC LIMIT 1",
            (zone_id,),
        ).fetchone()

    def latest_permit(self, conn, zone_id: int) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM permits WHERE zone_id=? ORDER BY id DESC LIMIT 1", (zone_id,)
        ).fetchone()

    def current_tasks(self, conn, zone_id: int) -> Dict[str, Any]:
        """任务编码 -> 行（仅活动/拟议占用）。"""
        rows = conn.execute(
            "SELECT * FROM resource_tasks WHERE zone_id=? AND status!='released'",
            (zone_id,),
        ).fetchall()
        return {row["task_code"]: dict(row) for row in rows}

    def apply_batch(self, batch_id: int, base_version: int, folded: dict,
                    actor: str) -> Dict[str, Any]:
        """把一个批次整体写入：快照读取、三方合并、跨区预检、观测、冲突、许可
        失效/重算、资源占用调整与版本链事件全部在同一个事务内提交，要么全成
        要么整批保留，不留下半条观测。"""
        from .rules import three_way_merge, disposal_decision
        now = utc_now()
        with self._lock, self.conn:
            conn = self.conn
            batch = conn.execute(
                "SELECT * FROM observation_batches WHERE id=?", (batch_id,)
            ).fetchone()
            if batch is None:
                raise NotFoundError("观测批次不存在")
            zone_id = int(batch["zone_id"])

            # 0) 同一事务内取基线/当前快照并做三方合并
            base_snapshot, current_snapshot, old_version, zonerow = \
                self.merge_snapshots(conn, zone_id, base_version)
            scalars, task_changes, conflicts = three_way_merge(
                base_snapshot, current_snapshot, folded)
            new_version = old_version + 1
            danger_length = zonerow["danger_length"]

            # 跨任务区预检：同一资源不能同时占用多个活动/拟议任务
            for task_code, resource_code in task_changes.items():
                if resource_code is None:
                    continue
                hit = conn.execute(
                    """SELECT z.id AS zone_id FROM resource_tasks rt JOIN zones z
                       ON z.id=rt.zone_id
                       WHERE rt.resource_code=? AND rt.zone_id!=?
                       AND rt.status!='released' LIMIT 1""",
                    (resource_code, zone_id),
                ).fetchone()
                if hit is not None:
                    raise ConflictError(
                        f"资源{resource_code}已被任务区{hit['zone_id']}的活动任务占用")

            # 风向或火线长度变化即触发原许可失效与按新值重算
            invalidate = bool(scalars.get("wind") is not None
                              or scalars.get("fireline_length") is not None)
            wind = scalars.get("wind", zonerow["wind"])
            length = scalars.get("fireline_length", zonerow["fireline_length"])
            decision = disposal_decision(wind, length, danger_length)

            # 1) 观测明细（先于状态翻转写入；事务失败则整批回滚，不留半条观测）
            payload = json.loads(batch["payload"])
            for seq, obs in enumerate(payload.get("observations", [])):
                conn.execute(
                    """INSERT INTO observations(batch_id, zone_id, field_time, kind, value,
                       task_code, resource_code, seq) VALUES(?,?,?,?,?,?,?,?)""",
                    (batch_id, zone_id, obs.get("field_time") or batch["field_time"],
                     obs["kind"],
                     str(obs["value"]) if obs["kind"] != "resource" else None,
                     obs.get("task_code"), obs.get("resource_code"), seq),
                )

            # 2) 两边都改过的字段：保留两份待复核
            conflict_ids = []
            for c in conflicts:
                cur = conn.execute(
                    """INSERT INTO field_conflicts(zone_id, batch_id, kind, task_code,
                       base_value, server_value, observed_value, status, created_at)
                       VALUES(?,?,?,?,?,?,?,'pending',?)""",
                    (zone_id, batch_id, c["kind"], c.get("task_code"),
                     None if c.get("base") is None else str(c["base"]),
                     None if c.get("server") is None else str(c["server"]),
                     None if c.get("observed") is None else str(c["observed"]), now),
                )
                conflict_ids.append(int(cur.lastrowid))

            # 3) 风向/火线长度变化：原许可立即失效、占用立即释放
            permit = self.latest_permit(conn, zone_id)
            approved = self.active_permit(conn, zone_id)
            permit_id: Optional[int] = permit["id"] if permit else None
            if invalidate and approved is not None:
                conn.execute(
                    "UPDATE permits SET status='invalidated', invalidated_at=? WHERE id=?",
                    (now, approved["id"]),
                )
                conn.execute(
                    "UPDATE resource_tasks SET status='released' WHERE zone_id=? AND status='active'",
                    (zone_id,),
                )
                permit_id = None
                self._append_zone_event(conn, zone_id, new_version, "permit_invalidated", actor, {
                    "permit_id": approved["id"], "batch_id": batch_id,
                    "reason": "风向或火线长度发生变化",
                    "wind": wind, "fireline_length": length,
                })
                self._insert_audit(conn, "permit_invalidated", "zone", zone_id, actor, {
                    "permit_id": approved["id"], "batch_id": batch_id,
                })

            # 4) 资源任务变更：释放被替换/撤销的占用，写入新的拟议占用
            current = self.current_tasks(conn, zone_id)
            proposed_permit_for_tasks = permit_id
            if invalidate:
                # 随新提案重建整套目标任务
                target = {code: res for code, res in task_changes.items() if res is not None}
            else:
                target = {code: (row["resource_code"]) for code, row in current.items()}
                for code, res in task_changes.items():
                    if res is None:
                        target.pop(code, None)
                    else:
                        target[code] = res
            changed_codes = set(task_changes)
            if invalidate:
                changed_codes = set(target)
            for code in changed_codes:
                res = target.get(code)
                existing = current.get(code)
                if existing is not None:
                    conn.execute(
                        "UPDATE resource_tasks SET status='released' WHERE id=?",
                        (existing["id"],),
                    )
                if res is not None:
                    try:
                        conn.execute(
                            """INSERT INTO resource_tasks(zone_id, task_code, resource_code,
                               permit_id, batch_id, status, created_at)
                               VALUES(?,?,?,?,?,'proposed',?)""",
                            (zone_id, code, res,
                             proposed_permit_for_tasks if not invalidate else None,
                             batch_id, now),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise ConflictError(
                            f"资源{res}已被其他活动任务占用") from exc

            # 5) 许可提案：风向/长度变化必按新值重算；若任务区此前没有任何许可
            # （例如首批只有资源观测），也建立一个反映当前判定的提案。
            need_proposal = invalidate or permit is None
            if need_proposal:
                cur = conn.execute(
                    """INSERT INTO permits(zone_id, status, decision, reasons,
                       based_on_version, based_on_wind, based_on_length, created_at)
                       VALUES(?, 'proposed', ?, ?, ?, ?, ?, ?)""",
                    (zone_id, "approve" if decision["can_approve"] else "deny",
                     json.dumps(decision["reasons"], ensure_ascii=False),
                     new_version, wind, length, now),
                )
                permit_id = int(cur.lastrowid)
                conn.execute(
                    "UPDATE resource_tasks SET permit_id=? WHERE zone_id=? AND status='proposed'",
                    (permit_id, zone_id),
                )
                self._append_zone_event(conn, zone_id, new_version, "permit_proposed", actor, {
                    "permit_id": permit_id, "batch_id": batch_id,
                    "decision": decision, "wind": wind, "fireline_length": length,
                })
                self._insert_audit(conn, "permit_proposed", "zone", zone_id, actor, {
                    "permit_id": permit_id, "batch_id": batch_id,
                    "can_approve": decision["can_approve"],
                })

            # 6) 冲突登记与任务区状态（有待复核冲突时进入 review）
            pending_n = int(conn.execute(
                "SELECT COUNT(*) AS n FROM field_conflicts WHERE zone_id=? AND status='pending'",
                (zone_id,),
            ).fetchone()["n"])
            zone_status = "review" if pending_n > 0 else "active"
            conn.execute(
                """UPDATE zones SET wind=?, fireline_length=?, status=?, version=?, updated_at=?
                   WHERE id=?""",
                (wind, length, zone_status, new_version, now, zone_id),
            )
            state_after = {"wind": wind, "fireline_length": length, "tasks": target}
            self._append_zone_event(conn, zone_id, new_version, "batch_applied", actor, {
                "batch_id": batch_id, "ticket_no": batch["ticket_no"],
                "field_time": batch["field_time"], "base_version": batch["base_version"],
                "scalars": scalars, "task_changes": task_changes,
                "conflict_ids": conflict_ids, "invalidate_permit": invalidate,
                "state_after": state_after,
            })
            self._insert_audit(conn, "batch_applied", "zone", zone_id, actor, {
                "batch_id": batch_id, "ticket_no": batch["ticket_no"],
                "conflicts": len(conflict_ids),
            })

            # 7) 批次标记为已应用，固化首次结果供同号重放沿用
            result = {"batch_id": batch_id, "zone_id": zone_id, "version": new_version,
                      "status": "applied", "conflict_ids": conflict_ids,
                      "permit_id": permit_id, "decision": decision if invalidate else None,
                      "state_after": state_after}
            conn.execute(
                """UPDATE observation_batches SET status='applied', attempts=attempts+1,
                   result=?, applied_at=?, last_error=NULL WHERE id=?""",
                (json.dumps(result, ensure_ascii=False), now, batch_id),
            )
            return result

    def list_conflicts(self, zone_id: int, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self.get_zone(zone_id)
        sql = "SELECT * FROM field_conflicts WHERE zone_id=?"
        params: tuple = (zone_id,)
        if status:
            sql += " AND status=?"
            params = (zone_id, status)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def resolve_conflict(self, conflict_id: int, resolution: str, actor: str) -> Dict[str, Any]:
        """复核裁决：选用服务器值或现场值。冲突清空后按当前值重算许可提案。"""
        now = utc_now()
        with self._lock, self.conn:
            conn = self.conn
            row = conn.execute(
                "SELECT * FROM field_conflicts WHERE id=?", (conflict_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("冲突不存在")
            if row["status"] == "resolved":
                raise ConflictError("该冲突已复核")
            zone_id = int(row["zone_id"])
            zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
            new_version = int(zone["version"]) + 1

            chosen_server = resolution == "server"
            if row["kind"] == "resource":
                chosen = row["server_value"] if chosen_server else row["observed_value"]
                current = self.current_tasks(conn, zone_id)
                existing = current.get(row["task_code"])
                if existing is not None:
                    conn.execute(
                        "UPDATE resource_tasks SET status='released' WHERE id=?",
                        (existing["id"],),
                    )
                if chosen is not None:
                    permit = self.latest_permit(conn, zone_id)
                    try:
                        conn.execute(
                            """INSERT INTO resource_tasks(zone_id, task_code, resource_code,
                               permit_id, status, created_at) VALUES(?,?,?,?, 'proposed', ?)""",
                            (zone_id, row["task_code"], chosen,
                             permit["id"] if permit else None, now),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise ConflictError(f"资源{chosen}已被其他活动任务占用") from exc
                new_value = chosen
            else:
                new_value = row["server_value"] if chosen_server else row["observed_value"]
                column = "wind" if row["kind"] == "wind" else "fireline_length"
                if column == "fireline_length" and new_value is not None:
                    new_value = float(new_value)
                conn.execute(
                    f"UPDATE zones SET {column}=?, version=version+1, updated_at=? WHERE id=?",
                    (new_value, now, zone_id),
                )

            conn.execute(
                """UPDATE field_conflicts SET status='resolved', resolution=?,
                   resolved_by=?, resolved_at=? WHERE id=?""",
                (resolution, actor, now, conflict_id),
            )
            pending_n = int(conn.execute(
                "SELECT COUNT(*) AS n FROM field_conflicts WHERE zone_id=? AND status='pending'",
                (zone_id,),
            ).fetchone()["n"])

            tasks = {code: (r["resource_code"])
                     for code, r in self.current_tasks(conn, zone_id).items()}
            zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
            # 复核期间不允许放行：按复核后的当前值重新计算许可提案
            from .rules import disposal_decision
            decision = disposal_decision(zone["wind"], zone["fireline_length"],
                                         zone["danger_length"])
            approved = self.active_permit(conn, zone_id)
            if approved is not None:
                conn.execute(
                    "UPDATE permits SET status='invalidated', invalidated_at=? WHERE id=?",
                    (now, approved["id"]),
                )
                conn.execute(
                    "UPDATE resource_tasks SET status='released' WHERE zone_id=? AND status='active'",
                    (zone_id,),
                )
            cur = conn.execute(
                """INSERT INTO permits(zone_id, status, decision, reasons, based_on_version,
                   based_on_wind, based_on_length, created_at)
                   VALUES(?, 'proposed', ?, ?, ?, ?, ?, ?)""",
                (zone_id, "approve" if decision["can_approve"] else "deny",
                 json.dumps(decision["reasons"], ensure_ascii=False),
                 new_version, zone["wind"], zone["fireline_length"], now),
            )
            permit_id = int(cur.lastrowid)
            conn.execute(
                "UPDATE resource_tasks SET permit_id=? WHERE zone_id=? AND status='proposed'",
                (permit_id, zone_id),
            )
            zone_status = "review" if pending_n > 0 else "active"
            conn.execute(
                "UPDATE zones SET status=?, updated_at=? WHERE id=?",
                (zone_status, now, zone_id),
            )
            self._append_zone_event(conn, zone_id, new_version, "conflict_resolved", actor, {
                "conflict_id": conflict_id, "kind": row["kind"],
                "task_code": row["task_code"], "resolution": resolution,
                "chosen_value": new_value, "pending": pending_n,
                "decision": decision,
                "state_after": {"wind": zone["wind"],
                                "fireline_length": zone["fireline_length"], "tasks": tasks},
            })
            self._insert_audit(conn, "conflict_resolved", "zone", zone_id, actor, {
                "conflict_id": conflict_id, "resolution": resolution,
            })
            return {"conflict_id": conflict_id, "zone_id": zone_id,
                    "version": new_version, "pending": pending_n,
                    "permit_id": permit_id, "decision": decision,
                    "zone_status": zone_status}

    def get_permit(self, permit_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM permits WHERE id=?", (permit_id,)).fetchone()
        if row is None:
            raise NotFoundError("许可不存在")
        item = dict(row)
        item["reasons"] = json.loads(item["reasons"])
        return item

    def list_permits(self, zone_id: int) -> List[Dict[str, Any]]:
        self.get_zone(zone_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM permits WHERE zone_id=? ORDER BY id", (zone_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["reasons"] = json.loads(item["reasons"])
            result.append(item)
        return result

    def approve_permit(self, permit_id: int, expected_version: int,
                       actor: str) -> Dict[str, Any]:
        """放行处置许可：复核前（zone 处于 review 或版本不匹配）一律挡住。"""
        now = utc_now()
        with self._lock, self.conn:
            conn = self.conn
            row = conn.execute("SELECT * FROM permits WHERE id=?", (permit_id,)).fetchone()
            if row is None:
                raise NotFoundError("许可不存在")
            zone_id = int(row["zone_id"])
            zone = conn.execute("SELECT * FROM zones WHERE id=?", (zone_id,)).fetchone()
            if int(zone["version"]) != expected_version:
                raise ConflictError("版本冲突，请刷新后重试")
            if zone["status"] == "review":
                raise ConflictError("仍有火线/资源冲突待复核，暂不能放行")
            if row["status"] == "invalidated":
                raise ConflictError("许可已因观测变化失效，请使用最新提案")
            if row["status"] == "approved":
                raise ConflictError("许可已经放行")
            if row["decision"] != "approve":
                raise ConflictError("当前风向或火线长度不满足放行条件："
                                    + "；".join(json.loads(row["reasons"])))
            # 占用激活：跨任务区资源重复占用由唯一索引兜底
            try:
                conn.execute(
                    "UPDATE resource_tasks SET status='active' WHERE permit_id=? AND status='proposed'",
                    (permit_id,),
                )
                conn.execute(
                    """UPDATE permits SET status='approved', approved_by=?, approved_at=?
                       WHERE id=?""",
                    (actor, now, permit_id),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("存在资源同时占用多个活动任务") from exc
            # 放行不改变任务区状态，版本号不递增（版本只随批次应用/复核推进）；
            # 但放行仍写入版本链与审计，且必须匹配当前版本。
            current_version = int(zone["version"])
            conn.execute("UPDATE zones SET updated_at=? WHERE id=?", (now, zone_id))
            self._append_zone_event(conn, zone_id, current_version, "permit_approved", actor, {
                "permit_id": permit_id, "expected_version": expected_version,
            })
            self._insert_audit(conn, "permit_approved", "zone", zone_id, actor, {
                "permit_id": permit_id,
            })
            return {"permit_id": permit_id, "zone_id": zone_id,
                    "version": current_version, "status": "approved"}

    def close(self) -> None:
        with self._lock:
            self.conn.close()
