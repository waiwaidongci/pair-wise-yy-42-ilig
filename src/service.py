from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from .domain import (ConflictError, DomainError, NotFoundError, ValidationError,
                     ensure_role, normalize_severity, require_list, require_number,
                     require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, OBS_RESOURCE, OBS_WIND,
                    OBSERVATION_KINDS, RECORD_ROLES, SAFE_WINDS, VIEW_ROLES,
                    completion_blockers, escalation_required, fold_observations,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)

ZONE_SUBMIT_ROLES = {"field_commander"}
ZONE_APPROVE_ROLES = {"incident_commander"}


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result

    # ------------------------------------------------------------------
    # 任务区 / 离线观测批次 / 处置许可
    # ------------------------------------------------------------------
    @staticmethod
    def _require_field_time(value: Any, field: str = "field_time") -> str:
        text = require_text(value, field, 40)
        try:
            datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field}必须是ISO-8601时刻") from exc
        return text

    def _validate_observations(self, payload: Dict[str, Any]) -> list:
        observations = require_list(payload.get("observations"), "observations")
        if not observations:
            raise ValidationError("观测批次至少包含一条观测")
        normalized = []
        for index, obs in enumerate(observations):
            if not isinstance(obs, dict):
                raise ValidationError(f"observations[{index}]必须是对象")
            kind = obs.get("kind")
            if kind not in OBSERVATION_KINDS:
                raise ValidationError(f"observations[{index}].kind非法")
            entry: Dict[str, Any] = {"kind": kind}
            if obs.get("field_time") is not None:
                entry["field_time"] = self._require_field_time(
                    obs["field_time"], f"observations[{index}].field_time")
            if kind == OBS_RESOURCE:
                entry["task_code"] = require_text(
                    obs.get("task_code"), f"observations[{index}].task_code", 80)
                entry["resource_code"] = require_text(
                    obs.get("resource_code"), f"observations[{index}].resource_code", 80)
            else:
                value = obs.get("value")
                if kind == OBS_WIND:
                    value = require_text(value, f"observations[{index}].value", 40)
                    if value not in SAFE_WINDS and value not in (
                            "uphill", "into_slope", "variable", "unknown"):
                        raise ValidationError(
                            f"observations[{index}].value不是已知风向")
                    entry["value"] = value
                else:
                    entry["value"] = require_number(
                        value, f"observations[{index}].value")
            normalized.append(entry)
        return normalized

    def create_zone(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, ZONE_SUBMIT_ROLES)
        actor = require_text(actor, "actor", 100)
        name = require_text(payload.get("name"), "name", 200)
        danger_length = require_number(
            payload.get("danger_length", 1000.0), "danger_length", 0.000001)
        wind = payload.get("wind")
        if wind is not None:
            wind = require_text(wind, "wind", 40)
        fireline_length = payload.get("fireline_length")
        if fireline_length is not None:
            fireline_length = require_number(fireline_length, "fireline_length")
        item_id = payload.get("item_id")
        if item_id is not None and not isinstance(item_id, int):
            raise ValidationError("item_id必须是整数")
        return self.repository.create_zone(
            name, danger_length, wind, fireline_length, item_id, actor)

    def list_zones(self, role: str) -> list:
        self._view(role)
        return [self._enrich_zone(z) for z in self.repository.list_zones()]

    def get_zone(self, zone_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self._enrich_zone(self.repository.get_zone(zone_id))

    def _enrich_zone(self, zone: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(zone)
        result["pending_conflicts"] = len(
            self.repository.list_conflicts(zone["id"], "pending"))
        return result

    def submit_batch(self, zone_id: int, payload: Dict[str, Any],
                     actor: str, role: str) -> Dict[str, Any]:
        """现场提交观测批次。先整批排队落库，再尝试合并：
        成功固化首次结果；失败整批保留为 failed，可随时重试，不留半条观测。"""
        ensure_role(role, ZONE_SUBMIT_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_zone(zone_id)
        ticket_no = require_text(payload.get("ticket_no"), "ticket_no", 100)
        field_time = self._require_field_time(payload.get("field_time"))
        base_version = payload.get("base_version")
        if base_version is not None:
            if isinstance(base_version, bool) or not isinstance(base_version, int) \
                    or base_version < 1:
                raise ValidationError("base_version必须是正整数")
        observations = self._validate_observations(payload)
        clean_payload = {"ticket_no": ticket_no, "field_time": field_time,
                         "base_version": base_version, "observations": observations}
        import json as _json
        # 同号重放沿用首次结果（已应用直接返回；失败则原地重试，不新建批次）
        existing = self._find_batch(zone_id, ticket_no)
        if existing is None:
            try:
                batch = self.repository.queue_batch(
                    zone_id, ticket_no, field_time, base_version,
                    _json.dumps(clean_payload, ensure_ascii=False), actor)
                batch_id = batch["id"]
            except ConflictError:
                # 并发下另一请求已以同现场单号排队：沿用该批次，不重复建单
                existing = self.repository.get_batch(zone_id, ticket_no)
                batch_id = existing["id"]
                if existing["status"] == "applied":
                    return {"replayed": True, **existing["result"],
                            "ticket_no": ticket_no}
        else:
            batch_id = existing["id"]
            if existing["status"] == "applied":
                return {"replayed": True, **existing["result"],
                        "ticket_no": ticket_no}

        return self._attempt_batch(batch_id, actor)

    def _find_batch(self, zone_id: int, ticket_no: str):
        try:
            return self.repository.get_batch(zone_id, ticket_no)
        except NotFoundError:
            return None

    def _attempt_batch(self, batch_id: int, actor: str) -> Dict[str, Any]:
        try:
            result = self._merge_and_apply(batch_id, actor)
            stored = self.repository.get_batch_by_id(batch_id)
            return {"replayed": False, **result,
                    "ticket_no": stored["ticket_no"]}
        except DomainError as exc:
            # 业务失败：整批保留（载荷、单号、现场时刻都不丢），恢复后可重试
            self.repository.mark_batch_failed(batch_id, {
                "error": exc.__class__.__name__, "message": exc.message,
            })
            stored = self.repository.get_batch_by_id(batch_id)
            return {"replayed": False, "status": "failed",
                    "batch_id": batch_id, "ticket_no": stored["ticket_no"],
                    "attempts": stored["attempts"],
                    "error": {"error": exc.__class__.__name__,
                              "message": exc.message}}

    def _merge_and_apply(self, batch_id: int, actor: str) -> Dict[str, Any]:
        batch = self.repository.get_batch_by_id(batch_id)
        zone_id = batch["zone_id"]
        observations = batch["payload"]["observations"]
        folded = fold_observations(observations, batch["field_time"])
        # 未带基线版本表示在线快进提交，默认以服务器当前版本为基线（不会产生冲突）；
        # 断网期间积压批次才会显式携带其离线时所依据的 base_version。
        zone = self.repository.get_zone(zone_id)
        base_version = batch["base_version"] or zone["version"]
        # 取基线/当前快照、三方合并、跨区资源冲突预检与整批写入全部在同一个
        # 数据库事务内完成，避免读到中间状态或留下半条观测。
        return self.repository.apply_batch(
            batch_id, base_version, folded, actor)

    def retry_batch(self, zone_id: int, ticket_no: str, actor: str,
                    role: str) -> Dict[str, Any]:
        """对失败后整批保留的批次原地重试。"""
        ensure_role(role, ZONE_SUBMIT_ROLES)
        actor = require_text(actor, "actor", 100)
        batch = self.repository.get_batch(zone_id, ticket_no)
        if batch["status"] == "applied":
            return {"replayed": True, **batch["result"], "ticket_no": ticket_no}
        return self._attempt_batch(batch["id"], actor)

    def recover_batches(self, zone_id: int, actor: str, role: str) -> Dict[str, Any]:
        """断网恢复：未应用批次按现场时刻排序依次整批合并；个别失败不阻断其余批次。"""
        ensure_role(role, ZONE_SUBMIT_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_zone(zone_id)
        results = []
        for batch in self.repository.pending_batches_ordered(zone_id):
            outcomes = self._attempt_batch(batch["id"], actor)
            results.append({"ticket_no": batch["ticket_no"], **outcomes})
        return {"zone_id": zone_id, "processed": len(results), "results": results}

    def list_batches(self, zone_id: int, role: str,
                     status: Optional[str] = None) -> list:
        self._view(role)
        return self.repository.list_batches(zone_id, status)

    def list_zone_events(self, zone_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_zone_events(zone_id)

    def verify_zone_chain(self, zone_id: int, role: str) -> dict:
        self._view(role)
        self.repository.get_zone(zone_id)
        return {"zone_id": zone_id,
                "valid": self.repository.verify_zone_chain(zone_id)}

    def list_conflicts(self, zone_id: int, role: str,
                       status: Optional[str] = None) -> list:
        self._view(role)
        return self.repository.list_conflicts(zone_id, status)

    def resolve_conflict(self, zone_id: int, conflict_id: int,
                         payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, ZONE_APPROVE_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_zone(zone_id)
        resolution = payload.get("resolution")
        if resolution not in ("server", "field"):
            raise ValidationError("resolution必须是server或field")
        if not any(c["id"] == conflict_id
                   for c in self.repository.list_conflicts(zone_id)):
            raise NotFoundError("冲突不存在")
        return self.repository.resolve_conflict(conflict_id, resolution, actor)

    def list_permits(self, zone_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_permits(zone_id)

    def approve_permit(self, zone_id: int, permit_id: int,
                       payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, ZONE_APPROVE_ROLES)
        actor = require_text(actor, "actor", 100)
        self.repository.get_zone(zone_id)
        permit = self.repository.get_permit(permit_id)
        if permit["zone_id"] != zone_id:
            raise NotFoundError("许可不存在")
        expected = payload.get("expected_version")
        if isinstance(expected, bool) or not isinstance(expected, int) or expected < 1:
            raise ValidationError("expected_version必须是正整数")
        return self.repository.approve_permit(permit_id, expected, actor)
