from __future__ import annotations

from typing import Any, Dict, Optional

from .domain import (ConflictError, NotFoundError, ValidationError, ensure_role,
                     normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, BATCH_ROLES, CREATE_ROLES, ENTITY, OBS_FIRELINE,
                    OBS_WIND, PERMIT_ROLES, RECORD_ROLES, REVIEW_ROLES, TITLE,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    judge_conditions, merge_observations, priority_score,
                    response_deadline_hours, role_for_transition,
                    validate_observations, validate_ticket_no, validate_transition)


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

    # ------------------------------------------------------------------
    # 观测批次（现场单号识别、整批保留、按现场时刻合并、冲突待复核）
    # ------------------------------------------------------------------
    def _build_plan(self, item: Dict[str, Any], observations: list) -> Dict[str, Any]:
        """依据判定规则生成批次应用计划。观测判定在 rules，批次存储在 repository。"""
        history = self.repository.history_observations(item["id"])
        merged = merge_observations(history, observations)
        conflict_resources = {c["resource"] for c in merged["resource_conflicts"]}
        resources_to_apply = {
            res: action for res, action in merged["resources"].items()
            if res not in conflict_resources
        }
        invalidate = any(o["kind"] in (OBS_WIND, OBS_FIRELINE) for o in observations)
        review_pending = merged["has_conflict"]
        return {
            "wind_direction": merged["wind_direction"],
            "fire_line_length": merged["fire_line_length"],
            "review_pending": review_pending,
            "invalidate": invalidate,
            "resources": resources_to_apply,
            "batch_status": "review" if review_pending else "applied",
            "result": {"merged": merged, "review_pending": review_pending},
        }

    def _apply_batch(self, batch: Dict[str, Any], observations: list) -> Dict[str, Any]:
        item = self.repository.get_item(batch["item_id"])
        plan = self._build_plan(item, observations)
        try:
            applied = self.repository.apply_batch_transaction(batch["id"], item["id"], plan)
        except Exception as exc:
            self.repository.mark_batch_failed(batch["id"], str(exc))
            self.repository.append_audit("batch_failed", ENTITY, item["id"], batch["actor"], {
                "ticket_no": batch["ticket_no"], "error": str(exc)[:300],
            })
            failed = self.repository.get_batch_by_ticket(batch["ticket_no"])
            return failed  # type: ignore[return-value]
        self.repository.append_audit("batch_apply", ENTITY, item["id"], batch["actor"], {
            "ticket_no": batch["ticket_no"], "status": applied["status"],
            "review_pending": plan["review_pending"],
            "invalidate": plan["invalidate"],
        })
        return applied

    def submit_batch(self, item_id: int, ticket_no: str, observations: list,
                     actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, BATCH_ROLES)
        actor = require_text(actor, "actor", 100)
        ticket_no = validate_ticket_no(ticket_no)
        observations = validate_observations(observations)
        self.repository.get_item(item_id)
        existing = self.repository.get_batch_by_ticket(ticket_no)
        if existing is not None:
            if existing["item_id"] != item_id:
                from .domain import ConflictError
                raise ConflictError("现场单号已属于其他任务区")
            # 同号重放：沿用首次结果，不重复应用
            if existing["status"] == "applied":
                return existing
            if existing["status"] == "review":
                return existing
            # failed/pending：整批保留，恢复后再试
            return self._apply_batch(existing, existing["observations"])
        batch = self.repository.create_batch(ticket_no, item_id, observations, actor)
        return self._apply_batch(batch, observations)

    def retry_batch(self, ticket_no: str, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, BATCH_ROLES)
        actor = require_text(actor, "actor", 100)
        ticket_no = validate_ticket_no(ticket_no)
        batch = self.repository.get_batch_by_ticket(ticket_no)
        if batch is None:
            from .domain import NotFoundError
            raise NotFoundError("批次不存在")
        if batch["status"] == "applied":
            return batch
        if batch["status"] == "review":
            return batch
        return self._apply_batch(batch, batch["observations"])

    def review_batch(self, batch_id: int, choices: Dict[str, str],
                     actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, REVIEW_ROLES)
        actor = require_text(actor, "actor", 100)
        if not isinstance(choices, dict):
            raise ValidationError("复核结论必须是对象")
        batch = self.repository.get_batch(batch_id)
        if batch is None:
            from .domain import NotFoundError
            raise NotFoundError("批次不存在")
        if batch["status"] != "review":
            from .domain import ConflictError
            raise ConflictError("批次不在待复核状态")
        merged = batch["result"]["merged"]
        fire_conflict = merged["fire_line_conflict"]
        resource_conflicts = merged["resource_conflicts"]
        resolved_fire = merged["fire_line_length"]
        if fire_conflict is not None:
            side = choices.get("fire_line_length")
            if side not in ("online", "offline"):
                raise ValidationError("火线冲突需选择online或offline")
            resolved_fire = fire_conflict[side]
        resolved_resources = dict(merged["resources"])
        for conflict in resource_conflicts:
            key = "resource:" + conflict["resource"]
            side = choices.get(key)
            if side not in ("online", "offline"):
                raise ValidationError(f"资源{conflict['resource']}冲突需选择online或offline")
            resolved_resources[conflict["resource"]] = conflict[side]
        plan = {
            "wind_direction": merged["wind_direction"],
            "fire_line_length": resolved_fire,
            "invalidate": True,
            "resources": resolved_resources,
            "result": {"merged": merged, "resolution": choices, "review_pending": False},
        }
        reviewed = self.repository.review_batch_transaction(batch_id, batch["item_id"],
                                                            plan, actor)
        self.repository.append_audit("batch_review", ENTITY, batch["item_id"], actor, {
            "ticket_no": batch["ticket_no"], "choices": choices,
        })
        return reviewed

    def list_batches(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_batches(item_id)

    # ------------------------------------------------------------------
    # 处置许可（按新值重算，复核前挡住重新放行）
    # ------------------------------------------------------------------
    def issue_permit(self, item_id: int, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, PERMIT_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        if item.get("review_pending"):
            from .domain import ConflictError
            raise ConflictError("复核完成前禁止重新放行")
        if self.repository.get_active_permit(item_id) is not None:
            from .domain import ConflictError
            raise ConflictError("已有有效许可")
        conditions = judge_conditions(item.get("wind_direction"), item["quantity"],
                                      item["severity"], item["threshold"])
        permit = self.repository.create_permit(item_id, item["version"],
                                               item.get("wind_direction"), item["quantity"],
                                               conditions, actor)
        self.repository.append_audit("permit_issue", ENTITY, item_id, actor, {
            "permit_id": permit["id"], "basis_version": item["version"],
            "conditions": conditions,
        })
        return permit

    def list_permits(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_permits(item_id)

    def release_permit(self, permit_id: int, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, PERMIT_ROLES)
        actor = require_text(actor, "actor", 100)
        permit = self.repository.release_permit(permit_id)
        if permit is None:
            from .domain import ConflictError
            raise ConflictError("许可不存在或已放行")
        self.repository.append_audit("permit_release", ENTITY, permit["item_id"], actor, {
            "permit_id": permit["id"],
        })
        return permit

    def list_assignments(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_assignments(item_id)

    def list_occupations(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_occupations(item_id)

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
