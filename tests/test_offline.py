import json
import tempfile
import unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.rules import disposal_decision, fold_observations, three_way_merge
from src.service import Service

FC = "field_commander"
IC = "incident_commander"
VIEWER = "viewer"
FT = "2026-09-30T22:00:00+00:00"


class MergeRulesTest(unittest.TestCase):
    def test_fold_uses_latest_field_time(self):
        folded = fold_observations([
            {"kind": "wind", "value": "downhill", "field_time": "2026-09-30T21:00:00+00:00"},
            {"kind": "wind", "value": "uphill", "field_time": "2026-09-30T22:00:00+00:00"},
            {"kind": "resource", "task_code": "A", "resource_code": "R1",
             "field_time": "2026-09-30T22:00:00+00:00"},
        ], FT)
        self.assertEqual(folded["wind"], "uphill")
        self.assertEqual(folded["tasks"], {"A": "R1"})

    def test_three_way_scalar_conflict(self):
        base = {"wind": "downhill", "fireline_length": 100.0, "tasks": {}}
        server = dict(base, wind="uphill")
        incoming = {"wind": "cross_slope", "fireline_length": None, "tasks": {}}
        scalars, _, conflicts = three_way_merge(base, server, incoming)
        self.assertNotIn("wind", scalars)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["server"], "uphill")
        self.assertEqual(conflicts[0]["observed"], "cross_slope")

    def test_three_way_resource_conflict_and_independent_adds(self):
        base = {"wind": None, "fireline_length": None, "tasks": {"A": "R1"}}
        # 服务器改 A，现场也改 A 但改成不同资源 -> 冲突；现场新增 B 独立合并
        server = {"wind": None, "fireline_length": None, "tasks": {"A": "R9"}}
        incoming = {"wind": None, "fireline_length": None,
                    "tasks": {"A": "R8", "B": "R2"}}
        _, task_changes, conflicts = three_way_merge(base, server, incoming)
        self.assertEqual(task_changes.get("B"), "R2")
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["task_code"], "A")

    def test_disposal_decision(self):
        yes = disposal_decision("downhill", 100.0, 500.0)
        no_wind = disposal_decision("uphill", 100.0, 500.0)
        no_len = disposal_decision("downhill", 600.0, 500.0)
        self.assertTrue(yes["can_approve"])
        self.assertFalse(no_wind["can_approve"])
        self.assertFalse(no_len["can_approve"])


class OfflineBatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.zone = self.service.create_zone(
            {"name": "北坡", "danger_length": 500, "wind": "uphill",
             "fireline_length": 800}, "alice", FC)
        self.zid = self.zone["id"]

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _submit(self, ticket, observations, field_time=FT, base_version=None):
        payload = {"ticket_no": ticket, "field_time": field_time,
                   "observations": observations}
        if base_version is not None:
            payload["base_version"] = base_version
        return self.service.submit_batch(self.zid, payload, "alice", FC)

    def test_ticket_replay_keeps_first_result(self):
        first = self._submit("T-1", [
            {"kind": "wind", "value": "downhill"},
            {"kind": "fireline_length", "value": 300},
            {"kind": "resource", "task_code": "A", "resource_code": "R1"},
        ])
        self.assertEqual(first["status"], "applied")
        replay = self._submit("T-1", [{"kind": "wind", "value": "uphill"}])
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["permit_id"], first["permit_id"])
        # 重放不得改变任务区状态
        self.assertEqual(self.service.get_zone(self.zid, VIEWER)["wind"], "downhill")
        # 同号批次只有一条
        self.assertEqual(len(self.service.list_batches(self.zid, VIEWER)), 1)

    def test_wind_change_invalidates_permit_and_releases_occupancy(self):
        first = self._submit("T-1", [
            {"kind": "wind", "value": "downhill"},
            {"kind": "fireline_length", "value": 300},
            {"kind": "resource", "task_code": "A", "resource_code": "R1"},
        ])
        permit_id = first["permit_id"]
        self.service.approve_permit(
            self.zid, permit_id, {"expected_version": first["version"]}, "bob", IC)
        active = self.repo.conn.execute(
            "SELECT COUNT(*) AS n FROM resource_tasks WHERE zone_id=? AND status='active'",
            (self.zid,)).fetchone()["n"]
        self.assertEqual(active, 1)
        changed = self._submit("T-2", [{"kind": "wind", "value": "uphill"}],
                               field_time="2026-09-30T23:00:00+00:00")
        self.assertEqual(changed["status"], "applied")
        self.assertEqual(self.repo.get_permit(permit_id)["status"], "invalidated")
        active = self.repo.conn.execute(
            "SELECT COUNT(*) AS n FROM resource_tasks WHERE zone_id=? AND status='active'",
            (self.zid,)).fetchone()["n"]
        self.assertEqual(active, 0)
        latest = self.service.list_permits(self.zid, VIEWER)[-1]
        self.assertEqual(latest["status"], "proposed")
        self.assertEqual(latest["decision"], "deny")
        # 失效许可无法放行
        with self.assertRaises(ConflictError):
            self.service.approve_permit(
                self.zid, permit_id, {"expected_version": changed["version"]}, "bob", IC)

    def test_review_blocks_approval_until_conflict_resolved(self):
        first = self._submit("T-1", [
            {"kind": "wind", "value": "cross_slope"},
            {"kind": "fireline_length", "value": 300},
        ])
        base = first["version"]
        self.service.submit_batch(self.zid, {
            "ticket_no": "S-1", "field_time": "2026-10-01T00:00:00+00:00",
            "observations": [{"kind": "fireline_length", "value": 250}]}, "alice", FC)
        field = self.service.submit_batch(self.zid, {
            "ticket_no": "F-1", "field_time": "2026-10-01T00:10:00+00:00",
            "base_version": base,
            "observations": [{"kind": "fireline_length", "value": 420}]}, "alice", FC)
        self.assertTrue(field["conflict_ids"])
        zone = self.service.get_zone(self.zid, VIEWER)
        self.assertEqual(zone["status"], "review")
        pending = self.service.list_conflicts(self.zid, VIEWER, "pending")
        proposed = self.service.list_permits(self.zid, VIEWER)[-1]
        with self.assertRaises(ConflictError):
            self.service.approve_permit(
                self.zid, proposed["id"], {"expected_version": zone["version"]}, "bob", IC)
        result = self.service.resolve_conflict(
            self.zid, pending[0]["id"], {"resolution": "field"}, "bob", IC)
        self.assertEqual(result["pending"], 0)
        self.assertEqual(self.service.get_zone(self.zid, VIEWER)["fireline_length"], 420.0)
        # 复核后按新值重算提案，此时长度420<500、cross_slope 安全，可放行
        self.service.approve_permit(
            self.zid, result["permit_id"],
            {"expected_version": result["version"]}, "bob", IC)

    def test_failed_batch_is_retained_and_retried_after_recovery(self):
        # 另一任务区活动占用 R1
        other = self.service.create_zone(
            {"name": "南坡", "danger_length": 500, "wind": "downhill",
             "fireline_length": 100}, "alice", FC)
        ob = self.service.submit_batch(other["id"], {
            "ticket_no": "O-1", "field_time": "2026-09-30T20:00:00+00:00",
            "observations": [{"kind": "resource", "task_code": "X",
                              "resource_code": "R1"}]}, "alice", FC)
        self.service.approve_permit(
            other["id"], ob["permit_id"], {"expected_version": ob["version"]}, "bob", IC)
        # 排队三个断网批次（不立即应用）
        for ticket, when in (
                ("OFF-B", "2026-09-30T21:00:00+00:00"),
                ("OFF-A", "2026-09-30T22:00:00+00:00"),
                ("OFF-C", "2026-09-30T23:00:00+00:00")):
            obs = ([{"kind": "resource", "task_code": "X", "resource_code": "R1"}]
                   if ticket == "OFF-B" else [{"kind": "wind", "value": "downhill"}])
            self.repo.queue_batch(
                self.zid, ticket, when, None,
                json.dumps({"ticket_no": ticket, "field_time": when,
                            "base_version": None, "observations": obs},
                           ensure_ascii=False), "alice")
        recovery = self.service.recover_batches(self.zid, "alice", FC)
        # 按现场时刻排序：B 先（失败整批保留），A、C 成功
        self.assertEqual([r["ticket_no"] for r in recovery["results"]],
                         ["OFF-B", "OFF-A", "OFF-C"])
        failed = self.repo.get_batch(self.zid, "OFF-B")
        self.assertEqual(failed["status"], "failed")
        self.assertTrue(failed["last_error"])
        # 载荷完整保留，且没有写入任何半条观测
        self.assertEqual(failed["payload"]["observations"][0]["resource_code"], "R1")
        self.assertEqual(self.repo.list_observations(self.zid, failed["id"]), [])
        # 解除跨区占用后重试失败批次
        self.service.submit_batch(other["id"], {
            "ticket_no": "O-2", "field_time": "2026-10-01T00:00:00+00:00",
            "observations": [{"kind": "wind", "value": "uphill"}]}, "alice", FC)
        retry = self.service.retry_batch(self.zid, "OFF-B", "alice", FC)
        self.assertEqual(retry["status"], "applied")
        applied = self.repo.get_batch(self.zid, "OFF-B")
        self.assertEqual(len(self.repo.list_observations(self.zid, applied["id"])), 1)

    def test_cross_zone_resource_double_booking_rejected(self):
        other = self.service.create_zone(
            {"name": "南坡", "danger_length": 500, "wind": "downhill",
             "fireline_length": 100}, "alice", FC)
        ob = self.service.submit_batch(other["id"], {
            "ticket_no": "O-1", "field_time": "2026-09-30T20:00:00+00:00",
            "observations": [{"kind": "resource", "task_code": "X",
                              "resource_code": "R1"}]}, "alice", FC)
        self.service.approve_permit(
            other["id"], ob["permit_id"], {"expected_version": ob["version"]}, "bob", IC)
        result = self._submit("DUP-R1", [
            {"kind": "resource", "task_code": "Y", "resource_code": "R1"}])
        self.assertEqual(result["status"], "failed")

    def test_roles_and_validation(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_zone({"name": "x"}, "a", VIEWER)
        with self.assertRaises(ValidationError):
            self.service.submit_batch(self.zid, {
                "ticket_no": "BAD", "field_time": "not-a-time",
                "observations": []}, "alice", FC)
        with self.assertRaises(PermissionDenied):
            self.service.approve_permit(
                self.zid, 1, {"expected_version": 1}, "alice", FC)

    def test_version_and_audit_chains_remain_valid(self):
        self._submit("T-1", [{"kind": "wind", "value": "downhill"},
                             {"kind": "fireline_length", "value": 300},
                             {"kind": "resource", "task_code": "A",
                              "resource_code": "R1"}])
        self._submit("T-2", [{"kind": "wind", "value": "uphill"}],
                     field_time="2026-09-30T23:00:00+00:00")
        self.assertTrue(self.repo.verify_zone_chain(self.zid))
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
