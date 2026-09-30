import tempfile, unittest
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service


class BatchPermitTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "ridge fire", "description": "night ops", "severity": "high",
             "quantity": 10, "threshold": 5, "external_ref": "WF-1"},
            "creator", "field_commander")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _obs(self, kind, value, at):
        return {"kind": kind, "value": value, "observed_at": at}

    def test_batch_idempotent_by_ticket(self):
        obs = [self._obs("wind_direction", "south", "2026-09-30T10:00:00+00:00")]
        first = self.service.submit_batch(self.item["id"], "T-1", obs, "r", "field_commander")
        self.assertEqual(first["status"], "applied")
        # 同号重放：沿用首次结果，不重复应用
        again = self.service.submit_batch(self.item["id"], "T-1", [
            self._obs("wind_direction", "north", "2026-09-30T11:00:00+00:00")],
            "r", "field_commander")
        self.assertEqual(again["id"], first["id"])
        self.assertEqual(again["result"]["merged"]["wind_direction"], "south")
        # 任务区版本不因重放而增加
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["version"], first["item_id"] and 2)

    def test_failed_batch_retained_and_retried(self):
        obs = [self._obs("wind_direction", "north", "2026-09-30T12:00:00+00:00")]
        orig = self.repo.apply_batch_transaction
        state = {"n": 0}

        def fail_once(batch_id, item_id, plan):
            state["n"] += 1
            if state["n"] == 1:
                raise RuntimeError("simulated outage")
            return orig(batch_id, item_id, plan)

        self.repo.apply_batch_transaction = fail_once
        failed = self.service.submit_batch(self.item["id"], "T-2", obs, "r", "field_commander")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(len(failed["observations"]), 1)
        self.repo.apply_batch_transaction = orig
        retried = self.service.retry_batch("T-2", "r", "field_commander")
        self.assertEqual(retried["status"], "applied")
        self.assertEqual(retried["attempts"], 2)

    def test_merge_by_site_time_late_observation_does_not_overwrite(self):
        self.service.submit_batch(self.item["id"], "T-3", [
            self._obs("fire_line_length", 20, "2026-09-30T10:10:00+00:00")],
            "r", "field_commander")
        # 晚到但现场时刻更早的观测不应覆盖更新的值
        self.service.submit_batch(self.item["id"], "T-4", [
            self._obs("fire_line_length", 5, "2026-09-30T09:00:00+00:00")],
            "r", "field_commander")
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["quantity"], 20.0)

    def test_conflicting_fireline_kept_for_review(self):
        self.service.submit_batch(self.item["id"], "T-5", [
            self._obs("fire_line_length", 20, "2026-09-30T10:10:00+00:00")],
            "r", "field_commander")
        conflict = self.service.submit_batch(self.item["id"], "T-6", [
            self._obs("fire_line_length", 30, "2026-09-30T10:12:00+00:00")],
            "r", "field_commander")
        self.assertEqual(conflict["status"], "review")
        fc = conflict["result"]["merged"]["fire_line_conflict"]
        self.assertEqual(fc["online"], 20.0)
        self.assertEqual(fc["offline"], 30.0)
        # 复核前挡住重新放行
        with self.assertRaises(ConflictError):
            self.service.issue_permit(self.item["id"], "ic", "incident_commander")
        # 复核选择现场值后落定
        reviewed = self.service.review_batch(conflict["id"], {"fire_line_length": "offline"},
                                              "ic", "incident_commander")
        self.assertEqual(reviewed["status"], "applied")
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["quantity"], 30.0)
        self.assertFalse(item["review_pending"])
        # 复核后可重新放行
        permit = self.service.issue_permit(self.item["id"], "ic", "incident_commander")
        self.assertEqual(permit["status"], "active")

    def test_wind_or_fireline_change_invalidates_permit(self):
        permit = self.service.issue_permit(self.item["id"], "ic", "incident_commander")
        self.assertEqual(permit["status"], "active")
        self.service.submit_batch(self.item["id"], "T-7", [
            self._obs("wind_direction", "south", "2026-09-30T10:00:00+00:00"),
            self._obs("fire_line_length", 25, "2026-09-30T10:05:00+00:00")],
            "r", "field_commander")
        permits = self.service.list_permits(self.item["id"], "viewer")
        self.assertEqual(permits[0]["status"], "invalid")
        # 按新值重算
        new_permit = self.service.issue_permit(self.item["id"], "ic", "incident_commander")
        self.assertEqual(new_permit["status"], "active")
        self.assertGreater(new_permit["conditions"]["risk_score"], 0)

    def test_roles_enforced(self):
        with self.assertRaises(PermissionDenied):
            self.service.submit_batch(self.item["id"], "T-8", [], "v", "viewer")
        with self.assertRaises(PermissionDenied):
            self.service.review_batch(1, {}, "v", "viewer")
        with self.assertRaises(PermissionDenied):
            self.service.issue_permit(self.item["id"], "v", "viewer")

    def test_audit_chain_valid(self):
        self.service.issue_permit(self.item["id"], "ic", "incident_commander")
        self.service.submit_batch(self.item["id"], "T-9", [
            self._obs("wind_direction", "east", "2026-09-30T10:00:00+00:00")],
            "r", "field_commander")
        self.assertTrue(self.repo.verify_audit_chain())
        events = self.service.audit("viewer", self.item["id"])
        actions = [e["action"] for e in events]
        self.assertIn("batch_apply", actions)
        self.assertIn("permit_issue", actions)


if __name__ == "__main__":
    unittest.main()
