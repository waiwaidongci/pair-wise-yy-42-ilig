import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from src.http_api import make_handler
from src.repository import Repository
from src.service import Service

FC = "field_commander"
IC = "incident_commander"


class HttpOfflineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.repo = Repository(str(Path(cls.tmp.name) / "http.db"))
        cls.service = Service(cls.repo)
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            make_handler(cls.service, str(Path("static").resolve())))
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.repo.close()
        cls.tmp.cleanup()

    def call(self, method, path, payload=None, role=FC, actor="alice"):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json",
                     "X-Actor": actor, "X-Role": role})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_batch_replay_and_permit_flow(self):
        _, zone = self.call("POST", "/api/zones", {
            "name": "北坡", "danger_length": 500,
            "wind": "uphill", "fireline_length": 800})
        zid = zone["id"]
        status, batch = self.call("POST", f"/api/zones/{zid}/batches", {
            "ticket_no": "T-1", "field_time": "2026-09-30T22:00:00+00:00",
            "observations": [
                {"kind": "wind", "value": "downhill"},
                {"kind": "fireline_length", "value": 300},
                {"kind": "resource", "task_code": "A", "resource_code": "R1"}]})
        self.assertEqual(status, 202)
        self.assertEqual(batch["status"], "applied")
        permit_id = batch["permit_id"]
        # 同号重放沿用首次结果
        _, replay = self.call("POST", f"/api/zones/{zid}/batches", {
            "ticket_no": "T-1", "field_time": "2026-09-30T22:00:00+00:00",
            "observations": [{"kind": "wind", "value": "uphill"}]})
        self.assertTrue(replay["replayed"])
        # 放行
        status, _ = self.call(
            "POST", f"/api/zones/{zid}/permits/{permit_id}/approve",
            {"expected_version": batch["version"]}, role=IC, actor="bob")
        self.assertEqual(status, 200)
        # 风向晚到 -> 原许可失效，新提案拒绝放行
        status, changed = self.call("POST", f"/api/zones/{zid}/batches", {
            "ticket_no": "T-2", "field_time": "2026-09-30T23:00:00+00:00",
            "observations": [{"kind": "wind", "value": "uphill"}]})
        self.assertEqual(status, 202)
        self.assertEqual(changed["status"], "applied")
        _, permits = self.call("GET", f"/api/zones/{zid}/permits", role=IC)
        self.assertEqual(permits["permits"][0]["status"], "invalidated")
        # 校验与权限
        self.assertEqual(self.call("POST", f"/api/zones/{zid}/batches", {
            "ticket_no": "BAD", "field_time": "x", "observations": []})[0], 422)
        self.assertEqual(self.call("POST", f"/api/zones/{zid}/recover",
                                   role=IC)[0], 403)
        # 版本链可验证
        _, verify = self.call("GET", f"/api/zones/{zid}/verify", role=IC)
        self.assertTrue(verify["valid"])
        # 原有接口不受影响
        self.assertEqual(self.call("GET", "/api/items", role="viewer")[0], 200)


if __name__ == "__main__":
    unittest.main()
