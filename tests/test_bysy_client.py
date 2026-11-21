"""北医三院客户端的离线单测（不联网，全部拦在 urlopen 之前）。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import bysy_client as by
from bysy_client import BysyAuthRequired, BysyClient, BysyNotCalibrated


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None) -> None:
        self._body = body
        self.status = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Recorder:
    """替掉 urllib.request.urlopen，记下请求，回固定 JSON。"""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.requests = []
        self._real = None

    def __enter__(self):
        self._real = by.urllib.request.urlopen
        by.urllib.request.urlopen = self._open
        return self

    def __exit__(self, *exc):
        by.urllib.request.urlopen = self._real
        return False

    def _open(self, req, timeout=None, context=None):
        self.requests.append(req)
        return _FakeResponse(json.dumps(self.payload).encode())


class HeadersTest(unittest.TestCase):
    def test_anonymous_headers_have_no_token(self):
        c = BysyClient(system="Android 17")
        h = c.build_headers()
        self.assertEqual(h["platform"], "wechat")
        self.assertEqual(h["version"], "2.2.2")
        self.assertEqual(h["system"], "Android 17")
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertNotIn("token", h)
        self.assertNotIn("userId", h)
        self.assertTrue(h["timestamp"].isdigit())

    def test_token_headers(self):
        c = BysyClient(token="t" * 16, user_id=42)
        h = c.build_headers()
        self.assertEqual(h["token"], "t" * 16)
        self.assertEqual(h["userId"], "42")

    def test_token_override_to_empty_strips_headers(self):
        # 免登录接口即使客户端带着 token 也不能带 token 头
        c = BysyClient(token="t" * 16, user_id=42)
        h = c.build_headers(token="")
        self.assertNotIn("token", h)
        self.assertNotIn("userId", h)


class BodyTest(unittest.TestCase):
    def test_anonymous_body_is_plain_json(self):
        c = BysyClient()
        self.assertEqual(c.wrap_body({"flag": 2}), {"flag": 2})

    def test_token_body_is_sm4_wrapped(self):
        c = BysyClient(token="0123456789abcdef")
        wrapped = c.wrap_body({"flag": 2})
        self.assertIn("encrypted", wrapped)
        self.assertEqual(len(wrapped["encrypted"]) % 32, 0)  # 16 字节 = 32 hex
        # 同样输入必须确定，方便以后跟真样本对比
        self.assertEqual(wrapped, c.wrap_body({"flag": 2}))

    def test_wrong_key_length_refuses(self):
        # 32 位 token 按 utf8 取不到 16 字节 -> 拒绝，而不是算出垃圾密文
        c = BysyClient(token="0d2sF3ll2OTXOi4Qk5ol2kAKZ02sF3lG")
        with self.assertRaises(BysyNotCalibrated):
            c.wrap_body({"flag": 2})

    def test_hex_key_encoding(self):
        c = BysyClient(token="0123456789abcdef" * 2, sm4_key_encoding="hex")
        self.assertEqual(len(by.sm4_key(c.token, encoding="hex")), 16)
        self.assertIn("encrypted", c.wrap_body({}))


class RequestTest(unittest.TestCase):
    def test_post_records_url_headers_payload(self):
        with _Recorder({"code": "200", "msg": "ok", "data": []}) as rec:
            c = BysyClient()
            res = c.post("api/v1/appointment/getHospitalAreas", {"flag": 2}, token="")
        self.assertTrue(res.ok)
        req = rec.requests[0]
        self.assertEqual(req.full_url, "https://patwx.puh3.net.cn/api/v1/appointment/getHospitalAreas")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(json.loads(req.data.decode()), {"flag": 2})

    def test_code_201_raises_auth_required(self):
        with _Recorder({"code": "201", "msg": "请升级到最新版本，或重新登录！", "data": {}}):
            res = BysyClient().post("api/v1/appointment/getDepartments", {}, token="")
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "201")
        with self.assertRaises(BysyAuthRequired):
            res.ensure_ok("getDepartments")

    def test_network_failure_does_not_raise(self):
        import socket

        def boom(*a, **kw):
            raise socket.timeout("timed out")

        real = by.urllib.request.urlopen
        by.urllib.request.urlopen = boom
        try:
            res = BysyClient().post("api/v1/doctor/department/getDoctors", {}, token="")
        finally:
            by.urllib.request.urlopen = real
        self.assertEqual(res.status, 0)
        self.assertIn("network", res.msg)

    def test_hospital_areas_parses_data_list(self):
        payload = {
            "code": "200",
            "msg": "获取成功",
            "data": [
                {"hospitalName": "北京大学第三医院(本部)", "position": "花园北路49号", "count": 333},
            ],
        }
        with _Recorder(payload):
            areas = BysyClient().hospital_areas()
        self.assertEqual(areas[0]["count"], 333)


class UncalibratedTest(unittest.TestCase):
    def test_schedules_refuses(self):
        with self.assertRaises(BysyNotCalibrated):
            BysyClient(token="0123456789abcdef").schedules()

    def test_create_appointment_refuses(self):
        with self.assertRaises(BysyNotCalibrated):
            BysyClient(token="0123456789abcdef").create_appointment()


class EndpointCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(Path(by.__file__).with_name("bysy_endpoints.json").read_text(encoding="utf-8"))

    def test_whitelist_matches_source(self):
        # 源码里 d=[...] 就是 9 条，顺序照抄
        self.assertEqual(len(by.PUBLIC_PATHS), 9)
        self.assertEqual(
            list(by.PUBLIC_PATHS),
            [v["path"] for v in self.doc["public"].values()],
        )

    def test_catalog_flags(self):
        self.assertEqual(len(self.doc["public"]), 9)
        self.assertTrue(all(v["token"] is False for v in self.doc["public"].values()))
        self.assertGreater(len(self.doc["auth"]), 100)
        self.assertTrue(all(v["token"] is True for v in self.doc["auth"].values()))

    def test_all_paths_wellformed(self):
        paths = [v["path"] for v in self.doc["public"].values()]
        paths += [v["path"] for v in self.doc["auth"].values()]
        paths += [v["path"] for v in self.doc["unnamed"]]
        self.assertGreaterEqual(len(paths), 200)
        for p in paths:
            self.assertTrue(p.startswith("api/v"), p)

    def test_appointment_chain_present(self):
        paths = {v["path"] for v in self.doc["auth"].values()}
        for p in (
            "api/v1/appointment/getDepartments",
            "api/v2/appointment/getDepartmentDoctors",
            "api/v2/appointment/area/getVisitSchedules",
            "api/v2/appointment/getVisitSchedulesTimes",
            "api/v2/appointment/createAppointment",
            "api/v1/payment/createPayment",
        ):
            self.assertIn(p, paths)


if __name__ == "__main__":
    unittest.main()
