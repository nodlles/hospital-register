#!/usr/bin/env python3
"""BdkqClient 的端到端测试：起一个本地假服务器，走真实 HTTP。

假服务器按协议做三件事：解请求体（用请求头 signature）、查业务、加密响应体。
这样能证明客户端把 URL、请求头、请求体封装、响应解密这一整条链路接对了——
但仍然证明不了「和真服务器一致」，那要靠 bdkq_probe.py 打真接口。
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bdkq_client import BdkqClient, BdkqError  # noqa: E402
from bdkq_crypto import response_key, sm4_decrypt, sm4_encrypt  # noqa: E402


def decrypt_request_body(envelope: dict, signature: str) -> dict:
    """请求体方向：key 是 signature[24:40] 的 ASCII，跟响应 key 不是同一个。"""
    blob = bytes.fromhex(envelope["data"])
    plain = sm4_decrypt(blob, signature[24:40].encode("ascii"))
    return json.loads(plain.decode("utf-8"))

SEEN: list[dict] = []


class FakeHandler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # 安静
        pass

    def _reply(self, payload: dict, *, extra_headers: dict[str, str] | None = None) -> None:
        signature = self.headers.get("signature") or ""
        key = response_key(signature)
        hexed = sm4_encrypt(json.dumps(payload, ensure_ascii=False).encode(), key).hex()
        body = json.dumps({"data": hexed}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _handle(self, method: str) -> None:
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        body = {}
        if raw:
            envelope = json.loads(raw)
            signature = self.headers.get("signature") or ""
            body = decrypt_request_body(envelope, signature)
        SEEN.append(
            {
                "method": method,
                "path": parts.path,
                "query": parse_qs(parts.query),
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
        )

        if "/login/wechat" in parts.path:
            self._reply({"status": 0, "message": "ok",
                         "data": {"accessToken": "tok-from-login"}},
                        extra_headers={"x-version": "332"})
            return
        if parts.path.endswith("/expired"):
            self._reply({"status": 1000, "message": "token 失效"})
            return
        if parts.path.endswith("/out-of-service"):
            self._reply({"status": 1001, "message": "系统维护"})
            return
        self._reply({"status": 0, "message": "ok",
                     "data": {"lists": [{"deptCode": "D1", "deptName": "口腔颌面外科",
                                         "remainCount": 3}]}})

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = HTTPServer(("127.0.0.1", 0), FakeHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        SEEN.clear()
        self.base = f"http://127.0.0.1:{self.port}"
        self.client = BdkqClient(self.base, tenant="t-wx", api_version="331",
                                 access_token="tok-head", timeout=5.0)

    def test_get_roundtrip(self) -> None:
        resp = self.client.dept_list("0")
        self.assertEqual(resp[0]["deptCode"], "D1")
        seen = SEEN[-1]
        self.assertEqual(seen["method"], "GET")
        self.assertEqual(seen["path"], "/t-wx@331/api/regist/getYyDeptList")
        self.assertEqual(seen["query"]["areaCode"], ["0"])
        self.assertEqual(seen["headers"]["access_token"], "tok-head")
        self.assertEqual(len(seen["headers"]["signature"]), 64)
        self.assertEqual(seen["headers"]["request_otp"].count("-"), 4)

    def test_post_body_decrypted_by_server(self) -> None:
        payload = {"deptCode": "D1", "doctorCode": "P1"}
        resp = self.client.post("/api/regist/getYyScheduleList", payload)
        self.assertTrue(resp.ok)
        seen = SEEN[-1]
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["body"], payload)

    def test_login_sets_token_and_version(self) -> None:
        resp = self.client.login_with_code("wx-code-123")
        self.assertTrue(resp.ok)
        self.assertEqual(self.client.access_token, "tok-from-login")
        # 登录响应头里的 x-version 覆盖后续版本
        self.assertEqual(self.client.api_version, "332")
        self.assertEqual(SEEN[-1]["path"], "/t-wx@default/login/wechat")
        self.assertEqual(SEEN[-1]["body"]["code"], "wx-code-123")

    def test_token_expired_triggers_relogin_once(self) -> None:
        calls = {"n": 0}

        def relogin(client: BdkqClient) -> None:
            calls["n"] += 1
            client.access_token = "fresh"

        client = BdkqClient(self.base, tenant="t-wx", api_version="331",
                            access_token="stale", timeout=5.0, auto_relogin=relogin)
        resp = client.get("/api/expired")
        self.assertEqual(calls["n"], 1)
        self.assertEqual(resp.status, 1000)      # 服务器一直回 1000，只重试一次
        self.assertEqual(SEEN[-1]["headers"]["access_token"], "fresh")

    def test_out_of_service_status(self) -> None:
        resp = self.client.get("/api/out-of-service")
        self.assertFalse(resp.ok)
        self.assertEqual(resp.status, 1001)

    def test_http_error_raises(self) -> None:
        client = BdkqClient(f"http://127.0.0.1:1", timeout=1.0)
        with self.assertRaises(BdkqError):
            client.get("/api/x")

    def test_ensure_ok_raises_on_bad_status(self) -> None:
        resp = self.client.get("/api/out-of-service")
        with self.assertRaises(BdkqError):
            resp.ensure_ok("test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
