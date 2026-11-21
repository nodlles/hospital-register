from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bdkq_crypto import response_key, sm4_encrypt  # noqa: E402
from bdkq_runtime import (  # noqa: E402
    BDKQ_APP_ID,
    BDKQ_HOST,
    Gateway,
    RuntimeLiftError,
    lift,
    login_state,
    pick_record,
    version_from_url,
    write_config,
)

SIGNATURE = "9a847e839f82be30693f250db16b583ec6996715979a0b05e2dbf46f2955b298"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.payload.sig"


def record(url: str, *, headers: dict | None = None, method: str = "POST",
           response_body: dict | None = None, at: str = "2026-11-21T18:50:00+08:00") -> dict:
    return {
        "id": "1",
        "url": url,
        "method": method,
        "status": 200,
        "requestHeaders": headers or {},
        "responseHeaders": {},
        "responseBody": json.dumps(response_body) if response_body else None,
        "at": at,
    }


def encrypted_login_record(token: str = TOKEN, version: str = "45ff03e9") -> dict:
    """造一条和真机一样形态的 /login/wechat 记录（响应体加密）。"""
    plain = {"status": 0, "message": "success", "data": {"accessToken": token}}
    cipher = sm4_encrypt(json.dumps(plain).encode(), response_key(SIGNATURE)).hex()
    item = record(
        f"https://{BDKQ_HOST}/xcx-bjdxkqyy-wx@default/login/wechat",
        headers={"signature": SIGNATURE, "access_token": "stale-token"},
        response_body={"data": cipher},
    )
    item["responseHeaders"] = {"x-version": version, "cipher": "true"}
    return item


class VersionTests(unittest.TestCase):
    def test_version_from_data_url(self) -> None:
        self.assertEqual(
            version_from_url(f"https://{BDKQ_HOST}/xcx-bjdxkqyy-wx@45ff03e9/api/system/dateList"),
            "45ff03e9",
        )

    def test_version_from_login_url_is_default(self) -> None:
        self.assertEqual(
            version_from_url(f"https://{BDKQ_HOST}/xcx-bjdxkqyy-wx@default/login/wechat"),
            "default",
        )

    def test_version_missing(self) -> None:
        self.assertEqual(version_from_url("https://example.com/x"), "")


class PickRecordTests(unittest.TestCase):
    def test_prefers_non_login_request_header(self) -> None:
        records = [
            encrypted_login_record("token-from-login"),
            record(
                f"https://{BDKQ_HOST}/xcx-bjdxkqyy-wx@45ff03e9/api/regist/getTodayDeptList",
                headers={"access_token": "token-from-header"},
                method="GET",
            ),
        ]
        picked = pick_record(records)
        assert picked is not None
        self.assertEqual(login_state(picked)["access_token"], "token-from-header")
        self.assertEqual(login_state(picked)["api_version"], "45ff03e9")

    def test_falls_back_to_login_response_body(self) -> None:
        picked = pick_record([encrypted_login_record("token-from-login")])
        assert picked is not None
        state = login_state(picked)
        self.assertEqual(state["access_token"], "token-from-login")
        # 登录 URL 是 @default，真版本号在响应头 x-version
        self.assertEqual(state["api_version"], "45ff03e9")

    def test_ignores_other_hosts(self) -> None:
        self.assertIsNone(pick_record([record("https://example.com/a", headers={"access_token": "x"})]))

    def test_ignores_records_without_token(self) -> None:
        self.assertIsNone(pick_record([record(f"https://{BDKQ_HOST}/xcx@45ff03e9/api/x")]))

    def test_missing_token_raises(self) -> None:
        with self.assertRaises(RuntimeLiftError):
            login_state(record(f"https://{BDKQ_HOST}/xcx@45ff03e9/api/x"))


class _FakeGateway(BaseHTTPRequestHandler):
    records: list[dict] = []
    restarted = False
    capture = False
    cleared = 0

    def log_message(self, *args) -> None:  # noqa: ANN002 - 静音
        pass

    def _send(self, payload) -> None:  # noqa: ANN001
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/v1/apps"):
            self._send({"apps": [{"appId": BDKQ_APP_ID, "state": "foreground"}]})
        elif self.path.startswith("/v1/config"):
            self._send({"network_capture": type(self).capture})
        elif self.path.startswith("/v1/hook/store"):
            self._send({"records": type(self).records, "capture": type(self).capture})
        else:
            self._send({})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        cls = type(self)
        if self.path.startswith("/v1/config"):
            cls.capture = bool(body.get("network_capture"))
            self._send({"network_capture": cls.capture})
        elif self.path.startswith("/v1/hook/clear"):
            cls.records = []
            cls.cleared += 1
            self._send({"ok": True})
        elif ":restart" in self.path:
            cls.restarted = True
            # 重启后小程序自己发一次请求（真机就是这样）
            cls.records = [
                record(
                    f"https://{BDKQ_HOST}/xcx-bjdxkqyy-wx@45ff03e9/api/org/content/pubList",
                    headers={"access_token": "token-after-restart"},
                )
            ]
            self._send({"ok": True})
        else:
            self._send({})


class LiftTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeGateway.records = []
        _FakeGateway.restarted = False
        _FakeGateway.capture = False
        _FakeGateway.cleared = 0
        self.server = HTTPServer(("127.0.0.1", 0), _FakeGateway)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def gateway(self) -> Gateway:
        return Gateway(f"http://127.0.0.1:{self.port}")

    def test_uses_existing_record_without_restart(self) -> None:
        _FakeGateway.records = [
            record(f"https://{BDKQ_HOST}/xcx-bjdxkqyy-wx@45ff03e9/api/regist/getTodayDeptList",
                   headers={"access_token": "tok"}, method="GET")
        ]
        # 先让 capture 为 true，避免 lift 重启
        _FakeGateway.capture = True
        state = lift(self.gateway(), timeout=2, poll=0.05)
        self.assertEqual(state["access_token"], "tok")
        self.assertFalse(_FakeGateway.restarted)

    def test_restarts_when_nothing_captured(self) -> None:
        state = lift(self.gateway(), timeout=5, poll=0.05)
        self.assertTrue(_FakeGateway.restarted)
        self.assertEqual(state["access_token"], "token-after-restart")
        self.assertEqual(state["api_version"], "45ff03e9")

    def test_raises_when_app_missing(self) -> None:
        original = Gateway.find_app

        def no_app(self, app_id=BDKQ_APP_ID):  # noqa: ANN001
            raise RuntimeLiftError(f"运行时里没有 {app_id}")

        Gateway.find_app = no_app  # type: ignore[assignment]
        try:
            with self.assertRaises(RuntimeLiftError):
                lift(self.gateway(), timeout=1, poll=0.05)
        finally:
            Gateway.find_app = original  # type: ignore[assignment]


class WriteConfigTests(unittest.TestCase):
    def test_keeps_other_fields_and_restricts_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.bdkq.local.json"
            path.write_text(json.dumps({"base_url": "https://x", "access_token": "old"}))
            state = {"access_token": "new", "api_version": "45ff03e9"}
            saved = write_config(path, state)
            data = json.loads(saved.read_text())
            self.assertEqual(data["base_url"], "https://x")
            self.assertEqual(data["access_token"], "new")
            self.assertEqual(data["api_version"], "45ff03e9")
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_creates_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "c.json"
            path.parent.mkdir()
            write_config(path, {"access_token": "t", "api_version": "v"})
            self.assertEqual(json.loads(path.read_text())["access_token"], "t")


if __name__ == "__main__":
    unittest.main()
