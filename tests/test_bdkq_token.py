#!/usr/bin/env python3
"""bdkq_token 的测试：JWT 解析、续期判定、缓存读写、来源选择。

全部离线：换 token 的函数用假的替身，不碰网络也不碰 adb。
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import bdkq_token  # noqa: E402
from bdkq_client import BdkqClient  # noqa: E402


def make_token(expires_in: int, *, extra: dict | None = None) -> str:
    """造一个只有 payload 有意义的 JWT。"""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    claims = {"iat": int(time.time()), "exp": int(time.time()) + expires_in}
    claims.update(extra or {})
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()).decode().rstrip("=")
    return f"{header}.{payload}.signature-not-checked"


def base_config(token: str = "", version: str = "default") -> dict:
    return {
        "base_url": "https://app.bdkq.mingxuan.store",
        "tenant": "xcx-bjdxkqyy-wx",
        "api_version": version,
        "access_token": token,
        "resolve": {},
    }


class JwtTest(unittest.TestCase):
    def test_decodes_claims(self) -> None:
        claims = bdkq_token.decode_jwt_claims(make_token(3600, extra={"userId": "u1"}))
        self.assertEqual(claims.get("userId"), "u1")
        self.assertIn("exp", claims)

    def test_garbage_is_empty(self) -> None:
        for token in ("", "abc", "a.b", "a.!!!.c", "..."):
            with self.subTest(token=token):
                self.assertEqual(bdkq_token.decode_jwt_claims(token), {})

    def test_expiry(self) -> None:
        token = make_token(600)
        expiry = bdkq_token.token_expiry(token)
        self.assertIsNotNone(expiry)
        self.assertGreater(expiry, int(time.time()) + 500)
        self.assertIsNone(bdkq_token.token_expiry("not-a-jwt"))

    def test_seconds_left(self) -> None:
        left = bdkq_token.token_seconds_left(make_token(600))
        self.assertTrue(590 <= left <= 601)
        self.assertIsNone(bdkq_token.token_seconds_left("not-a-jwt"))


class NeedsRefreshTest(unittest.TestCase):
    def test_empty_needs_refresh(self) -> None:
        self.assertTrue(bdkq_token.needs_refresh(""))

    def test_fresh_token_does_not(self) -> None:
        self.assertFalse(bdkq_token.needs_refresh(make_token(7200)))

    def test_expired_needs_refresh(self) -> None:
        self.assertTrue(bdkq_token.needs_refresh(make_token(-60)))

    def test_inside_margin_needs_refresh(self) -> None:
        self.assertTrue(bdkq_token.needs_refresh(make_token(60)))

    def test_non_jwt_is_left_alone(self) -> None:
        # 不是 JWT 就无法判断有效期，交给服务端回 401，别盲目换
        self.assertFalse(bdkq_token.needs_refresh("opaque-token"))


class CacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.config_path = Path(self.tmp.name) / "config.bdkq.local.json"
        self.config_path.write_text("{}", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_roundtrip(self) -> None:
        token = make_token(3600)
        bdkq_token.save_cache(self.config_path, token, "abc123")
        cache = bdkq_token.load_cache(self.config_path)
        self.assertEqual(cache["access_token"], token)
        self.assertEqual(cache["api_version"], "abc123")
        self.assertIsNotNone(cache["exp"])

    def test_file_is_private(self) -> None:
        bdkq_token.save_cache(self.config_path, make_token(600), "v")
        mode = os.stat(bdkq_token.cache_path(self.config_path)).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_missing_cache(self) -> None:
        self.assertEqual(bdkq_token.load_cache(self.config_path), {})

    def test_broken_cache(self) -> None:
        bdkq_token.cache_path(self.config_path).write_text("{not json", encoding="utf-8")
        self.assertEqual(bdkq_token.load_cache(self.config_path), {})


class EnsureClientTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.config_path = Path(self.tmp.name) / "config.bdkq.local.json"
        self.config_path.write_text("{}", encoding="utf-8")
        self.calls: list[str] = []

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def refresh(self, client: BdkqClient) -> BdkqClient:
        self.calls.append("refresh")
        client.access_token = make_token(7200)
        client.api_version = "fresh"           # api_version 每次登录都会变
        return client

    def test_uses_config_token_when_fresh(self) -> None:
        token = make_token(7200)
        client, source = bdkq_token.ensure_client(
            base_config(token, "cfg"), self.config_path, refresh_fn=self.refresh)
        self.assertEqual(source, "config")
        self.assertEqual(client.access_token, token)
        self.assertEqual(self.calls, [])

    def test_uses_cache_when_config_token_stale(self) -> None:
        cached = make_token(7200)
        bdkq_token.save_cache(self.config_path, cached, "cached")
        client, source = bdkq_token.ensure_client(
            base_config(make_token(-10), "cfg"), self.config_path, refresh_fn=self.refresh)
        self.assertEqual(source, "cache")
        self.assertEqual(client.access_token, cached)
        self.assertEqual(client.api_version, "cached")
        self.assertEqual(self.calls, [])

    def test_refreshes_when_nothing_usable(self) -> None:
        client, source = bdkq_token.ensure_client(
            base_config(""), self.config_path, refresh_fn=self.refresh)
        self.assertEqual(source, "refresh")
        self.assertEqual(self.calls, ["refresh"])
        self.assertEqual(client.api_version, "fresh")
        # 换完要落到缓存里，下次不用再换
        self.assertEqual(bdkq_token.load_cache(self.config_path)["access_token"], client.access_token)

    def test_force_ignores_valid_token(self) -> None:
        client, source = bdkq_token.ensure_client(
            base_config(make_token(7200)), self.config_path, force=True, refresh_fn=self.refresh)
        self.assertEqual(source, "refresh")
        self.assertEqual(self.calls, ["refresh"])
        self.assertEqual(client.api_version, "fresh")

    def test_expired_cache_also_refreshes(self) -> None:
        bdkq_token.save_cache(self.config_path, make_token(-100), "old")
        _, source = bdkq_token.ensure_client(
            base_config(""), self.config_path, refresh_fn=self.refresh)
        self.assertEqual(source, "refresh")


if __name__ == "__main__":
    unittest.main()
