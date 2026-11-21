#!/usr/bin/env python3
"""wxdevtools 的纯函数测试。

不碰 adb、不连 CDP：这里只证明「把采到的请求变成配置」那一段是对的。
真正的采集能力靠 `python3 wxdevtools.py --doctor` 在真机/模拟器上验。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import wxdevtools as wd  # noqa: E402


def make_request(url: str, headers: dict | None = None, *, method: str = "GET",
                 body: str = "") -> dict:
    return {"url": url, "method": method, "header": headers or {}, "body": body}


class HospitalUrlTest(unittest.TestCase):
    def test_both_supported_hospitals(self) -> None:
        self.assertTrue(wd.is_hospital_request("https://appaceso.zryhyy.com.cn/api/x"))
        self.assertTrue(wd.is_hospital_request("https://app.bdkq.mingxuan.store/api/x"))

    def test_other_hosts_rejected(self) -> None:
        for url in ("https://servicewechat.com/x", "https://example.com/app.bdkq.mingxuan.store",
                    "https://weixin.qq.com/api", "", "not a url"):
            with self.subTest(url=url):
                self.assertFalse(wd.is_hospital_request(url))

    def test_subdomain_matches(self) -> None:
        self.assertTrue(wd.is_hospital_request("https://cdn.appaceso.zryhyy.com.cn/a"))

    def test_host_of(self) -> None:
        self.assertEqual(wd.host_of("https://A.Example.com/x"), "a.example.com")
        self.assertEqual(wd.host_of(""), "")


class AuthHeaderTest(unittest.TestCase):
    def test_auth_headers(self) -> None:
        for name in ("A-Ticket", "Cookie", "Authorization", "access_token", "X-Session-Id"):
            with self.subTest(name=name):
                self.assertTrue(wd.is_auth_header(name))

    def test_plain_headers(self) -> None:
        for name in ("Content-Type", "Hos-Code", "Client-Channel", "", ":authority"):
            with self.subTest(name=name):
                self.assertFalse(wd.is_auth_header(name))


class CleanHeadersTest(unittest.TestCase):
    def test_drops_hop_by_hop_headers(self) -> None:
        cleaned = wd.clean_headers({
            "A-Ticket": "abc",
            "Host": "appaceso.zryhyy.com.cn",
            "Content-Length": "12",
            "Accept-Encoding": "gzip",
            "Connection": "keep-alive",
        })
        self.assertEqual(cleaned, {"A-Ticket": "abc"})

    def test_keeps_plain_headers_and_serialises_values(self) -> None:
        cleaned = wd.clean_headers({"Hos-Code": "01110002", "Weird": {"a": 1}})
        self.assertEqual(cleaned["Hos-Code"], "01110002")
        self.assertEqual(cleaned["Weird"], '{"a": 1}')

    def test_ignores_non_dict(self) -> None:
        self.assertEqual(wd.clean_headers(None), {})
        self.assertEqual(wd.clean_headers([("a", "b")]), {})

    def test_drops_empty_values(self) -> None:
        self.assertEqual(wd.clean_headers({"A": "", "B": None}), {})


class MergeSetCookieTest(unittest.TestCase):
    def test_merges_into_existing_cookie(self) -> None:
        headers = wd.merge_set_cookie({"Cookie": "sid=old; keep=1"}, "sid=new; Path=/; HttpOnly")
        self.assertIn("sid=new", headers["Cookie"])
        self.assertIn("keep=1", headers["Cookie"])

    def test_accepts_list(self) -> None:
        headers = wd.merge_set_cookie({}, ["a=1; Path=/", "b=2; Path=/"])
        self.assertEqual(headers["Cookie"], "a=1; b=2")

    def test_accepts_dict(self) -> None:
        headers = wd.merge_set_cookie({}, {"token": "t0k"})
        self.assertEqual(headers["Cookie"], "token=t0k")

    def test_no_cookie_left_when_nothing_to_merge(self) -> None:
        headers = wd.merge_set_cookie({"A-Ticket": "x"}, None)
        self.assertNotIn("Cookie", headers)


class ChooseRequestTest(unittest.TestCase):
    def test_prefers_auth_rich_business_request(self) -> None:
        requests = [
            make_request("https://appaceso.zryhyy.com.cn/api/mobile/common/banner/list",
                         {"Content-Type": "application/json"}),
            make_request("https://appaceso.zryhyy.com.cn/api/mobile/source/locking",
                         {"A-Ticket": "t", "Hos-Code": "1"}, method="POST"),
        ]
        chosen = wd.choose_request(requests)
        self.assertIsNotNone(chosen)
        self.assertTrue(chosen["url"].endswith("/source/locking"))

    def test_ignores_non_hospital_requests(self) -> None:
        requests = [make_request("https://servicewechat.com/x", {"Cookie": "a=1"})]
        self.assertIsNone(wd.choose_request(requests))

    def test_empty_input(self) -> None:
        self.assertIsNone(wd.choose_request([]))

    def test_score_grows_with_auth_headers(self) -> None:
        bare = make_request("https://app.bdkq.mingxuan.store/a")
        rich = make_request("https://app.bdkq.mingxuan.store/a", {"Cookie": "a=1", "Authorization": "b"})
        self.assertGreater(wd.request_score(rich), wd.request_score(bare))


class ToImportPayloadTest(unittest.TestCase):
    def test_splits_url_and_keeps_headers(self) -> None:
        payload = wd.to_import_payload(
            make_request("https://appaceso.zryhyy.com.cn/api/mobile/source/locking?x=1",
                         {"A-Ticket": "t", "Host": "appaceso.zryhyy.com.cn"}, method="post"))
        self.assertEqual(payload["base_url"], "https://appaceso.zryhyy.com.cn")
        self.assertEqual(payload["path"], "/api/mobile/source/locking")
        self.assertEqual(payload["method"], "POST")
        self.assertEqual(payload["headers"], {"A-Ticket": "t"})

    def test_fills_user_agent_and_referer(self) -> None:
        payload = wd.to_import_payload(make_request("https://app.bdkq.mingxuan.store/x"),
                                       user_agent="UA/1", referer="https://ref/")
        self.assertEqual(payload["headers"]["User-Agent"], "UA/1")
        self.assertEqual(payload["headers"]["Referer"], "https://ref/")

    def test_does_not_override_captured_values(self) -> None:
        payload = wd.to_import_payload(
            make_request("https://app.bdkq.mingxuan.store/x",
                         {"User-Agent": "captured", "Referer": "captured-ref"}),
            user_agent="other", referer="other-ref")
        self.assertEqual(payload["headers"]["User-Agent"], "captured")
        self.assertEqual(payload["headers"]["Referer"], "captured-ref")

    def test_merges_cookies_from_matching_response(self) -> None:
        url = "https://app.bdkq.mingxuan.store/x"
        payload = wd.to_import_payload(
            make_request(url), [{"url": url, "header": {"Set-Cookie": "sid=1; Path=/"}}])
        self.assertEqual(payload["headers"]["Cookie"], "sid=1")

    def test_ignores_response_of_another_url(self) -> None:
        payload = wd.to_import_payload(
            make_request("https://app.bdkq.mingxuan.store/x"),
            [{"url": "https://app.bdkq.mingxuan.store/y", "header": {"Set-Cookie": "sid=1"}}])
        self.assertNotIn("Cookie", payload["headers"])


class SummarizeTest(unittest.TestCase):
    def test_reports_header_names_only(self) -> None:
        lines = wd.summarize([make_request("https://appaceso.zryhyy.com.cn/api/mobile/x",
                                          {"A-Ticket": "SECRET-VALUE", "Hos-Code": "01110002"},
                                          method="POST")])
        self.assertEqual(len(lines), 1)
        self.assertIn("A-Ticket", lines[0])
        self.assertIn("Hos-Code", lines[0])
        self.assertNotIn("SECRET-VALUE", lines[0])
        self.assertNotIn("01110002", lines[0])

    def test_skips_other_hosts(self) -> None:
        self.assertEqual(wd.summarize([make_request("https://example.com/x")]), [])

    def test_does_not_leak_path_query_secrets(self) -> None:
        line = wd.summarize([make_request(
            "https://app.bdkq.mingxuan.store/api/x?_t=1", {"Cookie": "sid=SECRET"})])[0]
        self.assertIn("/api/x", line)
        self.assertNotIn("SECRET", line)


class SocketNamesTest(unittest.TestCase):
    def test_extracts_and_sorts(self) -> None:
        text = ("00000000: 00000002 00000000 00010000 0001 01 12345 "
                "@webview_devtools_remote_3708\n"
                "00000000: 00000002 00000000 00010000 0001 01 6789 "
                "@webview_devtools_remote_3418\n"
                "@devtools_remote\n")
        self.assertEqual(wd.socket_names_from(text),
                         ["webview_devtools_remote_3418", "webview_devtools_remote_3708"])

    def test_empty(self) -> None:
        self.assertEqual(wd.socket_names_from(""), [])
        self.assertEqual(wd.socket_names_from(None), [])  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
