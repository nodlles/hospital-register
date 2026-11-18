#!/usr/bin/env python3
"""bdkq_crypto.py 的离线测试。

两类测试：
  1. 国标向量 —— SM3/SM4 是否实现对了（这两条与医院无关，标准可查）
  2. 固定向量 —— 签名/加密的拼接方式是否被我改坏（回归用）

说明：签名和 URL 拼接规则是从混淆代码逆出来的，没有服务端可对照。
所以第 2 类只能证明「和之前跑出来的一致」，不能证明「和服务器一致」。
真正的校准要靠 bdkq_probe.py 打一次真实接口。
"""

from __future__ import annotations

import base64
import json
import sys
import unittest

ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bdkq_crypto import (  # noqa: E402
    API_SECRET,
    build_headers,
    build_signature,
    decrypt_response,
    encode_query,
    encrypt_body,
    make_rid,
    new_otp,
    response_key,
    sm3_hex,
    sm4_decrypt,
    sm4_encrypt,
)


class TestSM3(unittest.TestCase):
    def test_standard_vectors(self) -> None:
        self.assertEqual(sm3_hex("abc"), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
        self.assertEqual(
            sm3_hex("abcd" * 16),
            "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
        )

    def test_empty_input(self) -> None:
        self.assertEqual(sm3_hex(""), "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b")


class TestSM4(unittest.TestCase):
    def test_standard_vector(self) -> None:
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plain = bytes.fromhex("0123456789abcdeffedcba9876543210")
        cipher = sm4_encrypt(plain, key)
        # 国标向量是裸分组，我们这条路永远补 PKCS7（对齐时补一整块再加密），
        # 所以第一块对齐标准向量，总长是 32 字节，解密能还原。
        self.assertEqual(cipher[:16].hex(), "681edf34d206965e86b3e94f536e4246")
        self.assertEqual(len(cipher), 32)
        self.assertEqual(sm4_decrypt(cipher, key), plain)

    def test_padding_roundtrip(self) -> None:
        key = b"0123456789abcdef"
        for text in ("", "a", "中文测试", "x" * 15, "y" * 16, "z" * 17):
            blob = sm4_encrypt(text.encode(), key)
            self.assertEqual(len(blob) % 16, 0)
            self.assertEqual(sm4_decrypt(blob, key).decode(), text)


class TestSignature(unittest.TestCase):
    """固定向量。数值变了要么是改了算法，要么是改了拼接顺序。"""

    OTP = "6f1d2c3b-4e5a-4b7c-8d9e-0a1b2c3d4e5f"
    TIME = 1763440000123

    def test_fixed_signature(self) -> None:
        sig = build_signature(
            query={"areaCode": "0", "withRemain": "1"},
            body_text="",
            otp=self.OTP,
            request_time=self.TIME,
        )
        self.assertEqual(
            sig, "d9b36704219a822a13574d3d6a4060068674b6f2746ffe2e36051462ef2382cc"
        )

    def test_query_order_independent(self) -> None:
        a = build_signature(query={"b": "2", "a": "1"}, body_text="",
                           otp=self.OTP, request_time=self.TIME)
        b = build_signature(query={"a": "1", "b": "2"}, body_text="",
                           otp=self.OTP, request_time=self.TIME)
        self.assertEqual(a, b)

    def test_blank_values_skipped(self) -> None:
        blank = build_signature(
            query={"a": "1", "b": "", "c": None, "d": "{}", "e": "[]"},
            body_text="", otp=self.OTP, request_time=self.TIME,
        )
        only_a = build_signature(query={"a": "1"}, body_text="",
                                otp=self.OTP, request_time=self.TIME)
        self.assertEqual(blank, only_a)

    def test_body_changes_signature(self) -> None:
        with_body = build_signature(query={}, body_text='{"a":1}', otp=self.OTP,
                                    request_time=self.TIME)
        without = build_signature(query={}, body_text="", otp=self.OTP,
                                  request_time=self.TIME)
        self.assertNotEqual(with_body, without)

    def test_signature_shape(self) -> None:
        sig = build_signature(query={"a": "1"}, body_text="", otp=self.OTP,
                              request_time=self.TIME)
        self.assertEqual(len(sig), 64)
        int(sig, 16)  # 必须是合法 hex
        # 前两段的拼法：sm3("[" + c + "#" + sm3(f) + "#" + d + "]")
        self.assertEqual(sig, sig.lower())


class TestOtpAndRid(unittest.TestCase):
    def test_otp_is_uuid4(self) -> None:
        otp = new_otp()
        parts = otp.split("-")
        self.assertEqual([len(p) for p in parts], [8, 4, 4, 4, 12])
        self.assertEqual(parts[2][0], "4")
        self.assertIn(parts[3][0], "89ab")

    def test_rid_shape(self) -> None:
        rid = make_rid("token-abc")
        left, sep, right = rid.partition("#")
        self.assertEqual(sep, "#")
        self.assertEqual(len(left), 16)
        self.assertEqual(len(right), 16)
        int(left, 16)
        int(right, 16)

    def test_rid_differs_per_call(self) -> None:
        self.assertNotEqual(make_rid("t"), make_rid("t"))


class TestBodyAndResponse(unittest.TestCase):
    SIG = "d9b36704219a822a13574d3d6a4060068674b6f2746ffe2e36051462ef2382cc"

    def test_encrypt_body_is_hex(self) -> None:
        hexed = encrypt_body({"code": "abc"}, self.SIG)
        self.assertEqual(len(hexed) % 32, 0)
        bytes.fromhex(hexed)

    def test_body_key_is_signature_slice(self) -> None:
        # 请求体用的 key = signature[24:40]，与响应 key 不是同一个
        self.assertEqual(self.SIG[24:40], "6a4060068674b6f2")
        self.assertEqual(response_key(self.SIG).decode(), "f69b5d5cc8fa8a6c")
        self.assertNotEqual(self.SIG[24:40], response_key(self.SIG).decode())

    def test_response_roundtrip(self) -> None:
        payload = {"status": 0, "message": "ok", "data": {"lists": [{"deptCode": "123"}]}}
        key = response_key(self.SIG)
        hexed = sm4_encrypt(json.dumps(payload, ensure_ascii=False).encode(), key).hex()
        got = decrypt_response({"data": hexed}, self.SIG)
        self.assertEqual(got["status"], 0)
        self.assertEqual(got["data"]["lists"][0]["deptCode"], "123")

    def test_empty_response(self) -> None:
        self.assertEqual(decrypt_response({"data": ""}, self.SIG), {})


class TestQueryEncoding(unittest.TestCase):
    def test_simple(self) -> None:
        self.assertEqual(encode_query({"areaCode": "0", "withRemain": "1"}),
                         "areaCode=0&withRemain=1")

    def test_none_dropped(self) -> None:
        self.assertEqual(encode_query({"a": "1", "b": None}), "a=1")

    def test_unicode_quoted(self) -> None:
        self.assertEqual(encode_query({"kw": "牙"}), "kw=%E7%89%99")

    def test_empty(self) -> None:
        self.assertEqual(encode_query({}), "")


class TestApiSecret(unittest.TestCase):
    def test_secret_unchanged(self) -> None:
        self.assertEqual(API_SECRET, "nY-Pksdkjfiwejrksdf_LsJP_@#(*$##)")

    def test_base64_stable(self) -> None:
        joined = "a=1&requesttime=1&requestotp=o&secret=" + API_SECRET
        self.assertTrue(base64.b64decode(base64.b64encode(joined.encode())))


class TestHeaders(unittest.TestCase):
    def test_get_has_no_body(self) -> None:
        headers, body = build_headers(query={"a": "1"}, access_token="tok")
        self.assertIsNone(body)
        self.assertEqual(headers["access_token"], "tok")
        for key in ("request_otp", "request_time", "signature", "rid"):
            self.assertIn(key, headers)
        self.assertEqual(len(headers["signature"]), 64)

    def test_post_body_wrapped(self) -> None:
        headers, body = build_headers(payload={"code": "x"}, access_token="tok")
        self.assertIsInstance(body, str)
        parsed = json.loads(body)
        self.assertEqual(set(parsed), {"data"})
        bytes.fromhex(parsed["data"])


class TestClientUrl(unittest.TestCase):
    def test_version_rules(self) -> None:
        from bdkq_client import BdkqClient

        client = BdkqClient(base_url="https://h.example", tenant="t-wx", api_version="331")
        self.assertEqual(client.url_for("/api/regist/getYyDeptList"),
                         "https://h.example/t-wx@331/api/regist/getYyDeptList")
        # 含 /online 或 /common 不加版本号
        self.assertEqual(client.url_for("/api/online/x"), "https://h.example/t-wx/api/online/x")
        self.assertEqual(client.url_for("/api/common/y"), "https://h.example/t-wx/api/common/y")
        # 登录接口固定 default
        self.assertEqual(client.url_for("/login/wechat"),
                         "https://h.example/t-wx@default/login/wechat")


if __name__ == "__main__":
    unittest.main(verbosity=2)
