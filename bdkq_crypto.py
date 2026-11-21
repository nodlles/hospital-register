#!/usr/bin/env python3
"""北京大学口腔医院小程序（v331）的签名与国密加解密实现。

纯标准库实现，便于直接并进 hospital-register（项目本身不依赖第三方包）。

接口侧的约定（从 app-service.js 逆向得到）：

请求头
    access_token  登录后拿到的 token
    request_otp   uuid4
    request_time  毫秒时间戳
    rid           md5(token)[8:24] + "#" + md5(随机)[8:24]
    signature     见 build_signature()

POST 请求体
    {"data": sm4_encrypt(json(payload), key=signature[24:40] 的 ASCII)}

响应
    {"data": "<hex>"}，key = 相邻字符互换后的 sm3(signature + ":" + secret)[24:40]
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import random
import time
import urllib.parse
import uuid

API_SECRET = "nY-Pksdkjfiwejrksdf_LsJP_@#(*$##)"
JUMP_ENC_KEY = "Gu3V0qoBJA91xIgj"

# ---------------------------------------------------------------- SM3

_IV = [
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
]

_MASK32 = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _p1(x: int) -> int:
    return (x ^ _rotl(x, 15) ^ _rotl(x, 23)) & _MASK32


def _p0(x: int) -> int:
    return (x ^ _rotl(x, 9) ^ _rotl(x, 17)) & _MASK32


def _sm3_pad(data: bytes) -> bytes:
    length = len(data)
    bits = (length * 8) & 0xFFFFFFFFFFFFFFFF
    data += b"\x80"
    data += b"\x00" * ((56 - (length + 1) % 64) % 64)
    return data + bits.to_bytes(8, "big")


def sm3(data: bytes) -> bytes:
    v = list(_IV)
    padded = _sm3_pad(data)
    for offset in range(0, len(padded), 64):
        block = padded[offset:offset + 64]
        w = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(16)]
        for j in range(16, 68):
            w.append(
                _p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                ^ _rotl(w[j - 13], 7)
                ^ w[j - 6]
                & _MASK32
            )
        w1 = [w[j] ^ w[j + 4] for j in range(64)]
        a, b, c, d, e, f, g, h = v
        for j in range(64):
            if j < 16:
                t = 0x79CC4519
            else:
                t = 0x7A879D8A
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & _MASK32, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            if j < 16:
                ff = a ^ b ^ c
                gg = e ^ f ^ g
            else:
                ff = (a & b) | (a & c) | (b & c)
                gg = (e & f) | ((~e & _MASK32) & g)
            tt1 = (ff + d + ss2 + w1[j]) & _MASK32
            tt2 = (gg + h + ss1 + w[j]) & _MASK32
            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = _p0(tt2)
        v = [
            v[0] ^ a, v[1] ^ b, v[2] ^ c, v[3] ^ d,
            v[4] ^ e, v[5] ^ f, v[6] ^ g, v[7] ^ h,
        ]
    return b"".join(x.to_bytes(4, "big") for x in v)


def sm3_hex(text: str | bytes) -> str:
    if isinstance(text, str):
        text = text.encode("utf-8")
    return sm3(text).hex()


# ---------------------------------------------------------------- SM4

_SBOX = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
]

_FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
_CK = [
    int.from_bytes(bytes(((4 * i + j) * 7) % 256 for j in range(4)), "big")
    for i in range(32)
]


def _sm4_tau(a: int) -> int:
    return int.from_bytes(bytes(_SBOX[b] for b in a.to_bytes(4, "big")), "big")


def _sm4_key_schedule(key: bytes) -> list[int]:
    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes")
    k = [
        int.from_bytes(key[i * 4:i * 4 + 4], "big") ^ _FK[i] for i in range(4)
    ]
    rk = []
    for i in range(32):
        b = k[1] ^ k[2] ^ k[3] ^ _CK[i]
        t = _sm4_tau(b)
        t = (t ^ _rotl(t, 13) ^ _rotl(t, 23)) & _MASK32
        nk = k[0] ^ t
        k = [k[1], k[2], k[3], nk]
        rk.append(nk)
    return rk


def _sm4_round(x0, x1, x2, x3, rk):
    b = x1 ^ x2 ^ x3 ^ rk
    t = _sm4_tau(b)
    t = (t ^ _rotl(t, 2) ^ _rotl(t, 10) ^ _rotl(t, 18) ^ _rotl(t, 24)) & _MASK32
    return x0 ^ t


def _sm4_block(block: bytes, rk: list[int], decrypt: bool = False) -> bytes:
    x = [int.from_bytes(block[i * 4:i * 4 + 4], "big") for i in range(4)]
    keys = list(reversed(rk)) if decrypt else rk
    for i in range(32):
        x = [x[1], x[2], x[3], _sm4_round(x[0], x[1], x[2], x[3], keys[i])]
    return b"".join(v.to_bytes(4, "big") for v in (x[3], x[2], x[1], x[0]))


def sm4_encrypt(data: bytes, key: bytes) -> bytes:
    rk = _sm4_key_schedule(key)
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    return b"".join(
        _sm4_block(data[i:i + 16], rk) for i in range(0, len(data), 16)
    )


def sm4_decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("SM4 ciphertext length must be a multiple of 16")
    rk = _sm4_key_schedule(key)
    out = b"".join(
        _sm4_block(data[i:i + 16], rk, decrypt=True) for i in range(0, len(data), 16)
    )
    pad = out[-1]
    if 1 <= pad <= 16:
        out = out[:-pad]
    return out


# ---------------------------------------------------------------- 签名

def _escape_param(value: str) -> str:
    """按前端 O() 的规则转义：可打印 ASCII 原样，其余转成 \\uXXXX。"""
    out = []
    for ch in value:
        code = ord(ch)
        if 32 <= code < 127:
            out.append(ch)
        else:
            out.append("\\u%04x" % code)
    return out


def _sign_value(value) -> str:
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value).strip()


def _is_blank(value) -> bool:
    if value is None:
        return True
    text = _sign_value(value)
    lowered = text.lower()
    return (
        text == ""
        or lowered in ("null", "undefined", "{}", "[]")
        or len(text) > 2048
    )


def build_signature(
    *,
    query: dict,
    body_text: str,
    otp: str,
    request_time: int,
    secret: str = API_SECRET,
) -> str:
    parts = []
    for key in sorted(query):
        value = query[key]
        if _is_blank(value):
            continue
        parts.append(f"{''.join(_escape_param(str(key)))}={''.join(_escape_param(_sign_value(value)))}")
    if body_text and not _is_blank(body_text):
        parts.append("".join(_escape_param(body_text)))
    parts.append(f"requesttime={request_time}")
    parts.append(f"requestotp={otp}")
    parts.append(f"secret={secret}")

    joined = "&".join(parts)
    c = sm3_hex(f"{request_time}##{secret}")
    d = sm3_hex(f"{otp}##{secret}")
    f = base64.b64encode(joined.encode("utf-8")).decode()
    return sm3_hex(f"[{c}#{sm3_hex(f)}#{d}]")


def new_otp() -> str:
    return str(uuid.uuid4())


def make_rid(access_token: str | None = None) -> str:
    token_hash = hashlib.md5((access_token or "").encode()).hexdigest()
    rand = "%x%06x%04x%06x" % (
        int(time.time()),
        random.randint(0, 0xFFFFFF),
        random.randint(0, 0xFFFF),
        random.randint(0, 0xFFFFFF),
    )
    return f"{token_hash[8:24]}#{hashlib.md5(rand.encode()).hexdigest()[8:24]}"


# ---------------------------------------------------------------- 报文

def encrypt_body(payload: dict, signature: str) -> str:
    key = signature[24:40].encode("ascii")
    plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return sm4_encrypt(plain.encode("utf-8"), key).hex()


def response_key(signature: str, secret: str = API_SECRET) -> bytes:
    """响应解密用的 key。

    原文：sm3(P(o) ? o : o.split("").reverse().join(""))，o = signature + ":" + secret。
    P() 是「空值判断」而不是「可打印判断」，所以 o 永远非空 → 永远走反转分支。
    这一步之前漏了，导致拿真实响应解不出来（2026-11-18 用真服务器校准）。
    """
    material = f"{signature}:{secret}"[::-1]
    raw = list(sm3_hex(material)[24:40])
    for i in range(0, len(raw) - 1, 2):
        raw[i], raw[i + 1] = raw[i + 1], raw[i]
    return "".join(raw).encode("ascii")


def decrypt_response(data_hex: str, signature: str, secret: str = API_SECRET) -> dict:
    if isinstance(data_hex, dict):
        data_hex = data_hex.get("data", "")
    if not data_hex:
        return {}
    plain = sm4_decrypt(bytes.fromhex(data_hex), response_key(signature, secret))
    return json.loads(plain.decode("utf-8"))


def build_headers(
    *,
    query: dict | None = None,
    payload: dict | None = None,
    access_token: str = "",
) -> tuple[dict, str | None]:
    """返回 (headers, 加密后的请求体 JSON 字符串)。GET 时 body 为 None。"""
    query = query or {}
    otp = new_otp()
    request_time = int(time.time() * 1000)
    body_text = ""
    if payload is not None:
        body_text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    signature = build_signature(
        query=query, body_text=body_text, otp=otp, request_time=request_time
    )
    headers = {
        "Content-Type": "application/json",
        "access_token": access_token or "",
        "request_otp": otp,
        "request_time": str(request_time),
        "signature": signature,
        "rid": make_rid(access_token),
    }
    if payload is None:
        return headers, None
    return headers, json.dumps({"data": encrypt_body(payload, signature)})


def encode_query(query: dict) -> str:
    if not query:
        return ""
    pieces = []
    for key, value in query.items():
        if value is None:
            continue
        pieces.append(f"{urllib.parse.quote(str(key))}={urllib.parse.quote(_sign_value(value))}")
    return "&".join(pieces)
