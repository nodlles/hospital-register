#!/usr/bin/env python3
"""纯标准库 AES 解密（128/192/256，CBC + PKCS7）。

北医三院小程序的**响应**是 AES 加密的：

    lib/utils 里的 decryptAes(e, r, n)
        key = r  = loginUserInfo.userId      （24 字符 -> AES-192）
        iv  = n.substring(n.length-16)       = token 末 16 字符
        e   = 十六进制密文 -> 先 hex.parse 再 base64 喂给 CryptoJS

项目里没有 pycryptodome / cryptography，也不打算引，所以这里自己实现一份，
只做「解一个 AES 分组」这一件事，连 CBC 也一并写掉。

已用 FIPS-197 附录 C 的三条向量自测（128/192/256），`python3 bysy_aes.py` 可复现。
"""

from __future__ import annotations

# FIPS-197 S-box
SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


# 解密列混合要用的 9/11/13/14，预先算成表，比每次循环快一个量级
_MUL = {m: tuple(_gmul(x, m) for x in range(256)) for m in (9, 11, 13, 14)}


def _expand_key(key: bytes) -> tuple[list[list[int]], int]:
    """AES 密钥扩展，返回 (轮密钥字数组, 轮数)。"""
    nk = len(key) // 4
    if nk not in (4, 6, 8) or len(key) % 4:
        raise ValueError(f"AES key 必须是 16/24/32 字节，收到 {len(key)}")
    nr = nk + 6
    w = [list(key[i * 4: i * 4 + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """解一个 16 字节分组。"""
    w, nr = _expand_key(key)
    cols = [list(block[i * 4: i * 4 + 4]) for i in range(4)]
    st = [[cols[c][r] for c in range(4)] for r in range(4)]

    def add_round_key(rnd: int) -> None:
        for c in range(4):
            word = w[rnd * 4 + c]
            for r in range(4):
                st[r][c] ^= word[r]

    add_round_key(nr)
    m9, m11, m13, m14 = _MUL[9], _MUL[11], _MUL[13], _MUL[14]
    for rnd in range(nr - 1, -1, -1):
        for r in range(1, 4):                       # InvShiftRows
            st[r] = st[r][-r:] + st[r][:-r]
        for r in range(4):                          # InvSubBytes
            row = st[r]
            for c in range(4):
                row[c] = INV_SBOX[row[c]]
        add_round_key(rnd)
        if rnd:                                     # InvMixColumns
            for c in range(4):
                a0, a1, a2, a3 = st[0][c], st[1][c], st[2][c], st[3][c]
                st[0][c] = m14[a0] ^ m11[a1] ^ m13[a2] ^ m9[a3]
                st[1][c] = m9[a0] ^ m14[a1] ^ m11[a2] ^ m13[a3]
                st[2][c] = m13[a0] ^ m9[a1] ^ m14[a2] ^ m11[a3]
                st[3][c] = m11[a0] ^ m13[a1] ^ m9[a2] ^ m14[a3]
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[c * 4 + r] = st[r][c]
    return bytes(out)


def decrypt_cbc_pkcs7(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC 解密并去掉 PKCS7 填充；填充不合法时原样返回（交给调用方判断）。"""
    if len(iv) != 16:
        raise ValueError(f"iv 必须是 16 字节，收到 {len(iv)}")
    if len(data) % 16:
        raise ValueError(f"密文长度 {len(data)} 不是 16 的倍数")
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i: i + 16]
        dec = decrypt_block(blk, key)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    pad = out[-1] if out else 0
    if 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad:
        out = out[:-pad]
    return bytes(out)


def decrypt_hex_cbc(text: str, key: bytes, iv: bytes) -> bytes:
    """服务端返回的就是一串十六进制大写字母，直接吃它。"""
    return decrypt_cbc_pkcs7(bytes.fromhex(text.strip()), key, iv)


if __name__ == "__main__":
    # FIPS-197 附录 C.1/C.2/C.3：三种密钥长度各解一条，明文都是
    # 00112233445566778899aabbccddeeff
    cases = (
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
         "8ea2b7ca516745bfeafc49904b496089"),
    )
    want = "00112233445566778899aabbccddeeff"
    for k, ct in cases:
        got = decrypt_block(bytes.fromhex(ct), bytes.fromhex(k)).hex()
        print(f"AES-{len(k) * 4}: {'ok' if got == want else f'FAIL {got}'}")
