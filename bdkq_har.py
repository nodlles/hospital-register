#!/usr/bin/env python3
"""从 HAR 文件或 DevTools 的 cURL 命令里抠出北大口腔小程序的登录态。

用途：这个医院的接口要 access_token 才能读号源，token 只能靠微信运行时拿。
既然不方便每次都跑模拟器，就把浏览器/代理抓到的 HAR 或 cURL 丢进来，自动
生成 config.bdkq.local.json，供 bdkq_probe.py / bdkq_watch.py 直接用。

支持三种输入：
  1. .har（Chrome/Charles/Proxyman 导出的 HTTP Archive）
  2. .txt（DevTools 右键 Copy as cURL 粘出来的文本，可以一次粘多条）
  3. 任何含 app.bdkq.mingxuan.store 请求行的文本（例如 logcat 日志）

用法：
  python3 bdkq_har.py capture.har -o config.bdkq.local.json
  python3 bdkq_har.py curl.txt   -o config.bdkq.local.json
  python3 bdkq_har.py curl.txt --show     # 只打印抠到的东西，不落盘
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import urllib.parse
from pathlib import Path
from typing import Any

DEFAULT_TENANT = "xcx-bjdxkqyy-wx"
TENANT_RE = re.compile(r"/([a-z0-9-]+-wx)@([A-Za-z0-9._-]+)(/|$)")
URL_RE = re.compile(r"https?://[^\s\"'\\<>)]+")

# 抓 HAR 时这些头必留，其余（Cookie、Accept-Encoding 等）交给客户端自己管
KEEP_HEADERS = (
    "access_token",
    "request_time",
    "request_otp",
    "signature",
    "rid",
    "x-version",
    "referer",
    "user-agent",
    "origin",
    "content-type",
)


def _norm_url(url: str) -> str:
    """去掉 query 和 fragment，只留到 path。"""
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _tenant_of(url: str) -> tuple[str, str]:
    """从 URL path 里取 (tenant, version)。取不到就给默认值。"""
    match = TENANT_RE.search(urllib.parse.urlsplit(url).path)
    if match:
        return match.group(1), match.group(2)
    return DEFAULT_TENANT, "default"


def _origin_of(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _split_biz_path(url: str) -> str:
    path = urllib.parse.urlsplit(url).path
    marker = TENANT_RE.search(path)
    if marker:
        tail = path[marker.end():]
        return tail if tail.startswith("/") else "/" + tail
    return path


# --------------------------------------------------------------- HAR

def _from_har(data: dict[str, Any]) -> list[dict[str, Any]]:
    entries = (data.get("log") or {}).get("entries") or []
    out: list[dict[str, Any]] = []
    for entry in entries:
        request = entry.get("request") or {}
        url = request.get("url") or ""
        if "mingxuan.store" not in url:
            continue
        headers: dict[str, str] = {}
        for item in request.get("headers") or []:
            name = str(item.get("name") or "").strip().lower()
            if name:
                headers[name] = str(item.get("value") or "")
        body = ((request.get("postData") or {}).get("text")) or ""
        out.append(
            {
                "url": url,
                "method": (request.get("method") or "GET").upper(),
                "headers": headers,
                "body": body,
            }
        )
    return out


# --------------------------------------------------------------- cURL

def _parse_curl_blocks(text: str) -> list[dict[str, Any]]:
    """把一段文本里所有 curl 命令切出来逐条解析。也兼容裸 URL 行。"""
    calls: list[dict[str, Any]] = []
    # 用行首 curl 切块，续行（\ 结尾或紧跟 -H）都算同一条
    blocks: list[list[str]] = []
    current: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.strip().startswith("curl"):
            if current:
                blocks.append(current)
            current = [line.strip()]
        elif current is not None and line.strip():
            if current:
                current.append(line.strip())
    if current:
        blocks.append(current)

    for block in blocks:
        joined = " ".join(part.rstrip("\\").strip() for part in block)
        try:
            tokens = shlex.split(joined)
        except ValueError:
            continue
        if not tokens or tokens[0] != "curl":
            continue
        url = ""
        method = ""
        headers: dict[str, str] = {}
        body = ""
        i = 1
        while i < len(tokens):
            token = tokens[i]
            value = tokens[i + 1] if i + 1 < len(tokens) else ""
            if token in ("-H", "--header"):
                name, _, val = value.partition(":")
                if name.strip():
                    headers[name.strip().lower()] = val.strip()
                i += 2
            elif token in ("-X", "--request"):
                method = value.upper()
                i += 2
            elif token in ("--data", "--data-raw", "--data-binary", "-d", "--data-ascii"):
                body = value
                i += 2
            elif token in ("--url",):
                url = value
                i += 2
            elif token.startswith("http"):
                url = token
                i += 1
            else:
                i += 1
        if url and "mingxuan.store" in url:
            calls.append(
                {
                    "url": url,
                    "method": method or ("POST" if body else "GET"),
                    "headers": headers,
                    "body": body,
                }
            )

    # 兜底：纯文本里散落的 URL（例如 logcat）
    if not calls:
        for match in URL_RE.finditer(text):
            url = match.group(0)
            if "mingxuan.store" in url:
                calls.append({"url": url, "method": "GET", "headers": {}, "body": ""})
    return calls


# --------------------------------------------------------------- 汇总

def summarize(calls: list[dict[str, Any]]) -> dict[str, Any]:
    if not calls:
        raise SystemExit("没在输入里找到 mingxuan.store 的请求，检查一下抓包导出格式")

    # 登录成功的那些请求才有 access_token，取最后一个非空的
    token = ""
    version = ""
    referer = ""
    ua = ""
    origin = ""
    for call in calls:
        headers = call["headers"]
        if headers.get("access_token"):
            token = headers["access_token"]
        if headers.get("x-version"):
            version = headers["x-version"]
        referer = headers.get("referer") or referer
        ua = headers.get("user-agent") or ua
        origin = headers.get("origin") or origin

    # base_url 去掉 tenant@version 尾巴
    first = _norm_url(calls[0]["url"])
    marker = TENANT_RE.search(urllib.parse.urlsplit(first).path)
    if marker:
        prefix_path = urllib.parse.urlsplit(first).path[: marker.start()]
        base_url = _origin_of(first) + prefix_path.rstrip("/")
    else:
        base_url = _origin_of(first)

    tenant, _ = _tenant_of(calls[0]["url"])
    paths = sorted({_split_biz_path(call["url"]) for call in calls})
    hosts = sorted({urllib.parse.urlsplit(call["url"]).netloc for call in calls})

    return {
        "base_url": base_url,
        "tenant": tenant,
        "api_version": version or "default",
        "access_token": token,
        "referer": referer,
        "user_agent": ua,
        "origin": origin,
        "hosts": hosts,
        "paths": paths,
        "request_count": len(calls),
    }


def build_config(info: dict[str, Any]) -> dict[str, Any]:
    config: dict[str, Any] = {
        "base_url": info["base_url"],
        "tenant": info["tenant"],
        "api_version": info["api_version"],
        "access_token": info["access_token"],
        "referer": info["referer"],
        "user_agent": info["user_agent"],
    }
    if info.get("origin"):
        config["origin"] = info["origin"]
    return config


def load_input(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            return _from_har(json.loads(text))
        except json.JSONDecodeError:
            pass
    return _parse_curl_blocks(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="从 HAR / cURL 提取北大口腔登录态")
    parser.add_argument("input", help="HAR 文件、cURL 文本或日志文本")
    parser.add_argument("-o", "--output", default="config.bdkq.local.json", help="输出配置路径")
    parser.add_argument("--show", action="store_true", help="只打印，不写文件")
    args = parser.parse_args(argv)

    path = Path(args.input)
    if not path.exists():
        print(f"文件不存在: {path}", file=sys.stderr)
        return 2

    calls = load_input(path)
    info = summarize(calls)
    # token 只在内存里显示前 8 位，避免整段进日志
    display = dict(info)
    token = display.get("access_token") or ""
    display["access_token"] = (token[:8] + "…" + f"({len(token)} 位)") if token else "(没抓到)"
    print(json.dumps(display, ensure_ascii=False, indent=2))

    if not info["access_token"] and not args.show:
        print("警告：没抓到 access_token，生成的配置只能跑 /login/wechat 之前的接口", file=sys.stderr)

    if args.show:
        return 0

    out = Path(args.output)
    out.write_text(json.dumps(build_config(info), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out.chmod(0o600)
    print(f"\n已写入 {out}（权限 0600）")
    if info["paths"]:
        known = Path("endpoints.json")
        if known.exists():
            print(f"抓到 {len(info['paths'])} 个接口路径，可用于比对 endpoints.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
