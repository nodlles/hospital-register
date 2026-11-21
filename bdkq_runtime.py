#!/usr/bin/env python3
"""从 WeAppDev 运行时直接取北大口腔的登录态，不需要用户抓包。

背景：小程序换 token 的链路是 `wx.login()` 拿 code → `POST /login/wechat` 换 JWT，
每一步都要签名和国密，手工重放不了。而微信运行时（安卓模拟器里的容器）**自己**会发
真实请求，这些请求的 `access_token` 请求头和 URL 里的 `@<x-version>` 就是我们要的
两样东西。WeAppDev 的网关（默认 http://127.0.0.1:9400）把这类请求存在 `hook/store`，
于是「取登录态」变成一次 HTTP 读接口，不再需要 HAR 导出。

实测要点（2026-11-21，WeAppDev 1.0.1 + 安卓 37 模拟器）：

* `POST /v1/config {"network_capture":true}` 只是开总开关，`hook/store` 里的
  `capture` 位要等 `POST /v1/apps/{id}:restart` 之后才真正变成 true；
* 抓到的 `access_token` 请求头是**当次请求**用的那个 token。`/login/wechat` 那条
  带的是登录**之前**的旧 token，真正的新的 token 在它的响应体里（加密），所以
  优先从非登录请求的请求头取，只有登录记录时才解响应体；
* `api_version` 就是 URL 里的 `@45ff03e9` 这一段，不是 `default`（`default` 只在
  `/login/wechat` 用）；
* 域名在公共 DNS 里是 127.0.0.1，模拟器要先把 `tcp:443` 反代出来才能访问，
  见 BDKQ.md 的「adb reverse」一节。

用法：
    python3 bdkq_runtime.py                        # 打印能取到的 token 摘要
    python3 bdkq_runtime.py --write config.bdkq.json   # 写回配置
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from bdkq_crypto import decrypt_response
from bdkq_token import token_seconds_left

DEFAULT_GATEWAY = "http://127.0.0.1:9400"
BDKQ_APP_ID = "wxf47aa38d871be854"
BDKQ_HOST = "app.bdkq.mingxuan.store"

_VERSION_RE = re.compile(r"@([^/]+)/")


class RuntimeLiftError(RuntimeError):
    """取不到登录态。"""


def _json(url: str, *, method: str = "GET", body: Any = None, timeout: float = 8.0) -> Any:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - 本机网关
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeLiftError(f"{method} {url} → HTTP {exc.code}: {exc.read()[:200]!r}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeLiftError(f"连不上 WeAppDev 网关 {url}: {exc.reason}") from exc
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeLiftError(f"{url} 返回的不是 JSON: {raw[:200]!r}") from exc


class Gateway:
    """WeAppDev 本地网关的最小封装。"""

    def __init__(self, base: str = DEFAULT_GATEWAY, *, timeout: float = 8.0) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout

    def _call(self, path: str, *, method: str = "GET", body: Any = None) -> Any:
        return _json(self.base + path, method=method, body=body, timeout=self.timeout)

    # ------------------------------------------------------------ 探测

    def status(self) -> dict[str, Any]:
        return self._call("/v1/status")

    def apps(self) -> list[dict[str, Any]]:
        data = self._call("/v1/apps")
        apps = data.get("apps") if isinstance(data, dict) else data
        return list(apps or [])

    def find_app(self, app_id: str = BDKQ_APP_ID) -> dict[str, Any]:
        for app in self.apps():
            if app.get("appId") == app_id:
                return app
        visible = ", ".join(str(a.get("appId")) for a in self.apps()) or "（空）"
        raise RuntimeLiftError(
            f"运行时里没有 {app_id}（当前：{visible}）。先在小程序列表里打开北大口腔。"
        )

    # ------------------------------------------------------------ 抓包

    def enable_capture(self) -> dict[str, Any]:
        return self._call("/v1/config", method="POST", body={"network_capture": True})

    def capture_state(self) -> bool:
        try:
            data = self._call("/v1/config")
        except RuntimeLiftError:
            return False
        if isinstance(data, dict):
            for key in ("network_capture", "networkCapture", "capture"):
                if key in data:
                    return bool(data[key])
        return False

    def store(self, tail: int = 60) -> list[dict[str, Any]]:
        data = self._call(f"/v1/hook/store?tail={int(tail)}")
        if isinstance(data, dict):
            return list(data.get("records") or [])
        return list(data or [])

    def clear(self) -> None:
        self._call("/v1/hook/clear", method="POST", body={})

    def restart(self, app_id: str = BDKQ_APP_ID) -> dict[str, Any]:
        return self._call(f"/v1/apps/{app_id}:restart", method="POST", body={})


# ---------------------------------------------------------------- 记录解析

def _headers(record: dict[str, Any]) -> dict[str, str]:
    raw = record.get("requestHeaders") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k).lower(): v for k, v in raw.items()}


def _record_host(record: dict[str, Any]) -> str:
    url = str(record.get("url") or "")
    return urllib.parse.urlsplit(url).hostname or ""


def version_from_url(url: str) -> str:
    match = _VERSION_RE.search(url or "")
    return match.group(1) if match else ""


def _is_login(record: dict[str, Any]) -> bool:
    return "/login/" in str(record.get("url") or "")


def _token_from_login_body(record: dict[str, Any]) -> str:
    """登录请求的响应体里才是新 token；用签名解开信封。"""
    body = record.get("responseBody")
    signature = _headers(record).get("signature", "")
    if not body or not signature:
        return ""
    try:
        envelope = json.loads(body) if isinstance(body, str) else body
    except json.JSONDecodeError:
        return ""
    if not isinstance(envelope, dict) or not envelope.get("data"):
        return ""
    try:
        payload = decrypt_response(envelope, signature)
    except Exception:  # noqa: BLE001 - 解不开就当这条没用
        return ""
    data = payload.get("data")
    return str((data or {}).get("accessToken") or "") if isinstance(data, dict) else ""


def pick_record(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    """挑一条能给出登录态的记录：优先非登录请求的请求头，其次登录响应体。"""
    usable = [r for r in records if _record_host(r) == BDKQ_HOST]
    for record in reversed(usable):
        headers = _headers(record)
        if _is_login(record):
            continue
        if headers.get("access_token"):
            return record
    for record in reversed(usable):
        if _is_login(record) and _token_from_login_body(record):
            return record
    return None


def login_state(record: dict[str, Any]) -> dict[str, Any]:
    """把一条抓包记录翻译成 {access_token, api_version, ...}。"""
    url = str(record.get("url") or "")
    headers = _headers(record)
    if _is_login(record):
        token = _token_from_login_body(record)
        # /login/wechat 的 URL 里是 @default，真正的版本号在响应头 x-version
        version = ""
        response_headers = record.get("responseHeaders") or {}
        if isinstance(response_headers, dict):
            for key, value in response_headers.items():
                if str(key).lower() == "x-version":
                    version = str(value)
                    break
    else:
        token = str(headers.get("access_token") or "")
        version = version_from_url(url)
    if not token:
        raise RuntimeLiftError(f"这条记录里没有 token: {url}")
    return {
        "access_token": token,
        "api_version": version or "default",
        "source_url": url,
        "at": record.get("at"),
    }


# ---------------------------------------------------------------- 对外入口

def lift(
    gateway: Gateway | str = DEFAULT_GATEWAY,
    *,
    app_id: str = BDKQ_APP_ID,
    restart: bool = True,
    timeout: float = 30.0,
    poll: float = 1.0,
) -> dict[str, Any]:
    """从运行时取一份可用的登录态。

    先看 `hook/store` 里有没有现成记录；没有就重启一次小程序（它会自己发请求），
    然后轮询到超时。整个过程不需要人参与，也不需要导出 HAR。
    """
    gw = gateway if isinstance(gateway, Gateway) else Gateway(gateway)
    gw.find_app(app_id)

    def usable() -> dict[str, Any] | None:
        """现有记录里能直接用的一条；token 快过期了就不算。"""
        record = pick_record(gw.store())
        if record is None:
            return None
        state = login_state(record)
        left = token_seconds_left(state["access_token"])
        if isinstance(left, int) and left <= 60:
            return None      # 快过期了，宁可重启换一个新的
        state["seconds_left"] = left
        return state

    # 1) 运行时里已经有请求记录就直接用，不打扰小程序
    state = usable()
    if state is not None:
        return state

    # 2) 没有记录（或 token 要过期）：确保抓包开着，重启一次让它自己发请求
    if not restart:
        if not gw.capture_state():
            gw.enable_capture()
        raise RuntimeLiftError(
            "运行时里没有可用的北大口腔请求。确认小程序停在首页、模拟器能联网，"
            "再手动点一下「余号查询」重试（去掉 --no-restart 也能自动重启）。"
        )

    if not gw.capture_state():
        gw.enable_capture()
    gw.clear()
    gw.restart(app_id)
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        state = usable()
        if state is not None:
            return state

    raise RuntimeLiftError(
        "重启后仍然抓不到北大口腔的请求。确认模拟器能联网（域名指向 127.0.0.1 时"
        "要先做 adb reverse，见 BDKQ.md）。"
    )


def write_config(path: str | Path, state: dict[str, Any]) -> Path:
    """把 token 和版本号写回配置（其余字段原样保留，权限 0600）。"""
    target = Path(path)
    config = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
    config["access_token"] = state["access_token"]
    config["api_version"] = state.get("api_version") or config.get("api_version", "default")
    target.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    target.chmod(0o600)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="从 WeAppDev 运行时取北大口腔登录态")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY, help="WeAppDev 网关地址")
    parser.add_argument("--app-id", default=BDKQ_APP_ID, help="小程序 appId")
    parser.add_argument("--no-restart", action="store_true", help="不重启小程序，只读现有记录")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--write", default="", help="把结果写回这个配置文件")
    parser.add_argument("--json", action="store_true", help="输出完整 JSON")
    args = parser.parse_args(argv)

    try:
        state = lift(args.gateway, app_id=args.app_id,
                     restart=not args.no_restart, timeout=args.timeout)
    except RuntimeLiftError as exc:
        print(f"取登录态失败：{exc}")
        return 1

    if args.write:
        saved = write_config(args.write, state)
        print(f"已写入 {saved}")
    if args.json:
        print(json.dumps(state, ensure_ascii=False, indent=2))
    else:
        left = state.get("seconds_left")
        left_text = f"{left // 60} 分钟" if isinstance(left, int) else "未知"
        print(f"token: {state['access_token'][:24]}…（{len(state['access_token'])} 字符）")
        print(f"api_version: {state['api_version']}")
        print(f"剩余有效期: {left_text}")
        print(f"来源: {state['source_url']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
