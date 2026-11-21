#!/usr/bin/env python3
"""北大口腔 access_token 的自动续期。

小程序换 token 的链路是 `wx.login()` 拿 code → `POST /login/wechat` 换 JWT。
token 是 JWT，有效期 2 小时（`nbf` 到 `exp` 正好 7200 秒），
所以长期监控必须续期；而续期并不需要人参与，走 wxdevtools 通道再调一次 `wx.login` 就行。

配置里可以直接写 access_token（旧的手工方式），也可以留空 —— 留空就自动换。

用法：
    python3 bdkq_token.py --config config.bdkq.local.json          # 拿一次并写回缓存
    python3 bdkq_token.py --config config.bdkq.local.json --show   # 只看有效期
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import time
from pathlib import Path
from typing import Any

from bdkq_client import BdkqClient, BdkqError

# 提前 5 分钟续期，避免卡在过期边界上
REFRESH_MARGIN = 300


def decode_jwt_claims(token: str) -> dict[str, Any]:
    """不校验签名，只看 payload（exp/iat）。"""
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        data = json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001 - 解不开就当没有
        return {}
    return data if isinstance(data, dict) else {}


def token_expiry(token: str) -> int | None:
    claims = decode_jwt_claims(token)
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        return int(exp)
    return None


def token_seconds_left(token: str) -> int | None:
    exp = token_expiry(token)
    if exp is None:
        return None
    return exp - int(time.time())


def needs_refresh(token: str, margin: int = REFRESH_MARGIN) -> bool:
    """没有 token、解不出 exp、或者快到期了，都算需要续。"""
    if not token:
        return True
    left = token_seconds_left(token)
    if left is None:
        return False          # 不是 JWT，交给服务端判断，别乱续
    return left <= margin


def cache_path(config_path: str | Path) -> Path:
    path = Path(config_path)
    return path.with_name(path.name + ".token")


def load_cache(config_path: str | Path) -> dict[str, Any]:
    path = cache_path(config_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_cache(config_path: str | Path, token: str, api_version: str) -> Path:
    path = cache_path(config_path)
    payload = {"access_token": token, "api_version": api_version,
               "saved_at": int(time.time()), "exp": token_expiry(token)}
    path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def refresh_via_devtools(client: BdkqClient, *, ports: Any = None) -> BdkqClient:
    """走开发者工具通道拿 code 再换 token。"""
    from wxdevtools import DEFAULT_PORTS, HOSPITAL_APP_IDS, channel_from_local

    # wx.login 的 code 是按小程序发的：必须确认运行时里第一个开着的就是北大口腔，
    # 否则会拿中日友好的 code 去换 token，报一个看不懂的失败。
    channel = channel_from_local(ports or DEFAULT_PORTS,
                                 expect_app=HOSPITAL_APP_IDS["bdkq"])
    try:
        code = channel.login_code()
    finally:
        channel.close()
    response = client.login_with_code(code)
    if not client.access_token:
        raise BdkqError(f"换 token 失败: status={response.status} {response.message}")
    return client


def refresh_via_runtime(client: BdkqClient, *, gateway: str = "") -> BdkqClient:
    """走 WeAppDev 运行时取登录态（不需要人抓包，见 bdkq_runtime.py）。"""
    from bdkq_runtime import DEFAULT_GATEWAY, lift

    state = lift(gateway or DEFAULT_GATEWAY)
    client.access_token = state["access_token"]
    if state.get("api_version"):
        client.api_version = state["api_version"]
    return client


def ensure_client(config: dict[str, Any], config_path: str | Path | None = None,
                  *, force: bool = False, refresh_fn: Any = None) -> tuple[BdkqClient, str]:
    """保证拿到一个可用的客户端。

    返回 (client, 来源)，来源是 `config` / `cache` / `devtools`，方便日志里说清楚。
    """
    client = BdkqClient.from_config(config)
    source = "config"
    token = client.access_token
    version = client.api_version

    # 优先级：配置里还新鲜的 token > 缓存里还新鲜的 token > 现场换一个。
    # api_version 每次登录都会变，所以缓存里要连它一起存，不能只存 token。
    if config_path is not None and needs_refresh(token):
        cache = load_cache(config_path)
        cached = str(cache.get("access_token") or "")
        if cached and not needs_refresh(cached):
            token = cached
            version = str(cache.get("api_version") or version)
            source = "cache"

    if force or needs_refresh(token):
        refresh = refresh_fn or refresh_via_devtools
        client = refresh(client)
        token = client.access_token
        version = client.api_version
        source = "refresh"
        if config_path is not None:
            save_cache(config_path, token, version)

    client.access_token = token
    client.api_version = version or client.api_version
    return client, source


def main(argv: list[str] | None = None) -> int:
    from bdkq_client import load_config

    parser = argparse.ArgumentParser(description="北大口腔 token 自动续期")
    parser.add_argument("-c", "--config", default="config.bdkq.local.json")
    parser.add_argument("--show", action="store_true", help="只看当前有效期，不续期")
    parser.add_argument("--force", action="store_true", help="强制续期")
    parser.add_argument("--source", choices=("auto", "runtime", "devtools"), default="auto",
                        help="续期通道：runtime 走 WeAppDev 运行时（推荐），devtools 走微信开发者工具")
    args = parser.parse_args(argv)

    path = Path(args.config)
    if not path.exists():
        print(f"没找到配置 {path}")
        return 2
    config = load_config(str(path))

    if args.show:
        for label, token in (("配置", str(config.get("access_token") or "")),
                             ("缓存", str(load_cache(path).get("access_token") or ""))):
            left = token_seconds_left(token) if token else None
            print(f"{label}: {'有效 ' + str(left // 60) + ' 分钟' if left else '没有或不是 JWT'}")
        return 0

    if args.source == "runtime":
        refresh_fn = refresh_via_runtime
    elif args.source == "devtools":
        refresh_fn = refresh_via_devtools
    else:
        # 先试运行时（更稳、无需微信开发者工具），失败再退回开发者工具通道
        def refresh_fn(client: BdkqClient) -> BdkqClient:  # type: ignore[misc]
            try:
                return refresh_via_runtime(client)
            except Exception as exc:  # noqa: BLE001 - 换一条通道继续
                print(f"运行时通道不可用（{exc}），改用开发者工具")
                return refresh_via_devtools(client)

    client, source = ensure_client(config, path, force=args.force, refresh_fn=refresh_fn)
    left = token_seconds_left(client.access_token)
    print(f"token 来源: {source}，剩余 {left // 60 if left else '?'} 分钟，api_version={client.api_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
