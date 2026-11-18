#!/usr/bin/env python3
"""北大口腔号源只读监控。

**只读**：只调 getYyDeptList / getYyDoctorList 这类查询接口，不下单、不取消。
下单参数（yyOrder / todayOrder 的字段名）还没用真实响应校准过，故意没写进来，
等 bdkq_probe.py 跑通校准之后再单独做，避免拿着猜的字段往医院系统提交。

它能干的事：盯着某个科室的「剩余号源」字段，从 0 变正数就推送通知。

用法：
    python3 bdkq_watch.py -c config.bdkq.local.json --once
    python3 bdkq_watch.py -c config.bdkq.local.json --duration 300 --interval 5
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

from bdkq_client import BdkqClient, BdkqError, load_config

try:  # 复用主项目已经做好的通知通道（Bark / Server 酱 / Telegram / webhook）
    from hospital_watch import notify as desktop_notify
    from hospital_watch import send_notification
except Exception:  # noqa: BLE001 - 单独拷出来用时没有主项目也能跑
    send_notification = None  # type: ignore[assignment]
    desktop_notify = None  # type: ignore[assignment]

REMAIN_HINTS = ("remain", "left", "surplus", "yuyue", "available", "sourcecount", "number")


def extract_remain(item: dict[str, Any]) -> tuple[str, int] | None:
    """在科室/医生节点里找剩余号源字段。

    字段名是猜的（小程序是 uni-app 混淆产物），所以用启发式匹配 key，
    第一次见到的 key 会打日志提醒人工确认。找不到就走「有没有号」的二元判断。
    """
    for key, value in item.items():
        low = str(key).lower()
        if not any(hint in low for hint in REMAIN_HINTS):
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, str)):
            try:
                return str(key), int(value)
            except (TypeError, ValueError):
                continue
    return None


def flatten_lists(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in ("lists", "list", "records", "deptList", "rows"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def pick_dept(items: list[dict[str, Any]], keyword: str) -> dict[str, Any] | None:
    if not keyword:
        return items[0] if items else None
    for item in items:
        name = str(item.get("deptName") or item.get("name") or item.get("title") or "")
        if keyword in name:
            return item
    return None


def dept_label(item: dict[str, Any]) -> str:
    return str(item.get("deptName") or item.get("name") or item.get("title") or "(未命名科室)")


def watch_once(client: BdkqClient, config: dict[str, Any], state: dict[str, Any]) -> bool:
    target = config.get("target") or {}
    area_code = str(target.get("area_code") or "0")
    keyword = str(target.get("dept_keyword") or "").strip()

    try:
        resp = client.get(
            "/api/regist/getYyDeptList",
            {"areaCode": area_code, "withRemain": "1"},
        )
    except BdkqError as exc:
        print(f"[{time.strftime('%H:%M:%S')}] 请求失败: {exc}", file=sys.stderr)
        return False

    if not resp.ok:
        print(f"[{time.strftime('%H:%M:%S')}] 接口返回 status={resp.status} {resp.message}",
              file=sys.stderr)
        return False

    items = flatten_lists(resp.data)
    if not items:
        print("科室列表是空的，响应结构和我推断的不一样，跑一次 bdkq_probe.py 看看真实字段")
        return False

    dept = pick_dept(items, keyword)
    if dept is None:
        print(f"没在院区 {area_code} 找到含「{keyword}」的科室")
        return False

    name = dept_label(dept)
    remain = extract_remain(dept)
    if remain is None:
        print(f"{name}: 没识别出剩余号源字段，可用字段 {sorted(dept.keys())[:15]}")
        return False

    field, count = remain
    previous = state.get(name, {}).get("remain")
    state[name] = {"remain": count, "field": field, "at": time.strftime("%H:%M:%S")}
    stamp = time.strftime("%H:%M:%S")
    print(f"[{stamp}] {name}: {field}={count}（上次 {previous}）")

    if previous is None:
        return False                      # 第一次只记录基线，不通知
    if count > 0 and count != previous:   # 从更少涨上来
        title = f"北大口腔有号了：{name}"
        message = f"剩余 {count}（{field}），院区 {area_code}，{stamp}"
        if send_notification is not None:
            send_notification(config, title, message, event="bdkq_remain")
        if desktop_notify is not None:
            desktop_notify(title, message)
        else:
            print("\a", end="", flush=True)
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="北大口腔号源只读监控")
    parser.add_argument("-c", "--config", default="config.bdkq.local.json")
    parser.add_argument("--once", action="store_true", help="只查一次")
    parser.add_argument("--interval", type=float, default=None, help="轮询间隔秒数")
    parser.add_argument("--duration", type=float, default=None, help="持续多少秒后退出")
    args = parser.parse_args(argv)

    path = Path(args.config)
    if not path.exists():
        print(f"没找到配置 {path}，先用 bdkq_har.py 生成一份", file=sys.stderr)
        return 2

    config = load_config(str(path))
    client = BdkqClient.from_config(config)
    if not client.access_token:
        print("配置里没有 access_token，科室列表大概率读不到真实数据", file=sys.stderr)

    polling = config.get("polling") or {}
    interval = args.interval or float(polling.get("interval") or 5)
    duration = args.duration if args.duration is not None else float(polling.get("duration") or 0)

    state: dict[str, Any] = {}
    started = time.time()
    if args.once:
        watch_once(client, config, state)
        return 0

    print(f"开始监控，间隔 {interval}s，持续 {duration or '不限'}s，Ctrl-C 退出")
    try:
        while True:
            if watch_once(client, config, state):
                if config.get("polling", {}).get("stop_on_hit"):
                    break
            if duration and time.time() - started >= duration:
                break
            time.sleep(max(1.0, interval))
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
