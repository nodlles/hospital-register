#!/usr/bin/env python3
"""Watch hospital mini-program inventory and optionally submit after confirmation.

This tool intentionally requires an interactive confirmation before it sends a
real appointment request. It never pays an order.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


class WatchError(RuntimeError):
    pass


VERBOSE = False
UNSUPPORTED_REQUEST_HEADERS = {
    "content-length",
    "host",
    "connection",
    "accept-encoding",
}


def log_debug(message: str) -> None:
    if VERBOSE:
        print(f"[debug] {message}")


@dataclass(frozen=True)
class Source:
    dept_code: str
    doctor_code: str
    doctor_name: str
    source_code: str
    source_name: str
    visit_date: str
    period_type: str
    period_view: str
    price: str
    count: int
    support_time_interval: bool
    time_interval_code: str | None = None
    time_interval_view: str | None = None

    def label(self) -> str:
        interval = f" {self.time_interval_view}" if self.time_interval_view else ""
        return (
            f"{self.visit_date} {self.period_view}{interval} | "
            f"{self.doctor_name} | {self.source_name} | {self.price}元 | 余号 {self.count}"
        )


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    required = ["base_url", "headers", "target", "endpoints", "polling", "submit"]
    missing = [key for key in required if key not in cfg]
    if missing:
        raise WatchError(f"配置缺少字段: {', '.join(missing)}")
    return cfg


def validate_config(cfg: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    headers = cfg.get("headers") or {}
    if not headers:
        warnings.append("headers 未导入")
    for key, value in headers.items():
        if isinstance(value, str) and "REPLACE_WITH" in value:
            warnings.append(f"headers.{key} 仍是占位值")
    target = cfg.get("target") or {}
    if not target.get("patient_code") or "REPLACE_" in str(target.get("patient_code")):
        warnings.append("target.patient_code 未填写")
    endpoints = cfg.get("endpoints") or {}
    if not endpoints.get("submit") or "REPLACE_" in str(endpoints.get("submit")):
        warnings.append("endpoints.submit 未填写，无法提交预约")
    if not endpoints.get("calendar"):
        warnings.append("endpoints.calendar 未填写")
    if not endpoints.get("detail"):
        warnings.append("endpoints.detail 未填写")
    return warnings


def join_url(base_url: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return base_url.rstrip("/") + "/" + path.lstrip("/")


def request_json(
    cfg: dict[str, Any],
    path: str,
    *,
    method: str = "GET",
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = join_url(cfg["base_url"], path)
    if query:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query)
    log_debug(f"{method} {urllib.parse.urlsplit(url).path}")
    headers = sanitize_headers(dict(cfg.get("headers") or {}))
    headers.setdefault("Accept", "application/json")
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    context = build_ssl_context(cfg)
    try:
        with urllib.request.urlopen(req, timeout=8, context=context) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise WatchError(f"HTTP {exc.code}: {detail[:500]}") from exc
    except urllib.error.URLError as exc:
        raise WatchError(f"请求失败: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise WatchError(f"响应不是 JSON: {raw[:200]!r}") from exc


def build_ssl_context(cfg: dict[str, Any]) -> ssl.SSLContext | None:
    tls = cfg.get("tls") or {}
    if tls.get("insecure_skip_verify"):
        return ssl._create_unverified_context()  # noqa: SLF001 - explicit local opt-in.
    ca_bundle = tls.get("ca_bundle") or ""
    if ca_bundle:
        if os.path.exists(ca_bundle):
            return ssl.create_default_context(cafile=ca_bundle)
        log_debug(f"tls.ca_bundle 不存在，改用运行环境默认 CA: {ca_bundle}")
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return None


def sanitize_headers(headers: dict[str, Any]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key).strip()
        lower = name.lower()
        if not name or lower.startswith(":") or lower in UNSUPPORTED_REQUEST_HEADERS:
            log_debug(f"跳过不支持的请求头: {name}")
            continue
        cleaned[name] = str(value)
    return cleaned


def parse_clock(value: str) -> tuple[int, int, int]:
    parts = value.split(":")
    if len(parts) not in (2, 3):
        raise WatchError(f"时间格式应为 HH:MM 或 HH:MM:SS: {value}")
    hour, minute = int(parts[0]), int(parts[1])
    second = int(parts[2]) if len(parts) == 3 else 0
    return hour, minute, second


def today_at(value: str) -> datetime:
    hour, minute, second = parse_clock(value)
    now = datetime.now()
    return now.replace(hour=hour, minute=minute, second=second, microsecond=0)


def wait_until_start(cfg: dict[str, Any]) -> None:
    start_at = cfg["polling"].get("start_at")
    if not start_at:
        return
    target = today_at(start_at)
    now = datetime.now()
    if now >= target:
        return
    seconds = (target - now).total_seconds()
    print(f"[wait] 等待到 {target:%H:%M:%S} 开始，约 {seconds:.0f}s")
    while seconds > 0:
        step = min(seconds, 30)
        time.sleep(step)
        seconds = (target - datetime.now()).total_seconds()


def should_keep_source(src: Source, cfg: dict[str, Any]) -> bool:
    target = cfg["target"]
    prefer_periods = set(target.get("prefer_periods") or [])
    prefer_doctors = set(target.get("prefer_doctor_codes") or [])
    max_price = target.get("max_price")
    if prefer_periods and src.period_type not in prefer_periods:
        return False
    if prefer_doctors and src.doctor_code not in prefer_doctors:
        return False
    if target.get("expert_mode") == "required" and not is_preferred_source(src, cfg):
        return False
    if max_price is not None:
        try:
            if float(src.price) > float(max_price):
                return False
        except ValueError:
            return False
    return True


def is_preferred_source(src: Source, cfg: dict[str, Any]) -> bool:
    preferred_names = [str(item) for item in cfg["target"].get("prefer_source_names") or []]
    names = preferred_names or ["专家门诊", "专家"]
    label = f"{src.source_name} {src.label()}"
    return any(name and name in label for name in names)


def source_priority(src: Source, cfg: dict[str, Any]) -> tuple[int, str, str, str]:
    expert_mode = cfg["target"].get("expert_mode") or "prefer"
    preferred_rank = 0 if expert_mode == "prefer" and is_preferred_source(src, cfg) else 1
    return (preferred_rank, src.visit_date, src.period_type, src.doctor_name)


def fetch_calendar(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    query = {
        "_t": int(time.time() * 1000),
        "deptCode": cfg["target"]["dept_code"],
    }
    obj = request_json(cfg, cfg["endpoints"]["calendar"], query=query)
    ensure_success(obj, "calendar")
    rows = list((obj.get("data") or {}).get("list") or [])
    log_debug(f"calendar 返回 {len(rows)} 个日期")
    return rows


def fetch_detail(cfg: dict[str, Any], visit_date: str) -> list[dict[str, Any]]:
    query = {
        "_t": int(time.time() * 1000),
        "deptCode": cfg["target"]["dept_code"],
        "visitDate": visit_date,
    }
    obj = request_json(cfg, cfg["endpoints"]["detail"], query=query)
    ensure_success(obj, "detail")
    rows = list((obj.get("data") or {}).get("list") or [])
    log_debug(f"detail {visit_date} 返回 {len(rows)} 个时段")
    return rows


def fetch_time_intervals(cfg: dict[str, Any], src: Source) -> list[dict[str, Any]]:
    path = cfg["endpoints"].get("time_intervals")
    if not path:
        return []
    query = {
        "_t": int(time.time() * 1000),
        "deptCode": src.dept_code,
        "doctorCode": src.doctor_code,
        "sourceCode": src.source_code,
        "treatmentDate": src.visit_date,
        "treatmentPeriodType": src.period_type,
    }
    obj = request_json(cfg, path, query=query)
    ensure_success(obj, "time_intervals")
    rows = list((obj.get("data") or {}).get("list") or [])
    log_debug(f"time_intervals {src.visit_date} {src.period_view} 返回 {len(rows)} 个分时段")
    return rows


def ensure_success(obj: dict[str, Any], label: str) -> None:
    if obj.get("code") != 0:
        raise WatchError(f"{label} 返回异常: code={obj.get('code')} message={obj.get('message')}")


def _verify_source_available(cfg: dict[str, Any], src: Source) -> None:
    """提交前实时查询 detail 接口，确认号源仍然有余量；若已失效则抛出 WatchError。"""
    try:
        detail_rows = fetch_detail(cfg, src.visit_date)
    except WatchError as exc:
        # detail 查询失败时打印警告但不阻断提交，避免因接口抖动导致无法挂号
        print(f"[warn] 提交前 detail 验证失败（继续提交）: {exc}")
        return
    for period in detail_rows:
        if str(period.get("periodType") or "") != src.period_type:
            continue
        for item in period.get("sourceList") or []:
            if str(item.get("sourceCode") or "") != src.source_code:
                continue
            if item.get("sourceStatus") != "HAVE_INVENTORY":
                raise WatchError(
                    f"号源已失效（sourceStatus={item.get('sourceStatus')}），"
                    f"可能已被抢占：{src.label()}"
                )
            try:
                count = int(item.get("count") or 0)
            except (TypeError, ValueError):
                count = 0
            if count <= 0:
                raise WatchError(f"号源余量为 0，可能已被抢占：{src.label()}")
            return  # 验证通过
    # 未在 detail 结果中找到该号源，视为已失效
    raise WatchError(f"号源已从列表消失，可能已被抢占：{src.label()}")


def discover_sources(cfg: dict[str, Any]) -> list[Source]:
    calendar = fetch_calendar(cfg)
    visit_dates = [
        item.get("visitDate")
        for item in calendar
        if item.get("sourceStatus") == "HAVE_INVENTORY" and item.get("visitDate")
    ]
    found: list[Source] = []
    for visit_date in visit_dates:
        for period in fetch_detail(cfg, visit_date):
            period_type = str(period.get("periodType") or "")
            period_view = str(period.get("periodTypeView") or period_type)
            for item in period.get("sourceList") or []:
                if item.get("sourceStatus") != "HAVE_INVENTORY":
                    continue
                try:
                    count = int(item.get("count") or 0)
                except (TypeError, ValueError):
                    count = 0
                if count <= 0:
                    continue
                src = source_from_api_item(item, cfg["target"]["dept_code"], str(visit_date), period_type, period_view)
                if should_keep_source(src, cfg):
                    found.extend(expand_time_intervals(cfg, src))
    found.sort(key=lambda src: source_priority(src, cfg))
    log_debug(f"本轮可用候选号源 {len(found)} 个")
    return found


def source_from_api_item(
    item: dict[str, Any],
    fallback_dept_code: str,
    visit_date: str,
    period_type: str,
    period_view: str,
) -> Source:
    try:
        count = int(item.get("count") or 0)
    except (TypeError, ValueError):
        count = 0
    return Source(
        dept_code=str(item.get("deptCode") or fallback_dept_code),
        doctor_code=str(item.get("doctorCode") or ""),
        doctor_name=str(item.get("doctorName") or item.get("sourceName") or ""),
        source_code=str(item.get("sourceCode") or ""),
        source_name=str(item.get("sourceLevelView") or item.get("sourceName") or ""),
        visit_date=visit_date,
        period_type=period_type,
        period_view=period_view,
        price=str(item.get("price") or ""),
        count=count,
        support_time_interval=bool(item.get("supportTimeInterval")),
    )


def expand_time_intervals(cfg: dict[str, Any], src: Source) -> list[Source]:
    if not src.support_time_interval:
        return [src]
    intervals = fetch_time_intervals(cfg, src)
    if not intervals:
        # 该号源声明支持分时段，但接口返回空列表，回退到基础号源（提交时可能因缺少
        # timeIntervalCode 而失败）。用户应在配置中补充 endpoints.time_intervals。
        if not cfg["endpoints"].get("time_intervals"):
            print(
                f"[warn] {src.label()} 支持分时段 (supportTimeInterval=true)"
                " 但未配置 endpoints.time_intervals，"
                "提交时可能因缺少 timeIntervalCode 而失败。"
                "请从 Reqable 抓包补充分时段查询接口路径。"
            )
        else:
            print(
                f"[warn] time_intervals 接口返回空列表，"
                f"号源 {src.label()} 无可用分时段，回退到基础号源"
            )
        return [src]
    available: list[Source] = []
    for interval in intervals:
        try:
            count = int(interval.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        if count <= 0:
            continue
        available.append(
            Source(
                **{
                    **src.__dict__,
                    "count": min(src.count, count),
                    "time_interval_code": str(interval.get("timeIntervalCode") or ""),
                    "time_interval_view": str(interval.get("timeIntervalView") or ""),
                }
            )
        )
    return available or [src]


def notify(title: str, message: str) -> None:
    print("\a", end="", flush=True)
    if sys.platform == "darwin":
        script = (
            'display notification '
            + json.dumps(message)
            + " with title "
            + json.dumps(title)
        )
        try:
            subprocess.run(["osascript", "-e", script], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


def send_notification(
    cfg: dict[str, Any],
    title: str,
    message: str,
    *,
    event: str,
    sender: Any | None = None,
) -> dict[str, Any]:
    notify_cfg = cfg.get("notify") or {}
    if not notify_cfg.get("enabled"):
        return {"sent": 0, "results": []}
    channels = [item for item in notify_cfg.get("channels") or [] if notification_channel_configured(item)]
    if not channels:
        return {"sent": 0, "results": []}
    sender = sender or send_webhook
    results = []
    sent = 0
    for channel in channels:
        if channel.get("enabled") is False:
            continue
        try:
            status, text = send_notification_channel(channel, title, message, event, sender)
            ok = 200 <= status < 300
            sent += 1 if ok else 0
            item = {"name": channel.get("name") or channel.get("type") or "webhook", "ok": ok, "status": status}
            if not ok and text:
                item["error"] = notification_error_text(status, text)
            results.append(item)
            if not ok:
                log_debug(f"通知发送失败: status={status} body={text[:120]}")
        except Exception as exc:  # noqa: BLE001 - notification must not break monitoring.
            results.append({"name": channel.get("name") or channel.get("type") or "webhook", "ok": False, "error": str(exc)})
            log_debug(f"通知发送异常: {exc}")
    return {"sent": sent, "results": results}


def notification_error_text(status: int, text: str) -> str:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = {}
    description = str(data.get("description") or text or "").strip()
    if description:
        return f"HTTP {status}: {description[:160]}"
    return f"HTTP {status}"


def send_notification_channel(
    channel: dict[str, Any],
    title: str,
    message: str,
    event: str,
    sender: Any,
) -> tuple[int, str]:
    url = str(channel.get("url") or "")
    method = str(channel.get("method") or "POST").upper()
    channel_type = str(channel.get("type") or "webhook").lower()
    if channel_type == "bark":
        return send_bark_notification(channel, title, message, event, sender)
    if channel_type == "serverchan":
        return send_serverchan_notification(channel, title, message, event, sender)
    if channel_type == "telegram":
        return send_telegram_notification(channel, title, message, event, sender)
    headers = {"Content-Type": "application/json; charset=utf-8"}
    headers.update({str(k): str(v) for k, v in (channel.get("headers") or {}).items()})
    payload = {
        "title": title,
        "message": message,
        "event": event,
        "time": datetime.now().isoformat(timespec="seconds"),
    }
    if method == "GET":
        separator = "&" if "?" in url else "?"
        url = url + separator + urllib.parse.urlencode(payload)
        return sender(url, method, headers, b"")
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return sender(url, method, headers, body)


def notification_channel_configured(channel: dict[str, Any]) -> bool:
    channel_type = str(channel.get("type") or "webhook").lower()
    if channel_type == "bark":
        return bool(channel.get("device_key"))
    if channel_type == "serverchan":
        return bool(channel.get("send_key"))
    if channel_type == "telegram":
        return bool(channel.get("bot_token") and channel.get("chat_id"))
    return bool(channel.get("url"))


def send_bark_notification(
    channel: dict[str, Any],
    title: str,
    message: str,
    event: str,
    sender: Any,
) -> tuple[int, str]:
    server_url = str(channel.get("server_url") or "https://api.day.app").rstrip("/")
    url = f"{server_url}/push"
    headers = {"Content-Type": "application/json; charset=utf-8"}
    payload = {
        "device_key": str(channel.get("device_key") or ""),
        "title": title,
        "body": message,
        "group": str(channel.get("group") or "hospital-register"),
        "url": str(channel.get("open_url") or ""),
    }
    if not payload["url"]:
        payload.pop("url")
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return sender(url, "POST", headers, body)


def send_serverchan_notification(
    channel: dict[str, Any],
    title: str,
    message: str,
    event: str,
    sender: Any,
) -> tuple[int, str]:
    url = f"https://sctapi.ftqq.com/{urllib.parse.quote(str(channel.get('send_key') or ''), safe='')}.send"
    headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    body = urllib.parse.urlencode({"title": title, "desp": message}).encode("utf-8")
    return sender(url, "POST", headers, body)


def send_telegram_notification(
    channel: dict[str, Any],
    title: str,
    message: str,
    event: str,
    sender: Any,
) -> tuple[int, str]:
    token = str(channel.get("bot_token") or "")
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    headers = {"Content-Type": "application/json; charset=utf-8"}
    payload = {
        "chat_id": str(channel.get("chat_id") or ""),
        "text": f"{title}\n\n{message}",
        "disable_web_page_preview": True,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return sender(url, "POST", headers, body)


def send_webhook(url: str, method: str, headers: dict[str, str], body: bytes) -> tuple[int, str]:
    data = body if method != "GET" else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read(500)
            return resp.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read(500)
        return exc.code, raw.decode("utf-8", "replace")


def choose_source(sources: list[Source]) -> Source:
    print("\n[hit] 发现可预约号源:")
    for idx, src in enumerate(sources, 1):
        print(f"  {idx}. {src.label()}")
    if len(sources) == 1:
        return sources[0]
    while True:
        choice = input("选择要提交的序号，或直接回车选 1: ").strip()
        if not choice:
            return sources[0]
        if choice.isdigit() and 1 <= int(choice) <= len(sources):
            return sources[int(choice) - 1]
        print("输入无效。")


def build_submit_body(cfg: dict[str, Any], src: Source) -> dict[str, Any]:
    body = {
        "patientCode": cfg["target"]["patient_code"],
        "sourceCode": src.source_code,
        "deptCode": src.dept_code,
        "doctorCode": src.doctor_code,
        "treatmentDate": src.visit_date,
        "treatmentPeriodType": src.period_type,
        "sendMsg": bool(cfg["submit"].get("send_msg", False)),
    }
    if src.support_time_interval and not src.time_interval_code:
        # 该号源需要分时段预约但没有 timeIntervalCode，提交大概率失败
        raise WatchError(
            f"号源 {src.label()} 需要分时段预约 (supportTimeInterval=true)"
            " 但缺少 timeIntervalCode。"
            " 请在配置中补充 endpoints.time_intervals 分时段查询接口路径。"
        )
    if src.time_interval_code:
        body["timeIntervalCode"] = src.time_interval_code
    return body


def confirm_submit(cfg: dict[str, Any], src: Source, body: dict[str, Any]) -> bool:
    phrase = cfg["submit"].get("confirm_phrase") or "CONFIRM"
    print("\n[confirm] 即将真实提交预约，可能生成待支付订单。")
    print(f"号源: {src.label()}")
    redacted = {**body, "patientCode": "***"}
    print("请求体(脱敏):", json.dumps(redacted, ensure_ascii=False))
    answer = input(f"输入 {phrase!r} 才提交，其他输入取消: ").strip()
    return answer == phrase


def submit_order(cfg: dict[str, Any], src: Source) -> dict[str, Any]:
    path = cfg["endpoints"].get("submit")
    if not path or "REPLACE_" in path:
        raise WatchError("未配置提交接口 endpoints.submit，请从 Reqable 的最终提交请求复制路径。")
    body = build_submit_body(cfg, src)
    if not confirm_submit(cfg, src, body):
        raise WatchError("用户取消提交。")
    pre_check_path = cfg["endpoints"].get("pre_submit_check")
    if pre_check_path:
        pre_check = request_json(cfg, pre_check_path, method="POST", body=body)
        ensure_success(pre_check, "pre_submit_check")
    obj = request_json(cfg, path, method="POST", body=body)
    return obj


def submit_source(cfg: dict[str, Any], src: Source) -> dict[str, Any]:
    path = cfg["endpoints"].get("submit")
    if not path or "REPLACE_" in path:
        raise WatchError("未配置提交接口 endpoints.submit")
    # 提交前实时验证号源仍然可用，避免命中时号源已被抢占
    _verify_source_available(cfg, src)
    body = build_submit_body(cfg, src)
    pre_check_path = cfg["endpoints"].get("pre_submit_check")
    if pre_check_path:
        pre_check = request_json(cfg, pre_check_path, method="POST", body=body)
        ensure_success(pre_check, "pre_submit_check")
    obj = request_json(cfg, path, method="POST", body=body)
    # 医院接口即使 HTTP 200 也可能通过 code != 0 表示提交失败
    ensure_success(obj, "submit")
    return obj


def watch(cfg: dict[str, Any], *, once: bool, wait: bool) -> list[Source]:
    if wait:
        wait_until_start(cfg)
    started = datetime.now()
    end_at = started + timedelta(seconds=float(cfg["polling"].get("end_after_seconds", 240)))
    release_at = today_at(cfg["polling"].get("release_at", "15:00:00"))
    attempt = 0
    while True:
        attempt += 1
        now = datetime.now()
        try:
            sources = discover_sources(cfg)
        except WatchError as exc:
            print(f"[{now:%H:%M:%S}] 第 {attempt} 次检查失败: {exc}")
            sources = []
        if sources:
            notify("中日友好医院发现号源", sources[0].label())
            send_notification(
                cfg,
                "中日友好医院发现可预约号源",
                sources[0].label() + "\n请尽快打开监控页面确认提交。",
                event="hit",
            )
            return sources
        print(f"[{now:%H:%M:%S}] 第 {attempt} 次检查: 暂无可预约号源")
        if once or now >= end_at:
            return []
        interval = (
            float(cfg["polling"].get("interval_after_release", 0.5))
            if now >= release_at
            else float(cfg["polling"].get("interval_before_release", 1.0))
        )
        time.sleep(max(0.1, interval))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="监控中日友好医院小程序号源，确认后提交预约。")
    parser.add_argument("--config", default="config.local.json", help="配置文件路径")
    parser.add_argument("--once", action="store_true", help="只检查一次")
    parser.add_argument("--no-submit", action="store_true", help="只监控提醒，不进入提交确认")
    parser.add_argument("--now", action="store_true", help="忽略 start_at，立即开始")
    parser.add_argument("--check-config", action="store_true", help="只检查配置，不发送请求")
    parser.add_argument("--verbose", action="store_true", help="输出接口请求和解析过程日志，不打印敏感请求头")
    args = parser.parse_args(argv)

    global VERBOSE
    VERBOSE = args.verbose

    cfg = load_config(Path(args.config))
    warnings = validate_config(cfg)
    if args.check_config:
        if warnings:
            print("[config] 配置可读取，但有以下问题:")
            for item in warnings:
                print(f"  - {item}")
            return 1
        print("[config] 配置检查通过。")
        return 0
    if warnings:
        print("[config] 警告:")
        for item in warnings:
            print(f"  - {item}")
    sources = watch(cfg, once=args.once, wait=not args.now)
    if not sources:
        return 2
    src = choose_source(sources)
    if args.no_submit or not cfg["submit"].get("enabled", True):
        print("[done] 已发现号源，按配置不提交。")
        return 0
    result = submit_order(cfg, src)
    print("[submit] 响应:", json.dumps(result, ensure_ascii=False))
    if result.get("code") == 0:
        notify("中日友好医院预约已提交", f"返回: {result.get('data')}")
        send_notification(
            cfg,
            "中日友好医院预约已提交，待支付",
            "预约请求已提交成功，请尽快到微信小程序内完成支付。",
            event="submitted",
        )
        print("[done] 已提交，脚本不会进入支付。请在小程序里查看待支付订单。")
        return 0
    return 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[stop] 用户中断。")
        raise SystemExit(130)
    except WatchError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        raise SystemExit(1)
