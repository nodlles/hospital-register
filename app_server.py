#!/usr/bin/env python3
"""Small local web service for hospital registration monitoring."""

from __future__ import annotations

import json
import os
import shlex
import threading
import time
import traceback
import urllib.parse
from dataclasses import asdict
from datetime import date, datetime, timedelta
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import hospital_watch as watch


ROOT = Path(__file__).resolve().parent
WEB_ROOT = ROOT / "web"
CONFIG_PATH = Path(os.environ.get("HOSPITAL_CONFIG", ROOT / "config.local.json"))
CATALOG_CACHE_PATH = Path(os.environ.get("HOSPITAL_CATALOG_CACHE", CONFIG_PATH.with_name("catalog-cache.json")))
EXAMPLE_CONFIG_PATH = ROOT / "config.example.json"
API_CACHE: dict[tuple[Any, ...], tuple[float, Any]] = {}
API_COOLDOWNS: dict[tuple[Any, ...], float] = {}
CACHE_LOCK = threading.Lock()
CATALOG_CACHE_LOCK = threading.Lock()
CATALOG_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
RATE_LIMIT_COOLDOWN_SECONDS = 90
MONITOR_RATE_LIMIT_BACKOFF_SECONDS = (60, 90, 150, 240, 300)
MIN_MONITOR_POLL_INTERVAL_SECONDS = 2.0
PRE_RELEASE_FAR_POLL_INTERVAL_SECONDS = 300.0
PRE_RELEASE_SAME_DAY_POLL_INTERVAL_SECONDS = 60.0
PRE_RELEASE_NEAR_POLL_INTERVAL_SECONDS = 15.0
RELEASE_LEAD_DAYS = 7
SOURCE_RELEASE_HOUR = 15
SOURCE_RELEASE_MINUTE = 0


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "a-ticket",
    "u-u-ticket",
    "r-a-token",
    "token",
}
UNSUPPORTED_IMPORTED_HEADERS = {
    "content-length",
    "host",
    "connection",
    "accept-encoding",
}


def ensure_config_file() -> None:
    if CONFIG_PATH.exists():
        return
    if not EXAMPLE_CONFIG_PATH.exists():
        raise FileNotFoundError(f"缺少配置文件: {CONFIG_PATH}")
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(EXAMPLE_CONFIG_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    try:
        CONFIG_PATH.chmod(0o600)
    except OSError:
        pass


def load_cfg() -> dict[str, Any]:
    ensure_config_file()
    return watch.load_config(CONFIG_PATH)


def save_cfg(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CONFIG_PATH.with_name(f".{CONFIG_PATH.name}.tmp")
    tmp_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(CONFIG_PATH)
    try:
        CONFIG_PATH.chmod(0o600)
    except OSError:
        pass


def load_catalog_cache() -> dict[str, Any]:
    if not CATALOG_CACHE_PATH.exists():
        return {"districts": {}, "departments": {}}
    try:
        data = json.loads(CATALOG_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"districts": {}, "departments": {}}
    if not isinstance(data, dict):
        return {"districts": {}, "departments": {}}
    data.setdefault("districts", {})
    data.setdefault("departments", {})
    return data


def save_catalog_cache(data: dict[str, Any]) -> None:
    CATALOG_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CATALOG_CACHE_PATH.with_name(f".{CATALOG_CACHE_PATH.name}.tmp")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(CATALOG_CACHE_PATH)


def catalog_entry_items(entry: Any, *, allow_stale: bool = False) -> list[dict[str, Any]] | None:
    if not isinstance(entry, dict):
        return None
    items = entry.get("items")
    if not isinstance(items, list):
        return None
    created_at = float(entry.get("createdAt") or 0)
    if allow_stale or time.time() - created_at <= CATALOG_CACHE_TTL_SECONDS:
        return items
    return None


def cached_catalog_call(kind: str, key: str, loader: Any, *, force: bool = False) -> tuple[list[dict[str, Any]], bool]:
    with CATALOG_CACHE_LOCK:
        cache = load_catalog_cache()
        bucket = cache.setdefault(kind, {})
        entry = bucket.get(key)
        cached_items = catalog_entry_items(entry)
        if cached_items is not None and not force:
            return cached_items, True
    try:
        items = loader()
    except watch.WatchError as exc:
        stale_items = catalog_entry_items(entry, allow_stale=True)
        if stale_items is not None and is_rate_limit_error(exc):
            return stale_items, True
        raise
    with CATALOG_CACHE_LOCK:
        cache = load_catalog_cache()
        cache.setdefault(kind, {})[key] = {"createdAt": time.time(), "items": items}
        save_catalog_cache(cache)
    return items, False


def now_text() -> str:
    return datetime.now().strftime("%H:%M:%S")


def cached_api_call(key: tuple[Any, ...], ttl_seconds: float, loader: Any) -> Any:
    now = time.time()
    with CACHE_LOCK:
        cooldown_until = API_COOLDOWNS.get(key, 0)
        if cooldown_until > now:
            remain = int(cooldown_until - now)
            raise watch.WatchError(f"请求过于频繁，请稍后 {remain}s 再试。")
        cached = API_CACHE.get(key)
        if cached and cached[0] > now:
            return cached[1]
    try:
        value = loader()
    except watch.WatchError as exc:
        if is_rate_limit_error(exc):
            with CACHE_LOCK:
                API_COOLDOWNS[key] = time.time() + RATE_LIMIT_COOLDOWN_SECONDS
        raise
    with CACHE_LOCK:
        API_CACHE[key] = (time.time() + ttl_seconds, value)
    return value


def is_rate_limit_error(exc: BaseException) -> bool:
    text = str(exc)
    return "code=10000" in text or "请求过于频繁" in text


def is_auth_expired_error(exc: BaseException) -> bool:
    """判断是否为登录态过期错误（HTTP 401 或医院接口返回的常见 auth 错误码）。"""
    text = str(exc)
    # HTTP 层 401
    if "HTTP 401" in text:
        return True
    # 医院 JSON 业务码：401 / 40001 / 100001 常见于 token 过期
    if "code=401" in text or "code=40001" in text or "code=100001" in text:
        return True
    # 部分接口在 message 里直接说明未登录
    lower = text.lower()
    return ("未登录" in text or "登录过期" in text or "token" in lower and "expire" in lower)


def rate_limit_backoff_seconds(consecutive_count: int) -> int:
    index = max(1, consecutive_count) - 1
    return MONITOR_RATE_LIMIT_BACKOFF_SECONDS[min(index, len(MONITOR_RATE_LIMIT_BACKOFF_SECONDS) - 1)]


def estimated_release_at(target_date: str) -> datetime | None:
    if not target_date:
        return None
    try:
        target = date.fromisoformat(target_date)
    except ValueError:
        return None
    release_day = target - timedelta(days=RELEASE_LEAD_DAYS)
    return datetime(
        release_day.year,
        release_day.month,
        release_day.day,
        SOURCE_RELEASE_HOUR,
        SOURCE_RELEASE_MINUTE,
    )


def seconds_until_release(target_date: str, *, now: datetime | None = None) -> float | None:
    release_at = estimated_release_at(target_date)
    if release_at is None:
        return None
    current = now or datetime.now()
    return (release_at - current).total_seconds()


def monitor_poll_interval_seconds(
    requested_seconds: float,
    target_date: str = "",
    *,
    now: datetime | None = None,
    today: date | None = None,
) -> float:
    current = now
    if current is None and today is not None:
        current = datetime(today.year, today.month, today.day)
    remaining = seconds_until_release(target_date, now=current)
    floor = MIN_MONITOR_POLL_INTERVAL_SECONDS
    if remaining is not None and remaining > 0:
        if remaining <= 5 * 60:
            floor = MIN_MONITOR_POLL_INTERVAL_SECONDS
        elif remaining <= 30 * 60:
            floor = PRE_RELEASE_NEAR_POLL_INTERVAL_SECONDS
        elif remaining <= 6 * 60 * 60:
            floor = PRE_RELEASE_SAME_DAY_POLL_INTERVAL_SECONDS
        else:
            floor = PRE_RELEASE_FAR_POLL_INTERVAL_SECONDS
    return max(float(requested_seconds), floor)


def is_before_release_window(target_date: str, *, now: datetime | None = None, today: date | None = None) -> bool:
    current = now
    if current is None and today is not None:
        current = datetime(today.year, today.month, today.day)
    remaining = seconds_until_release(target_date, now=current)
    return remaining is not None and remaining > 0


def should_extend_monitor_for_pre_release(target_date: str, *, now: datetime | None = None) -> bool:
    return is_before_release_window(target_date, now=now)


def release_poll_reason(target_date: str, interval: float, requested_interval: float, *, now: datetime | None = None) -> str:
    remaining = seconds_until_release(target_date, now=now)
    release_at = estimated_release_at(target_date)
    release_text = release_at.strftime("%m-%d %H:%M") if release_at else "未知"
    if remaining is None or remaining <= 0:
        return f"已到预计放号时间 {release_text}，按 {format_wait_seconds(interval)} 间隔监控"
    if interval <= requested_interval:
        return f"预计放号 {release_text}，沿用 {format_wait_seconds(interval)} 间隔监控"
    if remaining <= 5 * 60:
        phase = "进入放号前 5 分钟"
    elif remaining <= 30 * 60:
        phase = "进入放号前 30 分钟"
    elif remaining <= 6 * 60 * 60:
        phase = "距离放号小于 6 小时"
    else:
        phase = "距离预计放号时间较远"
    return f"预计放号 {release_text}，{phase}，已自动将轮询间隔调整为 {format_wait_seconds(interval)}"


def default_visit_date_for_monitor(*, now: datetime | None = None) -> str:
    current = now or datetime.now()
    release_day = current.date()
    release_time = current.replace(
        hour=SOURCE_RELEASE_HOUR,
        minute=SOURCE_RELEASE_MINUTE,
        second=0,
        microsecond=0,
    )
    if current >= release_time:
        release_day += timedelta(days=1)
    return (release_day + timedelta(days=RELEASE_LEAD_DAYS)).isoformat()


def format_wait_seconds(seconds: float) -> str:
    if seconds >= 1:
        return f"{int(round(seconds))} 秒"
    return f"{seconds:.2f} 秒"


def parse_json_body(handler: SimpleHTTPRequestHandler) -> dict[str, Any]:
    size = int(handler.headers.get("Content-Length") or "0")
    if size <= 0:
        return {}
    raw = handler.rfile.read(size)
    return json.loads(raw.decode("utf-8"))


def public_config(cfg: dict[str, Any]) -> dict[str, Any]:
    target = dict(cfg.get("target") or {})
    patient_code = str(target.get("patient_code") or "")
    if patient_code and "REPLACE_" not in patient_code:
        target["patient_code"] = "CONFIGURED"
    setup = setup_status(cfg)
    return {
        "target": target,
        "polling": cfg.get("polling"),
        "submit": cfg.get("submit"),
        "endpoints": cfg.get("endpoints"),
        "baseUrl": cfg.get("base_url"),
        "auth": {
            "headers": summarize_headers(cfg.get("headers") or {}),
            "qrAuthSupported": False,
            "configPath": str(CONFIG_PATH),
        },
        "notify": public_notify_config(cfg.get("notify") or {}),
        "setup": setup,
        "warnings": watch.validate_config(cfg),
    }


def public_notify_config(notify_cfg: dict[str, Any]) -> dict[str, Any]:
    channels = []
    for channel in notify_cfg.get("channels") or []:
        channel_type = str(channel.get("type") or "webhook").lower()
        url = str(channel.get("url") or "")
        item = {
            "type": channel_type,
            "name": channel.get("name") or "",
            "enabled": channel.get("enabled", True) is not False,
            "method": channel.get("method") or "POST",
            "url": "CONFIGURED" if url else "",
        }
        if channel_type == "bark":
            item["serverUrl"] = channel.get("server_url") or "https://api.day.app"
            item["deviceKey"] = "CONFIGURED" if channel.get("device_key") else ""
        elif channel_type == "serverchan":
            item["sendKey"] = "CONFIGURED" if channel.get("send_key") else ""
        elif channel_type == "telegram":
            item["botToken"] = "CONFIGURED" if channel.get("bot_token") else ""
            item["chatId"] = "CONFIGURED" if channel.get("chat_id") else ""
        channels.append(item)
    return {
        "enabled": bool(notify_cfg.get("enabled")),
        "channels": channels,
        "configured": bool(channels),
    }


def setup_status(cfg: dict[str, Any]) -> dict[str, bool]:
    headers = cfg.get("headers") or {}
    auth_imported = bool(headers) and not any("REPLACE_WITH" in str(value) for value in headers.values())
    patient_code = str((cfg.get("target") or {}).get("patient_code") or "")
    patient_selected = bool(patient_code) and "REPLACE_" not in patient_code
    submit_path = str((cfg.get("endpoints") or {}).get("submit") or "")
    submit_endpoint = bool(submit_path) and "REPLACE_" not in submit_path
    return {
        "authImported": auth_imported,
        "authVerified": False,
        "patientSelected": patient_selected,
        "submitEndpoint": submit_endpoint,
        "localConfigSaved": CONFIG_PATH.exists(),
        "ready": auth_imported and patient_selected and submit_endpoint,
    }


def summarize_headers(headers: dict[str, Any]) -> list[dict[str, Any]]:
    items = []
    for key, value in sorted(headers.items(), key=lambda item: item[0].lower()):
        text = str(value)
        lower = key.lower()
        sensitive = lower in SENSITIVE_HEADER_NAMES or "ticket" in lower or "token" in lower
        if "REPLACE_WITH" in text:
            display = text
        elif sensitive and text:
            display = f"已配置 ({len(text)} 字符)"
        elif text:
            display = text if len(text) <= 80 else f"{text[:77]}..."
        else:
            display = "空"
        items.append({"name": key, "value": display, "sensitive": sensitive})
    return items


def parse_curl_command(command: str) -> dict[str, Any]:
    try:
        parts = shlex.split(command.replace("\\\n", " "))
    except ValueError as exc:
        raise ValueError(f"cURL 解析失败: {exc}") from exc
    if parts and parts[0].lower() == "curl":
        parts = parts[1:]
    url = ""
    headers: dict[str, str] = {}
    body = ""
    method = ""
    idx = 0
    while idx < len(parts):
        item = parts[idx]
        if item in ("-H", "--header") and idx + 1 < len(parts):
            add_header(headers, parts[idx + 1])
            idx += 2
            continue
        if item.startswith("--header="):
            add_header(headers, item.split("=", 1)[1])
            idx += 1
            continue
        if item in ("-A", "--user-agent") and idx + 1 < len(parts):
            headers["User-Agent"] = parts[idx + 1]
            idx += 2
            continue
        if item in ("-b", "--cookie") and idx + 1 < len(parts):
            headers["Cookie"] = parts[idx + 1]
            idx += 2
            continue
        if item.startswith("--cookie="):
            headers["Cookie"] = item.split("=", 1)[1]
            idx += 1
            continue
        if item in ("-X", "--request") and idx + 1 < len(parts):
            method = parts[idx + 1].upper()
            idx += 2
            continue
        if item in ("--data", "--data-raw", "--data-binary", "-d") and idx + 1 < len(parts):
            body = parts[idx + 1]
            method = method or "POST"
            idx += 2
            continue
        if item.startswith("http://") or item.startswith("https://"):
            url = item
        idx += 1
    if not url:
        raise ValueError("cURL 中没有找到 URL")
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("cURL URL 不是完整 http(s) 地址")
    return {
        "base_url": f"{parsed.scheme}://{parsed.netloc}",
        "path": parsed.path or "/",
        "headers": headers,
        "body": body,
        "method": method or "GET",
    }


def add_header(headers: dict[str, str], raw: str) -> None:
    if ":" not in raw:
        return
    name, value = raw.split(":", 1)
    name = name.strip()
    if not name:
        return
    if should_keep_imported_header(name):
        headers[name] = value.strip()


def should_keep_imported_header(name: str) -> bool:
    lower = name.strip().lower()
    if not lower or lower.startswith(":"):
        return False
    return lower not in UNSUPPORTED_IMPORTED_HEADERS


def import_curl_into_config(cfg: dict[str, Any], command: str) -> dict[str, Any]:
    parsed = parse_curl_command(command)
    return import_request_into_config(cfg, parsed, source="curl", candidates=1)


def import_request_into_config(
    cfg: dict[str, Any],
    parsed: dict[str, Any],
    *,
    source: str,
    candidates: int,
) -> dict[str, Any]:
    cfg["base_url"] = parsed["base_url"]
    if parsed["headers"]:
        cfg["headers"] = {key: value for key, value in parsed["headers"].items() if value}
    current_headers = cfg.setdefault("headers", {})
    path = str(parsed["path"])
    endpoints = cfg.setdefault("endpoints", {})
    if path.endswith("/source/locking/pre/check"):
        endpoints["pre_submit_check"] = path
    elif path.endswith("/source/locking"):
        endpoints["submit"] = path
    elif path.endswith("/source/dept/calendar"):
        endpoints["calendar"] = path
    elif path.endswith("/source/dept/detail"):
        endpoints["detail"] = path

    body = str(parsed.get("body") or "")
    if body:
        try:
            body_obj = json.loads(body)
        except json.JSONDecodeError:
            body_obj = {}
        patient_code = body_obj.get("patientCode")
        if patient_code:
            cfg.setdefault("target", {})["patient_code"] = str(patient_code)
    return {
        "source": source,
        "method": parsed["method"],
        "baseUrl": parsed["base_url"],
        "path": path,
        "headers": summarize_headers(current_headers),
        "patientCodeImported": bool((cfg.get("target") or {}).get("patient_code"))
        and "REPLACE_" not in str((cfg.get("target") or {}).get("patient_code")),
        "candidates": candidates,
    }


def import_har_into_config(cfg: dict[str, Any], content: str) -> dict[str, Any]:
    try:
        har = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"HAR 解析失败: {exc}") from exc
    entries = ((har.get("log") or {}).get("entries") or []) if isinstance(har, dict) else []
    requests = [request_from_har_entry(entry) for entry in entries]
    candidates = [item for item in requests if item and is_hospital_url(item["base_url"])]
    if not candidates:
        raise ValueError("HAR 中没有找到医院小程序请求")
    for item in candidates:
        update_known_endpoint(cfg.setdefault("endpoints", {}), item["path"])
        import_patient_code(cfg, item.get("body") or "")
    best = max(candidates, key=har_request_score)
    return import_request_into_config(cfg, best, source="har", candidates=len(candidates))


def request_from_har_entry(entry: dict[str, Any]) -> dict[str, Any] | None:
    request = entry.get("request") or {}
    url = str(request.get("url") or "")
    if not url:
        return None
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    headers = {
        str(item.get("name") or ""): str(item.get("value") or "")
        for item in request.get("headers") or []
        if item.get("name") and should_keep_imported_header(str(item.get("name") or ""))
    }
    body = str((request.get("postData") or {}).get("text") or "")
    return {
        "base_url": f"{parsed.scheme}://{parsed.netloc}",
        "path": parsed.path or "/",
        "headers": headers,
        "body": body,
        "method": str(request.get("method") or "GET").upper(),
    }


def is_hospital_url(base_url: str) -> bool:
    return urllib.parse.urlparse(base_url).netloc == "appaceso.zryhyy.com.cn"


def har_request_score(item: dict[str, Any]) -> tuple[int, int, int]:
    path = str(item.get("path") or "")
    headers = item.get("headers") or {}
    body = str(item.get("body") or "")
    endpoint_score = 3 if path.endswith("/source/locking") else 2 if "source/locking" in path else 1
    auth_score = sum(1 for key in headers if is_auth_header(key))
    patient_score = 1 if "patientCode" in body else 0
    return (endpoint_score, patient_score, auth_score)


def is_auth_header(name: str) -> bool:
    lower = name.lower()
    return lower in SENSITIVE_HEADER_NAMES or "ticket" in lower or "token" in lower


def update_known_endpoint(endpoints: dict[str, Any], path: str) -> None:
    if path.endswith("/source/locking/pre/check"):
        endpoints["pre_submit_check"] = path
    elif path.endswith("/source/locking"):
        endpoints["submit"] = path
    elif path.endswith("/source/dept/calendar"):
        endpoints["calendar"] = path
    elif path.endswith("/source/dept/detail"):
        endpoints["detail"] = path


def import_patient_code(cfg: dict[str, Any], body: str) -> None:
    if not body:
        return
    try:
        body_obj = json.loads(body)
    except json.JSONDecodeError:
        return
    patient_code = body_obj.get("patientCode")
    if patient_code:
        cfg.setdefault("target", {})["patient_code"] = str(patient_code)


def validate_auth_status(cfg: dict[str, Any], *, request_fn: Any = watch.request_json) -> dict[str, Any]:
    try:
        obj = request_fn(
            cfg,
            "/api/mobile/hospital/district/list",
            query={"_t": int(time.time() * 1000)},
        )
        watch.ensure_success(obj, "districts")
        count = len((obj.get("data") or {}).get("list") or [])
        return {
            "ok": True,
            "message": "登录态可用",
            "checkedEndpoint": "/api/mobile/hospital/district/list",
            "itemCount": count,
        }
    except Exception as exc:  # noqa: BLE001 - return a user-facing validation result.
        return {
            "ok": False,
            "message": str(exc),
            "checkedEndpoint": "/api/mobile/hospital/district/list",
        }


def update_notify_config(cfg: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    enabled = bool(payload.get("enabled"))
    channel_type = str(payload.get("type") or "webhook").lower()
    existing = find_existing_notify_channel(cfg, channel_type)
    channel = {
        "type": channel_type,
        "name": str(payload.get("name") or "手机通知"),
        "url": str(payload.get("url") or "").strip() or str(existing.get("url") or ""),
        "method": str(payload.get("method") or "POST").upper(),
        "enabled": True,
    }
    if channel_type == "bark":
        channel["server_url"] = str(payload.get("serverUrl") or existing.get("server_url") or "https://api.day.app").strip()
        channel["device_key"] = str(payload.get("deviceKey") or existing.get("device_key") or "").strip()
    elif channel_type == "serverchan":
        channel["send_key"] = str(payload.get("sendKey") or existing.get("send_key") or "").strip()
    elif channel_type == "telegram":
        channel["bot_token"] = str(payload.get("botToken") or existing.get("bot_token") or "").strip()
        channel["chat_id"] = str(payload.get("chatId") or existing.get("chat_id") or "").strip()
    if not is_notify_channel_configured(channel):
        cfg["notify"] = {"enabled": False, "channels": []}
    else:
        cfg["notify"] = {"enabled": enabled, "channels": [channel]}
    return cfg["notify"]


def find_existing_notify_channel(cfg: dict[str, Any], channel_type: str) -> dict[str, Any]:
    for channel in (cfg.get("notify") or {}).get("channels") or []:
        if str(channel.get("type") or "webhook").lower() == channel_type:
            return channel
    return {}


def is_notify_channel_configured(channel: dict[str, Any]) -> bool:
    channel_type = str(channel.get("type") or "webhook").lower()
    if channel_type == "bark":
        return bool(channel.get("device_key"))
    if channel_type == "serverchan":
        return bool(channel.get("send_key"))
    if channel_type == "telegram":
        return bool(channel.get("bot_token") and channel.get("chat_id"))
    return bool(channel.get("url"))


def truthy_query_flag(values: list[str] | None) -> bool:
    if not values:
        return False
    return str(values[0]).lower() in {"1", "true", "yes", "y"}


def load_district_items(cfg: dict[str, Any], *, force: bool = False) -> tuple[list[dict[str, Any]], bool]:
    def loader() -> list[dict[str, Any]]:
        obj = watch.request_json(cfg, "/api/mobile/hospital/district/list", query={"_t": int(time.time() * 1000)})
        watch.ensure_success(obj, "districts")
        return (obj.get("data") or {}).get("list") or []

    return cached_catalog_call("districts", "all", loader, force=force)


def load_department_items(cfg: dict[str, Any], district: str, *, force: bool = False) -> tuple[list[dict[str, Any]], bool]:
    def loader() -> list[dict[str, Any]]:
        obj = watch.request_json(
            cfg,
            "/api/mobile/department/list",
            query={"_t": int(time.time() * 1000), "districtCode": district},
        )
        watch.ensure_success(obj, "departments")
        return flatten_departments((obj.get("data") or {}).get("list") or [])

    return cached_catalog_call("departments", district, loader, force=force)


def send_test_notification(cfg: dict[str, Any]) -> dict[str, Any]:
    return watch.send_notification(
        cfg,
        "挂号监控测试通知",
        "这是一条测试通知。收到后，命中号源和提交成功也会推送到这里。",
        event="test",
    )


def notify_submit_result(
    cfg: dict[str, Any],
    result: dict[str, Any],
    *,
    notifier: Any = watch.send_notification,
) -> dict[str, Any] | None:
    if result.get("code") != 0:
        return None
    return notifier(
        cfg,
        "中日友好医院预约已提交，待支付",
        "预约请求已提交成功，请尽快到微信小程序内完成支付。",
        event="submitted",
    )


def format_notification_result(result: dict[str, Any] | None) -> str:
    if not result:
        return "通知未发送：没有返回发送结果"
    if result.get("sent"):
        return "通知已发送"
    results = result.get("results") or []
    if not results:
        return "通知未发送：通知未启用或没有可用通知通道"
    details = []
    for item in results:
        name = item.get("name") or "通知通道"
        if item.get("ok"):
            details.append(f"{name}: 已发送")
        elif item.get("error"):
            details.append(f"{name}: {item.get('error')}")
        else:
            details.append(f"{name}: HTTP {item.get('status') or '-'}")
    return "通知发送失败：" + "；".join(details)


def flatten_departments(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []

    def walk_node(node: dict[str, Any], parents: list[str]) -> None:
        name = str(node.get("deptName") or "")
        path = [*parents, name] if name else parents
        children = list(node.get("subList") or [])
        if node.get("isLeaf") or not children:
            flat.append(
                {
                    "deptCode": node.get("deptCode"),
                    "deptName": name,
                    "districtCode": node.get("districtCode"),
                    "haveInventory": bool(node.get("haveInventory")),
                    "path": " / ".join(item for item in path if item),
                }
            )
        for child in children:
            walk_node(child, path)

    for row in rows:
        walk_node(row, [])
    return [item for item in flat if item.get("deptCode")]


def source_to_dict(src: watch.Source) -> dict[str, Any]:
    return asdict(src) | {"label": src.label()}


def source_from_dict(data: dict[str, Any]) -> watch.Source:
    return watch.Source(
        dept_code=str(data.get("dept_code") or data.get("deptCode") or ""),
        doctor_code=str(data.get("doctor_code") or data.get("doctorCode") or ""),
        doctor_name=str(data.get("doctor_name") or data.get("doctorName") or ""),
        source_code=str(data.get("source_code") or data.get("sourceCode") or ""),
        source_name=str(data.get("source_name") or data.get("sourceName") or ""),
        visit_date=str(data.get("visit_date") or data.get("visitDate") or ""),
        period_type=str(data.get("period_type") or data.get("periodType") or ""),
        period_view=str(data.get("period_view") or data.get("periodView") or ""),
        price=str(data.get("price") or ""),
        count=int(data.get("count") or 0),
        support_time_interval=bool(data.get("support_time_interval") or data.get("supportTimeInterval")),
        time_interval_code=data.get("time_interval_code") or data.get("timeIntervalCode"),
        time_interval_view=data.get("time_interval_view") or data.get("timeIntervalView"),
    )


def target_dates(days: int = 10, *, now: datetime | None = None) -> list[dict[str, Any]]:
    current = now or datetime.now()
    today = current.date()
    default_visit_date = default_visit_date_for_monitor(now=current)
    week_names = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
    rows = []
    for offset in range(days):
        day = today + timedelta(days=offset)
        release_at = estimated_release_at(day.isoformat())
        within_window = bool(release_at and release_at <= current)
        rows.append(
            {
                "visitDate": day.isoformat(),
                "visitDateView": day.strftime("%m/%d"),
                "weekView": "今日" if offset == 0 else week_names[day.weekday()],
                "offsetDays": offset,
                "withinCurrentWindow": within_window,
                "sourceStatus": "PENDING_WINDOW" if not within_window else "",
                "sourceStatusView": "待放号" if not within_window else "",
                "estimatedReleaseAt": release_at.isoformat(timespec="seconds") if release_at else "",
                "defaultSelected": day.isoformat() == default_visit_date,
            }
        )
    return rows


def build_task_cfg(base: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    cfg = json.loads(json.dumps(base, ensure_ascii=False))
    target = cfg.setdefault("target", {})
    if payload.get("districtCode"):
        target["district_code"] = payload["districtCode"]
    if payload.get("deptCode"):
        target["dept_code"] = payload["deptCode"]
    if payload.get("deptName"):
        target["dept_name"] = payload["deptName"]
    target["expert_mode"] = str(payload.get("doctorMode") or target.get("expert_mode") or "prefer")
    target["prefer_doctor_codes"] = []
    periods = [str(payload["periodType"])] if payload.get("periodType") else ["AM", "PM"]
    target["prefer_periods"] = periods
    polling = cfg.setdefault("polling", {})
    if payload.get("intervalSeconds") is not None:
        interval = float(payload["intervalSeconds"])
        polling["interval_before_release"] = interval
        polling["interval_after_release"] = interval
    if payload.get("endAfterSeconds") is not None:
        polling["end_after_seconds"] = int(payload["endAfterSeconds"])
    return cfg


def filter_sources(sources: list[watch.Source], payload: dict[str, Any]) -> list[watch.Source]:
    visit_date = str(payload.get("visitDate") or "")
    period_type = str(payload.get("periodType") or "")
    filtered = []
    for src in sources:
        if visit_date and src.visit_date != visit_date:
            continue
        if period_type and src.period_type != period_type:
            continue
        filtered.append(src)
    return filtered


def format_task_notification_message(payload: dict[str, Any]) -> str:
    period_map = {"AM": "上午", "PM": "下午", "": "不限"}
    mode_map = {"any": "不限医生", "prefer": "专家优先", "required": "必须专家"}
    lines = [
        f"院区：{payload.get('districtCode') or '默认'}",
        f"科室：{payload.get('deptName') or payload.get('deptCode') or '未选择'}",
        f"日期：{payload.get('visitDate') or '未选择'}",
        f"时段：{period_map.get(str(payload.get('periodType') or ''), payload.get('periodType') or '不限')}",
        f"医生策略：{mode_map.get(str(payload.get('doctorMode') or ''), payload.get('doctorMode') or '默认')}",
        f"开始时间：{payload.get('startAt') or '立即'}",
        f"监控时长：{payload.get('endAfterSeconds') or 240} 秒",
        f"轮询间隔：{payload.get('intervalSeconds') or 1} 秒",
    ]
    return "\n".join(lines)


class MonitorManager:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.status: dict[str, Any] = {
            "running": False,
            "logs": [],
            "hits": [],
            "startedAt": None,
            "stoppedAt": None,
            "settings": {},
            "notifiedHit": False,
            "cooldownUntil": None,
            "cooldownSeconds": 0,
            "rateLimitCount": 0,
            "releaseAt": None,
            "pollIntervalSeconds": None,
        }

    def log(self, message: str) -> None:
        with self.lock:
            logs = self.status.setdefault("logs", [])
            logs.append(f"[{now_text()}] {message}")
            del logs[:-200]

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return json.loads(json.dumps(self.status, ensure_ascii=False))

    def start(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.stop()
        self.stop_event = threading.Event()
        with self.lock:
            self.status = {
                "running": True,
                "logs": [],
                "hits": [],
                "startedAt": datetime.now().isoformat(timespec="seconds"),
                "stoppedAt": None,
                "settings": payload,
                "notifiedHit": False,
                "cooldownUntil": None,
                "cooldownSeconds": 0,
                "rateLimitCount": 0,
                "releaseAt": None,
                "pollIntervalSeconds": None,
            }
        self.thread = threading.Thread(target=self._run, args=(payload,), daemon=True)
        self.thread.start()
        try:
            self._notify_task_lifecycle(load_cfg(), "started", payload)
        except Exception as exc:  # noqa: BLE001 - notification must not block monitoring.
            self.log(f"启动通知发送失败: {exc}")
        return self.snapshot()

    def stop(self) -> dict[str, Any]:
        payload = self.snapshot().get("settings") or {}
        old = self.thread
        if old and old.is_alive():
            self.stop_event.set()
            old.join(timeout=2)
        with self.lock:
            self.status["running"] = False
            self.status["stoppedAt"] = datetime.now().isoformat(timespec="seconds")
        self.thread = None
        if payload:
            try:
                self._notify_task_lifecycle(load_cfg(), "stopped", payload)
            except Exception as exc:  # noqa: BLE001
                self.log(f"停止通知发送失败: {exc}")
        return self.snapshot()

    def _sleep_until_start(self, payload: dict[str, Any]) -> bool:
        start_at = str(payload.get("startAt") or "").strip()
        if not start_at:
            return True
        target = watch.today_at(start_at)
        if target <= datetime.now():
            return True
        self.log(f"等待到 {target:%H:%M:%S} 开始监控")
        while datetime.now() < target:
            if self.stop_event.wait(timeout=1):
                self.log("监控已停止")
                return False
        return True

    def _run(self, payload: dict[str, Any]) -> None:
        try:
            cfg = build_task_cfg(load_cfg(), payload)
            target_date = str(payload.get("visitDate") or "")
            release_at = estimated_release_at(target_date)
            if release_at:
                with self.lock:
                    self.status["releaseAt"] = release_at.isoformat(timespec="seconds")
            if target_date:
                release_text = release_at.strftime("%m-%d %H:%M") if release_at else "未知"
                self.log(f"目标日期 {target_date}；预计放号时间 {release_text}")
            if not self._sleep_until_start(payload):
                return
            end_after = int(payload.get("endAfterSeconds") or cfg["polling"].get("end_after_seconds") or 240)
            end_at = datetime.now() + timedelta(seconds=end_after)
            requested_interval = max(0.2, float(payload.get("intervalSeconds") or 1.0))
            active_interval = requested_interval
            attempt = 0
            rate_limit_count = 0
            last_interval = None
            self.log("监控任务已启动")
            while not self.stop_event.is_set() and datetime.now() <= end_at:
                loop_now = datetime.now()
                active_interval = monitor_poll_interval_seconds(requested_interval, target_date, now=loop_now)
                if active_interval != last_interval:
                    self.log(release_poll_reason(target_date, active_interval, requested_interval, now=loop_now))
                    last_interval = active_interval
                with self.lock:
                    self.status["pollIntervalSeconds"] = active_interval
                attempt += 1
                try:
                    sources = filter_sources(watch.discover_sources(cfg), payload)
                    if rate_limit_count:
                        rate_limit_count = 0
                        self._clear_rate_limit_cooldown()
                    rows = [source_to_dict(src) for src in sources]
                    with self.lock:
                        self.status["hits"] = rows
                    if rows:
                        self.log(f"第 {attempt} 次检查命中 {len(rows)} 个号源")
                        self._notify_hit(cfg, sources)
                        break
                    self.log(f"第 {attempt} 次检查暂无号源")
                except Exception as exc:  # noqa: BLE001 - keep monitor alive.
                    if is_auth_expired_error(exc):
                        # 登录态已过期，继续轮询没有意义，停止并明确提示用户
                        msg = "授权已过期，请重新导入 headers 后再启动监控（" + str(exc) + "）"
                        self.log(msg)
                        try:
                            watch.send_notification(cfg, "中日友好医院监控已停止", msg, event="monitor_stopped")
                        except Exception:  # noqa: BLE001
                            pass
                        break
                    if is_rate_limit_error(exc):
                        rate_limit_count += 1
                        pause_seconds = rate_limit_backoff_seconds(rate_limit_count)
                        end_at += timedelta(seconds=pause_seconds)
                        cooldown_until = datetime.now() + timedelta(seconds=pause_seconds)
                        with self.lock:
                            self.status["cooldownUntil"] = cooldown_until.isoformat(timespec="seconds")
                            self.status["cooldownSeconds"] = pause_seconds
                            self.status["rateLimitCount"] = rate_limit_count
                        self.log(
                            f"第 {attempt} 次检查遇到医院接口限流，暂停 {format_wait_seconds(pause_seconds)} 后自动继续"
                            f"（连续 {rate_limit_count} 次，暂停时间不计入监控时长）"
                        )
                        if self.stop_event.wait(timeout=pause_seconds):
                            break
                        self._clear_rate_limit_cooldown()
                        continue
                    self.log(f"第 {attempt} 次检查失败: {exc}")
                if should_extend_monitor_for_pre_release(target_date, now=datetime.now()):
                    end_at += timedelta(seconds=active_interval)
                if self.stop_event.wait(timeout=active_interval):
                    break
            self.log("监控任务结束")
        finally:
            with self.lock:
                self.status["running"] = False
                self.status["stoppedAt"] = datetime.now().isoformat(timespec="seconds")
                self.status["cooldownUntil"] = None
                self.status["cooldownSeconds"] = 0

    def _notify_hit(
        self,
        cfg: dict[str, Any],
        sources: list[watch.Source],
        *,
        notifier: Any = watch.send_notification,
    ) -> dict[str, Any] | None:
        if not sources:
            return None
        with self.lock:
            if self.status.get("notifiedHit"):
                return None
            self.status["notifiedHit"] = True
        first = sources[0]
        extra = f"\n共命中 {len(sources)} 个候选号源。" if len(sources) > 1 else ""
        result = notifier(
            cfg,
            "中日友好医院发现可预约号源",
            first.label() + extra + "\n请尽快打开监控页面确认提交。",
            event="hit",
        )
        if result and result.get("sent"):
            self.log("已发送号源命中通知")
        else:
            self.log(format_notification_result(result))
        return result

    def _notify_task_lifecycle(
        self,
        cfg: dict[str, Any],
        action: str,
        payload: dict[str, Any],
        *,
        notifier: Any = watch.send_notification,
    ) -> dict[str, Any]:
        title = "中日友好医院监控已启动" if action == "started" else "中日友好医院监控已停止"
        event = "monitor_started" if action == "started" else "monitor_stopped"
        message = format_task_notification_message(payload)
        result = notifier(cfg, title, message, event=event)
        if result.get("sent"):
            self.log("已发送监控状态通知")
        else:
            self.log(format_notification_result(result))
        return result

    def _clear_rate_limit_cooldown(self) -> None:
        with self.lock:
            self.status["cooldownUntil"] = None
            self.status["cooldownSeconds"] = 0


MONITOR = MonitorManager()


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(WEB_ROOT), **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[web] {self.address_string()} {fmt % args}")

    def send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_error_json(self, exc: Exception, status: int = 500) -> None:
        traceback.print_exc()
        self.send_json({"ok": False, "error": str(exc)}, status)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path == "/api/health":
                self.send_json({"ok": True})
            elif parsed.path == "/api/config":
                cfg = load_cfg()
                self.send_json({"ok": True, "config": public_config(cfg)})
            elif parsed.path == "/api/districts":
                cfg = load_cfg()
                items, cached = load_district_items(cfg, force=truthy_query_flag(query.get("refresh")))
                self.send_json({"ok": True, "items": items, "cached": cached})
            elif parsed.path == "/api/departments":
                cfg = load_cfg()
                district = query.get("districtCode", [cfg["target"].get("district_code", "001")])[0]
                items, cached = load_department_items(cfg, district, force=truthy_query_flag(query.get("refresh")))
                self.send_json({"ok": True, "items": items, "cached": cached})
            elif parsed.path == "/api/calendar":
                cfg = load_cfg()
                dept = query.get("deptCode", [cfg["target"]["dept_code"]])[0]
                cfg["target"]["dept_code"] = dept
                calendar_rows = cached_api_call(
                    ("calendar", dept),
                    20,
                    lambda: watch.fetch_calendar(cfg),
                )
                calendar = {item.get("visitDate"): item for item in calendar_rows}
                items = []
                for item in target_dates(int(query.get("days", ["10"])[0])):
                    merged = {**item, **(calendar.get(item["visitDate"]) or {})}
                    if not calendar.get(item["visitDate"]) and merged.get("withinCurrentWindow"):
                        merged["sourceStatusView"] = merged.get("sourceStatusView") or "未返回"
                    items.append(merged)
                self.send_json({"ok": True, "items": items})
            elif parsed.path == "/api/doctors":
                cfg = load_cfg()
                dept = query.get("deptCode", [cfg["target"]["dept_code"]])[0]
                obj = watch.request_json(
                    cfg,
                    "/api/mobile/doctor/list",
                    query={"_t": int(time.time() * 1000), "deptCode": dept, "visitType": "OFFLINE"},
                )
                watch.ensure_success(obj, "doctors")
                self.send_json({"ok": True, "items": (obj.get("data") or {}).get("list") or []})
            elif parsed.path == "/api/sources":
                cfg = load_cfg()
                dept = query.get("deptCode", [cfg["target"]["dept_code"]])[0]
                date = query.get("visitDate", [""])[0]
                doctor_mode = query.get("doctorMode", [cfg["target"].get("expert_mode", "prefer")])[0]
                if not date:
                    self.send_json({"ok": True, "items": []})
                    return
                cfg["target"]["dept_code"] = dept
                cfg["target"]["expert_mode"] = doctor_mode
                rows = []
                sources = cached_api_call(
                    ("sources", dept, doctor_mode),
                    10,
                    lambda: watch.discover_sources(cfg),
                )
                for src in sources:
                    if src.visit_date == date:
                        rows.append(source_to_dict(src))
                self.send_json({"ok": True, "items": rows})
            elif parsed.path == "/api/tasks/status":
                self.send_json({"ok": True, "task": MONITOR.snapshot()})
            else:
                if parsed.path.startswith("/api/"):
                    self.send_json({"ok": False, "error": "not found"}, HTTPStatus.NOT_FOUND)
                else:
                    super().do_GET()
        except Exception as exc:  # noqa: BLE001
            self.send_error_json(exc)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        try:
            payload = parse_json_body(self)
            if parsed.path == "/api/config/target":
                cfg = load_cfg()
                target = cfg.setdefault("target", {})
                for api_key, cfg_key in [
                    ("districtCode", "district_code"),
                    ("deptCode", "dept_code"),
                    ("deptName", "dept_name"),
                    ("patientCode", "patient_code"),
                ]:
                    if payload.get(api_key) is not None:
                        target[cfg_key] = payload[api_key]
                if payload.get("doctorMode") is not None:
                    target["expert_mode"] = payload["doctorMode"]
                    target["prefer_doctor_codes"] = []
                if "preferSourceNames" in payload:
                    target["prefer_source_names"] = payload["preferSourceNames"]
                save_cfg(cfg)
                self.send_json({"ok": True, "config": public_config(cfg)})
            elif parsed.path == "/api/config/import-curl":
                cfg = load_cfg()
                result = import_curl_into_config(cfg, str(payload.get("curl") or ""))
                save_cfg(cfg)
                self.send_json({"ok": True, "imported": result, "config": public_config(cfg)})
            elif parsed.path == "/api/config/import-har":
                cfg = load_cfg()
                result = import_har_into_config(cfg, str(payload.get("har") or ""))
                save_cfg(cfg)
                self.send_json({"ok": True, "imported": result, "config": public_config(cfg)})
            elif parsed.path == "/api/config/validate-auth":
                cfg = load_cfg()
                result = validate_auth_status(cfg)
                self.send_json({"ok": True, "validation": result, "config": public_config(cfg)})
            elif parsed.path == "/api/config/notify":
                cfg = load_cfg()
                update_notify_config(cfg, payload)
                save_cfg(cfg)
                self.send_json({"ok": True, "config": public_config(cfg)})
            elif parsed.path == "/api/notify/test":
                cfg = load_cfg()
                result = send_test_notification(cfg)
                self.send_json({"ok": True, "notification": result, "config": public_config(cfg)})
            elif parsed.path == "/api/tasks/start":
                self.send_json({"ok": True, "task": MONITOR.start(payload)})
            elif parsed.path == "/api/tasks/stop":
                self.send_json({"ok": True, "task": MONITOR.stop()})
            elif parsed.path == "/api/submit":
                cfg = load_cfg()
                phrase = cfg.get("submit", {}).get("confirm_phrase") or "CONFIRM"
                if payload.get("confirmPhrase") != phrase:
                    self.send_json({"ok": False, "error": "确认词不匹配"}, HTTPStatus.BAD_REQUEST)
                    return
                src = source_from_dict(payload.get("source") or {})
                result = watch.submit_source(cfg, src)
                notify_submit_result(cfg, result)
                self.send_json({"ok": True, "result": result})
            else:
                self.send_json({"ok": False, "error": "not found"}, HTTPStatus.NOT_FOUND)
        except Exception as exc:  # noqa: BLE001
            self.send_error_json(exc)


def main() -> int:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[server] http://{host}:{port} config={CONFIG_PATH}")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
