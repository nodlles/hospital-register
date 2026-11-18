#!/usr/bin/env python3
"""从本机微信小程序运行时读登录态，省掉导出 HAR / 粘贴 cURL 这一步。

思路
----
手机端的「微信开发者工具」类运行时（WeAppDev / WMPF Studio）会在小程序逻辑层
暴露一个 V8 Inspector（CDP）。`adb forward` 出来以后就是标准 DevTools 协议，于是：

1. `wx_login_code()`：直接在逻辑层调 `wx.login()` 拿 code。
   北大口腔这类「code 换 token」的小程序，有了 code 就能自己换 token，
   连一条请求头都不用抄。

2. `harvest()`：在逻辑层装一个请求钩子（`__wmpfReqHooks` / `__wmpfRespHooks`），
   小程序自己发出去的每一条请求的 header、以及每条响应的 Set-Cookie 都会进我们的桶。
   中日友好这类「Cookie 就是登录态」的小程序，用它把 Cookie 捞出来写进配置即可。

也就是说：用户在手机上扫码登录一次，剩下的交给这里。HAR 导出退化成兜底方案。

前置条件
--------
- 一个跑着微信开发者工具的运行环境（本机模拟器即可），adb 能连上；
- 要采集的小程序已经在里面打开，并且**它是这个运行时里第一个打开的小程序**
  （这类运行时的 CDP 通道只挂第一个实例，换小程序要重启运行时）；
- 读登录态需要小程序停在**前台**，它不发请求就等于没数据。

用法
----
    python3 wxdevtools.py --doctor                 # 看看通道通不通
    python3 wxdevtools.py --login-code             # 只要 wx.login 的 code
    python3 wxdevtools.py --harvest                # 捞出请求头（脱敏打印）

也可以当库用：

    from wxdevtools import channel_from_local
    ch = channel_from_local()
    requests = ch.harvest(trigger="nudge")
"""

from __future__ import annotations

import base64
import json
import os
import re
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any, Iterable

DEFAULT_PORTS = (9400, 9429)
LOGIC_PATH = "/devtools/appservice"
TAP_LIMIT = 80

# 已知医院小程序的接口域名。判定「哪条请求算目标医院的」靠它。
# 两家已支持医院的 appId。wx.login 的 code 是「按小程序」发的，
# 在错的小程序里取 code 换不到的，所以要核对。
HOSPITAL_APP_IDS = {
    "zry": "wx869a0e459663d82a",     # 中日友好医院
    "bdkq": "wxf47aa38d871be854",    # 北京大学口腔医院
}

HOSPITAL_HOSTS = (
    "appaceso.zryhyy.com.cn",
    "app.bdkq.mingxuan.store",
)

# 光看名字就知道携带登录态的请求头
AUTH_HEADER_HINTS = ("cookie", "authorization", "token", "ticket", "session", "sid")

# 这些头抄下来没有意义，交给 HTTP 库自己生成
DROP_HEADERS = {"content-length", "host", "connection", "accept-encoding", "transfer-encoding"}


class DevtoolsError(RuntimeError):
    """通道打不通时抛这个，调用方可以据此退回 HAR 方案。"""


# --------------------------------------------------------------------------- #
# 极简 WebSocket（只用标准库；CDP 只跑在本机回环上）
# --------------------------------------------------------------------------- #
class Ws:
    def __init__(self, host: str, port: int, path: str, timeout: float = 10.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise DevtoolsError("WebSocket 握手被关闭")
            buf += chunk
        head, self._buf = buf.split(b"\r\n\r\n", 1)
        if b"101" not in head.split(b"\r\n")[0]:
            raise DevtoolsError("WebSocket 握手失败: " + head.decode("utf-8", "replace")[:200])

    def send(self, obj: dict[str, Any]) -> None:
        data = json.dumps(obj).encode()
        header = bytearray([0x81])
        size = len(data)
        if size < 126:
            header.append(0x80 | size)
        elif size < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", size)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", size)
        mask = os.urandom(4)
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        self.sock.sendall(bytes(header) + masked)

    def _fill(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise DevtoolsError("WebSocket 被对端关闭")
        self._buf += chunk

    def recv(self) -> str:
        while True:
            if len(self._buf) >= 2:
                opcode = self._buf[0] & 0x0F
                size = self._buf[1] & 0x7F
                offset = 2
                if size == 126:
                    if len(self._buf) < 4:
                        self._fill()
                        continue
                    size = struct.unpack(">H", self._buf[2:4])[0]
                    offset = 4
                elif size == 127:
                    if len(self._buf) < 10:
                        self._fill()
                        continue
                    size = struct.unpack(">Q", self._buf[2:10])[0]
                    offset = 10
                if len(self._buf) < offset + size:
                    self._fill()
                    continue
                payload = self._buf[offset:offset + size]
                self._buf = self._buf[offset + size:]
                if opcode == 8:
                    raise DevtoolsError("WebSocket 被对端关闭")
                if opcode in (1, 2):
                    return payload.decode("utf-8", "replace")
                continue
            self._fill()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# adb + target 发现
# --------------------------------------------------------------------------- #
def find_adb() -> str:
    """按 ANDROID_HOME / 常见安装位置找 adb。"""
    candidates = []
    env = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if env:
        candidates.append(os.path.join(env, "platform-tools", "adb"))
    home = os.path.expanduser("~")
    candidates += [
        os.path.join(home, "Library", "Android", "sdk", "platform-tools", "adb"),
        os.path.join(home, "Android", "Sdk", "platform-tools", "adb"),
    ]
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return "adb"


def adb_run(args: list[str], adb: str | None = None, timeout: float = 20.0) -> str:
    cmd = [adb or find_adb()] + args
    try:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise DevtoolsError(f"找不到 adb（{cmd[0]}），请安装 platform-tools 或设置 ANDROID_HOME") from exc
    except subprocess.TimeoutExpired as exc:
        raise DevtoolsError(f"adb {' '.join(args)} 超时") from exc
    if done.returncode != 0:
        raise DevtoolsError(f"adb {' '.join(args)} 失败: {(done.stderr or '').strip()[:200]}")
    return done.stdout


def first_device(adb: str | None = None) -> str:
    out = adb_run(["devices"], adb=adb)
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            return parts[0]
    raise DevtoolsError("没有连上的 android 设备/模拟器（adb devices 是空的）")


def forward_port(adb: str, serial: str, local: int, remote: int) -> None:
    adb_run(["-s", serial, "forward", f"tcp:{local}", f"tcp:{remote}"], adb=adb)


def forward_abstract(adb: str, serial: str, local: int, name: str) -> None:
    adb_run(["-s", serial, "forward", f"tcp:{local}", f"localabstract:{name}"], adb=adb)


def drop_forward(adb: str, serial: str, local: int) -> None:
    try:
        adb_run(["-s", serial, "forward", "--remove", f"tcp:{local}"], adb=adb)
    except DevtoolsError:
        pass


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def http_json(url: str, timeout: float = 5.0) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - 本机回环
        return json.loads(resp.read().decode("utf-8"))


def list_targets(port: int, host: str = "127.0.0.1") -> list[dict[str, Any]]:
    try:
        data = http_json(f"http://{host}:{port}/json/list")
    except Exception:  # noqa: BLE001 - 端口没开就是没有，交给上层汇总
        return []
    return data if isinstance(data, list) else []


def find_logic_target(ports: Iterable[int] = DEFAULT_PORTS, host: str = "127.0.0.1") -> dict[str, Any]:
    """找到小程序的逻辑层 target（带 wx 的那一层）。"""
    seen = []
    for port in ports:
        targets = list_targets(port, host)
        if not targets:
            seen.append(f":{port} 没有响应")
            continue
        for item in targets:
            kind = str(item.get("type") or "")
            if kind in ("app_service", "worker", "service") or "appservice" in str(item.get("url") or ""):
                return {"port": port, "webSocketDebuggerUrl": item.get("webSocketDebuggerUrl"),
                        "title": item.get("title") or "", "target": item}
        seen.append(f":{port} 有 {len(targets)} 个 target，但没有逻辑层")
    raise DevtoolsError("没找到小程序逻辑层：" + "；".join(seen))


RENDER_SOCKET_PREFIX = "webview_devtools_remote_"


def socket_names_from(text: str) -> list[str]:
    """从 /proc/net/unix 的内容里挑出渲染层调试 socket 名，按 pid 排序。"""
    names = {match.group(0) for match in re.finditer(RENDER_SOCKET_PREFIX + r"\d+", text or "")}
    return sorted(names, key=lambda item: int(item[len(RENDER_SOCKET_PREFIX):]))


def webview_sockets(adb: str | None = None, serial: str | None = None) -> list[str]:
    """设备上所有渲染层调试 socket 名字（webview_devtools_remote_<pid>）。"""
    args = (["-s", serial] if serial else []) + ["shell", "cat", "/proc/net/unix"]
    try:
        out = adb_run(args, adb=adb)
    except DevtoolsError:
        return []
    return socket_names_from(out)


def find_render_target(app_id: str, *, adb: str | None = None, host: str = "127.0.0.1"
                       ) -> dict[str, Any]:
    """找到这个小程序**渲染层**的 page target（转发保持打开，用完调 close_target）。

    逻辑层看不到 `navigator.userAgent`，但医院接口偏偏要校验它；渲染层就是
    微信自己那个 webview，里面的 UA 和原生层发出去的一模一样，直接读即可。
    """
    adb_path = adb or find_adb()
    serial = first_device(adb_path)
    tried: list[str] = []
    for name in webview_sockets(adb_path, serial):
        local = free_port()
        try:
            forward_abstract(adb_path, serial, local, name)
        except DevtoolsError as exc:
            tried.append(f"{name}: {exc}")
            continue
        found = None
        for item in list_targets(local, host):
            if str(item.get("type") or "") != "page":
                continue
            title = str(item.get("title") or "")
            if app_id and app_id not in title:
                continue
            found = {"port": local, "socket": name, "title": title,
                     "webSocketDebuggerUrl": item.get("webSocketDebuggerUrl"),
                     "adb": adb_path, "serial": serial}
            break
        if found:
            return found
        drop_forward(adb_path, serial, local)
        tried.append(f"{name}: 没有 {app_id or '小程序'} 的 page target")
    raise DevtoolsError("没找到小程序渲染层：" + ("；".join(tried) or "设备上没有 webview 调试 socket"))


def close_target(target: dict[str, Any]) -> None:
    """收掉 find_render_target 留下的端口转发。"""
    if target.get("adb") and target.get("serial") and target.get("port"):
        drop_forward(str(target["adb"]), str(target["serial"]), int(target["port"]))


def page_eval(ws_url: str, expression: str, timeout: float = 10.0) -> Any:
    """在渲染层 page target 里求值（不需要挑 contextId）。"""
    cdp = Cdp(ws_url, timeout=timeout)
    try:
        result = cdp.call("Runtime.evaluate",
                          {"expression": expression, "returnByValue": True,
                           "awaitPromise": True}, timeout=timeout)
    finally:
        cdp.close()
    if "exceptionDetails" in result:
        detail = result["exceptionDetails"]
        raise DevtoolsError(f"渲染层执行出错: {str(detail.get('text') or detail)[:200]}")
    return (result.get("result") or {}).get("value")


_UA_CACHE: dict[str, str] = {}


def read_user_agent(app_id: str, *, adb: str | None = None, host: str = "127.0.0.1",
                    use_cache: bool = True) -> str:
    """读小程序真实 UA（原生层对医院接口做的就是这一个值）。"""
    if use_cache and app_id in _UA_CACHE:
        return _UA_CACHE[app_id]
    target = find_render_target(app_id, adb=adb, host=host)
    try:
        value = str(page_eval(str(target.get("webSocketDebuggerUrl") or ""),
                              "navigator.userAgent") or "")
    finally:
        close_target(target)
    if not value:
        raise DevtoolsError("渲染层没给出 navigator.userAgent")
    if use_cache:
        _UA_CACHE[app_id] = value
    return value


# --------------------------------------------------------------------------- #
# CDP 会话
# --------------------------------------------------------------------------- #
class Cdp:
    def __init__(self, ws_url: str, timeout: float = 20.0) -> None:
        parsed = urllib.parse.urlparse(ws_url)
        if not parsed.hostname or not parsed.port:
            raise DevtoolsError(f"webSocketDebuggerUrl 不完整: {ws_url}")
        self.ws = Ws(parsed.hostname, parsed.port, parsed.path or LOGIC_PATH, timeout=timeout)
        self._id = 0
        self._events: list[dict[str, Any]] = []

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.ws.send({"method": method, "params": params or {}})

    def call(self, method: str, params: dict[str, Any] | None = None,
             timeout: float = 20.0) -> dict[str, Any]:
        self._id += 1
        want = self._id
        self.ws.send({"id": want, "method": method, "params": params or {}})
        deadline = time.time() + timeout
        while time.time() < deadline:
            message = json.loads(self.ws.recv())
            if message.get("id") == want:
                if "error" in message:
                    raise DevtoolsError(f"{method} 失败: {str(message['error'])[:200]}")
                return message.get("result") or {}
            if "method" in message:
                self._events.append(message)
        raise DevtoolsError(f"{method} 超时")

    def close(self) -> None:
        self.ws.close()


TAP_JS = """
(function(){
  if (globalThis.__tybotTap) return 'already';
  var hooks = globalThis.__wmpfReqHooks;
  if (!hooks) return 'no-hooks';
  var tap = {req: [], res: []};
  globalThis.__tybotTap = tap;
  function str(v){
    if (v === undefined || v === null) return '';
    if (typeof v === 'string') return v.length > 4000 ? v.slice(0, 4000) : v;
    try { return JSON.stringify(v).slice(0, 4000); } catch (e) { return String(v).slice(0, 4000); }
  }
  hooks.push(function(req){
    try {
      tap.req.push({url: str(req && req.url), method: str(req && req.method || 'GET'),
                    header: (req && req.header) || {}, body: str(req && req.data)});
      if (tap.req.length > %d) tap.req.shift();
    } catch (e) {}
    return undefined;   /* 返回对象会被当成改写请求，必须返回 undefined */
  });
  var resHooks = globalThis.__wmpfRespHooks;
  if (resHooks) {
    resHooks.push(function(resp){
      try {
        tap.res.push({url: str(resp && resp.req && resp.req.url),
                      status: (resp && resp.statusCode) || 0,
                      header: (resp && resp.header) || {},
                      body: str(resp && resp.data)});
        if (tap.res.length > %d) tap.res.shift();
      } catch (e) {}
      return undefined;
    });
  }
  return 'ok';
})()
""" % (TAP_LIMIT, TAP_LIMIT)

NUDGE_JS = """
(function(){
  try {
    var pages = (typeof getCurrentPages === 'function') ? getCurrentPages() : [];
    var page = pages[pages.length - 1];
    if (!page) return 'no-page';
    if (typeof page.onShow === 'function') {
      try { page.onShow(); return 'onShow'; } catch (e) {}
    }
    return 'no-hook';
  } catch (e) { return 'err'; }
})()
"""


class Channel:
    """一个小程序逻辑层的 CDP 通道。"""

    def __init__(self, port: int, ws_url: str, title: str = "") -> None:
        self.port = port
        self.ws_url = ws_url
        self.title = title
        self.cdp = Cdp(ws_url)
        self._context: int | None = None
        self.cdp.notify("Runtime.enable")
        # Runtime.enable 之后会推 executionContextCreated，给事件留点时间落地
        time.sleep(0.4)
        self._drain()

    # -- 基础 ------------------------------------------------------------- #
    def _drain(self) -> None:
        self.cdp._events.clear()

    @property
    def app_id(self) -> str:
        text = str(self.title or "")
        if "APPID:" in text:
            raw = text.split("APPID:", 1)[1]
            return raw.split(")")[0].strip()
        return ""

    def eval_js(self, expression: str, *, context_id: int | None = None,
                timeout: float = 25.0) -> Any:
        params: dict[str, Any] = {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        }
        cid = context_id if context_id is not None else self.context()
        if cid is not None:
            params["contextId"] = cid
        result = self.cdp.call("Runtime.evaluate", params, timeout=timeout)
        if "exceptionDetails" in result:
            detail = result["exceptionDetails"]
            raise DevtoolsError(f"页面里执行出错: {str(detail.get('text') or detail)[:200]}")
        return (result.get("result") or {}).get("value")

    def context(self) -> int | None:
        """找到 `wx` 所在的执行上下文。

        逻辑层里通常有多个上下文（主上下文 + 若干 WxaSub-*），
        `wx` / `getApp` / `require` 只在其中一个里，所以要挨个试。
        """
        if self._context is not None:
            return self._context
        ids: list[int] = []
        for event in self.cdp._events:
            if event.get("method") != "Runtime.executionContextCreated":
                continue
            ctx = (event.get("params") or {}).get("context") or {}
            if isinstance(ctx.get("id"), int):
                ids.append(int(ctx["id"]))
        for cid in ids or [1, 2, 3]:
            try:
                if self.eval_js("typeof wx", context_id=cid, timeout=8) == "object":
                    self._context = cid
                    return cid
            except DevtoolsError:
                continue
        return None

    # -- 能力 ------------------------------------------------------------- #
    def login_code(self, timeout: float = 25.0) -> str:
        """在逻辑层调 wx.login()，拿一次性 code。"""
        script = (
            "new Promise(function(resolve){"
            "wx.login({success:function(r){resolve(JSON.stringify(r||{}));},"
            "fail:function(e){resolve('ERR '+JSON.stringify(e||{}));}});"
            "})"
        )
        raw = self.eval_js(script, timeout=timeout)
        if not isinstance(raw, str) or raw.startswith("ERR"):
            raise DevtoolsError(f"wx.login 调用失败: {raw}")
        data = json.loads(raw)
        code = str(data.get("code") or "")
        if not code:
            raise DevtoolsError(f"wx.login 没给 code（微信登录态可能过期了）：{data}")
        return code

    def install_tap(self) -> str:
        return str(self.eval_js(TAP_JS, timeout=10) or "")

    def raw_tap(self) -> dict[str, Any]:
        raw = self.eval_js("JSON.stringify(globalThis.__tybotTap || {req:[],res:[]})", timeout=10)
        try:
            data = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {"req": [], "res": []}
        return {"req": data.get("req") or [], "res": data.get("res") or []}

    def clear_tap(self) -> None:
        self.eval_js("(globalThis.__tybotTap? (globalThis.__tybotTap.req.length=0,"
                     "globalThis.__tybotTap.res.length=0, 'ok') : 'none')", timeout=10)

    def nudge(self) -> str:
        """让当前页面重跑 onShow，触发它自己的刷新请求。"""
        return str(self.eval_js(NUDGE_JS, timeout=10) or "")

    # -- 元信息 ----------------------------------------------------------- #
    def account_info(self) -> dict[str, Any]:
        """`wx.getAccountInfoSync()` 里跟请求头有关的那几项。"""
        script = (
            "JSON.stringify((function(){try{var a=wx.getAccountInfoSync()||{};"
            "var m=a.miniProgram||{};return {appId:m.appId||'',version:m.version||'',"
            "envVersion:m.envVersion||''};}catch(e){return {err:String(e)};}})())"
        )
        raw = self.eval_js(script, timeout=10)
        try:
            data = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def system_info(self) -> dict[str, Any]:
        script = (
            "JSON.stringify((function(){try{return wx.getSystemInfoSync()||{};}"
            "catch(e){return {err:String(e)};}})())"
        )
        raw = self.eval_js(script, timeout=10)
        try:
            data = json.loads(raw or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def referer(self) -> str:
        """小程序的合法 Referer：servicewechat.com/<appId>/<version>/page-frame.html。"""
        info = self.account_info()
        app_id = str(info.get("appId") or self.app_id or "")
        version = str(info.get("version") or "")
        if not app_id or not version:
            return ""
        return f"https://servicewechat.com/{app_id}/{version}/page-frame.html"

    def user_agent(self, *, adb: str | None = None) -> str:
        """小程序真实 UA（从渲染层读，逻辑层拿不到完整值）。"""
        try:
            return read_user_agent(self.app_id, adb=adb)
        except DevtoolsError:
            return ""

    def collect(self, *, timeout: float = 15.0, trigger: str = "nudge",
                adb: str | None = None) -> dict[str, Any]:
        """一步到位：装钩子 → 触发 → 选请求 → 补 UA/Referer → 转成配置结构。

        返回的 `payload` 可以直接喂给
        `app_server.import_request_into_config()`。
        """
        data = self.harvest(timeout=timeout, trigger=trigger)
        item = choose_request(data["req"])
        if item is None:
            raise DevtoolsError(
                "没采到目标医院的请求。确认小程序停在前台、并且这个页面有数据请求"
                f"（本次共采到 {len(data['req'])} 条请求）")
        payload = to_import_payload(item, data["res"],
                                    user_agent=self.user_agent(adb=adb),
                                    referer=self.referer())
        return {
            "payload": payload,
            "requests": data["req"],
            "responses": data["res"],
            "summary": summarize(data["req"]),
            "userAgent": payload["headers"].get("User-Agent", ""),
            "referer": payload["headers"].get("Referer", ""),
        }

    def harvest(self, *, timeout: float = 15.0, minimum: int = 1,
                trigger: str = "nudge", settle: float = 2.5) -> dict[str, Any]:
        """装钩子 → 触发一次请求 → 把请求头/响应头收回来。"""
        status = self.install_tap()
        if status == "no-hooks":
            raise DevtoolsError("这个运行时没有 __wmpfReqHooks，装不上请求钩子")
        self.clear_tap()
        if trigger == "nudge":
            self.nudge()
        deadline = time.time() + timeout
        settle_deadline: float | None = None
        data = self.raw_tap()
        while time.time() < deadline:
            data = self.raw_tap()
            if len(data["req"]) >= minimum:
                if data["res"]:
                    break                      # 响应也到了，Set-Cookie 才有得看
                if settle_deadline is None:
                    settle_deadline = time.time() + settle
                if time.time() >= settle_deadline:
                    break                      # 这个接口本来就不带响应体的现场
            time.sleep(0.4)
        return data

    def close(self) -> None:
        self.cdp.close()


def channel_from_local(ports: Iterable[int] = DEFAULT_PORTS, host: str = "127.0.0.1",
                       adb: str | None = None, forward: bool = True,
                       expect_app: str = "") -> Channel:
    """连本机（模拟器）上的小程序逻辑层。

    `expect_app` 给期望的 appId：运行时的调试通道只挂在**第一个打开的小程序**
    上，所以换小程序必须重启运行时；对不上就明确报错，别拿着别人的 code 去换 token。
    """
    adb_path = adb or find_adb()
    if forward:
        try:
            serial = first_device(adb_path)
            for port in ports:
                try:
                    forward_port(adb_path, serial, port, port)
                except DevtoolsError:
                    continue
        except DevtoolsError:
            pass  # 端口已经转发过、或者本来就是真机直连，继续试
    target = find_logic_target(ports, host)
    channel = Channel(target["port"], str(target["webSocketDebuggerUrl"]),
                      str(target.get("title") or ""))
    if expect_app and channel.app_id and channel.app_id != expect_app:
        current = channel.app_id
        channel.close()
        raise DevtoolsError(
            f"运行时里挂着的是 {current}（{channel.title}），不是要的 {expect_app}。"
            "这个运行时的调试通道只给第一个打开的小程序：把目标小程序先打开，"
            "必要时 adb shell am force-stop github.ryf5584.weappdev 重启运行时再来。")
    return channel


def channel_from_port(port: int, host: str = "127.0.0.1") -> Channel:
    target = find_logic_target([port], host)
    return Channel(target["port"], str(target["webSocketDebuggerUrl"]), str(target.get("title") or ""))


# --------------------------------------------------------------------------- #
# 把抓到的请求变成配置
# --------------------------------------------------------------------------- #
def host_of(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc.lower()
    except ValueError:
        return ""


def is_hospital_request(url: str, hosts: Iterable[str] = HOSPITAL_HOSTS) -> bool:
    host = host_of(url)
    if not host:
        return False
    return any(host == item.lower() or host.endswith("." + item.lower()) for item in hosts)


def is_auth_header(name: str) -> bool:
    lower = str(name or "").strip().lower()
    if not lower or lower.startswith(":"):
        return False
    return any(hint in lower for hint in AUTH_HEADER_HINTS)


def clean_headers(raw: Any) -> dict[str, str]:
    """去掉没意义/会被 HTTP 库重算的头。"""
    out: dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        name = str(key or "").strip()
        if not name or name.lower() in DROP_HEADERS:
            continue
        if value is None:
            continue                      # 空值头一律不发，避免变成字符串 "null"
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        if text:
            out[name] = text
    return out


def set_cookie_values(header: Any) -> list[str]:
    """从响应头字典里取出所有 Set-Cookie（键名大小写不定，值可能是列表）。"""
    values: list[str] = []
    if not isinstance(header, dict):
        return values
    for key, value in header.items():
        if str(key or "").strip().lower() != "set-cookie":
            continue
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value)
    return values


def merge_set_cookie(headers: dict[str, str], set_cookie: Any) -> dict[str, str]:
    """把响应里的 Set-Cookie 合并进 Cookie 头，保证拿到的是最新会话。"""
    cookies = {}
    existing = str(headers.get("Cookie") or "")
    for chunk in existing.split(";"):
        if "=" in chunk:
            key, value = chunk.split("=", 1)
            cookies[key.strip()] = value.strip()
    items: list[str] = []
    if isinstance(set_cookie, str):
        items = [set_cookie]
    elif isinstance(set_cookie, list):
        items = [str(item) for item in set_cookie]
    elif isinstance(set_cookie, dict):
        items = [f"{key}={value}" for key, value in set_cookie.items()]
    for item in items:
        pair = item.split(";", 1)[0].strip()
        if "=" in pair:
            key, value = pair.split("=", 1)
            if key.strip() and value.strip():
                cookies[key.strip()] = value.strip()
    if cookies:
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
    return headers


def request_score(item: dict[str, Any]) -> tuple[int, int, int]:
    """挑「最像一次真实业务请求」的那条：接口越像下单、带的登录态头越多越优先。"""
    url = str(item.get("url") or "")
    path = urllib.parse.urlparse(url).path
    headers = item.get("header") or {}
    auth = sum(1 for key in headers if is_auth_header(str(key)))
    endpoint = 3 if path.endswith("/source/locking") else 2 if "locking" in path else 1
    return (auth, endpoint, 1 if str(item.get("method") or "").upper() == "POST" else 0)


def choose_request(requests: Iterable[dict[str, Any]],
                   hosts: Iterable[str] = HOSPITAL_HOSTS) -> dict[str, Any] | None:
    candidates = [item for item in requests if is_hospital_request(str(item.get("url") or ""), hosts)]
    if not candidates:
        return None
    return max(candidates, key=request_score)


def to_import_payload(item: dict[str, Any], responses: Iterable[dict[str, Any]] = (),
                      user_agent: str = "", referer: str = "") -> dict[str, Any]:
    """转成 app_server.import_request_into_config 吃的那种结构。

    UA / Referer 是微信原生层加的，钩子看不到，所以要单独补进来：
    医院接口会校验它们，缺了就「非法请求」。
    """
    url = str(item.get("url") or "")
    parsed = urllib.parse.urlparse(url)
    headers = clean_headers(item.get("header"))
    for resp in responses:
        if str(resp.get("url") or "").split("?")[0] == url.split("?")[0]:
            merge_set_cookie(headers, set_cookie_values(resp.get("header")))
    if user_agent and not any(key.lower() == "user-agent" for key in headers):
        headers["User-Agent"] = user_agent
    if referer and not any(key.lower() == "referer" for key in headers):
        headers["Referer"] = referer
    return {
        "base_url": f"{parsed.scheme}://{parsed.netloc}",
        "path": parsed.path or "/",
        "headers": headers,
        "body": str(item.get("body") or ""),
        "method": str(item.get("method") or "GET").upper(),
    }


def summarize(requests: Iterable[dict[str, Any]],
              hosts: Iterable[str] = HOSPITAL_HOSTS) -> list[str]:
    """脱敏的采集摘要，给日志和页面用：只报有哪些头，不报值。"""
    lines = []
    for item in requests:
        url = str(item.get("url") or "")
        if not is_hospital_request(url, hosts):
            continue
        names = sorted(clean_headers(item.get("header")))
        lines.append(f"{item.get('method') or 'GET'} {host_of(url)}{urllib.parse.urlparse(url).path} "
                     f"[{', '.join(names)}]")
    return lines


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _doctor() -> int:
    try:
        adb = find_adb()
        print(f"adb: {adb}")
        serial = first_device(adb)
        print(f"设备: {serial}")
        for port in DEFAULT_PORTS:
            try:
                forward_port(adb, serial, port, port)
            except DevtoolsError as exc:
                print(f"  :{port} 转发失败 {exc}")
    except DevtoolsError as exc:
        print(f"[!] {exc}")
        return 2
    for port in DEFAULT_PORTS:
        targets = list_targets(port)
        print(f":{port} -> {len(targets)} 个 target")
        for item in targets:
            if item.get("type") in ("app_service", "worker", "service"):
                print(f"    逻辑层: {item.get('title')}")
    try:
        channel = channel_from_local()
    except DevtoolsError as exc:
        print(f"[!] {exc}")
        return 2
    try:
        print(f"已连上: {channel.title}")
        print(f"执行上下文: {channel.context()}")
        print(f"装钩子: {channel.install_tap()}")
        print(f"nudge: {channel.nudge()}")
        info = channel.account_info()
        print(f"小程序: {info.get('appId')} v{info.get('version')}")
        print(f"Referer: {channel.referer()}")
        agent = channel.user_agent()
        print(f"UA: {agent[:80]}{'…' if len(agent) > 80 else ''}" if agent else "UA: (渲染层没读到)")
        data = channel.harvest(timeout=8)
        print(f"采到请求 {len(data['req'])} 条 / 响应 {len(data['res'])} 条")
        for line in summarize(data["req"]):
            print("   ", line)
    finally:
        channel.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="微信开发者工具登录态通道")
    parser.add_argument("--doctor", action="store_true", help="检查通道是否可用")
    parser.add_argument("--login-code", action="store_true", help="调 wx.login 只取 code")
    parser.add_argument("--harvest", action="store_true", help="采集请求头（脱敏打印）")
    parser.add_argument("--port", type=int, default=None, help="手动指定 CDP 端口")
    parser.add_argument("--expect", default="", choices=["", *HOSPITAL_APP_IDS],
                        help="要求运行时里是这个医院的小程序（zry / bdkq）")
    args = parser.parse_args(argv)

    if args.login_code or args.harvest:
        expect = HOSPITAL_APP_IDS.get(args.expect, "")
        channel = (channel_from_port(args.port) if args.port
                   else channel_from_local(expect_app=expect))
        try:
            if args.login_code:
                print(channel.login_code())
            if args.harvest:
                data = channel.harvest()
                for line in summarize(data["req"]) or ["(没采到目标医院的请求)"]:
                    print(line)
        finally:
            channel.close()
        return 0
    return _doctor()


if __name__ == "__main__":
    raise SystemExit(main())
