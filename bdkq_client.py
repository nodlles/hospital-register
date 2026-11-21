#!/usr/bin/env python3
"""北京大学口腔医院小程序（v331）接口客户端。

与 hospital_watch.py 里中日友好的「导入 HAR 拿 headers」思路一致，区别是这个
医院所有请求都要现算签名并用国密加密请求体/解密响应体，见 bdkq_crypto.py。

URL 拼接规则（逆向自 app-service.js）：
    {base_url}/{tenant}@{api_version}{path}
但 path 里含 /online 或 /common 时**不加** @version；/login/wechat 固定用 default。
"""

from __future__ import annotations

import http.client
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from bdkq_crypto import (
    API_SECRET,
    build_signature,
    decrypt_response,
    encode_query,
    encrypt_body,
    make_rid,
    new_otp,
)

DEFAULT_TENANT = "xcx-bjdxkqyy-wx"
# 余号查询接口的固定业务号（抓包校准，与账号无关）
DEFAULT_CASE_ID = "5665665556"
DEFAULT_REFERER = "https://servicewechat.com/wxf47aa38d871be854/331/page-frame.html"
DEFAULT_UA = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Version/4.0 Chrome/107.0.5304.141 Mobile Safari/537.36 "
    "XWEB/5075 MMWEBSDK/20230604 MicroMessenger/8.0.80.52(0x28005034) "
    "MiniProgramEnv/android Luggage/2.2.0.86552af0-IoT NetType/WIFI Language/zh_CN ABI/arm64"
)

# 域名 → IP 覆盖表。这个医院的域名在公共 DNS 里是 127.0.0.1（DNSPod 上就是这条
# A 记录），只有腾讯 HTTPDNS 才给真实回源 IP。为了不改系统 hosts 也能连，这里让
# 客户端自己做「连 IP、TLS 和 Host 头仍用域名」，SNI 和证书校验都照常。
_DNS_OVERRIDES: dict[str, str] = {}


class _MappedHTTPSConnection(http.client.HTTPSConnection):
    """连到覆盖表里的 IP，但 TLS 的 SNI 和 Host 头用的还是原域名。"""

    def connect(self) -> None:
        server_hostname = self._tunnel_host or self.host
        ip = _DNS_OVERRIDES.get(self.host)
        if not ip:
            return super().connect()
        self.sock = socket.create_connection(
            (ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class _MappedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        ip = _DNS_OVERRIDES.get(self.host)
        if not ip:
            return super().connect()
        self.sock = socket.create_connection(
            (ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


# 业务码：0 成功；1000 登录态失效；1001 停诊/维护
STATUS_OK = 0
STATUS_TOKEN_EXPIRED = 1000
STATUS_OUT_OF_SERVICE = 1001


class BdkqError(RuntimeError):
    """接口或网络错误。"""


@dataclass
class BdkqResponse:
    status: int
    message: str
    data: Any
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    def ensure_ok(self, label: str) -> "BdkqResponse":
        if not self.ok:
            raise BdkqError(f"{label} 失败: status={self.status} {self.message}".strip())
        return self


class BdkqClient:
    def __init__(
        self,
        base_url: str,
        *,
        tenant: str = DEFAULT_TENANT,
        api_version: str = "default",
        access_token: str = "",
        timeout: float = 8.0,
        ca_bundle: str = "",
        insecure_skip_verify: bool = False,
        extra_headers: dict[str, str] | None = None,
        verbose: bool = False,
        auto_relogin: Any | None = None,
        resolve: dict[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.tenant = tenant
        self.api_version = api_version
        self.access_token = access_token
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})
        self.verbose = verbose
        self.auto_relogin = auto_relogin
        self.resolve = dict(resolve or {})
        _DNS_OVERRIDES.update(self.resolve)
        self._ssl_context = self._build_ssl_context(ca_bundle, insecure_skip_verify)
        self._opener = self._build_opener()

    # ------------------------------------------------------------ 构造

    @classmethod
    def from_config(cls, cfg: dict[str, Any], **kwargs: Any) -> "BdkqClient":
        tls = cfg.get("tls") or {}
        # 配置里可以只写 referer / user_agent / origin，也可以直接给 headers 字典
        extra = dict(cfg.get("headers") or {})
        for src_key, header in (("referer", "Referer"), ("user_agent", "User-Agent"),
                                ("origin", "Origin")):
            value = cfg.get(src_key)
            if value and not any(k.lower() == header.lower() for k in extra):
                extra[header] = str(value)
        return cls(
            cfg["base_url"],
            tenant=cfg.get("tenant") or DEFAULT_TENANT,
            api_version=cfg.get("api_version") or "default",
            access_token=cfg.get("access_token") or "",
            timeout=float(cfg.get("timeout") or 8.0),
            ca_bundle=tls.get("ca_bundle") or "",
            insecure_skip_verify=bool(tls.get("insecure_skip_verify")),
            extra_headers=extra,
            resolve=cfg.get("resolve") or {},
            **kwargs,
        )

    @staticmethod
    def _build_ssl_context(ca_bundle: str, insecure: bool) -> ssl.SSLContext | None:
        if not ca_bundle and not insecure:
            return None
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context(cafile=ca_bundle)

    def _build_opener(self) -> urllib.request.OpenerDirector:
        context = self._ssl_context
        handlers: list[Any] = []

        class _HTTPS(urllib.request.HTTPSHandler):
            def https_open(self, req):  # noqa: ANN001
                return self.do_open(_MappedHTTPSConnection, req, context=context)

        class _HTTP(urllib.request.HTTPHandler):
            def http_open(self, req):  # noqa: ANN001
                return self.do_open(_MappedHTTPConnection, req)

        handlers.append(_HTTP())
        handlers.append(_HTTPS())
        return urllib.request.build_opener(*handlers)

    def url_for(self, path: str, query: dict[str, Any] | None = None) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            version_suffix = ""
            if "/online" not in path and "/common" not in path:
                version = "default" if "/login/wechat" in path else self.api_version
                version_suffix = f"@{version}"
            url = f"{self.base_url}/{self.tenant}{version_suffix}{path}"
        if query:
            encoded = encode_query(query)
            if encoded:
                url += ("&" if "?" in url else "?") + encoded
        return url

    # ------------------------------------------------------------ 请求

    def get(self, path: str, query: dict[str, Any] | None = None, **kw: Any) -> BdkqResponse:
        return self.request(path, method="GET", query=query, **kw)

    def post(self, path: str, body: dict[str, Any] | None = None, **kw: Any) -> BdkqResponse:
        return self.request(path, method="POST", body=body or {}, **kw)

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        retried: bool = False,
    ) -> BdkqResponse:
        query = dict(query or {})
        method = method.upper()

        otp = new_otp()
        request_time = int(time.time() * 1000)
        body_text = ""
        if method != "GET" and body is not None:
            body_text = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
        signature = build_signature(
            query=query if method == "GET" else {},
            body_text=body_text,
            otp=otp,
            request_time=request_time,
            secret=API_SECRET,
        )

        headers = {
            "Content-Type": "application/json",
            "Referer": DEFAULT_REFERER,
            "User-Agent": DEFAULT_UA,
            "access_token": self.access_token or "",
            "request_otp": otp,
            "request_time": str(request_time),
            "signature": signature,
            "rid": make_rid(self.access_token),
        }
        headers.update(self.extra_headers)

        data: bytes | None = None
        if method != "GET" and body is not None:
            payload = json.dumps({"data": encrypt_body(body, signature)}, ensure_ascii=False)
            data = payload.encode("utf-8")

        url = self.url_for(path, query if method == "GET" else None)
        if self.verbose:
            print(f"[bdkq] {method} {urllib.parse.urlsplit(url).path}")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw_bytes = resp.read()
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            raise BdkqError(f"HTTP {exc.code}: {detail[:300]}") from exc
        except urllib.error.URLError as exc:
            raise BdkqError(f"请求失败: {exc}") from exc

        # 登录响应头里的 x-version 决定后续请求用哪个版本号
        version_header = response_headers.get("x-version")
        if version_header and "/login/wechat" in path:
            self.api_version = version_header

        try:
            envelope = json.loads(raw_bytes.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise BdkqError(f"响应不是 JSON: {raw_bytes[:200]!r}") from exc

        # 原文：if ("false" != (header.cipher || false).toString()) 才解密。
        # 也就是「没有 cipher 头 = 不解密」（拒绝类响应直接给明文
        # {"status":1000,"message":"访问受限"}），「cipher: true = 解 data」。
        cipher = str(response_headers.get("cipher", "false")).lower() != "false"
        has_body = isinstance(envelope.get("data"), str) and envelope["data"]
        if cipher and has_body:
            result = decrypt_response(envelope, signature)
        else:
            result = envelope

        status = result.get("status")
        try:
            status_int = int(status)
        except (TypeError, ValueError):
            status_int = -1
        message = str(result.get("message") or result.get("msg") or "")
        # 登录态失效有两种表现：status 1000，或者网关回 {"code":"401","msg":...}
        code = str(result.get("code") or "")
        expired = status_int == STATUS_TOKEN_EXPIRED or code == "401"

        if expired and not retried and self.auto_relogin is not None:
            self.auto_relogin(self)
            return self.request(path, method=method, query=query, body=body, retried=True)

        if expired and status_int != STATUS_TOKEN_EXPIRED:
            status_int = STATUS_TOKEN_EXPIRED   # 统一成一个码，调用方只判一种
        return BdkqResponse(status=status_int, message=message, data=result.get("data"), raw=result)

    # ------------------------------------------------------------ 登录

    def login_with_code(self, code: str, *, gzh_code: str = "", device: str = "") -> BdkqResponse:
        """用 wx.login 的 code 换 token。code 只能用一次，必须在微信运行时里取。"""
        body = {
            "code": code,
            "gzhCode": gzh_code,
            "loginDevice": device or "android;Android 14;MicroMessenger 8.0.80",
        }
        resp = self.post("/login/wechat", body).ensure_ok("login")
        data = resp.data or {}
        token = data.get("accessToken") or ""
        if token:
            self.access_token = token
        return resp

    # ------------------------------------------------------------ 挂号数据

    def dept_list(self, area_code: str = "0", *, with_remain: bool = True) -> list[dict[str, Any]]:
        resp = self.get(
            "/api/regist/getYyDeptList",
            {"areaCode": str(area_code), "withRemain": "1" if with_remain else "0"},
        ).ensure_ok("getYyDeptList")
        data = resp.data or {}
        return list(data.get("lists") or [])

    def dept_search(self, keyword: str, area_code: str = "0") -> list[dict[str, Any]]:
        resp = self.get(
            "/api/regist/getYyDeptSearch", {"areaCode": str(area_code), "keyword": keyword}
        ).ensure_ok("getYyDeptSearch")
        data = resp.data or {}
        return list(data.get("lists") or [])

    def today_dept_list(self, area_code: str = "0") -> list[dict[str, Any]]:
        """当日/明日挂号用的科室列表（GET，参数只有 areaCode）。"""
        resp = self.get("/api/regist/getTodayDeptList",
                        {"areaCode": str(area_code)}).ensure_ok("getTodayDeptList")
        data = resp.data or []
        return list(data) if isinstance(data, list) else list(data.get("lists") or [])

    def doctor_list(self, dept_code: str, area_code: str = "0",
                    **extra: Any) -> list[dict[str, Any]]:
        """某科室的医生与号源。

        参数名用 2026-11-21 真机抓包校准过的 `deptCode` + `areaCode`（POST
        `/api/regist/getDoctorList`）。返回每项含 doctId / doctName / scheduleId /
        visitDate(毫秒) / amPm / numbers（剩余号数）/ fee / ygzc（职称）/ seqDoct。
        """
        body: dict[str, Any] = {"deptCode": str(dept_code), "areaCode": str(area_code)}
        body.update(extra)
        resp = self.post("/api/regist/getDoctorList", body).ensure_ok("getDoctorList")
        data = resp.data or []
        return list(data) if isinstance(data, list) else list(data.get("lists") or [])

    def doctor_list_v2(self, dept_code: str, area_code: str = "0",
                       **extra: Any) -> list[dict[str, Any]]:
        """预约挂号（非当日）的医生列表，参数与返回结构同 doctor_list，接口不同。"""
        body: dict[str, Any] = {"deptCode": str(dept_code), "areaCode": str(area_code)}
        body.update(extra)
        resp = self.post("/api/regist/getYyDoctorList", body).ensure_ok("getYyDoctorList")
        data = resp.data or []
        return list(data) if isinstance(data, list) else list(data.get("lists") or [])

    def remain_board(self, case_id: str = DEFAULT_CASE_ID) -> list[dict[str, Any]]:
        """余号查询（号源公示）：一条 POST 拿到全院「已满 / 余号」看板。

        返回每项含 informationContent（如「牙体牙髓科_普通_上午」）、
        regValue（「已满」或余号数）、updateTime。
        """
        resp = self.post("/api/his/queue/GetOutDepartmentReginfo",
                         {"caseId": str(case_id)}).ensure_ok("GetOutDepartmentReginfo")
        data = resp.data or []
        return list(data) if isinstance(data, list) else list(data.get("lists") or [])

    def schedule_list(self, **params: Any) -> list[dict[str, Any]]:
        resp = self.post("/api/regist/getYyScheduleList", params).ensure_ok("getYyScheduleList")
        data = resp.data or {}
        return list(data.get("lists") or [])

    def date_list(self, **params: Any) -> list[dict[str, Any]]:
        resp = self.get("/api/system/dateList", params or None).ensure_ok("dateList")
        data = resp.data
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return list(data.get("lists") or data.get("dates") or [])
        return []


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
