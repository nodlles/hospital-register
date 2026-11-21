#!/usr/bin/env python3
"""北京大学第三医院（北医三院）小程序接口客户端。

这里每一条协议事实都不是猜的，也不是抓包抄的，而是从**运行时 DevTools 拿到的小程序
源码**里读出来的（`app-service.js`，见 BYSY.md「怎么拿到源码」一节）：

    appId        wx3302a1b5a5f91dc4
    版本         2.2.2   -> 请求头 version=2.2.2
    BASEURL     https://patwx.puh3.net.cn
    统一包装     lib/utils/request，固定五个自定义头

分界线很清楚：

* **免登录白名单只有 9 个接口**（院区、科室、医生列表这些），无 token 直连就能拿，
  本模块已用真服务器验证。
* 号源、排班、下单、支付全部需要 token。无 token 打过去一律返回
  `{"code":"201","msg":"请升级到最新版本，或重新登录！"}` —— 这是通用错误码，
  不是参数错。
* token 只能用 `wx.login` 的 code **加手机号凭证**去换，
  `POST /api/v2/wx/patient/login {code, phoneCode|encryptedData+iv}`；
  只给 code 服务端明确回 `缺少手机号凭证`，且 code 单次有效。
* 带 token 时请求体被国密封装成
  `{"encrypted": base64(SM4-ECB(JSON.stringify(body), md5_upper(token)))}`。
* 响应体是一串十六进制密文，AES-192-CBC 解开后才是业务 JSON：
  key = loginUserInfo.userId，iv = token 最后 16 个字符。见 BYSY.md「加解密」。

用法（命令行走免登录那部分，不需要任何凭据）：

    python3 bysy_client.py areas          # 七个院区的当前号源数
    python3 bysy_client.py depts          # 科室树（约 70KB）
    python3 bysy_client.py hot            # 热门医生
    python3 bysy_client.py probe          # 逐个打 9 个白名单接口，报告状态
    python3 bysy_client.py slots [关键词]  # 要 token：全院八天号源，可只看有号的
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

BASE_URL = "https://patwx.puh3.net.cn"
APP_ID = "wx3302a1b5a5f91dc4"
APP_VERSION = "2.2.2"
DEFAULT_SYSTEM = "Android 17"
DEFAULT_REFERER = f"https://servicewechat.com/{APP_ID}/72/page-frame.html"
DEFAULT_UA = (
    "Mozilla/5.0 (Linux; Android 17; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Version/4.0 Chrome/128.0.0.0 Mobile Safari/537.36 "
    "MicroMessenger/8.0.55.2780(0x28003737) WeChat/arm64 Weixin NetType/WIFI "
    "Language/zh_CN ABI/arm64 miniProgram/wx3302a1b5a5f91dc4"
)

# 免登录白名单，顺序与 app-service.js 里的 d=[...] 一致
PUBLIC_PATHS: tuple[str, ...] = (
    "api/v1/doctor/departmentList",
    "api/v1/doctor/departmentItem",
    "api/v1/department/getDepartments",
    "api/v1/doctor/department/getDoctors",
    "api/v1/doctor/new/getDoctors",
    "api/v1/wx/evaluate/getEvaluates",
    "api/v1/consultation/patient/doctorHasDiagnoses",
    "api/v1/appointment/getHospitalAreas",
    "api/v1/patient/free/department/list",
)

# 号源/挂号主链路（全部要 token），路径取自 api/index 的 appointment 模块
PATH_AREAS = "api/v1/appointment/getHospitalAreas"
PATH_DEPARTMENTS = "api/v1/appointment/getDepartments"
PATH_DOCTORS = "api/v2/appointment/getDepartmentDoctors"
PATH_DOCTORS_BY_DATE = "api/v2/doctor/department/getSearchDoctorsByDate"
PATH_SCHEDULES = "api/v2/appointment/area/getVisitSchedules"
PATH_SCHEDULE_TIMES = "api/v2/appointment/getVisitSchedulesTimes"
PATH_CREATE = "api/v2/appointment/createAppointment"
PATH_PAY = "api/v1/payment/createPayment"
PATH_LOGIN = "api/v2/wx/patient/login"

CODE_OK = "200"
# 号源矩阵一次返回全院 8 天（10.9 MB），实测 100s，比普通接口慢两个量级
SCHEDULES_TIMEOUT = 300.0
PATH_AREAS_FOR_SCHEDULES = "api/v1/appointment/getDepartments"
CODE_NEED_LOGIN = "201"


class BysyError(RuntimeError):
    """协议层错误。"""


class BysyAuthRequired(BysyError):
    """服务端返回 code=201：没登录、token 过期，或两者都像。"""


class BysyNotCalibrated(BysyError):
    """这条路径的实现还缺真实样本校准，故意不往下走。"""


@dataclass
class BysyResponse:
    path: str
    status: int
    text: str
    payload: Any = None
    elapsed_ms: int = 0
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def code(self) -> str:
        if isinstance(self.payload, dict):
            return str(self.payload.get("code", ""))
        return ""

    @property
    def msg(self) -> str:
        if isinstance(self.payload, dict):
            return str(self.payload.get("msg", ""))
        return ""

    @property
    def data(self) -> Any:
        if isinstance(self.payload, dict):
            return self.payload.get("data")
        return None

    @property
    def ok(self) -> bool:
        return self.status == 200 and self.code in (CODE_OK, "")

    def ensure_ok(self, label: str = "") -> "BysyResponse":
        if self.code == CODE_NEED_LOGIN:
            raise BysyAuthRequired(
                f"{label or self.path}: 服务端要求登录（code=201 {self.msg}）"
            )
        if self.status != 200 or (self.code and self.code != CODE_OK):
            raise BysyError(f"{label or self.path}: HTTP {self.status} code={self.code} {self.msg}")
        return self


def sm4_key(token: str) -> bytes:
    """把 token 变成 SM4 的 16 字节密钥。

    源码（lib/utils/sm4-crypto.js）：

        SM4Encrypted(e, r) = gm.SM4.encrypt(e || "{}", md5_upper(r),
                            {inputEncoding: "utf8", outputEncoding: "base64"})

    调用方（lib/utils/request/request.js）把 r 传成 token。`md5_upper` 就是
    `CryptoJS.MD5(r).toString().toUpperCase()` —— 32 个十六进制字符，gm-crypto
    按 hex 解析成 16 字节。所以密钥**不是** token 本身，也不是 token 的前 16 字节。
    """
    if not token:
        raise BysyError("没有 token，算不出 SM4 密钥")
    digest = hashlib.md5(token.encode("utf-8")).hexdigest().upper()
    return bytes.fromhex(digest)


def response_key_iv(user_id: str | int, token: str) -> tuple[bytes, bytes]:
    """响应解密的 (key, iv)，同样照抄源码 decryptAes(e, r, n)：
    key = loginUserInfo.userId，iv = token 末 16 字符。userId 是 24 字符 -> AES-192。"""
    key = str(user_id or "").encode("utf-8")
    if len(key) not in (16, 24, 32):
        raise BysyError(f"userId 长度 {len(key)} 不是 16/24/32，不是合法 AES 密钥")
    if len(token) < 16:
        raise BysyError(f"token 长度 {len(token)} 不足 16，截不出 iv")
    return key, token[-16:].encode("utf-8")


def decrypt_response(text: str, user_id: str | int, token: str) -> Any:
    """把响应密文解成业务 JSON；不是密文（免登录接口）就返回 None。"""
    import bysy_aes

    body = (text or "").strip()
    if not body or not all(c in "0123456789abcdefABCDEF" for c in body) or len(body) % 32:
        return None
    key, iv = response_key_iv(user_id, token)
    try:
        raw = bysy_aes.decrypt_hex_cbc(body, key, iv)
    except (ValueError, IndexError):
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


class BysyClient:
    def __init__(
        self,
        base_url: str = BASE_URL,
        *,
        token: str = "",
        user_id: str | int = "",
        system: str = DEFAULT_SYSTEM,
        version: str = APP_VERSION,
        platform: str = "wechat",
        timeout: float = 15.0,
        insecure_skip_verify: bool = False,
        verbose: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.user_id = str(user_id or "")
        self.system = system
        self.version = version
        self.platform = platform
        self.timeout = timeout
        self.verbose = verbose
        self._ssl_context = None
        if insecure_skip_verify:
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    # ---------------------------------------------------------- 构造请求

    @classmethod
    def from_config(cls, cfg: dict[str, Any], **kwargs: Any) -> "BysyClient":
        """从 config.json 里 `bysy` 段建客户端；`token` 允许写成 `{"token": ...}`。"""
        cfg = dict(cfg or {})
        tok = cfg.pop("token", "")
        if isinstance(tok, dict):
            cfg.setdefault("user_id", tok.get("userId", "") or tok.get("user_id", ""))
            tok = tok.get("token", "") or ""
        cfg.pop("baseUrl", None)
        return cls(token=str(tok or ""), **{**cfg, **kwargs})

    @property
    def logged_in(self) -> bool:
        return bool(self.token)

    def url_for(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def build_headers(self, *, token: str | None = None, user_id: str | None = None) -> dict[str, str]:
        """统一请求头。

        逆向自 lib/utils/request：有 token 就多带 token 与 userId，其余五个头恒有。
        """
        tok = self.token if token is None else token
        uid = self.user_id if user_id is None else str(user_id)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": DEFAULT_UA,
            "Referer": DEFAULT_REFERER,
            "platform": self.platform,
            "version": self.version,
            "system": self.system,
            "timestamp": str(int(time.time() * 1000)),
        }
        if tok:
            headers["token"] = tok
            if uid:
                headers["userId"] = uid
        return headers

    def wrap_body(self, body: dict[str, Any] | None, *, token: str | None = None) -> Any:
        """有 token 时把请求体包成 {"encrypted": base64(SM4-ECB(json, md5_upper(token)))}。

        没有 token 的免登录接口原样发明文，服务端两种都收（实测 200）。
        """
        payload = dict(body or {})
        tok = self.token if token is None else token
        if not tok:
            return payload
        from bdkq_crypto import sm4_encrypt  # 复用已验证过的国密实现

        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return {"encrypted": base64.b64encode(sm4_encrypt(raw, sm4_key(tok))).decode("ascii")}

    def unwrap(self, text: str, *, token: str | None = None, user_id: str | None = None) -> Any:
        """解开响应密文；明文响应（免登录接口）返回 None，交给 json.loads。"""
        tok = self.token if token is None else token
        uid = self.user_id if user_id is None else str(user_id)
        if not tok or not uid:
            return None
        return decrypt_response(text, uid, tok)

    # ---------------------------------------------------------- 发请求

    def post(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        token: str | None = None,
        user_id: str | None = None,
        timeout: float | None = None,
    ) -> BysyResponse:
        return self.request("POST", path, body=body, token=token, user_id=user_id, timeout=timeout)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        token: str | None = None,
        user_id: str | None = None,
        timeout: float | None = None,
    ) -> BysyResponse:
        method = method.upper()
        headers = self.build_headers(token=token, user_id=user_id)
        data = None
        if method != "GET":
            wrapped = self.wrap_body(body, token=token)
            data = json.dumps(wrapped, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        req = urllib.request.Request(self.url_for(path), data=data, headers=headers, method=method)
        started = time.time()
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout if timeout is None else timeout, context=self._ssl_context
            ) as resp:
                text = resp.read().decode("utf-8", "replace")
                status = resp.status
                hdrs = dict(resp.headers or {})
        except urllib.error.HTTPError as exc:  # 4xx/5xx 也把响应体读出来
            text = exc.read().decode("utf-8", "replace")
            status = exc.code
            hdrs = dict(exc.headers or {})
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            # 网络层失败不抛，交给调用方看 status=0；监控类代码不该因为一次超时就崩
            reason = getattr(exc, "reason", exc)
            text = f'{{"code":"0","msg":"network: {reason}"}}'
            status = 0
            hdrs = {}
        elapsed = int((time.time() - started) * 1000)
        payload: Any = None
        decrypted = self.unwrap(text, token=token, user_id=user_id)
        if decrypted is not None:
            payload = decrypted
        else:
            try:
                payload = json.loads(text)
            except ValueError:
                payload = None
        if self.verbose:
            shown = json.dumps(payload, ensure_ascii=False)[:200] if payload is not None else text[:200]
            print(f"{method} {path} -> {status} {elapsed}ms {shown}", file=sys.stderr)
        return BysyResponse(
            path=path, status=status, text=text, payload=payload,
            elapsed_ms=elapsed, headers=hdrs,
        )

    # ---------------------------------------------------------- 免登录接口

    def hospital_areas(self, flag: int = 2) -> list[dict[str, Any]]:
        """七个院区 + 各自当前号源数。实测返回 data 数组。"""
        res = self.post(PATH_AREAS, {"flag": flag}, token="")
        data = res.ensure_ok("getHospitalAreas").data
        return data if isinstance(data, list) else []  # 字段: hospitalName / position / count

    def departments(self, *, is_show: bool = True, is_affiliated: bool = True) -> list[dict[str, Any]]:
        """全量科室树（约 70KB）。字段含 deptSn/deptName/pyCode/isAppointment 等。"""
        res = self.post(
            "api/v1/department/getDepartments",
            {"isShow": is_show, "isAffiliated": is_affiliated},
            token="",
        )
        data = res.ensure_ok("getDepartments").data
        return data if isinstance(data, list) else []

    def doctor_groups(self) -> list[dict[str, Any]]:
        """按院区给科室分组的规则（key 是正则，不是 id）。"""
        res = self.post("api/v1/doctor/departmentList", {}, token="")
        data = res.ensure_ok("departmentList").data
        return data if isinstance(data, list) else []

    def hot_doctors(self) -> list[dict[str, Any]]:
        res = self.post("api/v1/doctor/new/getDoctors", {"hot": True}, token="")
        data = res.ensure_ok("newGetDoctors").data
        return data if isinstance(data, list) else []

    # ---------------------------------------------------------- 要登录的接口

    def login_with_code(
        self,
        code: str,
        *,
        phone_code: str = "",
        encrypted_data: str = "",
        iv: str = "",
    ) -> BysyResponse:
        """用 wx.login 的 code 换 token。

        注意 `code` 单次有效：换完再发一次服务端会回 `code been used`。
        只给 code 不给手机号凭据时，服务端明确回 `缺少手机号凭证(phoneCode 或
        encryptedData/iv)` —— 也就是说这条路必须有真人的手机号，见 BYSY.md。
        """
        body: dict[str, Any] = {"code": code}
        if phone_code:
            body["phoneCode"] = phone_code
        if encrypted_data and iv:
            body["encryptedData"] = encrypted_data
            body["iv"] = iv
        return self.post(PATH_LOGIN, body, token="")

    def department_doctors(
        self,
        department_appointment_id: str | int,
        *,
        user_id: str | int = "",
        get_schedule: bool = True,
        is_today: bool = False,
        show_internet: bool = False,
    ) -> list[dict[str, Any]]:
        """带排班的医生列表（`getSchedule:true`）。

        请求体整份都是逆向自 modules/…/departmentDoctors 的调用点；字段名没有
        真实样本对过，所以拿不到号源前不要拿它下单。
        """
        body = {
            "departmentAppointmentId": department_appointment_id,
            "showInternet": show_internet,
            "getSchedule": get_schedule,
            "isToday": is_today,
            "departmentType": "gh",
            "userId": user_id or self.user_id,
            "mTicket": "",
            "mRandstr": "",
        }
        res = self.post(PATH_DOCTORS, body)
        data = res.ensure_ok("getDepartmentDoctors").data
        if isinstance(data, dict):
            data = data.get("data")
        return data if isinstance(data, list) else []

    def schedules(self, department_id: str = "", *, timeout: float = SCHEDULES_TIMEOUT) -> list[dict[str, Any]]:
        """**一次拿全院八天号源矩阵**。

        实测（真实 token）：

        * 传一个**真实科室 `_id`** → 100s 返回 10.9 MB，「276 个可挂号科室 × 8 天」
          的完整矩阵，换别的科室 id 也是同一份（服务端只拿它认路，不拿它筛）；
        * 传不存在的 id / 空串 → 服务端**一直算不回来**（600s 都没响应），
          空 body 则直接给 `[]`。

        所以 `department_id` 留空时这里会自动去科室列表里挑一个真实可挂号 id，
        筛选请在上层做。

        返回结构：[{deptName, hospitalName, position, id, visitSchedules: [...]}]
        visitSchedules 里每条的字段非常全（见 BYSY.md），关键的是：
            leftNum   剩余号数（0 = 没号）
            totalNum / useNum  总号数 / 已用
            visitDate 2026-11-21、am_pm AM|PM、nightFlag
            doctorName / doctorSn / doctor_code
            gh_fee / registerFee 挂号费、sop_name / clinicName 号别名称
            recordSn  下单时要回传的排班标识
        """
        # 这份矩阵一次就是全院八天号源（10.9 MB），服务端要算 100s 左右
        res = self.post(
            PATH_SCHEDULES,
            {"departmentId": str(department_id or self._schedule_anchor())},
            timeout=timeout,
        )
        data = res.ensure_ok("getVisitSchedules").data
        return data if isinstance(data, list) else []

    def _schedule_anchor(self) -> str:
        """给号源矩阵挑一个真实科室 id：服务端不认路时会一直转圈，认路才回数据。"""
        cached = getattr(self, "_anchor_id", "")
        if cached:
            return cached
        res = self.post(
            PATH_AREAS_FOR_SCHEDULES, {"isShow": True, "isAffiliated": True}, timeout=60
        )
        for dept in res.ensure_ok("getDepartments").data or []:
            if dept.get("isAppointment") and dept.get("_id"):
                self._anchor_id = str(dept["_id"])
                return self._anchor_id
        raise BysyError("科室列表里没有可挂号的科室 id，拿不到号源矩阵")

    def slot_rows(
        self, *, only_available: bool = False, timeout: float = SCHEDULES_TIMEOUT
    ) -> list[dict[str, Any]]:
        """把号源矩阵摊平成一行一个号（科室+医生+日期+午别），便于筛选。"""
        rows: list[dict[str, Any]] = []
        for dept in self.schedules(timeout=timeout):
            for s in dept.get("visitSchedules") or []:
                left = int(s.get("leftNum") or 0)
                if only_available and left <= 0:
                    continue
                rows.append({
                    "deptName": dept.get("deptName") or s.get("deptName"),
                    "hospitalName": dept.get("hospitalName") or s.get("hospitalName"),
                    "doctorName": s.get("doctorName"),
                    "doctorSn": s.get("doctorSn"),
                    "visitDate": s.get("visitDate"),
                    "amPm": s.get("am_pm") or s.get("amPm"),
                    "leftNum": left,
                    "totalNum": s.get("totalNum"),
                    "fee": s.get("gh_fee") or s.get("registerFee"),
                    "sopName": s.get("sop_name") or s.get("sopName"),
                    "recordSn": s.get("recordSn"),
                    "scheduleId": s.get("_id") or s.get("id"),
                    "nightFlag": s.get("nightFlag"),
                    "isStopVisit": s.get("isStopVisit"),
                })
        return rows

    def create_appointment(self, **params: Any) -> Any:
        raise BysyNotCalibrated(
            "createAppointment 是写接口：参数没和真实返回对齐前不提交，"
            "与 bdkq 那边的做法一致"
        )


# ------------------------------------------------------------------ CLI


def _load_endpoints() -> dict[str, Any]:
    from pathlib import Path

    p = Path(__file__).with_name("bysy_endpoints.json")
    return json.loads(p.read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    from pathlib import Path

    cmd = (argv[1] if len(argv) > 1 else "areas").strip()
    client = BysyClient(verbose=False)
    if cmd == "areas":
        for area in client.hospital_areas():
            print(f"{area.get('hospitalName', '')}\t{area.get('position', '')}\t号源={area.get('count', '')}")
        return 0
    if cmd == "depts":
        depts = client.departments()
        print(f"{len(depts)} 个科室")
        for d in depts[:20]:
            print(d.get("deptSn"), d.get("deptName"), "可挂号" if d.get("isAppointment") else "")
        return 0
    if cmd == "hot":
        docs = client.hot_doctors()
        print(f"{len(docs)} 位医生")
        for d in docs[:20]:
            print(d.get("doctorSn"), d.get("doctorName"), d.get("title"))
        return 0
    if cmd == "slots":
        cfg_path = Path(__file__).with_name("config.json")
        if not cfg_path.exists():
            print("需要 config.json 里的 bysy.token 才能查号源")
            return 2
        cfg = json.loads(cfg_path.read_text(encoding="utf-8")).get("bysy") or {}
        client = BysyClient.from_config(cfg)
        if not client.logged_in:
            print("config.json 里没有 bysy.token")
            return 2
        kw = argv[2] if len(argv) > 2 else ""
        rows = [r for r in client.slot_rows(only_available=True) if not kw or kw in (r["deptName"] or "")]
        print(f"{len(rows)} 个有号时段")
        for r in rows:
            print(f"{r['visitDate']} {r['amPm']}\t{r['hospitalName']}\t{r['deptName']}\t"
                  f"{r['doctorName']}\t余{r['leftNum']}/{r['totalNum']}\t{r['fee']}元")
        return 0
    if cmd == "probe":
        bodies = {
            "api/v1/doctor/departmentList": {},
            "api/v1/doctor/departmentItem": {},
            "api/v1/department/getDepartments": {"isShow": True, "isAffiliated": True},
            "api/v1/doctor/department/getDoctors": {},
            "api/v1/doctor/new/getDoctors": {"hot": True},
            "api/v1/wx/evaluate/getEvaluates": {},
            "api/v1/consultation/patient/doctorHasDiagnoses": {},
            "api/v1/appointment/getHospitalAreas": {"flag": 2},
            "api/v1/patient/free/department/list": {"flag": 2},
        }
        for path in PUBLIC_PATHS:
            res = client.post(path, bodies.get(path, {}), token="")
            size = len(res.text)
            print(f"{res.status}\tcode={res.code or '-'}\t{size}B\t{path}\t{res.msg}")
        return 0
    if cmd == "check-auth":
        # 有 token 时验一下还在不在有效期内（201 就是过期）
        if not client.logged_in:
            print("没有 token：先按 BYSY.md 的登录流程拿一个，写进 config 的 bysy.token")
            return 2
        res = client.post(PATH_AREAS, {"flag": 2})
        print(f"{res.status} code={res.code} {res.msg}")
        return 0 if res.ok else 1
    print(__doc__)
    print("可用命令: areas | depts | hot | probe | check-auth | slots")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
