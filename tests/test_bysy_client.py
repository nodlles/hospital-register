"""北医三院客户端的离线单测（不联网，全部拦在 urlopen 之前）。"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import bysy_client as by
from bysy_client import BysyAuthRequired, BysyClient, BysyNotCalibrated


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None) -> None:
        self._body = body
        self.status = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Recorder:
    """替掉 urllib.request.urlopen，记下请求，回固定 JSON。"""

    def __init__(self, payload) -> None:
        # payload 可以是 dict，也可以是 url -> dict 的函数（多处请求时按 url 分流）
        self.payload = payload
        self.requests = []
        self._real = None

    def __enter__(self):
        self._real = by.urllib.request.urlopen
        by.urllib.request.urlopen = self._open
        return self

    def __exit__(self, *exc):
        by.urllib.request.urlopen = self._real
        return False

    def _open(self, req, timeout=None, context=None):
        self.requests.append(req)
        payload = self.payload(req.full_url) if callable(self.payload) else self.payload
        return _FakeResponse(json.dumps(payload).encode())


class HeadersTest(unittest.TestCase):
    def test_anonymous_headers_have_no_token(self):
        c = BysyClient(system="Android 17")
        h = c.build_headers()
        self.assertEqual(h["platform"], "wechat")
        self.assertEqual(h["version"], "2.2.2")
        self.assertEqual(h["system"], "Android 17")
        self.assertEqual(h["Content-Type"], "application/json")
        self.assertNotIn("token", h)
        self.assertNotIn("userId", h)
        self.assertTrue(h["timestamp"].isdigit())

    def test_token_headers(self):
        c = BysyClient(token="t" * 16, user_id=42)
        h = c.build_headers()
        self.assertEqual(h["token"], "t" * 16)
        self.assertEqual(h["userId"], "42")

    def test_token_override_to_empty_strips_headers(self):
        # 免登录接口即使客户端带着 token 也不能带 token 头
        c = BysyClient(token="t" * 16, user_id=42)
        h = c.build_headers(token="")
        self.assertNotIn("token", h)
        self.assertNotIn("userId", h)


class BodyTest(unittest.TestCase):
    def test_anonymous_body_is_plain_json(self):
        c = BysyClient()
        self.assertEqual(c.wrap_body({"flag": 2}), {"flag": 2})

    def test_token_body_is_sm4_wrapped(self):
        c = BysyClient(token="0123456789abcdef")
        wrapped = c.wrap_body({"flag": 2})
        self.assertIn("encrypted", wrapped)
        # 服务端要 base64（源码 outputEncoding:"base64"），16 字节密文 -> 24 字符
        import base64

        raw = base64.b64decode(wrapped["encrypted"])
        self.assertEqual(len(raw) % 16, 0)
        # 同样输入必须确定，方便以后跟真样本对比
        self.assertEqual(wrapped, c.wrap_body({"flag": 2}))

    def test_sm4_key_is_md5_of_token(self):
        # lib/utils/sm4-crypto.js: gm.SM4.encrypt(body, md5_upper(token), {...})
        c = BysyClient(token="0123456789abcdef")
        self.assertEqual(by.sm4_key(c.token).hex(), by.hashlib.md5(b"0123456789abcdef").hexdigest())
        # md5 一定是 16 字节，所以任何长度 token 都能算出合法密钥
        self.assertEqual(len(by.sm4_key("0123456789abcdef" * 2)), 16)
        self.assertEqual(by.sm4_key("abc").hex(), "900150983cd24fb0d6963f7d28e17f72")

    def test_response_key_iv_follow_userid_and_token_tail(self):
        key, iv = by.response_key_iv("6b019acf47f32340f3a135cb", "X" * 140 + "E-3HZD42x8ozf7Sw")
        self.assertEqual(key, b"6b019acf47f32340f3a135cb")
        self.assertEqual(len(key), 24)          # 24 字节 -> AES-192
        self.assertEqual(iv, b"E-3HZD42x8ozf7Sw")

    def test_response_key_rejects_bad_lengths(self):
        with self.assertRaises(by.BysyError):
            by.response_key_iv("short", "X" * 32)
        with self.assertRaises(by.BysyError):
            by.response_key_iv("6b019acf47f32340f3a135cb", "short")

    def test_decrypt_response_ignores_plaintext(self):
        # 免登录接口回明文 JSON，不能当密文去解
        self.assertIsNone(by.decrypt_response('{"code":"200","data":[]}', "u" * 24, "t" * 16))
        self.assertIsNone(by.decrypt_response("", "u" * 24, "t" * 16))

    def test_decrypt_response_decrypts_known_block(self):
        # 真服务器响应的首块（所有响应开头都一样，CBC 固定 iv 导致）：
        #   key=userId=6b019acf47f32340f3a135cb  iv=token[-16:]=E-3HZD42x8ozf7Sw
        # 一个块不够凑 JSON，所以只验 AES-192-CBC 这一层。
        import bysy_aes

        key, iv = by.response_key_iv("6b019acf47f32340f3a135cb", "X" * 140 + "E-3HZD42x8ozf7Sw")
        plain = bysy_aes.decrypt_hex_cbc("9C68E27FC021A2B27ADEBD50B455AF49", key, iv)
        self.assertTrue(plain.startswith(b'{"code":"200",'), plain)


class RequestTest(unittest.TestCase):
    def test_post_records_url_headers_payload(self):
        with _Recorder({"code": "200", "msg": "ok", "data": []}) as rec:
            c = BysyClient()
            res = c.post("api/v1/appointment/getHospitalAreas", {"flag": 2}, token="")
        self.assertTrue(res.ok)
        req = rec.requests[0]
        self.assertEqual(req.full_url, "https://patwx.puh3.net.cn/api/v1/appointment/getHospitalAreas")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(json.loads(req.data.decode()), {"flag": 2})

    def test_code_201_raises_auth_required(self):
        with _Recorder({"code": "201", "msg": "请升级到最新版本，或重新登录！", "data": {}}):
            res = BysyClient().post("api/v1/appointment/getDepartments", {}, token="")
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "201")
        with self.assertRaises(BysyAuthRequired):
            res.ensure_ok("getDepartments")

    def test_network_failure_does_not_raise(self):
        import socket

        def boom(*a, **kw):
            raise socket.timeout("timed out")

        real = by.urllib.request.urlopen
        by.urllib.request.urlopen = boom
        try:
            res = BysyClient().post("api/v1/doctor/department/getDoctors", {}, token="")
        finally:
            by.urllib.request.urlopen = real
        self.assertEqual(res.status, 0)
        self.assertIn("network", res.msg)

    def test_hospital_areas_parses_data_list(self):
        payload = {
            "code": "200",
            "msg": "获取成功",
            "data": [
                {"hospitalName": "北京大学第三医院(本部)", "position": "花园北路49号", "count": 333},
            ],
        }
        with _Recorder(payload):
            areas = BysyClient().hospital_areas()
        self.assertEqual(areas[0]["count"], 333)


class SchedulesTest(unittest.TestCase):
    MATRIX = {
        "code": "200",
        "msg": "获取成功",
        "data": [
            {
                "deptName": "心血管科门诊",
                "hospitalName": "北京大学第三医院(本部)",
                "visitSchedules": [
                    {"doctorName": "张三", "visitDate": "2026-11-23", "am_pm": "AM",
                     "leftNum": 3, "totalNum": 40, "gh_fee": "50", "recordSn": "1|2|2026-11-23|a|"},
                    {"doctorName": "李四", "visitDate": "2026-11-23", "am_pm": "PM",
                     "leftNum": 0, "totalNum": 20},
                ],
            }
        ],
    }

    DEPTS = {
        "code": "200", "msg": "ok",
        "data": [
            {"_id": "stale-1", "deptName": "不挂号", "isAppointment": False},
            {"_id": "dep-1", "deptName": "心血管科门诊", "isAppointment": True},
        ],
    }

    def _route(self, url):
        return self.DEPTS if "getDepartments" in url else self.MATRIX

    def _sent(self, req):
        import base64

        from bdkq_crypto import sm4_decrypt

        wire = json.loads(req.data.decode())
        return json.loads(sm4_decrypt(base64.b64decode(wire["encrypted"]), by.sm4_key("0123456789abcdef")))

    def test_schedules_defaults_to_a_real_department_id(self):
        with _Recorder(self._route) as rec:
            rows = BysyClient(token="0123456789abcdef").slot_rows()
        # 先问科室列表挑真实 id，再拿矩阵：服务端认不出 id 会一直转圈
        self.assertEqual(len(rec.requests), 2)
        self.assertIn("getDepartments", rec.requests[0].full_url)
        self.assertIn("getVisitSchedules", rec.requests[1].full_url)
        self.assertEqual(self._sent(rec.requests[1]), {"departmentId": "dep-1"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["leftNum"], 3)
        self.assertEqual(rows[0]["amPm"], "AM")

    def test_schedules_reuses_the_anchor(self):
        client = BysyClient(token="0123456789abcdef")
        with _Recorder(self._route) as rec:
            client.schedules()
            client.schedules()
        self.assertEqual(len(rec.requests), 3)

    def test_schedules_takes_an_explicit_department_id(self):
        with _Recorder(self.MATRIX) as rec:
            BysyClient(token="0123456789abcdef").schedules("given-9")
        self.assertEqual(len(rec.requests), 1)
        self.assertEqual(self._sent(rec.requests[0]), {"departmentId": "given-9"})

    def test_slot_rows_only_available(self):
        payload = {
            "code": "200", "msg": "ok",
            "data": [
                {"deptName": "A", "visitSchedules": [
                    {"doctorName": "x", "visitDate": "2026-11-23", "leftNum": 0},
                    {"doctorName": "y", "visitDate": "2026-11-23", "leftNum": 2},
                ]},
            ],
        }
        with _Recorder(lambda url: self.DEPTS if "getDepartments" in url else payload):
            rows = BysyClient(token="0123456789abcdef").slot_rows(only_available=True)
        self.assertEqual([r["doctorName"] for r in rows], ["y"])



class ScheduleTimesTest(unittest.TestCase):
    """分时段：源码是「整条排班 + userId」打过去，回一个号一条时段。"""

    SCHEDULE = {
        "_id": "6b00d1945a94e09e7662f9b2",
        "doctorName": "任川",
        "deptName": "心血管科门诊",
        "visitDate": "2026-11-25",
        "am_pm": "PM",
        "leftNum": 2,
        "recordSn": "1010101|411|2026-11-25|p| ",
        "gh_fee": "60",
    }

    INTERVALS = [
        {"_id": "6b00d1945a94e09e7662f9b2", "id": "6b00d1945a94e09e7662f9b2",
         "beginTime": "15:40", "endTime": "15:50", "sortSn": 23, "yyhSn": "175224192",
         "schduleTimeSn": "175224192|4465615", "timeText": "无", "leftNum": 0},
        {"_id": "6b00d1945a94e09e7662f9b2", "id": "6b00d1945a94e09e7662f9b2",
         "beginTime": "15:30", "endTime": "15:40", "sortSn": 20, "yyhSn": "175224186",
         "schduleTimeSn": "175224186|4465615", "timeText": "无", "leftNum": 0},
    ]

    def _client(self):
        return BysyClient(token="0123456789abcdef", user_id="6b019acf47f32340f3a135cb")

    def test_posts_whole_schedule_plus_user_id(self):
        with _Recorder({"code": "200", "msg": "获取成功", "data": self.INTERVALS}) as rec:
            rows = self._client().schedule_times(self.SCHEDULE)
        sent = json.loads(
            __import__("bdkq_crypto").sm4_decrypt(
                __import__("base64").b64decode(json.loads(rec.requests[0].data.decode())["encrypted"]),
                by.sm4_key("0123456789abcdef"),
            )
        )
        # 源码 Object.assign({}, schedule, {userId})：排班字段原样带过去
        self.assertEqual(sent["_id"], self.SCHEDULE["_id"])
        self.assertEqual(sent["recordSn"], self.SCHEDULE["recordSn"])
        self.assertEqual(sent["userId"], "6b019acf47f32340f3a135cb")
        self.assertEqual(len(rows), 2)

    def test_interval_rows_sorted_by_begin_time(self):
        with _Recorder({"code": "200", "msg": "获取成功", "data": self.INTERVALS}):
            rows = self._client().interval_rows(self.SCHEDULE)
        self.assertEqual([r["beginTime"] for r in rows], ["15:30", "15:40"])
        self.assertEqual(rows[0]["yyhSn"], "175224186")
        self.assertEqual(rows[0]["sortSn"], 20)

    def test_accepts_object_response(self):
        payload = {"code": "200", "msg": "ok", "data": {"a": self.INTERVALS[0]}}
        with _Recorder(payload):
            rows = self._client().schedule_times(self.SCHEDULE)
        self.assertEqual(len(rows), 1)


class PatientTest(unittest.TestCase):
    def test_empty_patient_list(self):
        with _Recorder({"code": "200", "msg": "请求成功", "data": []}) as rec:
            people = BysyClient(token="t" * 32, user_id="6b019acf47f32340f3a135cb").patients()
        self.assertEqual(people, [])
        self.assertIn("patientManager", rec.requests[0].full_url)


class BookingPayloadTest(unittest.TestCase):
    """下单请求体必须和源码 createAppointment 逐字段对齐。"""

    SCHEDULE = ScheduleTimesTest.SCHEDULE
    TIME = {"_id": "6b00d1945a94e09e7662f9b2", "beginTime": "15:30", "endTime": "15:40",
            "sortSn": 20, "yyhSn": "175224186"}

    def _client(self):
        return BysyClient(token="0123456789abcdef", user_id="6b019acf47f32340f3a135cb")

    def test_self_pay_payload(self):
        body = self._client().build_appointment_payload(
            self.SCHEDULE, patient_card_id="card-7", time_info=self.TIME, m_ticket="tk", m_randstr="rs"
        )
        self.assertEqual(body["scheduleId"], self.SCHEDULE["_id"])
        self.assertEqual(body["visitScheduleTimeId"], self.TIME["_id"])
        self.assertEqual(body["patientCardId"], "card-7")
        self.assertEqual(body["appointmentType"], "zf")
        self.assertEqual(body["beginTime"], "15:30")
        self.assertEqual(body["endTime"], "15:40")
        self.assertEqual(body["sortSn"], 20)
        self.assertEqual(body["yyhSn"], "175224186")
        self.assertEqual(body["mTicket"], "tk")
        self.assertEqual(body["mRandstr"], "rs")
        self.assertEqual(body["userId"], "6b019acf47f32340f3a135cb")
        self.assertEqual(body["clientType"], "wechat")
        # 排班字段原样跟着走（源码 g 最后合并）
        self.assertEqual(body["recordSn"], self.SCHEDULE["recordSn"])
        self.assertEqual(body["doctorName"], "任川")

    def test_yibao_and_no_time_info(self):
        body = self._client().build_appointment_payload(
            self.SCHEDULE, patient_card_id="card-7", self_pay=False
        )
        self.assertEqual(body["appointmentType"], "yb")
        self.assertIsNone(body["visitScheduleTimeId"])
        self.assertEqual(body["beginTime"], "")

    def test_dry_run_does_not_send(self):
        with _Recorder({"code": "200", "msg": "ok", "data": {}}) as rec:
            body = self._client().create_appointment(self.SCHEDULE, patient_card_id="card-7")
        self.assertEqual(rec.requests, [])
        self.assertEqual(body["patientCardId"], "card-7")

    def test_live_call_requires_patient_card(self):
        with self.assertRaises(by.BysyError):
            self._client().create_appointment(self.SCHEDULE, dry_run=False)


class PaymentTest(unittest.TestCase):
    def test_payment_payload_matches_source(self):
        c = BysyClient(token="0123456789abcdef", user_id="6b019acf47f32340f3a135cb")
        self.assertEqual(
            c.build_payment_payload("appt-1", "openid-1"),
            {"appointmentId": "appt-1", "payWay": "MINIPROGRAM", "openId": "openid-1"},
        )

    def test_create_payment_parses_order_info(self):
        payload = {"code": "200", "msg": "ok",
                   "data": {"orderInfo": '{"timeStamp":"1","nonceStr":"n","package":"p","signType":"RSA","paySign":"s"}'}}
        with _Recorder(payload):
            data = BysyClient(token="0123456789abcdef", user_id="6b019acf47f32340f3a135cb").create_payment("appt-1", "openid-1")
        self.assertEqual(json.loads(data["orderInfo"])["signType"], "RSA")


class EndpointCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(Path(by.__file__).with_name("bysy_endpoints.json").read_text(encoding="utf-8"))

    def test_whitelist_matches_source(self):
        # 源码里 d=[...] 就是 9 条，顺序照抄
        self.assertEqual(len(by.PUBLIC_PATHS), 9)
        self.assertEqual(
            list(by.PUBLIC_PATHS),
            [v["path"] for v in self.doc["public"].values()],
        )

    def test_catalog_flags(self):
        self.assertEqual(len(self.doc["public"]), 9)
        self.assertTrue(all(v["token"] is False for v in self.doc["public"].values()))
        self.assertGreater(len(self.doc["auth"]), 100)
        self.assertTrue(all(v["token"] is True for v in self.doc["auth"].values()))

    def test_all_paths_wellformed(self):
        paths = [v["path"] for v in self.doc["public"].values()]
        paths += [v["path"] for v in self.doc["auth"].values()]
        paths += [v["path"] for v in self.doc["unnamed"]]
        self.assertGreaterEqual(len(paths), 200)
        for p in paths:
            self.assertTrue(p.startswith("api/v"), p)

    def test_appointment_chain_present(self):
        paths = {v["path"] for v in self.doc["auth"].values()}
        for p in (
            "api/v1/appointment/getDepartments",
            "api/v2/appointment/getDepartmentDoctors",
            "api/v2/appointment/area/getVisitSchedules",
            "api/v2/appointment/getVisitSchedulesTimes",
            "api/v2/appointment/createAppointment",
            "api/v1/payment/createPayment",
        ):
            self.assertIn(p, paths)


if __name__ == "__main__":
    unittest.main()
