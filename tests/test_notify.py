from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app_server  # noqa: E402
import hospital_watch as watch  # noqa: E402


def example_config() -> dict:
    return json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))


def sample_source() -> watch.Source:
    return watch.Source(
        dept_code="D1",
        doctor_code="DR1",
        doctor_name="测试医生",
        source_code="S1",
        source_name="专家门诊",
        visit_date="2026-05-04",
        period_type="AM",
        period_view="上午",
        price="50",
        count=1,
        support_time_interval=False,
    )


class NotifyTests(unittest.TestCase):
    def test_public_config_masks_notify_webhook_url(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": True,
            "channels": [
                {"type": "webhook", "name": "手机通知", "url": "https://push.example/token-secret"}
            ],
        }

        public = app_server.public_config(cfg)
        serialized = json.dumps(public, ensure_ascii=False)

        self.assertTrue(public["notify"]["enabled"])
        self.assertEqual(public["notify"]["channels"][0]["url"], "CONFIGURED")
        self.assertNotIn("token-secret", serialized)

    def test_public_config_masks_channel_specific_secrets(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": True,
            "channels": [
                {"type": "bark", "device_key": "bark-secret"},
                {"type": "serverchan", "send_key": "server-secret"},
                {"type": "telegram", "bot_token": "telegram-secret", "chat_id": "chat-secret"},
            ],
        }

        public = app_server.public_config(cfg)
        serialized = json.dumps(public, ensure_ascii=False)

        self.assertEqual(public["notify"]["channels"][0]["deviceKey"], "CONFIGURED")
        self.assertEqual(public["notify"]["channels"][1]["sendKey"], "CONFIGURED")
        self.assertEqual(public["notify"]["channels"][2]["botToken"], "CONFIGURED")
        self.assertEqual(public["notify"]["channels"][2]["chatId"], "CONFIGURED")
        self.assertNotIn("bark-secret", serialized)
        self.assertNotIn("server-secret", serialized)
        self.assertNotIn("telegram-secret", serialized)
        self.assertNotIn("chat-secret", serialized)

    def test_update_notify_config_persists_enabled_for_existing_channel(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": False,
            "channels": [
                {
                    "type": "telegram",
                    "name": "手机通知",
                    "bot_token": "telegram-secret",
                    "chat_id": "chat-secret",
                }
            ],
        }

        updated = app_server.update_notify_config(
            cfg,
            {
                "enabled": True,
                "type": "telegram",
                "name": "手机通知",
                "botToken": "",
                "chatId": "",
            },
        )
        public = app_server.public_config(cfg)

        self.assertTrue(updated["enabled"])
        self.assertTrue(public["notify"]["enabled"])
        self.assertEqual(public["notify"]["channels"][0]["type"], "telegram")
        self.assertEqual(public["notify"]["channels"][0]["botToken"], "CONFIGURED")

    def test_send_notification_posts_json_without_secrets(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": True,
            "channels": [{"type": "webhook", "name": "test", "url": "https://push.example/hook"}],
        }
        calls = []

        def fake_sender(url: str, method: str, headers: dict, body: bytes) -> tuple[int, str]:
            calls.append((url, method, headers, json.loads(body.decode("utf-8"))))
            return 200, "ok"

        result = watch.send_notification(
            cfg,
            "发现可预约号源",
            "2026-05-04 上午 | 测试医生",
            event="hit",
            sender=fake_sender,
        )

        self.assertEqual(result["sent"], 1)
        self.assertEqual(calls[0][0], "https://push.example/hook")
        self.assertEqual(calls[0][1], "POST")
        self.assertEqual(calls[0][3]["title"], "发现可预约号源")
        self.assertNotIn("patientCode", json.dumps(calls[0][3], ensure_ascii=False))

    def test_send_notification_supports_bark_channel(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": True,
            "channels": [
                {
                    "type": "bark",
                    "name": "bark",
                    "server_url": "https://api.day.app",
                    "device_key": "bark-key",
                }
            ],
        }
        calls = []

        def fake_sender(url: str, method: str, headers: dict, body: bytes) -> tuple[int, str]:
            calls.append((url, method, headers, json.loads(body.decode("utf-8"))))
            return 200, "ok"

        watch.send_notification(cfg, "标题", "内容", event="test", sender=fake_sender)

        self.assertEqual(calls[0][0], "https://api.day.app/push")
        self.assertEqual(calls[0][3]["device_key"], "bark-key")
        self.assertEqual(calls[0][3]["title"], "标题")
        self.assertEqual(calls[0][3]["body"], "内容")

    def test_send_notification_supports_serverchan_channel(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": True,
            "channels": [{"type": "serverchan", "name": "server", "send_key": "sct-key"}],
        }
        calls = []

        def fake_sender(url: str, method: str, headers: dict, body: bytes) -> tuple[int, str]:
            calls.append((url, method, headers, body.decode("utf-8")))
            return 200, "ok"

        watch.send_notification(cfg, "标题", "内容", event="test", sender=fake_sender)

        self.assertEqual(calls[0][0], "https://sctapi.ftqq.com/sct-key.send")
        self.assertEqual(calls[0][2]["Content-Type"], "application/x-www-form-urlencoded; charset=utf-8")
        self.assertIn("title=", calls[0][3])
        self.assertIn("desp=", calls[0][3])

    def test_send_notification_supports_telegram_channel(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": True,
            "channels": [
                {"type": "telegram", "name": "tg", "bot_token": "bot-token", "chat_id": "12345"}
            ],
        }
        calls = []

        def fake_sender(url: str, method: str, headers: dict, body: bytes) -> tuple[int, str]:
            calls.append((url, method, headers, json.loads(body.decode("utf-8"))))
            return 200, "ok"

        watch.send_notification(cfg, "标题", "内容", event="test", sender=fake_sender)

        self.assertEqual(calls[0][0], "https://api.telegram.org/botbot-token/sendMessage")
        self.assertEqual(calls[0][3]["chat_id"], "12345")
        self.assertIn("标题", calls[0][3]["text"])

    def test_send_notification_surfaces_telegram_error_description(self) -> None:
        cfg = example_config()
        cfg["notify"] = {
            "enabled": True,
            "channels": [
                {"type": "telegram", "name": "tg", "bot_token": "bot-token", "chat_id": "bad-chat"}
            ],
        }

        result = watch.send_notification(
            cfg,
            "标题",
            "内容",
            event="test",
            sender=lambda *args, **kwargs: (
                400,
                '{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}',
            ),
        )

        self.assertEqual(result["sent"], 0)
        self.assertIn("chat not found", result["results"][0]["error"])

    def test_monitor_sends_hit_notification_once(self) -> None:
        cfg = example_config()
        cfg["notify"] = {"enabled": True, "channels": [{"type": "webhook", "url": "https://push.example/hook"}]}
        manager = app_server.MonitorManager()
        calls = []
        src = sample_source()

        manager._notify_hit(cfg, [src], notifier=lambda *args, **kwargs: calls.append((args, kwargs)) or {"sent": 1})
        manager._notify_hit(cfg, [src], notifier=lambda *args, **kwargs: calls.append((args, kwargs)) or {"sent": 1})

        self.assertEqual(len(calls), 1)
        self.assertIn("发现可预约号源", calls[0][0][1])

    def test_monitor_sends_start_and_stop_notifications_with_settings(self) -> None:
        cfg = example_config()
        manager = app_server.MonitorManager()
        calls = []
        payload = {
            "districtCode": "001",
            "deptCode": "0147",
            "deptName": "疼痛门诊",
            "visitDate": "2026-05-06",
            "periodType": "AM",
            "doctorMode": "any",
            "startAt": "14:58:00",
            "endAfterSeconds": 240,
            "intervalSeconds": 1,
        }

        manager._notify_task_lifecycle(
            cfg,
            "started",
            payload,
            notifier=lambda *args, **kwargs: calls.append((args, kwargs)) or {"sent": 1},
        )
        manager._notify_task_lifecycle(
            cfg,
            "stopped",
            payload,
            notifier=lambda *args, **kwargs: calls.append((args, kwargs)) or {"sent": 1},
        )

        self.assertEqual(len(calls), 2)
        self.assertIn("监控已启动", calls[0][0][1])
        self.assertIn("疼痛门诊", calls[0][0][2])
        self.assertIn("2026-05-06", calls[0][0][2])
        self.assertIn("监控已停止", calls[1][0][1])

    def test_monitor_logs_notification_failures(self) -> None:
        cfg = example_config()
        manager = app_server.MonitorManager()
        payload = {
            "districtCode": "001",
            "deptCode": "0147",
            "deptName": "疼痛门诊",
            "visitDate": "2026-05-06",
        }

        manager._notify_task_lifecycle(
            cfg,
            "started",
            payload,
            notifier=lambda *args, **kwargs: {"sent": 0, "results": [{"name": "Telegram", "ok": False, "status": 400}]},
        )

        self.assertIn("通知发送失败：Telegram: HTTP 400", "\n".join(manager.snapshot()["logs"]))

    def test_submit_success_sends_payment_notification(self) -> None:
        cfg = copy.deepcopy(example_config())
        cfg["submit"]["confirm_phrase"] = "OK"
        calls = []
        result = {"code": 0, "data": {"orderId": "O1"}}

        app_server.notify_submit_result(
            cfg,
            result,
            notifier=lambda *args, **kwargs: calls.append((args, kwargs)) or {"sent": 1},
        )

        self.assertEqual(len(calls), 1)
        self.assertIn("待支付", calls[0][0][1])


if __name__ == "__main__":
    unittest.main()
