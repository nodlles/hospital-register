from __future__ import annotations

import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app_server  # noqa: E402
import hospital_watch as watch  # noqa: E402


def example_config() -> dict:
    return watch.load_config(ROOT / "config.example.json")


def sample_source() -> watch.Source:
    return watch.Source(
        dept_code="0147",
        doctor_code="DR1",
        doctor_name="测试医生",
        source_code="S1",
        source_name="专家门诊",
        visit_date="2026-05-06",
        period_type="AM",
        period_view="上午",
        price="50",
        count=1,
        support_time_interval=False,
    )


class RateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        app_server.API_CACHE.clear()
        app_server.API_COOLDOWNS.clear()

    def test_cached_call_reuses_value_within_ttl(self) -> None:
        calls = []

        def loader() -> dict:
            calls.append(1)
            return {"value": len(calls)}

        first = app_server.cached_api_call(("calendar", "0147"), 60, loader)
        second = app_server.cached_api_call(("calendar", "0147"), 60, loader)

        self.assertEqual(first, {"value": 1})
        self.assertEqual(second, {"value": 1})
        self.assertEqual(len(calls), 1)

    def test_catalog_cache_persists_and_reuses_items(self) -> None:
        original_path = app_server.CATALOG_CACHE_PATH
        try:
            with tempfile.TemporaryDirectory() as tmp:
                app_server.CATALOG_CACHE_PATH = Path(tmp) / "catalog-cache.json"
                calls = []

                def loader() -> list[dict]:
                    calls.append(1)
                    return [{"districtCode": "001", "districtName": "本部"}]

                first, first_cached = app_server.cached_catalog_call("districts", "all", loader)
                second, second_cached = app_server.cached_catalog_call("districts", "all", loader)

                self.assertFalse(first_cached)
                self.assertTrue(second_cached)
                self.assertEqual(first, second)
                self.assertEqual(len(calls), 1)
                self.assertTrue(app_server.CATALOG_CACHE_PATH.exists())
        finally:
            app_server.CATALOG_CACHE_PATH = original_path

    def test_catalog_cache_falls_back_to_stale_items_on_rate_limit(self) -> None:
        original_path = app_server.CATALOG_CACHE_PATH
        try:
            with tempfile.TemporaryDirectory() as tmp:
                app_server.CATALOG_CACHE_PATH = Path(tmp) / "catalog-cache.json"
                stale = {"createdAt": time.time() - app_server.CATALOG_CACHE_TTL_SECONDS - 10, "items": [{"deptCode": "0147"}]}
                app_server.save_catalog_cache({"districts": {}, "departments": {"001": stale}})

                items, cached = app_server.cached_catalog_call(
                    "departments",
                    "001",
                    lambda: (_ for _ in ()).throw(watch.WatchError("code=10000 message=请求过于频繁")),
                )

                self.assertTrue(cached)
                self.assertEqual(items, [{"deptCode": "0147"}])
        finally:
            app_server.CATALOG_CACHE_PATH = original_path

    def test_rate_limit_error_sets_cooldown(self) -> None:
        def loader() -> dict:
            raise watch.WatchError("calendar 返回异常: code=10000 message=请求过于频繁")

        with self.assertRaises(watch.WatchError):
            app_server.cached_api_call(("calendar", "0147"), 60, loader)

        cooldown = app_server.API_COOLDOWNS[("calendar", "0147")]
        self.assertGreater(cooldown, time.time())

        with self.assertRaises(watch.WatchError) as ctx:
            app_server.cached_api_call(("calendar", "0147"), 60, lambda: {"value": 2})

        self.assertIn("请求过于频繁", str(ctx.exception))
        self.assertIn("请稍后", str(ctx.exception))

    def test_rate_limit_error_detection_matches_hospital_response(self) -> None:
        self.assertTrue(app_server.is_rate_limit_error(watch.WatchError("calendar 返回异常: code=10000 message=请求过于频繁")))
        self.assertTrue(app_server.is_rate_limit_error(watch.WatchError("请求过于频繁，请稍后 89s 再试。")))
        self.assertFalse(app_server.is_rate_limit_error(watch.WatchError("HTTP 500: upstream failed")))

    def test_monitor_rate_limit_backoff_escalates_and_caps(self) -> None:
        values = [app_server.rate_limit_backoff_seconds(count) for count in range(1, 8)]

        self.assertEqual(values, [60, 90, 150, 240, 300, 300, 300])

    def test_estimated_release_time_uses_15_00_seven_days_before_visit(self) -> None:
        release_at = app_server.estimated_release_at("2026-05-12")

        self.assertEqual(release_at, datetime(2026, 5, 5, 15, 0))

    def test_monitor_interval_is_low_frequency_far_before_release_time(self) -> None:
        interval = app_server.monitor_poll_interval_seconds(
            0.5,
            "2026-05-12",
            now=datetime(2026, 5, 3, 18, 26),
        )

        self.assertEqual(interval, 300.0)

    def test_monitor_interval_ramps_up_near_release_time(self) -> None:
        self.assertEqual(
            app_server.monitor_poll_interval_seconds(0.5, "2026-05-12", now=datetime(2026, 5, 5, 14, 35)),
            15.0,
        )
        self.assertEqual(
            app_server.monitor_poll_interval_seconds(0.5, "2026-05-12", now=datetime(2026, 5, 5, 14, 58)),
            2.0,
        )

    def test_monitor_interval_is_throttled_after_release_time(self) -> None:
        interval = app_server.monitor_poll_interval_seconds(
            0.5,
            "2026-05-12",
            now=datetime(2026, 5, 5, 15, 1),
        )

        self.assertEqual(interval, 2.0)

    def test_monitor_interval_respects_slower_user_setting(self) -> None:
        interval = app_server.monitor_poll_interval_seconds(
            450,
            "2026-05-12",
            now=datetime(2026, 5, 3, 18, 26),
        )

        self.assertEqual(interval, 450.0)

    def test_pre_release_wait_does_not_consume_active_monitor_duration(self) -> None:
        self.assertTrue(app_server.should_extend_monitor_for_pre_release("2026-05-12", now=datetime(2026, 5, 3, 18, 26)))
        self.assertFalse(app_server.should_extend_monitor_for_pre_release("2026-05-12", now=datetime(2026, 5, 5, 15, 1)))

    def test_default_visit_date_targets_today_release_before_15_00(self) -> None:
        self.assertEqual(
            app_server.default_visit_date_for_monitor(now=datetime(2026, 5, 3, 14, 59)),
            "2026-05-10",
        )

    def test_default_visit_date_targets_next_day_release_after_15_00(self) -> None:
        self.assertEqual(
            app_server.default_visit_date_for_monitor(now=datetime(2026, 5, 3, 18, 42)),
            "2026-05-11",
        )

    def test_target_dates_marks_default_release_target(self) -> None:
        rows = app_server.target_dates(10, now=datetime(2026, 5, 3, 18, 42))
        selected = [item["visitDate"] for item in rows if item.get("defaultSelected")]

        self.assertEqual(selected, ["2026-05-11"])

    def test_monitor_pauses_and_resumes_after_rate_limit(self) -> None:
        manager = app_server.MonitorManager()
        manager.stop_event = threading.Event()
        payload = {
            "deptCode": "0147",
            "deptName": "疼痛门诊",
            "visitDate": "2026-05-06",
            "periodType": "AM",
            "doctorMode": "any",
            "endAfterSeconds": 2,
            "intervalSeconds": 0.01,
        }
        calls = []
        old_load_cfg = app_server.load_cfg
        old_discover_sources = watch.discover_sources
        old_backoff = app_server.rate_limit_backoff_seconds

        def fake_discover_sources(cfg: dict) -> list[watch.Source]:
            calls.append(1)
            if len(calls) == 1:
                raise watch.WatchError("detail 返回异常: code=10000 message=请求过于频繁")
            return [sample_source()]

        try:
            app_server.load_cfg = example_config
            watch.discover_sources = fake_discover_sources
            app_server.rate_limit_backoff_seconds = lambda count: 0.01

            manager._run(payload)
        finally:
            app_server.load_cfg = old_load_cfg
            watch.discover_sources = old_discover_sources
            app_server.rate_limit_backoff_seconds = old_backoff

        logs = "\n".join(manager.snapshot()["logs"])
        self.assertEqual(len(calls), 2)
        self.assertIn("医院接口限流", logs)
        self.assertIn("自动继续", logs)
        self.assertEqual(len(manager.snapshot()["hits"]), 1)


if __name__ == "__main__":
    unittest.main()
