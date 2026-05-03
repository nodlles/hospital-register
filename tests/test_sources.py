from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import hospital_watch as watch  # noqa: E402


class SourceParsingTests(unittest.TestCase):
    def test_expand_time_intervals_keeps_source_when_interval_endpoint_is_missing(self) -> None:
        src = watch.Source(
            dept_code="0147",
            doctor_code="332441",
            doctor_name="张毅",
            source_code="96761827",
            source_name="普通门诊",
            visit_date="2026-05-06",
            period_type="AM",
            period_view="上午号源",
            price="50.00",
            count=14,
            support_time_interval=True,
        )
        cfg = {"endpoints": {"time_intervals": ""}}

        self.assertEqual(watch.expand_time_intervals(cfg, src), [src])

    def test_parse_source_uses_source_name_when_doctor_name_is_empty(self) -> None:
        item = {
            "deptCode": "0147",
            "doctorCode": "",
            "doctorName": "",
            "sourceCode": "96761829",
            "sourceName": "普通号",
            "sourceLevelView": "普通门诊",
            "price": "50.00",
            "count": 15,
            "supportTimeInterval": False,
        }

        src = watch.source_from_api_item(item, "0147", "2026-05-06", "AM", "上午号源")

        self.assertEqual(src.doctor_name, "普通号")
        self.assertEqual(src.source_name, "普通门诊")


if __name__ == "__main__":
    unittest.main()
