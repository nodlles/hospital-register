from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import app_server  # noqa: E402


def example_config() -> dict:
    return json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))


class AuthWizardTests(unittest.TestCase):
    def test_default_config_path_uses_local_config(self) -> None:
        self.assertEqual(app_server.CONFIG_PATH.name, "config.local.json")

    def test_ensure_config_file_creates_nested_local_config_directory(self) -> None:
        original_path = app_server.CONFIG_PATH
        try:
            with tempfile.TemporaryDirectory() as tmp:
                app_server.CONFIG_PATH = Path(tmp) / "state" / "config.local.json"
                app_server.ensure_config_file()
                self.assertTrue(app_server.CONFIG_PATH.exists())
                self.assertEqual(app_server.CONFIG_PATH.stat().st_mode & 0o777, 0o600)
        finally:
            app_server.CONFIG_PATH = original_path

    def test_har_import_extracts_auth_headers_submit_endpoint_and_patient_code(self) -> None:
        cfg = example_config()
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://example.com/api/mobile/source/locking",
                            "headers": [{"name": "a-ticket", "value": "wrong"}],
                        },
                    },
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://appaceso.zryhyy.com.cn/api/mobile/source/locking",
                            "headers": [
                                {"name": ":method", "value": "POST"},
                                {"name": ":path", "value": "/api/mobile/source/locking"},
                                {"name": "a-ticket", "value": "secret-ticket"},
                                {"name": "u-u-ticket", "value": "user-ticket"},
                                {"name": "content-length", "value": "123"},
                                {"name": "Referer", "value": "https://servicewechat.com/wx/example.html"},
                            ],
                            "postData": {
                                "text": json.dumps(
                                    {
                                        "patientCode": "P0001",
                                        "sourceCode": "SRC",
                                    }
                                )
                            },
                        }
                    },
                ]
            }
        }

        result = app_server.import_har_into_config(cfg, json.dumps(har))

        self.assertEqual(cfg["base_url"], "https://appaceso.zryhyy.com.cn")
        self.assertEqual(cfg["headers"]["a-ticket"], "secret-ticket")
        self.assertEqual(cfg["headers"]["u-u-ticket"], "user-ticket")
        self.assertNotIn(":method", cfg["headers"])
        self.assertNotIn("content-length", cfg["headers"])
        self.assertEqual(cfg["endpoints"]["submit"], "/api/mobile/source/locking")
        self.assertEqual(cfg["target"]["patient_code"], "P0001")
        self.assertEqual(result["source"], "har")
        self.assertTrue(result["patientCodeImported"])
        self.assertEqual(result["candidates"], 1)

    def test_public_config_reports_setup_checklist_without_secret_values(self) -> None:
        cfg = copy.deepcopy(example_config())
        cfg["headers"] = {"a-ticket": "secret-ticket", "User-Agent": "UA"}
        cfg["target"]["patient_code"] = "P0001"
        cfg["endpoints"]["submit"] = "/api/mobile/source/locking"

        public = app_server.public_config(cfg)

        self.assertEqual(public["target"]["patient_code"], "CONFIGURED")
        self.assertIn("setup", public)
        self.assertTrue(public["setup"]["authImported"])
        self.assertTrue(public["setup"]["patientSelected"])
        self.assertTrue(public["setup"]["submitEndpoint"])
        serialized = json.dumps(public, ensure_ascii=False)
        self.assertNotIn("secret-ticket", serialized)
        self.assertNotIn("P0001", serialized)

    def test_validate_auth_status_uses_district_list_without_exposing_headers(self) -> None:
        cfg = copy.deepcopy(example_config())
        calls = []

        def fake_request(request_cfg: dict, path: str, **kwargs: dict) -> dict:
            calls.append((request_cfg, path, kwargs))
            return {"code": 0, "data": {"list": [{"districtCode": "001"}]}}

        result = app_server.validate_auth_status(cfg, request_fn=fake_request)

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][1], "/api/mobile/hospital/district/list")
        self.assertNotIn("headers", result)


if __name__ == "__main__":
    unittest.main()
