#!/usr/bin/env python3
"""北大口腔小程序接口探测器。

目的只有一个：把真实返回的字段名打出来，不靠猜。
逆出来的 132 个接口里，挂号链路的参数名和返回字段是我从混淆过的
app-service.js 里推断的，必须用真实响应校准一次。

流程（只用 GET/POST 读数据，不下单、不取消）：
    dateList → getYyDeptList(areaCode=0) → 挑一个科室
             → getYyDoctorList(deptCode) → getYyScheduleList(...)

用法：
    python3 bdkq_probe.py -c config.bdkq.local.json
    python3 bdkq_probe.py -c config.bdkq.local.json --area 6 --dept-limit 3
    python3 bdkq_probe.py                       # 无配置时只打印探测计划

产物：
    probe-result.json  每一步的入参、状态码、截断后的原始 data、推断出的字段表
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from bdkq_client import BdkqClient, BdkqError, load_config

MAX_ITEMS = 3          # 每个列表只留前 N 条样本
MAX_STR = 120          # 长字符串截断
MAX_DEPTH = 6


def truncate(value: Any, depth: int = 0) -> Any:
    """把响应裁到能读的大小，同时保留结构。"""
    if depth > MAX_DEPTH:
        return "…"
    if isinstance(value, dict):
        return {k: truncate(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        head = [truncate(v, depth + 1) for v in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            head.append(f"… 共 {len(value)} 条")
        return head
    if isinstance(value, str) and len(value) > MAX_STR:
        return value[:MAX_STR] + "…"
    return value


def schema_of(value: Any, prefix: str = "", out: dict[str, str] | None = None, depth: int = 0) -> dict[str, str]:
    """把 JSON 拍平成 {字段路径: 类型}，用来跟推断的参数名对照。"""
    if out is None:
        out = {}
    if depth > MAX_DEPTH:
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(item, (dict, list)):
                out[path] = type(item).__name__
                schema_of(item, path, out, depth + 1)
            else:
                out[path] = type(item).__name__
    elif isinstance(value, list):
        out[prefix or "$"] = f"list[{len(value)}]"
        for item in value[:MAX_ITEMS]:
            schema_of(item, f"{prefix}[]", out, depth + 1)
    return out


class Probe:
    def __init__(self, client: BdkqClient, report: dict[str, Any]) -> None:
        self.client = client
        self.report = report

    def step(self, name: str, path: str, *, method: str = "GET",
             query: dict[str, Any] | None = None, body: dict[str, Any] | None = None) -> Any:
        record: dict[str, Any] = {"name": name, "path": path, "method": method,
                                  "query": query, "body": body}
        try:
            resp = self.client.request(path, method=method, query=query, body=body)
            record["status"] = resp.status
            record["message"] = resp.message
            record["data"] = truncate(resp.data)
            record["schema"] = schema_of(resp.data)
            record["ok"] = resp.ok
            print(f"  {name:26s} status={resp.status:<5} {resp.message}")
            self.report["steps"].append(record)
            return resp.data
        except BdkqError as exc:
            record["error"] = str(exc)
            record["ok"] = False
            print(f"  {name:26s} 失败: {exc}")
            self.report["steps"].append(record)
            return None


def first_code(items: Any, *keys: str) -> str:
    """从列表里挑第一个非空 code 字段。候选字段名是推断的，取到了就算校准成功。"""
    if not isinstance(items, list):
        return ""
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in keys:
            value = item.get(key)
            if value not in (None, "", 0, "0"):
                return str(value)
    return ""


def run_probe(client: BdkqClient, area_code: str, dept_limit: int) -> dict[str, Any]:
    report: dict[str, Any] = {"area_code": area_code, "steps": [], "calibrated": {}}
    probe = Probe(client, report)

    print("1) 日期列表")
    probe.step("dateList", "/api/system/dateList")

    print(f"2) 科室列表 areaCode={area_code}")
    depts = probe.step("getYyDeptList", "/api/regist/getYyDeptList",
                       query={"areaCode": area_code, "withRemain": "1"})
    flat = depts
    if isinstance(depts, dict):
        for key in ("lists", "list", "deptList", "records"):
            if isinstance(depts.get(key), list):
                flat = depts[key]
                report["calibrated"]["dept_list_field"] = key
                break
    dept_code = first_code(flat, "deptCode", "code", "deptId", "id")
    report["calibrated"]["dept_code_field_value"] = dept_code
    if isinstance(flat, list) and flat:
        report["calibrated"]["dept_fields"] = sorted(flat[0].keys()) if isinstance(flat[0], dict) else []

    if not dept_code:
        print("  没取到 deptCode，后续步骤跳过（先用 --area 换院区试试）")
        return report

    print(f"3) 医生列表 deptCode={dept_code}")
    doctors = probe.step("getYyDoctorList", "/api/regist/getYyDoctorList",
                         query={"deptCode": dept_code})
    doc_flat = doctors
    if isinstance(doctors, dict):
        for key in ("lists", "list", "doctorList", "records"):
            if isinstance(doctors.get(key), list):
                doc_flat = doctors[key]
                report["calibrated"]["doctor_list_field"] = key
                break
    if isinstance(doc_flat, list) and doc_flat:
        report["calibrated"]["doctor_fields"] = sorted(doc_flat[0].keys()) if isinstance(doc_flat[0], dict) else []
    doctor_code = first_code(doc_flat, "doctorCode", "personCode", "code", "doctorId", "id")
    report["calibrated"]["doctor_code_field_value"] = doctor_code

    print("4) 排班列表（参数名待校准，逐个试）")
    candidates: list[dict[str, Any]] = []
    if doctor_code:
        candidates.append({"deptCode": dept_code, "doctorCode": doctor_code})
        candidates.append({"deptCode": dept_code, "personCode": doctor_code})
    candidates.append({"deptCode": dept_code})
    for idx, payload in enumerate(candidates[:dept_limit], 1):
        data = probe.step(f"getYyScheduleList#{idx}", "/api/regist/getYyScheduleList",
                          method="POST", body=payload)
        if data:
            report["calibrated"]["schedule_params"] = payload
            break

    print("5) 其他院区号源")
    probe.step("queryYyOtherAreaNumber", "/api/regist/queryYyOtherAreaNumber",
               method="POST", body={"areaCode": area_code})

    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="北大口腔接口探测")
    parser.add_argument("-c", "--config", default="config.bdkq.local.json")
    parser.add_argument("--area", default="0", help="院区代码，默认 0 魏公村总院区")
    parser.add_argument("--dept-limit", type=int, default=2, help="排班参数最多试几次")
    parser.add_argument("-o", "--output", default="probe-result.json")
    args = parser.parse_args(argv)

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"没找到配置 {config_path}。先用 bdkq_har.py 从 HAR/cURL 生成，")
        print("或者手写一份（字段见 config.bdkq.example.json）。")
        print("\n有配置后的探测顺序：dateList → getYyDeptList → getYyDoctorList → getYyScheduleList")
        return 2

    config = load_config(str(config_path))
    client = BdkqClient.from_config(config)
    if not client.access_token:
        print("配置里没有 access_token，只能调不需要登录的接口", file=sys.stderr)

    print(f"目标 {client.base_url}  租户 {client.tenant}  版本 {client.api_version}\n")
    try:
        report = run_probe(client, str(args.area), args.dept_limit)
    except BdkqError as exc:
        print(f"探测中断: {exc}", file=sys.stderr)
        return 1

    out = Path(args.output)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n结果已写入 {out}")
    calibrated = report.get("calibrated") or {}
    if calibrated:
        print("校准到的字段：")
        for key, value in calibrated.items():
            print(f"  {key} = {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
