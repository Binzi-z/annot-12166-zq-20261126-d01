#!/usr/bin/env python3
"""离线复现与复核 12166 —— 一键入口（仅 Python 3.12 标准库）。

用法：
    python solve.py

退出码 0 表示全部机器断言通过；任一题面要点不符则退出码 1。
产物：
    synthetic/                 确定性合成的路径/策略/授权代规则（求解器只读这里）
    reports/report.json        全量结构化结果
    reports/REPORT.md          人工复核报告
    reports/full_access_results.csv  60000 节点全量访问判定
    artifacts/concurrency/     WAL / 幂等 / 回执恢复的真实落盘状态
"""
from __future__ import annotations

import sys
from pathlib import Path

# 允许直接 `python solve.py`（把脚本所在目录放到 sys.path）
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Windows 终端默认编码可能不是 UTF-8，统一输出编码避免打印中文/符号报错
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except Exception:
        pass

from sec12166.checks import run_checks  # noqa: E402


def main() -> int:
    rep = run_checks()
    print("=" * 78)
    print("离线安全复核 12166")
    print("=" * 78)
    for row in rep["requirement_matrix"]:
        print(f"[{'PASS' if row['ok'] else 'FAIL'}] {row['requirement']}")
    print("-" * 78)

    sc = rep["scale"]
    n = sc["numbers"]
    print(f"规模: 总节点={n['total_nodes']}  "
          f"实际访问={n['unique_nodes_accessed']} (calls={n['read_calls']})  "
          f"变更={n['revision_changed_nodes']}  "
          f"全量结果={sum(sc['full_result_counts'].values())} 行")
    print(f"未改分区: {sc['unchanged_partitions']}")
    cc = rep["concurrency"]
    print(f"并发: A={cc['scenarios'][0]['ok']} B={cc['scenarios'][1]['ok']} "
          f"stress={cc['stress']['ok']} outcomes={cc['stress']['outcomes']}")
    print("-" * 78)
    print(f"JSON 报告 : {rep['report_json']}")
    print(f"Markdown  : {rep['report_md']}")
    print("=" * 78)
    print("总体结论:", "全部通过 ✅" if rep["overall_ok"] else "存在失败 ❌")
    return 0 if rep["overall_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
