"""把总复核结果渲染成可人工复核的 Markdown。"""
from __future__ import annotations

import json
from pathlib import Path


def _badge(ok: bool) -> str:
    return "✅ PASS" if ok else "❌ FAIL"


def render_markdown(rep: dict) -> str:
    L: list[str] = []
    add = L.append
    add("# 离线安全复核报告 12166")
    add("")
    add(f"总体结论：**{_badge(rep['overall_ok'])}**")
    add("")
    add("> 全程仅使用 Python 3.12 标准库，仅读取 `synthetic/` 下的合成路径、策略与授权代规则；")
    add("> 不读取真实 Windows 路径 / ACL / 注册表。所有数字由确定性种子生成并可重复复算。")
    add("")

    # 题面要求映射
    add("## 1. 题面要求 → 证据映射")
    add("")
    add("| 题面要求 | 落地证据 | 结论 |")
    add("|---|---|---|")
    for row in rep["requirement_matrix"]:
        add(f"| {row['requirement']} | {row['evidence']} | {_badge(row['ok'])} |")
    add("")

    # 会签
    cs = rep["countersign"]
    add("## 2. 已会签回退的绑定与双人独立")
    add("")
    add(f"结论：{_badge(cs['ok'])}")
    add("")
    b = cs["binding"]
    add("绑定四要素（+ 可选版本摘要）：")
    add("")
    add("```json")
    add(json.dumps(b, ensure_ascii=False, indent=2))
    add("```")
    add("")
    add("正向验签通过项：")
    for c in cs["happy_verification"]["passed_checks"]:
        add(f"- {c}")
    add("")
    add("负向用例（必须全部被拒）：")
    add("")
    add("| 攻击/违规情形 | 是否被拒 | 触发的错误（摘） |")
    add("|---|---|---|")
    for neg in cs["negative_cases"]:
        err = neg["errors"][0] if neg["errors"] else ""
        add(f"| {neg['case']} | {_badge(not neg['accepted'])} | `{err}` |")
    add("")

    # 并发
    add("## 3. 双线程并行回退/撤回与屏障复测")
    add("")
    for suite in rep["concurrency"]["scenarios"]:
        add(f"### {suite['name']} — {_badge(suite['ok'])}")
        add("")
        for c in suite["checks"]:
            add(f"- {_badge(c['pass'])} {c['name']}" + (f"  _( {c['detail']} )_" if c.get("detail") else ""))
        add("")
    st = rep["concurrency"]["stress"]
    add(f"### {st['name']} — {_badge(st['ok'])}")
    add("")
    add(f"- 轮次：{st['trials']}；结果分布：提交生效 {st['outcomes']['committed']} / 撤回生效 {st['outcomes']['revoked']}")
    add(f"- 是否在无编排压测中观察到两种胜序：{st['both_orderings_observed']}")
    if st["violations"]:
        add(f"- 违例：{st['violations']}")
    add("")

    # 小树差异区间
    dt = rep["diff_tree"]
    add("## 4. 独立小树：恢复前后差异区间与最短见证路径")
    add("")
    add(f"结论：{_badge(dt['assertions_ok'])}")
    s = dt["summary"]
    add(f"- 隔离目录 DFS 节点数：{s['total_nodes']}；结论变化：{s['changed_verdict_nodes']}；"
        f"由放行恢复为封闭：{s['closed_by_restore_nodes']}；不变：{s['unchanged_nodes']}")
    add(f"- 压缩后差异区间数：{len(dt['report']['diff_intervals'])}；"
        f"区间长度：{[i['count'] for i in dt['report']['diff_intervals']]}")
    add("")
    add("### 差异区间（DFS 先序，整棵子树连续）")
    add("")
    for iv in dt["report"]["diff_intervals"]:
        add(f"#### 区间 [{iv['start_index']}..{iv['end_index']}] 共 {iv['count']} 节点")
        add(f"- 起点：`{iv['start_path']}`")
        add(f"- 终点：`{iv['end_path']}`")
        add("")
        add("| nid | 名称 | 回退前(v2) | 恢复后(v3) | 恢复后依据 | 断开继承 |")
        add("|---|---|---|---|---|---|")
        for v in iv["verdicts"]:
            add(f"| {v['nid']} | {v['name']} | {v['old']} | {v['new']} | `{v['new_basis']}` | {'是' if v['block'] else ''} |")
        add("")

    add("### 最短可复核见证路径")
    add("")
    for key, w in dt["report"]["witnesses"].items():
        add(f"#### {key} → **{w['verdict']}** `{w['path']}`")
        if w.get("depth_from_isolation_root") is not None:
            add(f"- 距隔离根深度：{w['depth_from_isolation_root']}")
        add(f"- 判定依据：`{w['basis']}`；说明：{w.get('note') or '—'}")
        if w.get("via_mount"):
            add(f"- 穿过挂接点 reparse 跳：{w['mount_hops']}（按目标 DACL 判定）")
        if w.get("decisive_deny"):
            a = w["decisive_deny"]
            add(f"- 决定性 DENY：`{a['ace_id']}` {a['kind']} {a['sid']} mask={a['mask']} "
                f"flags={a['flags']} inherited={a['inherited']} origin=`{a.get('origin_path', a['origin'])}`")
        if w.get("decisive_allow"):
            a = w["decisive_allow"]
            add(f"- 决定性 ALLOW：`{a['ace_id']}` {a['kind']} {a['sid']} mask={a['mask']} "
                f"flags={a['flags']} inherited={a['inherited']} origin=`{a.get('origin_path', a['origin'])}`")
        add("- 节点链：")
        for c in w["chain"]:
            tags = []
            if c["block_inheritance"]:
                tags.append("BLOCK_INHERIT")
            if c["mount_target"]:
                tags.append(f"MOUNT->{c['mount_target']}")
            add(f"  - `{c['path']}` ({c['kind']}) {' '.join(tags)}")
        add("")

    # 规模
    sc = rep["scale"]
    add("## 5. 六万节点规模核验")
    add("")
    add(f"结论：{_badge(sc['ok'])}（耗时 {sc['elapsed_seconds']}s）")
    add("")
    n = sc["numbers"]
    add("| 指标 | 数值 |")
    add("|---|---:|")
    add(f"| 全树节点 | {n['total_nodes']} |")
    add(f"| 朴素全树遍历会访问 | {n['naive_full_tree_access']} |")
    add(f"| 隔离 anchor 子树总节点 | {n['anchor_subtree_size']} |")
    add(f"| 断开继承裁剪掉的后代 | {n['block_pruned_descendants']} |")
    add(f"| **单租户回退实际访问唯一节点** | **{n['unique_nodes_accessed']}** |")
    add(f"| 计量 get 调用次数 | {n['read_calls']} |")
    add(f"| 独立作用域参考数 | {n['reference_visited']} |")
    add(f"| 规则适用/盖戳节点 | {n['rule_applied_nodes']} |")
    add(f"| 版本戳实际变更节点 | {n['revision_changed_nodes']} |")
    add("")
    add("### 分区哈希（SHA-256 规范摘要）")
    add("")
    add("| 分区 | 回退前 | 回退后 | 一致 |")
    add("|---|---|---|---|")
    for p in ["P-A", "P-B", "P-C", "P-D"]:
        same = sc["partition_hashes_before"][p] == sc["partition_hashes_after"][p]
        add(f"| {p} | `{sc['partition_hashes_before'][p][:16]}…` | "
            f"`{sc['partition_hashes_after'][p][:16]}…` | {'✅' if same else '🔄 changed'} |")
    add("")
    add(f"- 未改分区：{sc['unchanged_partitions']}；变化分区：{sc['changed_partitions']}")
    add("")
    add("### 全量结果对账")
    add("")
    add(f"- 全量 CSV：`{sc['full_csv']}`")
    add(f"- 判定分类计数：`{json.dumps(sc['full_result_counts'], ensure_ascii=False)}`")
    add("")
    add("| 分区 | ALLOW | DENY | IMPLICIT_DENY |")
    add("|---|---:|---:|---:|")
    for p, pc in sc["partition_verdict_counts"].items():
        add(f"| {p} | {pc.get('ALLOW',0)} | {pc.get('DENY',0)} | {pc.get('IMPLICIT_DENY',0)} |")
    add("")

    # 全部断言清单
    add("## 6. 全部机器断言")
    add("")
    for group_name, checks in rep["all_check_groups"]:
        add(f"### {group_name}")
        for c in checks:
            detail = c.get("detail", "")
            add(f"- {_badge(c['pass'])} {c['name']}" + (f"  _( {detail} )_" if detail else ""))
        add("")

    add("## 7. 复跑方式")
    add("")
    add("```bash")
    add("python solve.py                 # 重新合成 + 全量复核 + 生成 reports/")
    add("python -m unittest discover -s tests -v")
    add("```")
    add("")
    return "\n".join(L)


def write_outputs(rep: dict, reports_dir: Path) -> tuple[Path, Path]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    jpath = reports_dir / "report.json"
    mpath = reports_dir / "REPORT.md"
    jpath.write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    mpath.write_text(render_markdown(rep), encoding="utf-8")
    return jpath, mpath
