"""六万节点规模核验。

核验三件事并全部给出可复核数字：
1. 单租户规则回退“实际访问的节点数”：用计量仓储统计真实 get 的唯一节点，
   与独立的 rule_scope_ids 集合、以及算术常量 44905/44904 三重对账；
   并证明零跨租户/零跨挂接目标读取。
2. 未改分区哈希：回退前后对 P-A/P-B/P-C/P-D 分别计算规范分区摘要，
   P-B/P-C/P-D 必须逐字节一致，P-A 必须变化。
3. 全量结果：对全部 60000 节点逐一做访问判定，写 CSV，并把分类计数对账到 60000。
"""
from __future__ import annotations

import csv
import time
from dataclasses import replace
from pathlib import Path

from .authz import PrincipalIndex, evaluate_access, rule_scope_ids
from .model import partition_digest
from .synthetic import (
    POLICY_NEW,
    SyntheticJail,
    load_scale_repo,
)


def run_scale_check(jail: SyntheticJail, policies: dict, rules: dict,
                    reports_dir: Path) -> dict:
    t0 = time.perf_counter()
    repo, anchor, mount = load_scale_repo(jail)
    const = policies["scale_constants"]
    versions = policies["versions"]
    old_v = next(v for v in versions if versions[v]["seq"] == 2)
    new_v = next(v for v in versions if versions[v]["seq"] == 3)

    pidx = PrincipalIndex(rules["group_members"])
    probe = rules["probe"]["principal"]
    right = rules["probe"]["right"]

    parts = ["P-A", "P-B", "P-C", "P-D"]
    hash_before = {p: partition_digest(repo, p) for p in parts}

    # 独立参考作用域（结构计算，不计量）
    visited_ref, apply_ref = rule_scope_ids(repo, anchor)

    # 回退前版本戳快照
    rev_before = {nid: n.applied_rev for nid, n in repo.nodes.items()}

    # ---- 执行“单租户规则回退”，全程计量实际节点读取 ----------------------
    anchor_node = repo.raw(anchor)
    rule_ace = next(a for a in anchor_node.dacl if a.ace_id == "anc-iso-rule")
    old_mask = versions[old_v]["anchor_deny_mask"]
    new_dacl = [replace(rule_ace, mask=old_mask) if a.ace_id == rule_ace.ace_id else a
                for a in anchor_node.dacl]

    meter_error = None
    with repo.meter() as meter:
        anchor_node.dacl = new_dacl
        stack = [anchor]
        seen: set[int] = set()
        while stack:
            nid = stack.pop()
            if nid in seen:
                continue
            seen.add(nid)
            n = repo.get(nid)  # 唯一受计量的数据面读取入口

            if nid != anchor and n.block_inheritance:
                continue  # 读到断开继承边界后整支裁剪

            if n.applied_rev != old_v:
                n.applied_rev = old_v

            if n.kind == "mount":
                continue  # 挂接边界：不跨入目标

            stack.extend(repo.child_ids(nid))

    rev_after = {nid: n.applied_rev for nid, n in repo.nodes.items()}
    rev_diff = sorted(nid for nid in repo.nodes if rev_before[nid] != rev_after[nid])

    hash_after = {p: partition_digest(repo, p) for p in parts}

    read_set = set(repo.read_ids)
    target_id = repo.raw(mount).mount_target
    out_of_scope_reads = sorted(
        nid for nid in read_set if repo.raw(nid).tenant != policies["tenant"]
        and repo.raw(nid).part != "P-A"
    )
    non_pa_reads = [nid for nid in read_set if repo.raw(nid).part != "P-A"]

    block_mid = next(nid for nid in visited_ref
                     if nid != anchor and repo.raw(nid).block_inheritance)

    # 回退后，规则适用集对 probe/READ 必须全部 ALLOW（旧掩码只拒 WRITE）
    apply_verdicts = {}
    for nid in apply_ref:
        d = evaluate_access(repo, nid, probe, right, pidx)
        apply_verdicts[d.verdict] = apply_verdicts.get(d.verdict, 0) + 1

    # ---- 全量 60000 节点访问判定 + 写 CSV --------------------------------
    reports_dir.mkdir(parents=True, exist_ok=True)
    csv_path = reports_dir / "full_access_results.csv"
    counts: dict[str, int] = {}
    part_counts: dict[str, dict[str, int]] = {}
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["nid", "part", "tenant", "kind", "depth_hint", "block",
                    "mount", "principal_sid", "right", "verdict", "basis",
                    "applied_rev", "path"])
        for nid in sorted(repo.nodes):
            n = repo.raw(nid)
            d = evaluate_access(repo, nid, probe, right, pidx)
            counts[d.verdict] = counts.get(d.verdict, 0) + 1
            pc = part_counts.setdefault(n.part, {})
            pc[d.verdict] = pc.get(d.verdict, 0) + 1
            w.writerow([nid, n.part, n.tenant or "", n.kind, "",
                        int(n.block_inheritance), n.mount_target or "",
                        probe, right, d.verdict, d.basis(),
                        n.applied_rev or "", n.path])

    total_results = sum(counts.values())
    elapsed = time.perf_counter() - t0

    checks = [
        ("规模树恰为 60000 节点", len(repo) == const["total_nodes"] == 60000,
         f"nodes={len(repo)}"),
        ("实际读取唯一节点数=44905", meter.unique_nodes == const["rollback_nodes_accessed"] == 44905,
         f"unique={meter.unique_nodes} calls={meter.read_calls}"),
        ("读取调用次数=唯一节点数(每节点仅读一次)", meter.read_calls == meter.unique_nodes,
         f"calls={meter.read_calls} unique={meter.unique_nodes}"),
        ("计量读取集合==独立作用域集合", read_set == set(visited_ref),
         f"meter={len(read_set)} ref={len(visited_ref)}"),
        ("规则适用集合=44904", len(apply_ref) == const["rollback_nodes_applied_or_mutated"] == 44904,
         f"apply={len(apply_ref)}"),
        ("版本戳实际变更节点恰为 44904 且==适用集",
         len(rev_diff) == 44904 and set(rev_diff) == set(apply_ref),
         f"rev_diff={len(rev_diff)}"),
        ("断开继承边界节点被读但未改、后代未读",
         block_mid in read_set and block_mid not in set(rev_diff)
         and not any(repo.raw(x).parent == block_mid for x in read_set),
         f"block_mid={block_mid}"),
        ("挂接点被读/被改但目标分区节点未被读",
         mount in read_set and mount in set(rev_diff) and target_id not in read_set,
         f"mount={mount} target={target_id}"),
        ("零非 P-A 分区读取(不跨租户/分区)", not non_pa_reads, f"non_pa={non_pa_reads[:5]}"),
        ("无跨出租户的读取", not out_of_scope_reads, f"oob={out_of_scope_reads[:5]}"),
        ("P-A 摘要在回退后变化", hash_before["P-A"] != hash_after["P-A"], ""),
        ("P-B 摘要不变(其它租户)", hash_before["P-B"] == hash_after["P-B"], hash_after["P-B"]),
        ("P-C 摘要不变(挂接目标/数据分区)", hash_before["P-C"] == hash_after["P-C"], hash_after["P-C"]),
        ("P-D 摘要不变(未改分区)", hash_before["P-D"] == hash_after["P-D"], hash_after["P-D"]),
        ("全量结果行数=60000 且分类对账", total_results == 60000 and sum(counts.values()) == len(repo),
         f"rows={total_results} counts={counts}"),
        ("规则适用集回退后 READ 全放行(旧掩码只拒 WRITE)",
         apply_verdicts.get("ALLOW", 0) == len(apply_ref) and len(apply_verdicts) == 1,
         str(apply_verdicts)),
        ("全量判定三类结论均出现",
         all(k in counts for k in ("ALLOW", "DENY", "IMPLICIT_DENY")), str(counts)),
    ]

    return {
        "name": "六万节点单租户回退规模核验",
        "ok": all(c[1] for c in checks),
        "elapsed_seconds": round(elapsed, 3),
        "numbers": {
            "total_nodes": len(repo),
            "read_calls": meter.read_calls,
            "unique_nodes_accessed": meter.unique_nodes,
            "reference_visited": len(visited_ref),
            "rule_applied_nodes": len(apply_ref),
            "revision_changed_nodes": len(rev_diff),
            "naive_full_tree_access": 60000,
            "anchor_subtree_size": const["anchor_subtree_nodes"],
            "block_pruned_descendants": const["block_pruned_descendants"],
        },
        "partition_hashes_before": hash_before,
        "partition_hashes_after": hash_after,
        "unchanged_partitions": [p for p in parts if hash_before[p] == hash_after[p]],
        "changed_partitions": [p for p in parts if hash_before[p] != hash_after[p]],
        "full_result_counts": counts,
        "partition_verdict_counts": part_counts,
        "apply_set_verdicts_after_rollback": apply_verdicts,
        "full_csv": str(csv_path.relative_to(csv_path.parents[1])) if csv_path.is_relative_to(csv_path.parents[1]) else str(csv_path),
        "checks": [{"name": n, "pass": okk, "detail": str(d)} for n, okk, d in checks],
    }
