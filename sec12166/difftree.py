"""独立小树：枚举恢复前后的差异区间，给出最短可复核放行/拒绝路径。

“恢复前”= 回退到旧版 v2（宽松，出现允许项）；“恢复后”= 重新应用加固新版 v3。
按 DFS 先序给隔离目录节点编号，整棵子树在先序里天然连续，因此把“结论发生
变化”的相邻编号压缩成差异区间。每个区间都能对应到具体机制：
  区间一：Sealed 子树拒绝在旧版缺失 -> 继承允许直接放行；
  中段岛：HR 子树拒绝两版都在 -> 结论不变（证明不能只看继承允许）；
  区间二：Vault 断开继承被回退掉 -> 继承允许流入；以及 Bridge 挂接点自身被新增拒绝。
"""
from __future__ import annotations

from dataclasses import asdict

from .authz import (
    ALLOW,
    DENY,
    IMPLICIT_DENY,
    Decision,
    PrincipalIndex,
    evaluate_access,
    evaluate_mounted_path,
)
from .model import Repo


def preorder(repo: Repo, root_id: int) -> list[int]:
    out: list[int] = []
    stack = [root_id]
    seen: set[int] = set()
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        out.append(nid)
        for cid in reversed(repo.child_ids(nid)):
            if cid not in seen:
                stack.append(cid)
    return out


def _ace_line(repo: Repo, ace) -> dict:
    d = ace.to_dict()
    if ace.origin is not None and ace.origin in repo.nodes:
        d["origin_path"] = repo.raw(ace.origin).path
    return d


def explain_decision(repo: Repo, d: Decision) -> dict:
    chain = []
    for nid in d.chain_ids:
        n = repo.raw(nid)
        chain.append({
            "nid": nid, "name": n.name, "kind": n.kind, "path": n.path,
            "block_inheritance": n.block_inheritance,
            "mount_target": n.mount_target,
            "explicit_aces": [a.to_dict() for a in n.dacl],
        })
    return {
        "verdict": d.verdict,
        "principal": d.principal,
        "right": d.right,
        "path": d.path,
        "via_mount": d.via_mount,
        "mount_hops": d.mount_hops,
        "note": d.note,
        "basis": d.basis(),
        "decisive_deny": _ace_line(repo, d.deny_ace) if d.deny_ace else None,
        "decisive_allow": _ace_line(repo, d.allow_ace) if d.allow_ace else None,
        "chain": chain,
    }


def _shortest(repo: Repo, root_id: int, principal: str, right: str,
              want: str, pidx: PrincipalIndex, *, files_only: bool = False
              ) -> tuple[int, Decision] | None:
    """BFS 找最浅的指定结论；返回 (距 root 深度, Decision)。"""
    queue: list[tuple[int, int]] = [(root_id, 0)]
    seen = {root_id}
    while queue:
        nid, depth = queue.pop(0)
        n = repo.raw(nid)
        d = evaluate_access(repo, nid, principal, right, pidx)
        if d.verdict == want and (not files_only or n.kind == "file"):
            return depth, d
        if n.kind != "mount":
            for cid in repo.child_ids(nid):
                if cid not in seen:
                    seen.add(cid)
                    queue.append((cid, depth + 1))
    return None


def build_diff_report(
    old_repo: Repo,
    new_repo: Repo,
    pidx: PrincipalIndex,
    *,
    principal: str,
    deny_principal: str,
    right: str = "READ",
    isolation_root: int = 101,
    mount_id: int = 111,
    mount_rel: list[str] | None = None,
) -> dict:
    mount_rel = mount_rel or ["readme.txt"]
    order = preorder(new_repo, isolation_root)

    rows = []
    changed_flags: list[bool] = []
    for idx, nid in enumerate(order):
        do = evaluate_access(old_repo, nid, principal, right, pidx)
        dn = evaluate_access(new_repo, nid, principal, right, pidx)
        changed = do.verdict != dn.verdict
        changed_flags.append(changed)
        n = new_repo.raw(nid)
        rows.append({
            "index": idx,
            "nid": nid,
            "name": n.name,
            "kind": n.kind,
            "path": n.path,
            "block_inheritance": n.block_inheritance,
            "old_verdict": do.verdict,
            "new_verdict": dn.verdict,
            "changed": changed,
            "closed_by_restore": do.verdict == ALLOW and dn.verdict != ALLOW,
            "old_basis": do.basis(),
            "new_basis": dn.basis(),
        })

    # 压缩连续 changed 索引为差异区间
    intervals: list[dict] = []
    i = 0
    while i < len(rows):
        if not rows[i]["changed"]:
            i += 1
            continue
        j = i
        while j + 1 < len(rows) and rows[j + 1]["changed"]:
            j += 1
        seg = rows[i:j + 1]
        intervals.append({
            "start_index": rows[i]["index"],
            "end_index": rows[j]["index"],
            "count": j - i + 1,
            "start_path": rows[i]["path"],
            "end_path": rows[j]["path"],
            "all_closed_by_restore": all(r["closed_by_restore"] for r in seg),
            "verdicts": [
                {"nid": r["nid"], "name": r["name"],
                 "old": r["old_verdict"], "new": r["new_verdict"],
                 "new_basis": r["new_basis"], "block": r["block_inheritance"]}
                for r in seg
            ],
        })
        i = j + 1

    changed_rows = [r for r in rows if r["changed"]]
    report = {
        "enumeration": "DFS-preorder over isolation root",
        "isolation_root_id": isolation_root,
        "total_nodes": len(rows),
        "changed_verdict_nodes": len(changed_rows),
        "closed_by_restore_nodes": sum(r["closed_by_restore"] for r in rows),
        "unchanged_nodes": len(rows) - len(changed_rows),
        "diff_intervals": intervals,
        "rows": rows,
    }

    # ---- 最短可复核见证路径 ---------------------------------------------
    witnesses: dict[str, dict] = {}

    allow_hit = _shortest(old_repo, isolation_root, principal, right, ALLOW, pidx)
    if allow_hit:
        depth, d = allow_hit
        witnesses["shortest_allow_rolled_back"] = {
            "depth_from_isolation_root": depth,
            **explain_decision(old_repo, d),
        }

    allow_file = _shortest(old_repo, isolation_root, principal, right, ALLOW, pidx,
                           files_only=True)
    if allow_file:
        depth, d = allow_file
        witnesses["shortest_allow_file_rolled_back"] = {
            "depth_from_isolation_root": depth,
            **explain_decision(old_repo, d),
        }

    deny_hit = _shortest(old_repo, isolation_root, deny_principal, right, DENY, pidx)
    if deny_hit:
        depth, d = deny_hit
        witnesses["shortest_deny_subtree"] = {
            "depth_from_isolation_root": depth,
            "probe_principal": deny_principal,
            **explain_decision(old_repo, d),
        }

    # 挂接点：挂接点自身在新版被拒，但穿过 reparse 到 P-OPEN 目标却放行
    mp_new = evaluate_access(new_repo, mount_id, principal, right, pidx)
    witnesses["mount_point_itself_restored"] = explain_decision(new_repo, mp_new)
    through = evaluate_mounted_path(new_repo, mount_id, mount_rel, principal, right, pidx)
    witnesses["allow_via_mount_alias_after_restore"] = explain_decision(new_repo, through)

    # 断开继承见证：新版 Vault/secret 对 alice 为隐式拒绝
    block_d = evaluate_access(new_repo, 110, principal, right, pidx)
    witnesses["blocked_inheritance_implicit_deny"] = explain_decision(new_repo, block_d)

    report["witnesses"] = witnesses

    # ---- 机器可核验的关键断言（也供 unittest 复用） ----------------------
    report["expectations"] = {
        "interval_count": len(intervals),
        "interval_sizes": [iv["count"] for iv in intervals],
        "mount_alias_is_allow": through.verdict == ALLOW,
        "mount_point_self_is_deny": mp_new.verdict == DENY,
        "block_case_is_non_allow": block_d.verdict != ALLOW,
    }
    return report
