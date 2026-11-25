"""总复核编排：一键跑完全部题面要点并产出 reports/。"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

from .concurrency import scenario_receipt_lost, scenario_revoke_first, stress_parallel
from .countersign import (
    build_happy_ticket,
    verify_ticket,
)
from .difftree import build_diff_report
from .model import digest_obj, subtree_digest
from .reporting import write_outputs
from .scalecheck import run_scale_check
from .synthetic import (
    DEFAULT_SYNTHETIC_DIR,
    POLICY_NEW,
    POLICY_OLD,
    SyntheticJail,
    build_authz_rules,
    build_policies,
    materialize,
)

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def run_jail_self_test(jail: SyntheticJail) -> list[dict]:
    checks = []

    def case(name, fn, should_raise: bool):
        try:
            fn()
            raised = None
        except Exception as exc:  # noqa: BLE001
            raised = type(exc).__name__
        ok = (raised is not None) if should_raise else (raised is None)
        detail = raised or "ok"
        checks.append({"name": name, "pass": ok, "detail": detail})

    case("可经监牢读取 authz_rules.json", lambda: jail.read_json("authz_rules.json"), False)
    case("可经监牢读取 policies.json", lambda: jail.read_json("policies.json"), False)
    case("拒绝绝对盘符路径 C:/Windows/...",
         lambda: jail.read_text("C:/Windows/System32/config/SAM"), True)
    case("拒绝 ../../ 路径穿越",
         lambda: jail.read_text("../../../../Windows/win.ini"), True)
    case("拒绝反斜杠穿越 ..\\..\\",
         lambda: jail.read_text("..\\..\\secret.txt"), True)
    return checks


def run_countersign_checks(jail: SyntheticJail, rules: dict, policies: dict) -> dict:
    controllers = rules["dual_control"]["controllers"]
    old_v, new_v = POLICY_OLD, POLICY_NEW

    # 隔离目录摘要：从落盘的合成 small_tree(v3) 重算，挂接点不跨目标
    from .synthetic import load_small_repo
    new_repo = load_small_repo(jail, POLICY_NEW)
    isolation_digest = subtree_digest(new_repo, 101, skip_mount_targets=True)

    submitter = "svc-drill-orchestrator"
    ticket = build_happy_ticket(
        controllers,
        ticket_id="CS-20261126-0001",
        old_version=old_v,
        new_version=new_v,
        tenant=policies["tenant"],
        isolation_digest=isolation_digest,
        submitter=submitter,
        old_policy_digest=digest_obj(policies["versions"][old_v]),
        new_policy_digest=digest_obj(policies["versions"][new_v]),
    )

    happy = verify_ticket(
        ticket, rules,
        expected_old_version=old_v, expected_new_version=new_v,
        expected_tenant=policies["tenant"],
        expected_isolation_digest=isolation_digest,
        expected_submitter=submitter,
    )

    negatives = []

    # 1) 篡改租户
    t1 = copy.deepcopy(ticket)
    t1.tenant = "t-attacker"
    v1 = verify_ticket(t1, rules, expected_tenant=policies["tenant"])
    negatives.append({"case": "篡改目标租户", "accepted": v1.ok, "errors": v1.errors})

    # 2) 篡改隔离目录摘要
    t2 = copy.deepcopy(ticket)
    t2.isolation_digest = "0" * 64
    v2 = verify_ticket(t2, rules, expected_isolation_digest=isolation_digest)
    negatives.append({"case": "篡改隔离目录摘要", "accepted": v2.ok, "errors": v2.errors})

    # 3) 同一实际控制人会签两次
    from .countersign import approve
    t3 = copy.deepcopy(ticket)
    zhao = controllers[0]
    t3.approvals = [approve(zhao, t3.core()), approve(zhao, t3.core())]
    v3 = verify_ticket(t3, rules)
    negatives.append({"case": "同一人重复会签（不独立）", "accepted": v3.ok, "errors": v3.errors})

    # 4) 两名控制人共享同一密钥
    rules_shared = copy.deepcopy(rules)
    rules_shared["dual_control"]["controllers"][1]["key_seed"] = \
        rules_shared["dual_control"]["controllers"][0]["key_seed"]
    qian_shared = rules_shared["dual_control"]["controllers"][1]
    t4 = copy.deepcopy(ticket)
    t4.approvals = [approve(controllers[0], t4.core()), approve(qian_shared, t4.core())]
    v4 = verify_ticket(t4, rules_shared)
    negatives.append({"case": "两名控制人共享密钥（不独立）", "accepted": v4.ok, "errors": v4.errors})

    # 5) 合法签名但绑定到错误的现场摘要（票-现场不符）
    t5 = build_happy_ticket(
        controllers, ticket_id="CS-other-digest", old_version=old_v, new_version=new_v,
        tenant=policies["tenant"], isolation_digest="a" * 64, submitter=submitter,
    )
    v5 = verify_ticket(t5, rules, expected_isolation_digest=isolation_digest)
    negatives.append({"case": "票据摘要与现场重算不符", "accepted": v5.ok, "errors": v5.errors})

    # 6) 提交人兼任控制人
    rules_sub = copy.deepcopy(rules)
    t6 = copy.deepcopy(ticket)
    t6.submitter = controllers[0]["cid"]
    v6 = verify_ticket(t6, rules_sub, expected_submitter=controllers[0]["cid"])
    negatives.append({"case": "提交人兼任实际控制人", "accepted": v6.ok, "errors": v6.errors})

    neg_all_rejected = all(not n["accepted"] for n in negatives)
    independence_ok = (
        any("自然人不同" in c for c in happy.passed_checks)
        and any("密钥独立" in c for c in happy.passed_checks)
        and not v3.ok and not v4.ok
    )
    ok = happy.ok and neg_all_rejected and independence_ok

    happy_checks = [{"name": c, "pass": True, "detail": ""} for c in happy.passed_checks]
    happy_checks += [{"name": "正向会签整体通过", "pass": happy.ok,
                      "detail": "; ".join(happy.errors)}]
    happy_checks += [{"name": "全部 6 个负向用例均被拒", "pass": neg_all_rejected,
                      "detail": f"rejected={sum(not n['accepted'] for n in negatives)}/6"}]

    return {
        "ok": ok,
        "isolation_digest": isolation_digest,
        "binding": {
            "ticket_id": ticket.ticket_id,
            "old_version": ticket.old_version,
            "new_version": ticket.new_version,
            "tenant": ticket.tenant,
            "isolation_digest": ticket.isolation_digest,
            "old_policy_digest": ticket.old_policy_digest,
            "new_policy_digest": ticket.new_policy_digest,
            "submitter": ticket.submitter,
            "approvals": [
                {"cid": a["cid"], "person_id": a["person_id"],
                 "control_group": a["control_group"], "mac_prefix": a["mac"][:16] + "…"}
                for a in ticket.approvals
            ],
        },
        "ticket_dict": ticket.to_dict(),
        "happy_verification": {
            "ok": happy.ok,
            "passed_checks": happy.passed_checks,
            "errors": happy.errors,
        },
        "negative_cases": negatives,
        "independence_ok": independence_ok,
        "checks": happy_checks,
    }


def run_diff_checks(jail: SyntheticJail, rules: dict) -> dict:
    from .authz import PrincipalIndex
    from .synthetic import load_small_repo
    old_repo = load_small_repo(jail, POLICY_OLD)
    new_repo = load_small_repo(jail, POLICY_NEW)
    pidx = PrincipalIndex(rules["group_members"])
    probe = rules["probe"]["principal"]
    deny_probe = rules["probe"]["deny_probe_principal"]
    right = rules["probe"]["right"]

    rep = build_diff_report(
        old_repo, new_repo, pidx,
        principal=probe, deny_principal=deny_probe, right=right,
    )
    exp = rep["expectations"]
    w = rep["witnesses"]
    checks = [
        {"name": "差异区间数=2（缺失子树拒绝段 + 断开继承/挂接点段）",
         "pass": exp["interval_count"] == 2, "detail": f"count={exp['interval_count']}"},
        {"name": "两区间长度=[4,3]", "pass": exp["interval_sizes"] == [4, 3],
         "detail": str(exp["interval_sizes"])},
        {"name": "隔离目录 11 节点中 7 个结论变化",
         "pass": rep["changed_verdict_nodes"] == 7 and rep["total_nodes"] == 11,
         "detail": f"changed={rep['changed_verdict_nodes']}/{rep['total_nodes']}"},
        {"name": "存在最短 ALLOW 见证（回退态）",
         "pass": "shortest_allow_rolled_back" in w
         and w["shortest_allow_rolled_back"]["verdict"] == "ALLOW", "detail": ""},
        {"name": "存在最短 ALLOW 文件见证",
         "pass": "shortest_allow_file_rolled_back" in w, "detail": ""},
        {"name": "存在最短 DENY 子树见证（子树拒绝压过继承允许）",
         "pass": "shortest_deny_subtree" in w
         and w["shortest_deny_subtree"]["verdict"] == "DENY"
         and w["shortest_deny_subtree"]["decisive_deny"] is not None, "detail": ""},
        {"name": "挂接别名路径为 ALLOW（封闭区经 reparse 绕出）",
         "pass": exp["mount_alias_is_allow"], "detail": ""},
        {"name": "挂接点自身在恢复后为 DENY",
         "pass": exp["mount_point_self_is_deny"], "detail": ""},
        {"name": "断开继承节点恢复后非 ALLOW",
         "pass": exp["block_case_is_non_allow"], "detail": ""},
    ]
    return {
        "ok": all(c["pass"] for c in checks),
        "checks": checks,
        "assertions_ok": all(c["pass"] for c in checks),
        "summary": {
            "total_nodes": rep["total_nodes"],
            "changed_verdict_nodes": rep["changed_verdict_nodes"],
            "closed_by_restore_nodes": rep["closed_by_restore_nodes"],
            "unchanged_nodes": rep["unchanged_nodes"],
        },
        "report": rep,
    }


def run_checks(workspace_root: Path | None = None) -> dict:
    root = Path(workspace_root) if workspace_root else WORKSPACE_ROOT
    synth_dir = root / "synthetic"
    reports_dir = root / "reports"
    artifacts_dir = root / "artifacts" / "concurrency"

    # 1) 确定性重新合成（保证报告数字与当前代码一致），再只通过监牢读回
    materialize(synth_dir)
    jail = SyntheticJail(synth_dir)
    rules = jail.read_json("authz_rules.json")
    policies = jail.read_json("policies.json")

    jail_checks = run_jail_self_test(jail)
    jail_ok = all(c["pass"] for c in jail_checks)

    # 2) 会签 + 双人独立
    cs = run_countersign_checks(jail, rules, policies)

    # 3) 并发屏障复测（使用真实落盘 WAL）
    ticket_dict = cs["ticket_dict"]
    s_a = scenario_revoke_first(artifacts_dir, ticket_dict, policies)
    s_b = scenario_receipt_lost(artifacts_dir, ticket_dict, policies)
    stress = stress_parallel(artifacts_dir, lambda i: {"ticket_id": f"STRESS-{i:04d}"},
                             policies, trials=32)
    concurrency_ok = s_a["ok"] and s_b["ok"] and stress["ok"]
    concurrency = {"ok": concurrency_ok, "scenarios": [s_a, s_b], "stress": stress}

    # 4) 小树差异区间 + 见证
    diff_tree = run_diff_checks(jail, rules)

    # 5) 60000 节点规模
    scale = run_scale_check(jail, policies, rules, reports_dir)

    # ---- 题面要求矩阵 ----------------------------------------------------
    matrix = [
        {"requirement": "Python 3.12 标准库、离线、仅读合成路径/策略/授权代规则",
         "evidence": "SyntheticJail 限定 synthetic/，绝对路径与穿越自检", "ok": jail_ok},
        {"requirement": "会签回退绑定旧版/新版/目标租户/隔离目录摘要",
         "evidence": "HMAC 绑定 core，改任一字段验签失败", "ok": cs["ok"]},
        {"requirement": "两名实际控制人必须独立",
         "evidence": "cid/person/控制组/密钥 + 同人同密钥负例", "ok": cs["independence_ok"]},
        {"requirement": "考虑继承允许",
         "evidence": "OI/CI 传播；见证中 origin 为祖先的 allow", "ok": diff_tree["ok"]},
        {"requirement": "考虑子树拒绝（拒绝优先）",
         "evidence": "HR 最短 DENY 见证 + 两版不变拒绝岛", "ok": diff_tree["ok"]},
        {"requirement": "考虑挂接点",
         "evidence": "挂接点自身 DENY 与穿 reparse 别名 ALLOW 同时给出", "ok": diff_tree["ok"]},
        {"requirement": "考虑断开继承",
         "evidence": "Vault block 后祖先 ACE 丢弃，恢复为 IMPLICIT_DENY", "ok": diff_tree["ok"]},
        {"requirement": "两线程并行回退/撤回 + 屏障复测两情形",
         "evidence": "撤销先持久化 / 承诺成功回执丢失 / 32 轮竞态", "ok": concurrency_ok},
        {"requirement": "独立小树枚举恢复前后差异区间 + 最短可复核路径",
         "evidence": "2 个 DFS 区间 [4,3] + ALLOW/DENY/mount/block 见证", "ok": diff_tree["ok"]},
        {"requirement": "六万节点核验单租户回退实际访问节点数",
         "evidence": "计量 44905 读 / 44904 改，三重对账", "ok": scale["ok"]},
        {"requirement": "核验未改分区哈希",
         "evidence": "P-B/P-C/P-D 前后摘要一致，P-A 变化",
         "ok": all(p in scale["unchanged_partitions"] for p in ("P-B", "P-C", "P-D"))},
        {"requirement": "核验并留存全量结果",
         "evidence": "full_access_results.csv 60000 行 + 分类对账",
         "ok": scale["full_result_counts"] and sum(scale["full_result_counts"].values()) == 60000},
    ]

    all_groups = [
        ("合成监牢：仅读合成输入", jail_checks),
        ("会签绑定与双人独立", cs["checks"]),
        (s_a["name"], s_a["checks"]),
        (s_b["name"], s_b["checks"]),
        ("小树差异/见证断言", diff_tree["checks"]),
        ("六万节点规模断言", scale["checks"]),
    ]
    overall_ok = all(r["ok"] for r in matrix) and all(g[1] and all(c["pass"] for c in g[1]) for g in all_groups)

    rep = {
        "schema": "sec12166.report/v1",
        "python": sys.version.split()[0],
        "overall_ok": overall_ok,
        "requirement_matrix": matrix,
        "jail_checks": jail_checks,
        "countersign": {k: v for k, v in cs.items() if k != "checks"},
        "concurrency": concurrency,
        "diff_tree": diff_tree,
        "scale": scale,
        "all_check_groups": all_groups,
    }
    reports_dir.mkdir(parents=True, exist_ok=True)
    rep["report_json"] = str(reports_dir / "report.json")
    rep["report_md"] = str(reports_dir / "REPORT.md")
    jpath, mpath = write_outputs(rep, reports_dir)
    return rep
