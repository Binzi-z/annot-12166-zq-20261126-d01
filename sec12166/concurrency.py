"""双线程并行“回退 vs 撤回”，用 Barrier 做屏障复测。

包含：
1. 确定性 interleaving：撤销先持久化 -> 回退必须被围栏，零副作用。
2. 确定性 crash 模型：承诺成功但回执丢失 -> 幂等重试/重开恢复，副作用恰好一次；
   并行的撤回此时必须得到 AlreadyCommitted，不能悄悄撤掉已承诺提交。
3. 多轮无编排竞态压测：任意调度下终态必须满足 XOR 不变量。
"""
from __future__ import annotations

import shutil
import threading
import time
from pathlib import Path

from .durable import (
    AlreadyCommitted,
    DurableTicketStore,
    PolicyApplier,
    ReceiptLost,
    RevocationFence,
)


def _versions(policy: dict) -> tuple[str, str]:
    return policy["rollback_direction"].split(" -> ")


def scenario_revoke_first(base_dir: Path, ticket: dict, policy: dict) -> dict:
    d = base_dir / "revoke_first"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    new_v, old_v = _versions(policy)

    applier = PolicyApplier(d, initial_version=new_v)
    store = DurableTicketStore(d, applier)
    barrier = threading.Barrier(2)
    revoke_done = threading.Event()
    out: dict = {}
    errs: dict = {}

    def revoker():
        barrier.wait()
        try:
            out["revoke"] = store.persist_revocation(
                ticket["ticket_id"], revoker="ctrl-qian", reason="演练叫停：授权撤回"
            )
        except BaseException as exc:  # noqa: BLE001 - 跨线程收集
            errs["revoke"] = f"{type(exc).__name__}: {exc}"
        finally:
            revoke_done.set()

    def committer():
        barrier.wait()
        # 精确构造“撤销的持久化线性化点先于回退”这一 interleaving
        if not revoke_done.wait(timeout=10):
            errs["commit"] = "timed out waiting revoke_done"
            return
        try:
            store.commit_rollback(
                ticket=ticket, idem_key="idem-revoke-first",
                expected_current=new_v, target_version=old_v,
            )
            out["commit"] = "UNEXPECTED_OK"
        except RevocationFence as exc:
            out["commit"] = "FENCED"
            out["fence_message"] = str(exc)
        except BaseException as exc:  # noqa: BLE001
            errs["commit"] = f"{type(exc).__name__}: {exc}"

    t1 = threading.Thread(target=revoker, name="revoker", daemon=True)
    t2 = threading.Thread(target=committer, name="committer", daemon=True)
    t1.start(); t2.start()
    t1.join(15); t2.join(15)

    checks = [
        ("两线程均在屏障后完成", not t1.is_alive() and not t2.is_alive(), ""),
        ("撤回返回 persisted", out.get("revoke", {}).get("status") == "revocation-persisted", ""),
        ("回退被撤销围栏拒绝", out.get("commit") == "FENCED", out.get("commit", "")),
        ("无跨线程未预期异常", not errs, str(errs)),
        ("回退副作用为 0", applier.effect_lines_on_disk() == 0,
         f"effects={applier.effect_lines_on_disk()}"),
        ("策略版本仍为新版(未回退)", applier.current == new_v, applier.current),
        ("WAL 无 rollback-committed 事件", not store.committed_ticket, ""),
    ]
    ok = all(c[1] for c in checks)
    return {"name": "屏障复测A：撤销先持久化", "ok": ok,
            "checks": [{"name": n, "pass": p, "detail": x} for n, p, x in checks],
            "fence_message": out.get("fence_message"), "errors": errs}


def scenario_receipt_lost(base_dir: Path, ticket: dict, policy: dict) -> dict:
    d = base_dir / "receipt_lost"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    new_v, old_v = _versions(policy)
    idem = "idem-receipt-lost"

    applier = PolicyApplier(d, initial_version=new_v)
    store = DurableTicketStore(d, applier)
    barrier = threading.Barrier(2)
    commit_durable = threading.Event()
    out: dict = {}
    errs: dict = {}

    def committer():
        barrier.wait()
        try:
            store.commit_rollback(
                ticket=ticket, idem_key=idem,
                expected_current=new_v, target_version=old_v,
                stats={"nodes_applied": 44904}, lose_receipt=True,
            )
            errs["commit_first"] = "应当丢失回执却正常返回"
        except ReceiptLost as exc:
            out["first"] = "RECEIPT_LOST_AFTER_COMMIT"
            out["receipt_id"] = exc.receipt_id
        except BaseException as exc:  # noqa: BLE001
            errs["commit_first"] = f"{type(exc).__name__}: {exc}"
        finally:
            # 无论回执是否丢失，提交事件此刻已 fsync
            commit_durable.set()

    def revoker():
        barrier.wait()
        if not commit_durable.wait(timeout=10):
            errs["revoke"] = "timed out waiting commit_durable"
            return
        time.sleep(0.01)  # 确保提交线性化点已完成
        try:
            store.persist_revocation(ticket["ticket_id"], "ctrl-zhao", "迟到的撤回")
            out["late_revoke"] = "UNEXPECTED_OK"
        except AlreadyCommitted as exc:
            out["late_revoke"] = "ALREADY_COMMITTED"
            out["already_message"] = str(exc)
        except BaseException as exc:  # noqa: BLE001
            errs["revoke"] = f"{type(exc).__name__}: {exc}"

    tc = threading.Thread(target=committer, name="committer", daemon=True)
    tr = threading.Thread(target=revoker, name="late-revoker", daemon=True)
    tc.start(); tr.start()
    tc.join(15); tr.join(15)

    # 客户端用同一幂等键重试（同进程）
    retry = store.commit_rollback(
        ticket=ticket, idem_key=idem, expected_current=new_v, target_version=old_v
    )
    same_receipt = retry.receipt_id == out.get("receipt_id")

    # 模拟进程重启：新 applier + 新 store 重放 WAL，再重试
    applier2 = PolicyApplier(d, initial_version=new_v)  # initial 仅在文件缺失时使用
    store2 = DurableTicketStore(d, applier2)
    retry2 = store2.commit_rollback(
        ticket=ticket, idem_key=idem, expected_current=new_v, target_version=old_v
    )

    effects_on_disk = applier.effect_lines_on_disk()
    checks = [
        ("两线程完成且无卡死", not tc.is_alive() and not tr.is_alive(), ""),
        ("首次调用在持久化后回执丢失", out.get("first") == "RECEIPT_LOST_AFTER_COMMIT", ""),
        ("迟到撤回得到 AlreadyCommitted", out.get("late_revoke") == "ALREADY_COMMITTED",
         out.get("late_revoke", "")),
        ("同进程重试识别为 replayed", retry.replayed and retry.status == "committed-replayed",
         retry.status),
        ("重试返回同一 receipt_id", same_receipt, f"{retry.receipt_id} vs {out.get('receipt_id')}"),
        ("重开存储后 WAL 恢复已提交", retry2.replayed and retry2.receipt_id == out.get("receipt_id"),
         retry2.status),
        ("重启后的 applier 未再执行副作用", applier2.apply_count == 0, f"count={applier2.apply_count}"),
        ("副作用日志恰好 1 条", effects_on_disk == 1, f"lines={effects_on_disk}"),
        ("策略版本持久化为旧版", applier2.current == old_v, applier2.current),
        ("无未预期异常", not errs, str(errs)),
    ]
    ok = all(c[1] for c in checks)
    return {"name": "屏障复测B：承诺成功但回执丢失", "ok": ok,
            "checks": [{"name": n, "pass": p, "detail": str(x)} for n, p, x in checks],
            "receipt_id": out.get("receipt_id"), "errors": errs}


def stress_parallel(base_dir: Path, ticket_factory, policy: dict, trials: int = 32) -> dict:
    """无编排竞态压测。ticket_factory(i)->ticket dict（每 trial 独立票据）。"""
    root = base_dir / "stress"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    new_v, old_v = _versions(policy)
    outcomes = {"committed": 0, "revoked": 0}
    violations: list[str] = []

    for i in range(trials):
        d = root / f"t{i:03d}"
        d.mkdir()
        ticket = ticket_factory(i)
        applier = PolicyApplier(d, initial_version=new_v)
        store = DurableTicketStore(d, applier)
        barrier = threading.Barrier(2)
        result: dict = {}
        errs: list[str] = []

        def commit_job():
            barrier.wait()
            try:
                store.commit_rollback(
                    ticket=ticket, idem_key=f"idem-{i}",
                    expected_current=new_v, target_version=old_v,
                )
                result["c"] = "committed"
            except RevocationFence:
                result["c"] = "fenced"
            except BaseException as exc:  # noqa: BLE001
                errs.append(f"commit:{type(exc).__name__}:{exc}")

        def revoke_job():
            barrier.wait()
            try:
                store.persist_revocation(ticket["ticket_id"], "ctrl-zhao", "race")
                result["r"] = "revoked"
            except AlreadyCommitted:
                result["r"] = "too-late"
            except BaseException as exc:  # noqa: BLE001
                errs.append(f"revoke:{type(exc).__name__}:{exc}")

        tc = threading.Thread(target=commit_job, daemon=True)
        tr = threading.Thread(target=revoke_job, daemon=True)
        tc.start(); tr.start(); tc.join(15); tr.join(15)

        tid = ticket["ticket_id"]
        is_committed = tid in store.committed_ticket
        is_revoked = tid in store.revoked
        effects = applier.effect_lines_on_disk()

        # XOR 不变量：要么提交且恰好一次副作用，要么撤回且零副作用，绝不两者并存
        if is_committed and is_revoked:
            violations.append(f"trial {i}: committed AND revoked")
        if is_committed and effects != 1:
            violations.append(f"trial {i}: committed but effects={effects}")
        if is_revoked and (is_committed or effects != 0):
            violations.append(f"trial {i}: revoked but committed={is_committed} effects={effects}")
        if not is_committed and not is_revoked:
            violations.append(f"trial {i}: neither terminal state; errs={errs}")
        if errs:
            violations.append(f"trial {i}: unexpected errors {errs}")
        if tc.is_alive() or tr.is_alive():
            violations.append(f"trial {i}: thread hung")

        if is_committed:
            outcomes["committed"] += 1
        elif is_revoked:
            outcomes["revoked"] += 1

    ok = not violations
    return {
        "name": f"双线程竞态压测 x{trials}", "ok": ok, "trials": trials,
        "outcomes": outcomes, "violations": violations[:10],
        "both_orderings_observed": outcomes["committed"] > 0 and outcomes["revoked"] > 0,
    }
