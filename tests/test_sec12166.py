"""sec12166 离线复核的可复跑单元/集成测试（仅标准库 unittest）。

运行：
    python -m unittest discover -s tests -v
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sec12166.authz import (  # noqa: E402
    ALLOW,
    DENY,
    IMPLICIT_DENY,
    PrincipalIndex,
    effective_aces,
    evaluate_access,
    evaluate_mounted_path,
    rule_scope_ids,
)
from sec12166.countersign import (  # noqa: E402
    approve,
    build_happy_ticket,
    verify_ticket,
)
from sec12166.durable import (  # noqa: E402
    AlreadyCommitted,
    DurableTicketStore,
    PolicyApplier,
    ReceiptLost,
    RevocationFence,
)
from sec12166.model import subtree_digest  # noqa: E402
from sec12166.synthetic import (  # noqa: E402
    ALICE,
    BOB,
    POLICY_NEW,
    POLICY_OLD,
    build_authz_rules,
    build_policies,
    build_scale_repo,
    build_small_repo,
)


class SmallTreeAuthzTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = build_authz_rules()
        cls.pidx = PrincipalIndex(cls.rules["group_members"])
        cls.old = build_small_repo(POLICY_OLD)
        cls.new = build_small_repo(POLICY_NEW)

    def test_inherited_allow_rollback_state(self):
        # 旧版缺少 Sealed 子树拒绝：普通用户沿继承允许在 Sealed/Dropbox 放行
        for nid in (101, 102, 103, 104):
            d = evaluate_access(self.old, nid, ALICE, "READ", self.pidx)
            self.assertEqual(d.verdict, ALLOW, nid)
            self.assertTrue(d.allow_ace.inherited)
            self.assertEqual(d.allow_ace.origin, 100)

    def test_subtree_deny_overrides_inherited_allow(self):
        # HR 的子树拒绝两版都在：bob 同时在 Users/Contractors，拒绝压过继承允许
        for repo in (self.old, self.new):
            for nid in (105, 106, 107, 108):
                d = evaluate_access(repo, nid, BOB, "READ", self.pidx)
                self.assertEqual(d.verdict, DENY, nid)
                self.assertIsNotNone(d.deny_ace)
                self.assertIsNotNone(d.allow_ace)  # 确有可竞争的继承允许

    def test_restore_sealed_deny(self):
        for nid in (101, 102, 103, 104):
            d = evaluate_access(self.new, nid, ALICE, "READ", self.pidx)
            self.assertEqual(d.verdict, DENY, nid)

    def test_blocked_inheritance_vault(self):
        # 新版 Vault 断开继承：祖先的允许与拒绝都不流入，alice 隐式拒绝
        for nid in (109, 110):
            d = evaluate_access(self.new, nid, ALICE, "READ", self.pidx)
            self.assertEqual(d.verdict, IMPLICIT_DENY, nid)
        # 旧版未断开：继承允许流入
        self.assertEqual(evaluate_access(self.old, 110, ALICE, "READ", self.pidx).verdict, ALLOW)

    def test_mount_self_deny_but_alias_allow(self):
        self.assertEqual(
            evaluate_access(self.new, 111, ALICE, "READ", self.pidx).verdict, DENY
        )
        d = evaluate_mounted_path(self.new, 111, ["readme.txt"], ALICE, "READ", self.pidx)
        self.assertEqual(d.verdict, ALLOW)
        self.assertTrue(d.via_mount)
        self.assertEqual(d.mount_hops[0], (111, 201))

    def test_effective_aces_do_not_leak_noninheritable_ancestor_ace(self):
        # 有效列表只能包含目标显式 ACE + 映射到目标的继承 ACE（不能混入祖先自身 ACE）
        _, aces = effective_aces(self.new, 103)
        for a in aces:
            if not a.inherited:
                # 目标 103 无显式 ACE，因此所有有效 ACE 都必须是继承的
                self.fail(f"unexpected explicit ancestor ace in target DACL: {a.ace_id}")


class CountersignTests(unittest.TestCase):
    def setUp(self):
        self.rules = build_authz_rules()
        self.ctrls = self.rules["dual_control"]["controllers"]
        self.digest = subtree_digest(build_small_repo(POLICY_NEW), 101)
        self.kw = dict(
            ticket_id="T1", old_version=POLICY_OLD, new_version=POLICY_NEW,
            tenant=build_policies()["tenant"], isolation_digest=self.digest,
            submitter="svc-submitter",
        )

    def test_happy_path_independent_controllers(self):
        t = build_happy_ticket(self.ctrls, **self.kw)
        v = verify_ticket(t, self.rules, expected_old_version=POLICY_OLD,
                          expected_new_version=POLICY_NEW,
                          expected_tenant=self.kw["tenant"],
                          expected_isolation_digest=self.digest,
                          expected_submitter="svc-submitter")
        self.assertTrue(v.ok, v.errors)

    def test_tampered_binding_rejected(self):
        t = build_happy_ticket(self.ctrls, **self.kw)
        t.tenant = "t-evil"
        v = verify_ticket(t, self.rules, expected_tenant=self.kw["tenant"])
        self.assertFalse(v.ok)

    def test_same_person_twice_rejected(self):
        t = build_happy_ticket(self.ctrls, **self.kw)
        z = self.ctrls[0]
        t.approvals = [approve(z, t.core()), approve(z, t.core())]
        self.assertFalse(verify_ticket(t, self.rules).ok)

    def test_wrong_live_digest_rejected(self):
        t = build_happy_ticket(self.ctrls, **{**self.kw, "isolation_digest": "a" * 64})
        v = verify_ticket(t, self.rules, expected_isolation_digest=self.digest)
        self.assertFalse(v.ok)


class DurableConcurrencyTests(unittest.TestCase):
    def setUp(self):
        # 用 mkdtemp + 容错 rmtree，避免 Windows Defender 短暂占用导致清理误报
        self.d = Path(tempfile.mkdtemp(prefix="sec12166-"))
        self.new_v = POLICY_NEW
        self.old_v = POLICY_OLD
        self.ticket = {"ticket_id": "T-conc"}

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def _store(self):
        applier = PolicyApplier(self.d, initial_version=self.new_v)
        return DurableTicketStore(self.d, applier), applier

    def test_revocation_first_fences_rollback(self):
        store, applier = self._store()
        store.persist_revocation("T-conc", "qian", "stop")
        with self.assertRaises(RevocationFence):
            store.commit_rollback(ticket=self.ticket, idem_key="k",
                                  expected_current=self.new_v, target_version=self.old_v)
        self.assertEqual(applier.effect_lines_on_disk(), 0)
        self.assertEqual(applier.current, self.new_v)

    def test_receipt_lost_then_retry_and_reopen_exactly_once(self):
        store, applier = self._store()
        with self.assertRaises(ReceiptLost):
            store.commit_rollback(ticket=self.ticket, idem_key="k2",
                                  expected_current=self.new_v, target_version=self.old_v,
                                  lose_receipt=True)
        self.assertEqual(applier.effect_lines_on_disk(), 1)

        # 迟到撤回必须失败
        with self.assertRaises(AlreadyCommitted):
            store.persist_revocation("T-conc", "zhao", "late")

        r1 = store.commit_rollback(ticket=self.ticket, idem_key="k2",
                                   expected_current=self.new_v, target_version=self.old_v)
        self.assertTrue(r1.replayed)
        self.assertEqual(applier.apply_count, 1)

        # 模拟重启：重放 WAL
        applier2 = PolicyApplier(self.d, initial_version=self.new_v)
        store2 = DurableTicketStore(self.d, applier2)
        r2 = store2.commit_rollback(ticket=self.ticket, idem_key="k2",
                                    expected_current=self.new_v, target_version=self.old_v)
        self.assertTrue(r2.replayed)
        self.assertEqual(r2.receipt_id, r1.receipt_id)
        self.assertEqual(applier2.apply_count, 0)
        self.assertEqual(applier.effect_lines_on_disk(), 1)
        self.assertEqual(applier2.current, self.old_v)


class ScaleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo, cls.anchor, cls.mount = build_scale_repo()

    def test_exact_sixty_thousand(self):
        self.assertEqual(len(self.repo), 60000)

    def test_scope_counts(self):
        visited, applied = rule_scope_ids(self.repo, self.anchor)
        self.assertEqual(len(visited), 44905)
        self.assertEqual(len(applied), 44904)

    def test_scope_does_not_cross_mount_or_block_descendants(self):
        visited, _ = rule_scope_ids(self.repo, self.anchor)
        ids = set(visited)
        target = self.repo.raw(self.mount).mount_target
        self.assertIn(self.mount, ids)
        self.assertNotIn(target, ids)
        block_mid = next(n for n in visited
                         if n != self.anchor and self.repo.raw(n).block_inheritance)
        self.assertIn(block_mid, ids)
        block_children = self.repo.child_ids(block_mid)
        self.assertTrue(block_children)
        for cid in block_children:
            self.assertNotIn(cid, ids)


class EndToEndRunChecks(unittest.TestCase):
    def test_run_checks_all_green_in_temp_workspace(self):
        from sec12166.checks import run_checks
        td = tempfile.mkdtemp(prefix="sec12166-e2e-")
        try:
            rep = run_checks(Path(td))
            failed = [c["name"] for g in rep["all_check_groups"] for c in g[1] if not c["pass"]]
            self.assertTrue(rep["overall_ok"], msg="; ".join(failed))
            csv_path = Path(td) / "reports" / "full_access_results.csv"
            self.assertTrue(csv_path.exists())
            self.assertEqual(sum(1 for _ in csv_path.open(encoding="utf-8")) - 1, 60000)
            self.assertTrue((Path(td) / "reports" / "REPORT.md").exists())
        finally:
            shutil.rmtree(td, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
