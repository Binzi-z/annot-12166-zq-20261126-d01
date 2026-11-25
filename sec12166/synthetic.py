"""确定性合成输入：合成路径、策略版本、授权代规则。

安全约束（题面“仅读合成路径、策略及授权代规则”）：
- 所有安全数据都是本模块用固定种子/固定结构生成的合成物，绝不读取真实
  Windows 路径、真实 ACL、注册表或线上策略。
- 读取侧统一经过 SyntheticJail，任何绝对路径 / 盘符 / `..` 逃逸都会被拒绝，
  且 resolve 后必须仍位于 synthetic 根目录内。
"""
from __future__ import annotations

import json
from pathlib import Path

from .authz import rule_scope_ids
from .model import ACE, RIGHT_ALL, RIGHTS, Node, Repo, canonical_bytes, digest_obj

SEED = 20261126
TENANT = "t-7f3a"
POLICY_OLD = "iso-policy-2026.11.10-v2"   # 回退目标：较宽松旧版
POLICY_NEW = "iso-policy-2026.11.20-v3"   # 已会签当前/恢复基线：加固新版

# 合成主体 / 组 SID
USERS = "S-1-5-21-12166-513"
CONTRACTORS = "S-1-5-21-12166-514"
ISO_OPS = "S-1-5-21-12166-520"
ALICE = "S-1-5-21-12166-1101"
BOB = "S-1-5-21-12166-1102"
ISO_SVC = "S-1-5-21-12166-1200"
ZHAO = "S-1-5-21-12166-2001"
QIAN = "S-1-5-21-12166-2002"

READ = RIGHTS["READ"]
WRITE = RIGHTS["WRITE"]
EXEC = RIGHTS["EXEC"]

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SYNTHETIC_DIR = WORKSPACE_ROOT / "synthetic"


class SyntheticJail:
    """把所有“读合成输入”限制在 synthetic 根内。"""

    def __init__(self, root: str | Path = DEFAULT_SYNTHETIC_DIR):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, rel: str) -> Path:
        if not isinstance(rel, str) or not rel:
            raise ValueError("相对路径不能为空")
        # 先做与宿主平台无关的规范化检查（同时识别 / 与 \ 、盘符、UNC）
        norm = rel.replace("\\", "/")
        if norm.startswith("/") or norm.startswith("//"):
            raise PermissionError(f"拒绝绝对/UNC 路径: {rel!r}")
        if len(norm) >= 2 and norm[1] == ":":
            raise PermissionError(f"拒绝盘符路径: {rel!r}")
        if any(seg == ".." for seg in norm.split("/")):
            raise PermissionError(f"拒绝路径穿越: {rel!r}")
        p = Path(rel)
        if p.is_absolute() or getattr(p, "drive", ""):
            raise PermissionError(f"拒绝绝对/盘符路径: {rel!r}")
        full = (self.root / p).resolve()
        if not full.is_relative_to(self.root):
            raise PermissionError(f"解析后逃逸合成根: {rel!r} -> {full}")
        return full

    def read_text(self, rel: str) -> str:
        return self.resolve(rel).read_text(encoding="utf-8")

    def read_json(self, rel: str) -> dict:
        return json.loads(self.read_text(rel))

    def read_json_lines(self, rel: str):
        with self.resolve(rel).open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if line:
                    yield lineno, json.loads(line)

    def write_json(self, rel: str, obj) -> Path:
        path = self.resolve(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False),
            encoding="utf-8",
        )
        return path

    def write_json_lines(self, rel: str, rows: list[dict]) -> Path:
        path = self.resolve(rel)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
                fh.write("\n")
        return path


# ---------------------------------------------------------------------------
# 授权代规则（主体/组、判定优先级、遍历口径、双人独立控制规则）
# ---------------------------------------------------------------------------
def build_authz_rules() -> dict:
    return {
        "schema": "sec12166.authz-rules/v1",
        "seed": SEED,
        "decision_precedence": [
            "explicit-deny", "explicit-allow", "inherited-deny", "inherited-allow"
        ],
        "deny_overrides_allow": True,
        "implicit_when_no_ace": "DENY",
        "traverse_checking": "BYPASS_TRAVERSE_CHECKING",
        "mount_rule": (
            "枚举/回退把 mount 当边界，不跨入目标；沿逻辑路径穿过 mount 访问"
            "数据时，按 reparse 目标自身 DACL 判定（遍历特权默认绕过父目录检查）。"
        ),
        "block_inheritance_rule": "SP_DACL_PROTECTED：在该节点丢弃全部祖先 ACE，且不再下传。",
        "inheritance_flags": ["OI", "CI", "NP", "IO"],
        "group_members": {
            USERS: [ALICE, BOB],
            CONTRACTORS: [BOB],
            ISO_OPS: [ISO_SVC, ZHAO, QIAN],
        },
        "names": {
            USERS: "Syn-DomainUsers",
            CONTRACTORS: "Syn-Contractors",
            ISO_OPS: "Syn-IsolationOps",
            ALICE: "alice",
            BOB: "bob",
            ISO_SVC: "svc-isolation",
            ZHAO: "ctrl-zhao",
            QIAN: "ctrl-qian",
        },
        "probe": {"principal": ALICE, "deny_probe_principal": BOB, "right": "READ"},
        "dual_control": {
            "required_independent_actual_controllers": 2,
            "submitter_must_differ_from_controllers": True,
            "controllers": [
                {
                    "cid": "ctrl-zhao",
                    "sid": ZHAO,
                    "person_id": "PRSN-2001-Z",
                    "name": "实际控制人 赵",
                    "control_group": "board-a",
                    "key_seed": "sec12166/controller/zhao/v1",
                },
                {
                    "cid": "ctrl-qian",
                    "sid": QIAN,
                    "person_id": "PRSN-2002-Q",
                    "name": "实际控制人 钱",
                    "control_group": "board-b",
                    "key_seed": "sec12166/controller/qian/v1",
                },
            ],
            "independence_checks": [
                "distinct cid",
                "distinct person_id",
                "distinct control_group",
                "distinct derived HMAC key",
                "neither controller equals submitter",
            ],
        },
    }


def build_policies() -> dict:
    return {
        "schema": "sec12166.policies/v1",
        "tenant": TENANT,
        "versions": {
            POLICY_OLD: {
                "seq": 2,
                "label": "rollback-target / 较宽松旧版",
                "anchor_deny_mask": WRITE,
                "anchor_effect": "仅拒绝 WRITE；READ 经 P-A 根的继承允许放行",
                "vault_block_inheritance": False,
                "sealed_subtree_deny_present": False,
            },
            POLICY_NEW: {
                "seq": 3,
                "label": "已会签当前 / 加固恢复基线",
                "anchor_deny_mask": READ | WRITE,
                "anchor_effect": "拒绝 READ|WRITE，封闭隔离目录",
                "vault_block_inheritance": True,
                "sealed_subtree_deny_present": True,
            },
        },
        "rollback_direction": f"{POLICY_NEW} -> {POLICY_OLD}",
        "small_isolation_path": r"SYNTH:\P-ISO\Sealed",
        "scale_anchor_path": r"SYNTH:\P-A\Isolation",
        "scale_constants": {
            "total_nodes": 60000,
            "normal_branches": 22,
            "full_branch_nodes": 2041,
            "leaf_dirs_per_branch": 40,
            "files_per_leaf": 50,
            "block_branch_nodes": 2041,
            "block_boundary_nodes_read": 1,
            "block_pruned_descendants": 2040,
            "mount_nodes": 1,
            "anchor_subtree_nodes": 46945,
            "rollback_nodes_accessed": 44905,
            "rollback_nodes_applied_or_mutated": 44904,
            "partition_allocations": {"P-A": 47446, "P-B": 3000, "P-C": 2000, "P-D": 7554},
        },
    }


# ---------------------------------------------------------------------------
# 独立小树：14(P-ISO) + 5(P-OPEN) 个节点，覆盖四个考点
# ---------------------------------------------------------------------------
def _small_topology(version: str) -> list[Node]:
    is_new = version == POLICY_NEW or version == "v3"

    def ace(*args, **kw):
        return ACE(*args, **kw)

    nodes: list[Node] = []

    def add(nid, name, kind, parent, part, dacl=None, block=False, target=None):
        if parent is None:
            path = rf"SYNTH:\{part}"
        else:
            p = next(x for x in nodes if x.nid == parent)
            path = p.path + "\\" + name
        nodes.append(
            Node(
                nid=nid, name=name, kind=kind, parent=parent, part=part, path=path,
                dacl=dacl or [], block_inheritance=block, mount_target=target,
                tenant=TENANT if part == "P-ISO" else None,
            )
        )

    base_users = ACE("a-iso-users-base", "allow", USERS, READ, ("OI", "CI"))
    ops_all = ACE("a-iso-ops-all", "allow", ISO_OPS, RIGHT_ALL, ("OI", "CI"))
    sealed_deny = ACE("a-sealed-deny-users", "deny", USERS, READ | WRITE | EXEC, ("OI", "CI"))
    sealed_ops = ACE("a-sealed-ops", "allow", ISO_OPS, RIGHT_ALL, ("OI", "CI"))
    hr_deny = ACE("a-hr-deny-users", "deny", USERS, READ, ("OI", "CI"))
    vault_svc = ACE("a-vault-svc-read", "allow", ISO_SVC, READ, ("OI", "CI"))

    add(100, "P-ISO", "dir", None, "P-ISO", [base_users, ops_all])
    sealed_dacl = [sealed_ops] + ([sealed_deny] if is_new else [])
    add(101, "Sealed", "dir", 100, "P-ISO", sealed_dacl)
    add(102, "Dropbox", "dir", 101, "P-ISO")
    add(103, "incoming.txt", "file", 102, "P-ISO")
    add(104, "notes.txt", "file", 102, "P-ISO")
    add(105, "HR", "dir", 101, "P-ISO", [hr_deny])  # 两版都在：子树拒绝“不变岛”
    add(106, "salaries.xlsx", "file", 105, "P-ISO")
    add(107, "records", "dir", 105, "P-ISO")
    add(108, "review.docx", "file", 107, "P-ISO")
    add(109, "Vault", "dir", 101, "P-ISO",
        [vault_svc] if is_new else [], block=is_new)  # 新版断开继承
    add(110, "secret.txt", "file", 109, "P-ISO")
    add(111, "Bridge", "mount", 101, "P-ISO", target=201)
    add(112, "Outside", "dir", 100, "P-ISO")
    add(113, "normal.txt", "file", 112, "P-ISO")

    add(200, "P-OPEN", "dir", None, "P-OPEN")
    add(201, "OpenShare", "dir", 200, "P-OPEN",
        [ACE("a-open-users-read", "allow", USERS, READ, ("OI", "CI"))])
    add(202, "readme.txt", "file", 201, "P-OPEN")
    add(203, "Reports", "dir", 201, "P-OPEN")
    add(204, "q4.txt", "file", 203, "P-OPEN")
    return nodes


def build_small_repo(version: str) -> Repo:
    return Repo(_small_topology(version))


# ---------------------------------------------------------------------------
# 60000 节点规模树（结构计数是算术确定的，便于独立核验）
# ---------------------------------------------------------------------------
LB = 40   # 每个主干下叶子目录数
FPF = 50  # 每个叶子目录下文件数
NORMAL_BRANCHES = 22


def build_scale_repo() -> tuple[Repo, int, int]:
    """返回 (repo, anchor_id, mount_id)。总节点恰为 60000。"""
    repo = Repo()
    seq = 0

    def add(name, kind, parent, part, dacl=None, block=False, target=None,
            tenant=None) -> int:
        nonlocal seq
        seq += 1
        nid = seq
        if parent is None:
            path = rf"SYNTH:\{part}"
        else:
            path = repo.raw(parent).path + "\\" + name
        repo.add(Node(
            nid=nid, name=name, kind=kind, parent=parent, part=part, path=path,
            dacl=dacl or [], block_inheritance=block, mount_target=target,
            tenant=tenant,
        ))
        return nid

    users_allow_read = ACE("sc-part-users-allow", "allow", USERS, READ, ("OI", "CI"))

    # ---- P-A 目标租户分区 -------------------------------------------------
    pa = add("P-A", "dir", None, "P-A", [users_allow_read], tenant=TENANT)
    anchor_rule = ACE("anc-iso-rule", "deny", USERS, READ | WRITE, ("OI", "CI"))
    anchor = add("Isolation", "dir", pa, "P-A", [anchor_rule], tenant=TENANT)

    def full_branch(prefix: str, block: bool) -> int:
        mid = add(prefix, "dir", anchor, "P-A", block=block, tenant=TENANT)
        for li in range(LB):
            leaf = add(f"d{li:02d}", "dir", mid, "P-A", tenant=TENANT)
            for fi in range(FPF):
                add(f"f{fi:03d}.dat", "file", leaf, "P-A", tenant=TENANT)
        return mid

    for i in range(NORMAL_BRANCHES):
        full_branch(f"box-{i:02d}", block=False)
    block_mid = full_branch("box-block", block=True)  # 断开继承支

    # ---- P-B 另一租户：整分区子树拒绝 ------------------------------------
    pb = add("P-B", "dir", None, "P-B",
             [ACE("sc-pb-deny-read", "deny", USERS, READ, ("OI", "CI"))],
             tenant="t-other-01")
    for i in range(2999):
        add(f"b-{i:05d}.dat", "file", pb, "P-B", tenant="t-other-01")

    # ---- P-C 数据分区 + 挂接目标 -----------------------------------------
    pc = add("P-C", "dir", None, "P-C", [users_allow_read])
    pc_target = add("MountedData", "dir", pc, "P-C")
    for i in range(99):
        add(f"m-{i:03d}.dat", "file", pc_target, "P-C")
    for i in range(1899):
        add(f"c-{i:05d}.dat", "file", pc, "P-C")

    # 挂接点位于 anchor 下，目标在 P-C（回退不得跨入）
    mount = add("bridge-to-c", "mount", anchor, "P-A", target=pc_target,
                tenant=TENANT)

    # ---- P-A 内但 anchor 外的其它目录：回退不得访问 -----------------------
    other = add("Other", "dir", pa, "P-A", tenant=TENANT)
    for i in range(499):
        add(f"o-{i:03d}.dat", "file", other, "P-A", tenant=TENANT)

    # ---- P-D 无 ACE 分区，补足到恰好 60000 -------------------------------
    pd = add("P-D", "dir", None, "P-D")
    i = 0
    while len(repo) < 60000:
        add(f"d-{i:05d}.tmp", "file", pd, "P-D")
        i += 1

    assert len(repo) == 60000, f"规模树节点数应为 60000，实际 {len(repo)}"

    # 用同一套作用域语义给“规则适用节点”盖 v3 戳（setup，不计入回退计量）
    visited, apply_ids = rule_scope_ids(repo, anchor)
    for nid in apply_ids:
        repo.raw(nid).applied_rev = POLICY_NEW
    # 其它 P-A 节点也标记当前基线版本（但不属于隔离规则作用域）
    for n in repo.by_part("P-A"):
        if n.applied_rev is None:
            n.applied_rev = POLICY_NEW
    return repo, anchor, mount


# ---------------------------------------------------------------------------
# 落盘 / 加载：求解器只通过 SyntheticJail 读这些合成文件
# ---------------------------------------------------------------------------
def materialize(root: str | Path = DEFAULT_SYNTHETIC_DIR) -> SyntheticJail:
    jail = SyntheticJail(root)
    jail.write_json("authz_rules.json", build_authz_rules())
    jail.write_json("policies.json", build_policies())

    small = {
        "schema": "sec12166.small-tree/v1",
        "description": "独立小树：继承允许/子树拒绝/挂接点/断开继承",
        POLICY_OLD: [n.to_dict() for n in _small_topology(POLICY_OLD)],
        POLICY_NEW: [n.to_dict() for n in _small_topology(POLICY_NEW)],
    }
    jail.write_json("small_tree.json", small)

    scale_repo, anchor, mount = build_scale_repo()
    rows = [scale_repo.raw(i).to_dict() for i in sorted(scale_repo.nodes)]
    jail.write_json_lines("scale_paths.jsonl", rows)
    meta = {
        "schema": "sec12166.scale-meta/v1",
        "anchor_id": anchor,
        "mount_id": mount,
        "count": len(rows),
        "scale_constants": build_policies()["scale_constants"],
    }
    jail.write_json("scale_meta.json", meta)
    return jail


def load_small_repo(jail: SyntheticJail, version: str) -> Repo:
    data = jail.read_json("small_tree.json")
    key = version if version in data else (POLICY_OLD if version in ("v2",) else POLICY_NEW)
    return Repo([Node.from_dict(d) for d in data[key]])


def load_scale_repo(jail: SyntheticJail) -> tuple[Repo, int, int]:
    meta = jail.read_json("scale_meta.json")
    repo = Repo()
    for _lineno, row in jail.read_json_lines("scale_paths.jsonl"):
        repo.add(Node.from_dict(row))
    return repo, int(meta["anchor_id"]), int(meta["mount_id"])
