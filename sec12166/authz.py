"""授权代规则引擎：Windows 风格继承 + 拒绝优先 + 断开继承 + 挂接点。

这是对 Windows 访问检查 / ACE 继承规则的“合成可复核子集”，规则本身来自
synthetic/authz_rules.json，不读取真实系统的安全描述符。

关键口径（与题面四个考点一一对应）：
1. 继承允许：祖先处带 OI/CI 的 Allow ACE 会传播到文件/目录。
2. 子树拒绝：祖先处带 OI|CI 的 Deny ACE 覆盖整棵子树；拒绝优先于允许。
3. 挂接点  ：mount/reparse 节点是枚举与回退的边界（不跨入目标、不重复计数）；
             但“沿逻辑路径穿过挂接点访问”时，改按目标节点的 DACL 判定，
             因此可能出现“封闭分区里经挂接点绕出的允许项”。
4. 断开继承：节点 block_inheritance（SP_DACL_PROTECTED）后，祖先 ACE 在该节点
             处被丢弃，且不再向下传播；该节点自身显式 ACE 仍可向下传播。
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from .model import ACE, FLAG_CI, FLAG_IO, FLAG_NP, FLAG_OI, Node, Repo

ALLOW = "ALLOW"
DENY = "DENY"
IMPLICIT_DENY = "IMPLICIT_DENY"


# ---------------------------------------------------------------------------
# 主体 / 组
# ---------------------------------------------------------------------------
class PrincipalIndex:
    def __init__(self, group_members: dict[str, list[str]] | None = None):
        # group sid -> member sids
        self.group_members = group_members or {}
        # 反向：sid -> 它所属的组集合（含自身）
        self._membership: dict[str, set[str]] = {}
        for grp, members in self.group_members.items():
            for m in members:
                self._membership.setdefault(m, set()).add(grp)

    def sids_for(self, sid: str) -> set[str]:
        s = {sid}
        s |= self._membership.get(sid, set())
        return s


# ---------------------------------------------------------------------------
# ACE 继承传播
# ---------------------------------------------------------------------------
def propagate_to_child(ace: ACE, child: Node, source_nid: int) -> ACE | None:
    """按 OI/CI/NP/IO 合成规则，把 source_nid 上的 ace 映射为 child 上的继承 ACE。

    返回 None 表示该 ACE 不被 child 继承。
    """
    oi, ci = ace.has(FLAG_OI), ace.has(FLAG_CI)
    if not (oi or ci):
        return None

    container = child.is_container()
    inherit_only = False
    if container:
        if ci:
            inherit_only = False           # CI：对容器生效
        elif oi:
            inherit_only = True            # 仅 OI 落到容器：变成“仅继承”，容器自身不生效
        else:
            return None
    else:
        if oi:
            inherit_only = False           # OI：对文件/对象生效
        else:
            return None                    # 仅 CI 不落到文件

    if ace.has(FLAG_NP):
        next_flags: tuple[str, ...] = ()   # NP：只传一代，子 ACE 不再下传
    else:
        fl: list[str] = []
        if oi:
            fl.append(FLAG_OI)
        if ci:
            fl.append(FLAG_CI)
        if inherit_only:
            fl.append(FLAG_IO)
        next_flags = tuple(fl)

    origin = ace.origin if ace.inherited else source_nid
    return ACE(
        ace_id=ace.ace_id,
        kind=ace.kind,
        sid=ace.sid,
        mask=ace.mask,
        flags=next_flags,
        inherited=True,
        origin=origin,
    )


def effective_aces(repo: Repo, nid: int) -> tuple[list[Node], list[ACE]]:
    """计算节点上“可用于访问检查”的有效 ACE（已应用继承与断开继承）。

    返回 (root→target 节点链, 有效且非 IO 的 ACE 列表，顺序近似规范 DACL 顺序)。
    """
    chain: list[Node] = []
    cur: int | None = nid
    while cur is not None:
        n = repo.raw(cur)
        chain.append(n)
        cur = n.parent
    chain.reverse()

    inherited: list[ACE] = []
    for idx, node in enumerate(chain):
        if node.block_inheritance:
            inherited = []  # 断开继承：祖先流入的 ACE 全部丢弃

        # 目标节点的有效 DACL = 其显式 ACE + 已映射到本节点的继承 ACE。
        if idx == len(chain) - 1:
            effective: list[ACE] = []
            for ace in list(node.dacl) + inherited:
                if ace.has(FLAG_IO):
                    continue  # 仅继承 ACE 不参与本对象访问检查
                if not ace.inherited and ace.origin is None:
                    ace = replace(ace, origin=node.nid)
                effective.append(ace)
            # 近似 Windows 规范顺序：显式 deny、显式 allow、继承 deny、继承 allow。
            effective.sort(key=lambda a: (
                1 if a.inherited else 0,
                0 if a.kind == "deny" else 1,
            ))
            return chain, effective

        nxt = chain[idx + 1]
        source_aces = list(node.dacl) + inherited
        new_inherited: list[ACE] = []
        for ace in source_aces:
            mapped = propagate_to_child(ace, nxt, node.nid)
            if mapped is not None:
                new_inherited.append(mapped)
        inherited = new_inherited

    return chain, []  # 不可达：chain 至少含目标自身


def _match(ace: ACE, sids: set[str], bit: int) -> bool:
    return ace.sid in sids and bool(ace.mask & bit)


@dataclass
class Decision:
    nid: int
    path: str
    principal: str
    right: str
    verdict: str
    chain_ids: list[int] = field(default_factory=list)
    deny_ace: ACE | None = None
    allow_ace: ACE | None = None
    via_mount: bool = False
    mount_hops: list[tuple[int, int]] = field(default_factory=list)
    note: str = ""

    def basis(self) -> str:
        if self.verdict == DENY and self.deny_ace is not None:
            a = self.deny_ace
            return f"deny:{a.ace_id}@{a.origin}{'/inh' if a.inherited else '/exp'}"
        if self.verdict == ALLOW and self.allow_ace is not None:
            a = self.allow_ace
            return f"allow:{a.ace_id}@{a.origin}{'/inh' if a.inherited else '/exp'}"
        return "implicit-deny:no-matching-ace"


def evaluate_access(
    repo: Repo,
    nid: int,
    principal: str,
    right: str = "READ",
    principals: PrincipalIndex | None = None,
) -> Decision:
    bit = _right_bit(right)
    pidx = principals or PrincipalIndex()
    sids = pidx.sids_for(principal)
    chain, aces = effective_aces(repo, nid)
    deny = next((a for a in aces if a.kind == "deny" and _match(a, sids, bit)), None)
    allow = next((a for a in aces if a.kind == "allow" and _match(a, sids, bit)), None)
    if deny is not None:
        verdict, dace, aace = DENY, deny, allow
    elif allow is not None:
        verdict, dace, aace = ALLOW, None, allow
    else:
        verdict, dace, aace = IMPLICIT_DENY, None, None
    node = repo.raw(nid)
    return Decision(
        nid=nid,
        path=node.path,
        principal=principal,
        right=right,
        verdict=verdict,
        chain_ids=[n.nid for n in chain],
        deny_ace=dace,
        allow_ace=aace,
        note="拒绝优先于允许" if deny is not None and allow is not None else "",
    )


def _right_bit(right: str | int) -> int:
    if isinstance(right, int):
        return right
    from .model import RIGHTS

    if right not in RIGHTS:
        raise ValueError(f"未知权限 {right!r}，可选 {sorted(RIGHTS)}")
    return RIGHTS[right]


# ---------------------------------------------------------------------------
# 挂接点解析：沿逻辑路径穿过 mount -> target，再按名称下降
# ---------------------------------------------------------------------------
def resolve_through_mount(
    repo: Repo, mount_id: int, rel_names: list[str]
) -> tuple[Node, list[tuple[int, int]], list[Node]]:
    m = repo.raw(mount_id)
    if m.kind != "mount" or m.mount_target is None:
        raise ValueError(f"节点 {mount_id} 不是带目标的挂接点")
    hops: list[tuple[int, int]] = [(mount_id, m.mount_target)]
    trail: list[Node] = [m, repo.raw(m.mount_target)]
    cur = m.mount_target
    for name in rel_names:
        nxt = next((c for c in repo.children(cur) if c.name == name), None)
        if nxt is None:
            raise KeyError(f"挂接目标 {cur} 下找不到 {name!r}")
        cur = nxt.nid
        trail.append(nxt)
    return repo.raw(cur), hops, trail


def evaluate_mounted_path(
    repo: Repo,
    mount_id: int,
    rel_names: list[str],
    principal: str,
    right: str = "READ",
    principals: PrincipalIndex | None = None,
) -> Decision:
    target, hops, _trail = resolve_through_mount(repo, mount_id, rel_names)
    d = evaluate_access(repo, target.nid, principal, right, principals)
    d.via_mount = True
    d.mount_hops = hops
    d.path = repo.raw(mount_id).path + "\\" + "\\".join(rel_names) + "  [reparse-> " + target.path + "]"
    return d


def rule_scope_ids(repo: Repo, anchor_id: int) -> tuple[list[int], list[int]]:
    """单条可继承规则从 anchor 回退/传播时的节点作用域（合成口径）。

    返回 (visited_ids, apply_ids)：
    - visited_ids：规划/回退必须实际 get 读取的节点。读到“断开继承”节点后
      才能知道要裁剪，因此该边界节点被读取，但它的后代完全不读。
    - apply_ids  ：规则真正适用/盖戳的节点 = visited 去掉被断开继承的边界节点。
    - 挂接点自身适用并被读取，但绝不跨入 mount_target，也不枚举其它分区。
    """
    visited: list[int] = []
    apply: list[int] = []
    stack = [anchor_id]
    seen: set[int] = set()
    while stack:
        nid = stack.pop()
        if nid in seen:
            continue
        seen.add(nid)
        n = repo.raw(nid)
        visited.append(nid)

        blocked_here = nid != anchor_id and n.block_inheritance
        if blocked_here:
            continue  # 断开继承：规则不适用，且后代整支裁剪

        apply.append(nid)
        if n.kind == "mount":
            continue  # 挂接边界：不跨入目标

        stack.extend(repo.child_ids(nid))
    return visited, apply


def shallowest_decisive_descendant(
    repo: Repo,
    root_id: int,
    principal: str,
    right: str,
    want: str,
    principals: PrincipalIndex | None = None,
    *,
    max_nodes: int | None = None,
) -> tuple[Node, Decision] | None:
    """在 root 子树（不跨挂接点目标）里按 BFS 找最浅的指定结论节点。

    want ∈ {ALLOW, DENY, IMPLICIT_DENY}。用于“最短可复核路径”。
    """
    queue: list[tuple[int, int]] = [(root_id, 0)]
    seen = {root_id}
    scanned = 0
    while queue:
        nid, depth = queue.pop(0)
        scanned += 1
        if max_nodes and scanned > max_nodes:
            return None
        d = evaluate_access(repo, nid, principal, right, principals)
        if d.verdict == want:
            return repo.raw(nid), d
        n = repo.raw(nid)
        if n.kind == "mount":
            continue  # 枚举不跨挂接目标；跨挂接的见证单独构造
        for cid in repo.child_ids(nid):
            if cid not in seen:
                seen.add(cid)
                queue.append((cid, depth + 1))
    return None
