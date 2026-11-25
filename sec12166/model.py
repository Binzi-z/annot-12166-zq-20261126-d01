"""核心领域模型：合成路径节点、ACE、规范序列化与摘要、带访问计量的仓储。

不访问真实 Windows ACL / 真实文件系统；这里的一切路径与安全描述符都是合成数据。
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable

# ---------------------------------------------------------------------------
# 权限位（合成子集，映射常见 Windows 通用/标准权限语义）
# ---------------------------------------------------------------------------
RIGHTS: dict[str, int] = {
    "READ": 0x00000001,
    "WRITE": 0x00000002,
    "EXEC": 0x00000004,
    "DELETE": 0x00010000,
    "CHANGE_PERM": 0x00040000,   # WRITE_DAC
    "TAKE_OWNER": 0x00080000,    # WRITE_OWNER
}
RIGHT_ALL = 0x1 | 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000


def right_names(mask: int) -> list[str]:
    return [name for name, bit in RIGHTS.items() if mask & bit]


# ACE 继承标志（对应 Windows ACE 标志位的合成子集）
FLAG_OI = "OI"  # OBJECT_INHERIT_ACE
FLAG_CI = "CI"  # CONTAINER_INHERIT_ACE
FLAG_NP = "NP"  # NO_PROPAGATE_INHERIT_ACE
FLAG_IO = "IO"  # INHERIT_ONLY_ACE


@dataclass(frozen=True, slots=True)
class ACE:
    """一条访问控制项。

    kind   : "allow" | "deny"
    sid    : 被授权主体 / 组的合成 SID
    mask   : 权限位
    flags  : 继承标志集合，元素取自 OI/CI/NP/IO
    inherited: 该 ACE 是否为由祖先继承得到（显式 ACE 为 False）
    origin : 若为继承 ACE，其显式定义所在节点 id；显式 ACE 等于所在节点 id
    ace_id : 稳定标识，便于见证与报告引用
    """

    ace_id: str
    kind: str
    sid: str
    mask: int
    flags: tuple[str, ...] = ()
    inherited: bool = False
    origin: int | None = None

    def has(self, flag: str) -> bool:
        return flag in self.flags

    def to_dict(self) -> dict:
        return {
            "ace_id": self.ace_id,
            "kind": self.kind,
            "sid": self.sid,
            "mask": self.mask,
            "rights": right_names(self.mask),
            "flags": list(self.flags),
            "inherited": self.inherited,
            "origin": self.origin,
        }

    @staticmethod
    def from_dict(d: dict) -> "ACE":
        return ACE(
            ace_id=d["ace_id"],
            kind=d["kind"],
            sid=d["sid"],
            mask=int(d["mask"]),
            flags=tuple(d.get("flags", ())),
            inherited=bool(d.get("inherited", False)),
            origin=d.get("origin"),
        )


@dataclass(slots=True)
class Node:
    nid: int
    name: str
    kind: str                 # "dir" | "file" | "mount"
    parent: int | None
    part: str                 # 分区标识，如 P-A
    path: str                 # 合成完整路径（仅合成，不触真实 FS）
    dacl: list[ACE] = field(default_factory=list)
    block_inheritance: bool = False   # SP_DACL_PROTECTED / “断开继承”
    mount_target: int | None = None  # 挂接点(reparse)目标节点 id
    tenant: str | None = None
    applied_rev: str | None = None    # 规模核验：当前盖到节点上的策略版本戳

    def is_container(self) -> bool:
        # mount 若指向目录按容器处理；节点自身 kind=="dir" 即容器。
        return self.kind == "dir" or self.kind == "mount"

    def to_dict(self) -> dict:
        return {
            "nid": self.nid,
            "name": self.name,
            "kind": self.kind,
            "parent": self.parent,
            "part": self.part,
            "path": self.path,
            "dacl": [a.to_dict() for a in self.dacl],
            "block_inheritance": self.block_inheritance,
            "mount_target": self.mount_target,
            "tenant": self.tenant,
            "applied_rev": self.applied_rev,
        }

    @staticmethod
    def from_dict(d: dict) -> "Node":
        return Node(
            nid=int(d["nid"]),
            name=d["name"],
            kind=d["kind"],
            parent=d.get("parent"),
            part=d["part"],
            path=d["path"],
            dacl=[ACE.from_dict(a) for a in d.get("dacl", [])],
            block_inheritance=bool(d.get("block_inheritance", False)),
            mount_target=d.get("mount_target"),
            tenant=d.get("tenant"),
            applied_rev=d.get("applied_rev"),
        )


def canonical_bytes(obj: object) -> bytes:
    """规范 JSON 字节：排序键、无空白、不转义非 ASCII，用于绑定与哈希。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_obj(obj: object) -> str:
    return sha256_hex(canonical_bytes(obj))


def node_record_for_hash(n: Node) -> dict:
    """参与分区/目录摘要的节点记录（显式白名单，避免把计量态混入）。"""
    return {
        "nid": n.nid,
        "name": n.name,
        "kind": n.kind,
        "parent": n.parent,
        "path": n.path,
        "dacl": [
            {
                "ace_id": a.ace_id,
                "kind": a.kind,
                "sid": a.sid,
                "mask": a.mask,
                "flags": list(a.flags),
                "inherited": a.inherited,
                "origin": a.origin,
            }
            for a in n.dacl
        ],
        "block_inheritance": n.block_inheritance,
        "mount_target": n.mount_target,
        "tenant": n.tenant,
        "applied_rev": n.applied_rev,
    }


def subtree_digest(nodes: "Repo | dict[int, Node]", root_id: int,
                   *, skip_mount_targets: bool = True) -> str:
    """计算某子树的稳定摘要。

    skip_mount_targets=True 时挂接点只计入挂接点自身，不跨入目标，
    与隔离目录“不把别的分区卷进来”的口径一致。
    """
    repo = nodes
    if isinstance(nodes, Repo):
        repo = nodes.nodes
    collected: list[dict] = []
    stack = [root_id]
    seen: set[int] = set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        n = repo[cur]
        collected.append(node_record_for_hash(n))
        if n.kind == "mount" and skip_mount_targets:
            continue
        # 子节点由 parent 反查代价高；这里要求 Repo 提供 child_ids。
        if isinstance(nodes, Repo):
            stack.extend(nodes.child_ids(cur))
        else:
            # 纯 dict 场景：调用方一般传 Repo；兜底线性扫描不展开。
            pass
    collected.sort(key=lambda d: d["nid"])
    return digest_obj(collected)


def partition_digest(repo: "Repo", part: str) -> str:
    """分区摘要 = 对分区内全部节点记录（按 nid 排序）的列表哈希。"""
    recs = [
        node_record_for_hash(n)
        for n in sorted(repo.by_part(part), key=lambda x: x.nid)
    ]
    return digest_obj({"part": part, "nodes": recs})


class Repo:
    """节点仓储。enabled 时对 get() 做唯一节点访问计量。"""

    def __init__(self, nodes: Iterable[Node] | None = None):
        self.nodes: dict[int, Node] = {}
        self._children: dict[int, list[int]] = {}
        self.parts: dict[str, list[int]] = {}
        # 计量状态
        self.metering = False
        self.read_calls = 0
        self.read_ids: set[int] = set()
        if nodes:
            for n in nodes:
                self.add(n)

    def add(self, n: Node) -> None:
        self.nodes[n.nid] = n
        if n.parent is not None:
            self._children.setdefault(n.parent, []).append(n.nid)
        self.parts.setdefault(n.part, []).append(n.nid)

    def child_ids(self, nid: int) -> list[int]:
        return list(self._children.get(nid, ()))

    def children(self, nid: int) -> list[Node]:
        return [self.nodes[c] for c in self._children.get(nid, ())]

    def by_part(self, part: str) -> list[Node]:
        return [self.nodes[i] for i in self.parts.get(part, ())]

    def get(self, nid: int) -> Node:
        if self.metering:
            self.read_calls += 1
            self.read_ids.add(nid)
        return self.nodes[nid]

    def raw(self, nid: int) -> Node:
        return self.nodes[nid]

    def __len__(self) -> int:
        return len(self.nodes)

    # ---- 计量上下文 -----------------------------------------------------
    class _Meter:
        def __init__(self, repo: "Repo"):
            self.repo = repo

        def __enter__(self) -> "Repo._Meter":
            self.repo.metering = True
            self.repo.read_calls = 0
            self.repo.read_ids = set()
            return self

        def __exit__(self, *exc) -> None:
            self.repo.metering = False

        @property
        def unique_nodes(self) -> int:
            return len(self.repo.read_ids)

        @property
        def read_calls(self) -> int:
            return self.repo.read_calls

    def meter(self) -> "Repo._Meter":
        return Repo._Meter(self)
