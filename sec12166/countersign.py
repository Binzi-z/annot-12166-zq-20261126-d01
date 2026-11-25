"""已会签回退的绑定与“两名实际控制人独立”校验（离线合成 HMAC 方案）。

绑定四要素（缺一不可，任一字段被篡改都会使签名失效）：
    旧版 old_version / 新版 new_version / 目标租户 tenant / 隔离目录摘要 isolation_digest

两名实际控制人必须独立：不同 cid、不同自然人 person_id、不同控制组、
不同派生密钥，且都不能是提交人。HMAC-SHA256 在此作为离线合成的批准令牌；
真实环境应替换为智能卡/非对称签名，但其“绑定 + 双人独立”的复核口径不变。
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
from dataclasses import dataclass, field

from .model import canonical_bytes, digest_obj

DOMAIN = b"sec12166/countersign/v1"


class CountersignError(ValueError):
    pass


def controller_key(controller: dict) -> bytes:
    """从合成 key_seed 派生每控制器独立密钥（非真实秘密，仅用于演练）。"""
    return hashlib.sha256(b"sec12166/controller-key/v1|" + controller["key_seed"].encode("utf-8")).digest()


def binding_core(
    *,
    ticket_id: str,
    old_version: str,
    new_version: str,
    tenant: str,
    isolation_digest: str,
    old_policy_digest: str | None = None,
    new_policy_digest: str | None = None,
) -> dict:
    core = {
        "domain": DOMAIN.decode(),
        "ticket_id": ticket_id,
        "old_version": old_version,
        "new_version": new_version,
        "tenant": tenant,
        "isolation_digest": isolation_digest,
    }
    if old_policy_digest:
        core["old_policy_digest"] = old_policy_digest
    if new_policy_digest:
        core["new_policy_digest"] = new_policy_digest
    return core


def signing_message(core: dict) -> bytes:
    return DOMAIN + b"|" + canonical_bytes(core)


def approve(controller: dict, core: dict) -> dict:
    mac = hmac.new(controller_key(controller), signing_message(core), hashlib.sha256).hexdigest()
    return {
        "cid": controller["cid"],
        "person_id": controller["person_id"],
        "control_group": controller.get("control_group"),
        "sid": controller.get("sid"),
        "mac": mac,
    }


@dataclass
class CountersignTicket:
    ticket_id: str
    old_version: str
    new_version: str
    tenant: str
    isolation_digest: str
    approvals: list[dict] = field(default_factory=list)
    old_policy_digest: str | None = None
    new_policy_digest: str | None = None
    submitter: str | None = None

    def core(self) -> dict:
        return binding_core(
            ticket_id=self.ticket_id,
            old_version=self.old_version,
            new_version=self.new_version,
            tenant=self.tenant,
            isolation_digest=self.isolation_digest,
            old_policy_digest=self.old_policy_digest,
            new_policy_digest=self.new_policy_digest,
        )

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "CountersignTicket":
        known = {f.name for f in dataclasses.fields(CountersignTicket)}
        return CountersignTicket(**{k: v for k, v in d.items() if k in known})


def build_happy_ticket(
    controllers: list[dict],
    *,
    ticket_id: str,
    old_version: str,
    new_version: str,
    tenant: str,
    isolation_digest: str,
    submitter: str,
    old_policy_digest: str | None = None,
    new_policy_digest: str | None = None,
) -> CountersignTicket:
    if len(controllers) < 2:
        raise CountersignError("至少需要两名实际控制人")
    t = CountersignTicket(
        ticket_id=ticket_id,
        old_version=old_version,
        new_version=new_version,
        tenant=tenant,
        isolation_digest=isolation_digest,
        old_policy_digest=old_policy_digest,
        new_policy_digest=new_policy_digest,
        submitter=submitter,
    )
    core = t.core()
    t.approvals = [approve(controllers[0], core), approve(controllers[1], core)]
    return t


@dataclass
class Verification:
    ok: bool
    errors: list[str] = field(default_factory=list)
    passed_checks: list[str] = field(default_factory=list)

    def require(self, cond: bool, ok_msg: str, err_msg: str) -> None:
        if cond:
            self.passed_checks.append(ok_msg)
        else:
            self.errors.append(err_msg)
            self.ok = False


def verify_ticket(
    ticket: CountersignTicket | dict,
    authz_rules: dict,
    *,
    expected_old_version: str | None = None,
    expected_new_version: str | None = None,
    expected_tenant: str | None = None,
    expected_isolation_digest: str | None = None,
    expected_submitter: str | None = None,
) -> Verification:
    if isinstance(ticket, dict):
        ticket = CountersignTicket.from_dict(ticket)
    v = Verification(ok=True)
    dc = authz_rules["dual_control"]
    registry = {c["cid"]: c for c in dc["controllers"]}
    need = int(dc["required_independent_actual_controllers"])

    v.require(bool(ticket.ticket_id), "ticket_id 非空", "缺少 ticket_id")
    v.require(bool(ticket.old_version), "绑定旧版", "未绑定 old_version")
    v.require(bool(ticket.new_version), "绑定新版", "未绑定 new_version")
    v.require(bool(ticket.tenant), "绑定目标租户", "未绑定 tenant")
    v.require(
        bool(ticket.isolation_digest) and len(ticket.isolation_digest) == 64,
        "绑定隔离目录 SHA256 摘要",
        "缺少或格式错误的 isolation_digest",
    )

    # 与当前复核期望值一致（防止拿合法旧票冒用到别的租户/目录/版本）
    if expected_old_version is not None:
        v.require(ticket.old_version == expected_old_version,
                  "旧版与期望一致", f"旧版不匹配: {ticket.old_version!r} != {expected_old_version!r}")
    if expected_new_version is not None:
        v.require(ticket.new_version == expected_new_version,
                  "新版与期望一致", f"新版不匹配: {ticket.new_version!r} != {expected_new_version!r}")
    if expected_tenant is not None:
        v.require(ticket.tenant == expected_tenant,
                  "目标租户与期望一致", f"租户不匹配: {ticket.tenant!r} != {expected_tenant!r}")
    if expected_isolation_digest is not None:
        v.require(hmac.compare_digest(ticket.isolation_digest, expected_isolation_digest),
                  "隔离目录摘要与现场重算一致", "隔离目录摘要不一致：目录已变化或绑定错误")
    if expected_submitter is not None:
        v.require(ticket.submitter == expected_submitter,
                  "提交人与期望一致", "提交人不匹配")

    apps = ticket.approvals
    v.require(len(apps) == need, f"会签人数={need}", f"会签人数应为 {need}，实际 {len(apps)}")

    core = ticket.core()
    msg = signing_message(core)
    seen_cid: set[str] = set()
    seen_person: set[str] = set()
    seen_group: set[str] = set()
    seen_key: set[bytes] = set()
    valid_macs = 0

    for a in apps:
        cid = a.get("cid")
        ctrl = registry.get(cid)
        v.require(ctrl is not None, f"审批人 {cid} 已登记", f"未知审批人 {cid!r}")
        if ctrl is None:
            continue
        expected_mac = hmac.new(controller_key(ctrl), msg, hashlib.sha256).hexdigest()
        mac_ok = hmac.compare_digest(a.get("mac", ""), expected_mac)
        v.require(mac_ok, f"{cid} 签名对绑定四要素有效", f"{cid} 签名无效（可能篡改绑定字段）")
        valid_macs += int(mac_ok)

        # 审批记录里的自然人/控制组必须与登记一致，防止替换
        v.require(a.get("person_id") == ctrl["person_id"],
                  f"{cid} 自然人编号一致", f"{cid} 的 person_id 与登记不符")
        v.require(a.get("control_group") == ctrl.get("control_group"),
                  f"{cid} 控制组一致", f"{cid} 的 control_group 与登记不符")

        seen_cid.add(cid)
        seen_person.add(ctrl["person_id"])
        seen_group.add(ctrl["control_group"])
        seen_key.add(controller_key(ctrl))

        if dc.get("submitter_must_differ_from_controllers") and ticket.submitter:
            sub = ticket.submitter
            differ = sub not in (cid, ctrl.get("sid"), ctrl["person_id"])
            v.require(differ, f"{cid} 独立于提交人", f"实际控制人 {cid} 不能同时是提交人 {sub}")

    if len(apps) >= 2:
        v.require(len(seen_cid) == len(apps), "两名控制人 cid 不同", "存在重复 cid（同一人会签两次）")
        v.require(len(seen_person) == len(apps), "两名控制人自然人不同", "两名控制人 person_id 相同，非独立")
        v.require(len(seen_group) == len(apps), "两名控制人控制组不同", "两名控制人来自同一控制组，不独立")
        v.require(len(seen_key) == len(apps), "两名控制人密钥独立", "两名控制人共享/派生得到同一密钥")

    # 票整体指纹，供 WAL / 报告引用
    ticket_fingerprint = digest_obj(ticket.to_dict())
    v.passed_checks.append(f"ticket_fingerprint={ticket_fingerprint[:16]}…")
    return v
