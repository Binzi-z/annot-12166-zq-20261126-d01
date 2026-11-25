"""持久化、幂等提交与崩溃/回执恢复（标准库 WAL + 原子文件）。

设计要点：
- WAL（append-only，逐条 flush+fsync，行内带 SHA256）是唯一事实源；重开时重放，
  末尾校验失败的半行视为崩溃撕裂写并忽略。
- 所有“检查 + 线性化写”都在同一把 RLock 内完成，因此两个线程的回退/撤回
  不可能同时生效。
- 提交事件本身已 fsync 后，才是“承诺成功”；调用方在拿到回执前崩溃/回执丢失，
  客户端用同一 idempotency_key 重试：重放已提交事件并返回同一回执，副作用不重复。
- PolicyApplier 用 CAS 版本号 + effects.log 证明回退副作用恰好一次。
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from .model import digest_obj, sha256_hex


class DurableError(RuntimeError):
    pass


class RevocationFence(DurableError):
    """撤回已先持久化，回退被围栏拒绝。"""


class AlreadyCommitted(DurableError):
    """回退已承诺，撤回无法再撤销（需走补偿/前滚流程）。"""


class VersionConflict(DurableError):
    pass


class ReceiptLost(DurableError):
    """模拟“服务端已承诺，但回执在返回途中丢失”。"""

    def __init__(self, receipt_id: str):
        super().__init__(f"receipt lost after durable commit: {receipt_id}")
        self.receipt_id = receipt_id


def fsync_file(fh) -> None:
    fh.flush()
    try:
        os.fsync(fh.fileno())
    except (OSError, AttributeError):
        pass


def atomic_write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fsync_file(fh)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# 策略副作用：版本 CAS + effects.log，可跨“重启”核对恰好一次
# ---------------------------------------------------------------------------
class PolicyApplier:
    def __init__(self, directory: str | Path, initial_version: str):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.dir / "policy_state.json"
        self.effects_path = self.dir / "policy_effects.log"
        self.apply_count = 0
        if self.state_path.exists():
            self.current = json.loads(self.state_path.read_text("utf-8"))["current"]
        else:
            self.current = initial_version
            atomic_write_json(self.state_path, {"current": self.current})

    def effect_lines_on_disk(self) -> int:
        if not self.effects_path.exists():
            return 0
        return sum(1 for line in self.effects_path.read_text("utf-8").splitlines() if line.strip())

    def apply_rollback(self, *, expected_current: str, target_version: str,
                       idem_key: str, stats: dict) -> dict:
        if self.current != expected_current:
            raise VersionConflict(
                f"当前版本 {self.current!r} != 期望 {expected_current!r}，拒绝回退"
            )
        self.apply_count += 1
        effect = {
            "seq": self.effect_lines_on_disk() + 1,
            "idem_key": idem_key,
            "from": expected_current,
            "to": target_version,
            "stats": stats,
        }
        with self.effects_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(effect, ensure_ascii=False, separators=(",", ":")) + "\n")
            fsync_file(fh)
        self.current = target_version
        atomic_write_json(self.state_path, {"current": target_version, "last_effect": effect})
        return effect


# ---------------------------------------------------------------------------
# WAL 支撑的票据状态存储
# ---------------------------------------------------------------------------
@dataclass
class Receipt:
    receipt_id: str
    ticket_id: str
    idem_key: str
    status: str
    payload: dict
    replayed: bool = False

    def to_dict(self) -> dict:
        return {
            "receipt_id": self.receipt_id,
            "ticket_id": self.ticket_id,
            "idem_key": self.idem_key,
            "status": self.status,
            "replayed": self.replayed,
            **self.payload,
        }


class DurableTicketStore:
    def __init__(self, directory: str | Path, applier: PolicyApplier | None = None):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.wal_path = self.dir / "tickets.wal.jsonl"
        self.applier = applier
        self.lock = threading.RLock()
        self.events: list[dict] = []
        self.revoked: set[str] = set()
        self.revocation_records: dict[str, dict] = {}
        self.committed_idem: dict[str, dict] = {}
        self.committed_ticket: dict[str, dict] = {}
        self._replay()

    # ---- WAL 底层 -------------------------------------------------------
    def _append_event(self, etype: str, body: dict) -> dict:
        seq = len(self.events) + 1
        event = {"seq": seq, "type": etype, **body}
        event["sha256"] = digest_obj({k: v for k, v in event.items() if k != "sha256"})
        with self.wal_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
            fsync_file(fh)
        self.events.append(event)
        self._derive(event)
        return event

    def _replay(self) -> None:
        if not self.wal_path.exists():
            return
        data = self.wal_path.read_bytes()
        n = len(data)
        offset = 0
        cut: int | None = None
        # 必须按精确的 b"\n" 分帧：bytes.splitlines() 会把 UTF-8 续接字节 0x85
        # （NEL）误当成行边界，从而破坏含中文内容的事件。
        while offset < n:
            nl = data.find(b"\n", offset)
            if nl == -1:
                cut = offset  # 没有结尾换行 = 崩溃撕裂的半行
                break
            line_start = offset
            raw = data[offset:nl]
            offset = nl + 1
            if not raw.strip():
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
                if not isinstance(event, dict):
                    raise ValueError("WAL event is not an object")
                check = event.pop("sha256")
                if not isinstance(check, str):
                    raise TypeError("sha256 must be a string")
                expect = digest_obj(event)
                if not _const_eq(check, expect):
                    raise ValueError("bad checksum")
                event["sha256"] = check
            except (ValueError, KeyError, TypeError, AttributeError):
                # 契约：追加式 WAL 中第一条坏记录只可能是末尾撕裂写，
                # 从该记录起点截断，避免下次追加与之粘连成一行。
                cut = line_start
                break
            self.events.append(event)
            self._derive(event)

        if cut is not None:
            with self.wal_path.open("r+b") as fh:
                fh.truncate(cut)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except OSError:
                    pass

    def _derive(self, event: dict) -> None:
        t = event["type"]
        if t == "revocation-persisted":
            self.revoked.add(event["ticket_id"])
            self.revocation_records[event["ticket_id"]] = event
        elif t == "rollback-committed":
            self.committed_idem[event["idem_key"]] = event
            self.committed_ticket[event["ticket_id"]] = event

    # ---- 撤回 -----------------------------------------------------------
    def persist_revocation(self, ticket_id: str, revoker: str, reason: str) -> dict:
        with self.lock:
            if ticket_id in self.committed_ticket:
                raise AlreadyCommitted(f"票据 {ticket_id} 已提交，撤回不能再生效")
            if ticket_id in self.revoked:
                return {"status": "revocation-already-persisted",
                        "record": self.revocation_records[ticket_id]}
            event = self._append_event("revocation-persisted", {
                "ticket_id": ticket_id, "revoker": revoker, "reason": reason,
            })
            return {"status": "revocation-persisted", "seq": event["seq"]}

    # ---- 回退提交（幂等） ----------------------------------------------
    def commit_rollback(
        self,
        *,
        ticket: dict,
        idem_key: str,
        expected_current: str,
        target_version: str,
        stats: dict | None = None,
        lose_receipt: bool = False,
    ) -> Receipt:
        ticket_id = ticket["ticket_id"]
        with self.lock:
            prior = self.committed_idem.get(idem_key)
            if prior is not None:
                # 崩溃/丢回执后的安全重试：同一 idem_key 必须返回同一结果
                if prior["ticket_id"] != ticket_id:
                    raise DurableError("idem_key 被用于不同票据，拒绝")
                receipt = Receipt(
                    receipt_id=prior["receipt_id"], ticket_id=ticket_id,
                    idem_key=idem_key, status="committed-replayed",
                    payload={"seq": prior["seq"], "target_version": prior["target_version"]},
                    replayed=True,
                )
                return receipt

            if ticket_id in self.revoked:
                rec = self.revocation_records[ticket_id]
                raise RevocationFence(
                    f"票据 {ticket_id} 的撤回已先持久化(seq={rec['seq']})，回退被围栏拒绝"
                )

            effect = None
            if self.applier is not None:
                effect = self.applier.apply_rollback(
                    expected_current=expected_current,
                    target_version=target_version,
                    idem_key=idem_key,
                    stats=stats or {},
                )

            receipt_id = "rcpt-" + sha256_hex((idem_key + "|" + ticket_id).encode())[:16]
            event = self._append_event("rollback-committed", {
                "ticket_id": ticket_id,
                "idem_key": idem_key,
                "receipt_id": receipt_id,
                "expected_current": expected_current,
                "target_version": target_version,
                "stats": stats or {},
                "effect_seq": effect["seq"] if effect else None,
            })

        receipt = Receipt(
            receipt_id=receipt_id, ticket_id=ticket_id, idem_key=idem_key,
            status="committed", payload={"seq": event["seq"],
                                         "target_version": target_version},
        )
        if lose_receipt:
            # 事件已 fsync、副作用已落盘，仅“返回回执”这一步丢失
            raise ReceiptLost(receipt_id)
        return receipt

    def write_snapshot(self, path: str | Path) -> None:
        atomic_write_json(Path(path), {
            "events": self.events,
            "revoked": sorted(self.revoked),
            "committed_tickets": sorted(self.committed_ticket),
            "committed_idem_keys": sorted(self.committed_idem),
        })


def _const_eq(a: str, b: str) -> bool:
    import hmac
    return hmac.compare_digest(a, b)
