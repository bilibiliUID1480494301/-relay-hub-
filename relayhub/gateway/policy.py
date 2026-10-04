"""接入策略：拉黑（IP / 设备）+ 优先队列（IP / 设备）。

「配置 APP」把中转站开给学生之后，管理面要能回答三件事：
  * **拉黑**：某台设备/某个 IP 在刷或滥用 → 一键 403，立刻生效；
  * **限流**：每设备（令牌 rpm/日配额，tokens.py 已有）+ 每 IP（serve --ip-rpm
    已有）——本模块不重复做，只把「谁该被限」标出来；
  * **优先队列**：并发闸门（ConcurrencyGate）满员排队时，VIP 设备/IP 插队。
    搜题高峰期老师可以把自己/值班设备标成优先。

为什么是独立文件而不是塞进 tokens.json：
  * 令牌是「发放时定死的配置」，策略是「运行中随时改的管理动作」；
    放一起会让 token add/rm 的落盘和策略变更互相踩。
  * 键是 **IP 或 设备 ID（did）或令牌名**——App 不带身份头时还能按 IP 管。

热加载与 tokens.py 同一套指纹思路：每请求核对指纹，文件被后台管理改了
下一请求立即生效，不用重启网关。写失败不炸请求路径（与 audit 同纪律）。
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# 单条目的两种管理动作（可同时为真：又拉黑又优先没有意义，拉黑赢）
KIND_IP = "ip"
KIND_DEVICE = "device"

SCHEMA_VERSION = 1


class PolicyError(RuntimeError):
    """策略参数错误。"""


@dataclass
class PolicyEntry:
    blocked: bool = False
    priority: bool = False
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"blocked": self.blocked, "priority": self.priority, "note": self.note}


def _fingerprint(path: Path) -> str | None:
    try:
        raw = Path(path).read_bytes()
    except OSError:
        return None
    return hashlib.sha256(raw).hexdigest()


@dataclass
class _State:
    ips: dict[str, PolicyEntry] = field(default_factory=dict)
    devices: dict[str, PolicyEntry] = field(default_factory=dict)


class PolicyStore:
    """黑名单 + 优先名单。JSON 落盘，指纹热加载，线程安全。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._fingerprint = _fingerprint(self.path)
        self._state = self._load()

    # -- 载入 ------------------------------------------------------------

    def _load(self) -> _State:
        state = _State()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return state
        if not isinstance(raw, dict):
            return state
        for key, target in (("ips", state.ips), ("devices", state.devices)):
            for value, entry in (raw.get(key) or {}).items():
                if isinstance(entry, dict):
                    target[str(value)] = PolicyEntry(
                        blocked=bool(entry.get("blocked")),
                        priority=bool(entry.get("priority")),
                        note=str(entry.get("note") or ""),
                    )
        return state

    def _save(self) -> None:
        payload = {
            "schemaVersion": SCHEMA_VERSION,
            "ips": {k: v.to_dict() for k, v in self._state.ips.items()},
            "devices": {k: v.to_dict() for k, v in self._state.devices.items()},
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            self._fingerprint = _fingerprint(self.path)
        except OSError:
            # 写失败：内存策略仍在（本次进程继续生效），指纹不更新 →
            # 下次请求会重读文件自动收敛；stderr 留痕给运维。
            import sys

            print(f"警告：策略文件写入失败（{self.path}）", file=sys.stderr)

    def _refresh(self) -> None:
        fp = _fingerprint(self.path)
        if fp != self._fingerprint:
            self._state = self._load()
            self._fingerprint = fp

    # -- 查询（请求路径，热加载） -----------------------------------------

    def _entry(self, kind: str, value: str) -> PolicyEntry | None:
        with self._lock:
            self._refresh()
            table = self._state.ips if kind == KIND_IP else self._state.devices
            return table.get(value)

    def is_ip_blocked(self, ip: str) -> bool:
        entry = self._entry(KIND_IP, ip)
        return bool(entry and entry.blocked)

    def is_ip_priority(self, ip: str) -> bool:
        entry = self._entry(KIND_IP, ip)
        return bool(entry and entry.priority)

    def is_device_blocked(self, *identifiers: str) -> bool:
        """设备是否被拉黑。identifiers 按序匹配（did → 令牌名），命中即真。"""
        for value in identifiers:
            if not value:
                continue
            entry = self._entry(KIND_DEVICE, value)
            if entry and entry.blocked:
                return True
        return False

    def is_device_priority(self, *identifiers: str) -> bool:
        for value in identifiers:
            if not value:
                continue
            entry = self._entry(KIND_DEVICE, value)
            if entry and entry.priority:
                return True
        return False

    # -- 管理（后台控制台/CLI） -------------------------------------------

    def set(self, kind: str, value: str, *, blocked: bool | None = None,
            priority: bool | None = None, note: str | None = None) -> PolicyEntry:
        """设置/更新一条策略。value 非空校验在这里收口。"""
        value = value.strip()
        if not value:
            raise PolicyError("策略值不能为空")
        if kind not in (KIND_IP, KIND_DEVICE):
            raise PolicyError(f"未知策略类型 {kind!r}")
        with self._lock:
            self._refresh()
            table = self._state.ips if kind == KIND_IP else self._state.devices
            entry = table.setdefault(value, PolicyEntry())
            if blocked is not None:
                entry.blocked = blocked
                if blocked:
                    entry.priority = False  # 拉黑与优先互斥，拉黑赢
            if priority is not None:
                if priority and entry.blocked:
                    raise PolicyError(f"{value} 已被拉黑，先解除拉黑再设优先")
                entry.priority = priority
            if note is not None:
                entry.note = note
            self._save()
            return entry

    def remove(self, kind: str, value: str) -> bool:
        with self._lock:
            self._refresh()
            table = self._state.ips if kind == KIND_IP else self._state.devices
            if value in table:
                del table[value]
                self._save()
                return True
            return False

    def state(self) -> dict[str, Any]:
        with self._lock:
            self._refresh()
            return {
                "path": str(self.path),
                "ips": {k: v.to_dict() for k, v in self._state.ips.items()},
                "devices": {k: v.to_dict() for k, v in self._state.devices.items()},
            }
