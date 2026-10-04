"""带外配对：新设备用一枚一次性 6 位码换取它自己的下游令牌。

这是目标链路「局域网发现 → 加密配对 → 写入配置」的中间一环，标准库简化版：

    网关侧：relayhub.gateway pair begin        → 生成 6 位码 + 写配对窗口文件，码显示在控制台
    设备侧：relayhub.gateway pair request      → 发现网关（discovery.py）→ POST /v1/pair 带码
    成  功：serve 兑换 → 发放该设备专属的 DownstreamToken → 返回对应客户端的 onboarding 载荷

两种发放模式（serve --pair-mode）：

  * `code`（默认）：下面的窗口/兑换流程。端点平时关闭，开窗才有攻击面。
  * `auto-lan`：可信局域网免码。仅当请求来源是回环/RFC1918 私有地址时，
    无码直接发放；同设备（同名单）幂等复用旧令牌，不发新。公网来源一律
    仍要配对码——对外服务关闭免码通道，攻击面不随便利扩大。

安全模型（诚实版，不是「已加密」版）：

  * 码是**带外**传递的（人眼从网关控制台抄到设备），6 位、单窗口单码、
    默认 5 分钟过期、最多 5 次尝试——爆破上限被窗口锁死。
  * 成功即焚：兑换成功后窗口文件删除，同一枚码不能换第二枚令牌。
  * **明示的残余风险**：/v1/pair 走 HTTP 明文，同网段攻击者在窗口内抓包
    可以看到码与令牌。README「六」规划的 X25519→HKDF→AES-GCM 属于加密套件
    那一步，标准库做不了，这里不假装做了；窗口短 + 单次 + 可随时 cancel
    是现阶段的风险控制。auto-lan 模式下令牌本身就在内网明文飞，风险等同。
  * 端点默认**关闭**：没有窗口文件且未开 auto-lan 时 /v1/pair 直接拒绝。

状态走文件（pairing.json）而不是进程内存：开窗在控制面进程、兑换在数据面
进程，唯一可靠的共享物就是文件——与号池/令牌同一套架构约定。
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import secrets
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from . import audit
from .tokens import TokenPool
from .tokens import DownstreamToken, TokenStore, generate_token

PAIRING_TTL = 300.0
PAIRING_MAX_ATTEMPTS = 5


class PairingError(RuntimeError):
    """配对被拒（无窗口/过期/次数用尽/码错/设备名冲突）。message 会直接回给客户端。"""


def open_window(
    path: Path,
    *,
    client_id: str,
    ttl: float = PAIRING_TTL,
    clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """开一个配对窗口（已开的话旧窗口作废——同时只允许一枚活码，好排查也好收回）。"""
    code = f"{secrets.randbelow(1_000_000):06d}"
    window = {
        "schemaVersion": 1,
        "window_id": str(uuid.uuid4()),
        "code": code,
        "client_id": client_id,
        "expires_at": clock() + ttl,
        "attempts": 0,
        "max_attempts": PAIRING_MAX_ATTEMPTS,
    }
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(window, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    audit.record("pair.begin", path=audit_path_of(path), client_id=client_id, ttl=ttl)
    return window


def cancel_window(path: Path) -> bool:
    """手动关窗。返回是否有窗可关。"""
    path = Path(path)
    existed = path.is_file()
    if existed:
        path.unlink()
        audit.record("pair.cancel", path=audit_path_of(path))
    return existed


def window_open(path: Path, *, clock: Callable[[], float] = time.time) -> bool:
    """给发现应答器用的轻量判断：窗口开着且未过期。"""
    window = _read_window(path)
    return window is not None and clock() < float(window.get("expires_at") or 0)


class PairingService:
    """数据面侧的兑换器。挂在 serve 上，处理 /v1/pair。"""

    def __init__(
        self,
        tokens: TokenStore,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.tokens = tokens
        self.path = Path(path)
        self._clock = clock

    # -- 查询 ------------------------------------------------------------

    def window_open(self) -> bool:
        return window_open(self.path, clock=self._clock)

    # -- 兑换 ------------------------------------------------------------

    def redeem(self, code: str, device_name: str, client_id: str) -> DownstreamToken:
        """校验码 → 发令牌 → 焚窗。任何拒绝都会留下 pair.reject 审计。"""
        window = self._read_window()
        now = self._clock()
        if window is None:
            raise self._reject("没有开启中的配对窗口")
        if now >= float(window.get("expires_at") or 0):
            raise self._reject("配对码已过期，请在网关重新执行 `pair begin`")
        attempts = int(window.get("attempts") or 0)
        max_attempts = int(window.get("max_attempts") or PAIRING_MAX_ATTEMPTS)
        if attempts >= max_attempts:
            raise self._reject("尝试次数已用尽，请在网关重新执行 `pair begin`")

        expected = str(window.get("code") or "")
        if not code or not expected or not hmac.compare_digest(code, expected):
            window["attempts"] = attempts + 1
            self._write_window(window)
            remaining = max_attempts - attempts - 1
            raise self._reject(f"配对码不正确（剩余 {remaining} 次尝试）")

        window_client = str(window.get("client_id") or "")
        if client_id and window_client and client_id != window_client:
            raise self._reject(f"该窗口只给客户端 {window_client} 配对，收到 {client_id!r}")

        name = _sanitize_device_name(device_name)
        record = DownstreamToken(
            token_id=str(uuid.uuid4()),
            name=name,
            token=generate_token(),
            note=f"paired:{window_client or client_id or 'unknown'}",
        )
        try:
            self.tokens.add(record)
        except Exception as exc:  # TokenError（重名等）——窗不焚，让设备改名重试
            raise self._reject(f"令牌发放失败：{exc}") from exc

        self._remove_window()
        audit.record(
            "pair.success",
            path=audit_path_of(self.path),
            device=name,
            client_id=window_client or client_id,
            token_hint=f"…{record.token[-4:]}",
        )
        return record

    # -- 免码配对（可信局域网） ---------------------------------------------

    def auto_pair(self, device_name: str, client_id: str, *, ip: str) -> DownstreamToken:
        """局域网免码发放：私有网段来源直接发，同设备重绑轮换旧令牌。

        幂等规则：note=autopaired:<client> 且同名且启用中的令牌视为同一台
        设备——重新绑定不新增令牌位，而是作废旧令牌、发放新枚（明文令牌
        落盘只存哈希，无法二次下发原文，轮换是唯一诚实的“再来一次”）。
        公网来源不走这里（_handle_pair 已挡），这里再校验一道纵深。
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise self._reject(f"无法识别来源地址 {ip!r}") from None
        if not (addr.is_private or addr.is_loopback):
            raise self._reject("免码配对只对局域网来源开放，公网请使用配对码")

        name = _sanitize_device_name(device_name)
        note = f"autopaired:{client_id or 'unknown'}"
        rotated = None
        for existing in self.tokens.pool.tokens:
            if existing.note == note and existing.name == name and existing.enabled:
                rotated = existing
                break
        record = DownstreamToken(
            token_id=str(uuid.uuid4()),
            name=name,
            token=generate_token(),
            note=note,
        )
        def _rotate_and_add(pool: TokenPool) -> None:
            # 删旧+加新必须在同一把锁里完成，避免并发窗口里同设备两枚钥匙
            if rotated is not None:
                pool.remove(rotated.token_id)
            pool.add(record)

        try:
            self.tokens.mutate(_rotate_and_add)
        except Exception as exc:  # TokenError（重名等）
            raise self._reject(f"令牌发放失败：{exc}") from exc
        audit.record(
            "pair.auto",
            path=audit_path_of(self.path),
            device=name,
            client_id=client_id,
            rotated=rotated is not None,
            ip=ip,
        )
        return record

    # -- 窗口文件 ----------------------------------------------------------

    def _read_window(self) -> dict[str, Any] | None:
        return _read_window(self.path)

    def _write_window(self, window: dict[str, Any]) -> None:
        self.path.write_text(
            json.dumps(window, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    def _remove_window(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass

    def _reject(self, message: str) -> PairingError:
        audit.record("pair.reject", path=audit_path_of(self.path), reason=message)
        return PairingError(message)


def _sanitize_device_name(raw: str) -> str:
    name = " ".join((raw or "").split())
    if not name:
        raise PairingError("缺少设备名 name")
    if len(name) > 40:
        raise PairingError("设备名过长（<= 40 字符）")
    return name


def _read_window(path: Path) -> dict[str, Any] | None:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return raw if isinstance(raw, dict) else None


def audit_path_of(path: Path):
    """审计落点跟随数据根（测试里传沙箱路径时审计也进沙箱）。

    pairing.json 在 RELAYHUB_HOME 下时审计用默认路径；在别处（沙箱/临时目录）
    时审计写到同目录，保证测试之间互不污染。
    """
    from .. import paths

    try:
        if Path(path).parent == paths.relayhub_home():
            return None  # None → audit.record 用默认路径
    except (OSError, RuntimeError):
        return None
    return Path(path).parent / "audit.jsonl"
