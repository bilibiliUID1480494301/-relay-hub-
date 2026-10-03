"""用户与计费（对标 new-api 的用户/额度/兑换码/计费规则，纯 stdlib 版）。

设计取舍（刻意的，与 new-api 的差异）：
  * **额度单位 = 点**。成本 = 输入/输出 tokens 按单价折点 × 用户分组倍率，
    向上取整。不做表达式定价——那是多租户商业化的复杂度，这里用不上。
  * **成功才扣费**。new-api 有「输入预消耗倍率」防刷；我们先不做预扣，
    因为 test 令牌不烧真钱、normal 令牌只发给自己人。被刷了再加预扣。
  * **密码 PBKDF2-HMAC-SHA256**（10 万轮），格式 `pbkdf2$iter$salt$hash`。
  * 用户与令牌的关系：DownstreamToken.user_id 关联（空 = 无主令牌，
    走旧的设备令牌逻辑，不参与计费）。
  * 兑换码一次性：核销后记录 used_by/used_at，不可复用。
  * 热加载指纹与 tokens.py 同源：排除运行时字段（quota 扣减会频繁写盘）。
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

PBKDF2_ITERATIONS = 100_000
# 这些字段是运行时状态，不参与指纹（quota 每请求都可能变，指纹变了就是每请求重载）
_RUNTIME_ONLY_FIELDS = ("used",)


class UserError(RuntimeError):
    """用户系统的配置或使用错误。"""


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, hash_hex = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
        return secrets.compare_digest(digest.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


@dataclass
class User:
    user_id: str
    username: str
    password_hash: str
    role: str = "user"  # admin | user
    enabled: bool = True
    # 剩余额度（点）。0 = 用尽；-1 = 不限量（管理员自己）
    quota: int = 0
    used: int = 0
    group: str = "default"
    note: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        data = asdict(self)
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "User":
        return cls(
            user_id=str(raw.get("user_id") or uuid.uuid4()),
            username=str(raw.get("username") or ""),
            password_hash=str(raw.get("password_hash") or ""),
            role=str(raw.get("role") or "user"),
            enabled=bool(raw.get("enabled", True)),
            quota=int(raw.get("quota", 0) or 0),
            used=int(raw.get("used", 0) or 0),
            group=str(raw.get("group") or "default"),
            note=str(raw.get("note", "")),
            created_at=float(raw.get("created_at", 0.0) or 0.0),
        )


def _fingerprint(path: Path) -> str | None:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    blob = json.dumps(
        {k: v for k, v in raw.items() if k != "users"},
        sort_keys=True,
        ensure_ascii=False,
    )
    users = [
        {k: v for k, v in item.items() if k not in _RUNTIME_ONLY_FIELDS}
        for item in raw.get("users") or []
        if isinstance(item, dict)
    ]
    blob += json.dumps(users, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class UserPool:
    """一组用户 + 鉴权 + 计费规则。纯数据；热加载在 UserStore。"""

    def __init__(
        self,
        users: list[User] | None = None,
        *,
        allow_register: bool = False,
        default_quota: int = 1000,
        price_in_per_1k: float = 2.0,
        price_out_per_1k: float = 6.0,
        groups: dict[str, float] | None = None,
    ) -> None:
        self.users: list[User] = list(users or [])
        self.allow_register = bool(allow_register)
        self.default_quota = int(default_quota)
        self.price_in_per_1k = float(price_in_per_1k)
        self.price_out_per_1k = float(price_out_per_1k)
        self.groups: dict[str, float] = dict(groups or {"default": 1.0})

    @classmethod
    def load(cls, path: Path) -> "UserPool":
        path = Path(path)
        if not path.is_file():
            return cls()
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            [User.from_dict(item) for item in raw.get("users", [])],
            allow_register=bool(raw.get("allow_register", False)),
            default_quota=int(raw.get("default_quota", 1000) or 0),
            price_in_per_1k=float(raw.get("price_in_per_1k", 2.0) or 0.0),
            price_out_per_1k=float(raw.get("price_out_per_1k", 6.0) or 0.0),
            groups={str(k): float(v) for k, v in (raw.get("groups") or {"default": 1.0}).items()},
        )

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schemaVersion": 1,
            "allow_register": self.allow_register,
            "default_quota": self.default_quota,
            "price_in_per_1k": self.price_in_per_1k,
            "price_out_per_1k": self.price_out_per_1k,
            "groups": self.groups,
            "users": [u.to_dict() for u in self.users],
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # -- 查询 ------------------------------------------------------------

    def get(self, user_id: str) -> User | None:
        return next((u for u in self.users if u.user_id == user_id), None)

    def find_by_name(self, username: str) -> User | None:
        return next((u for u in self.users if u.username == username), None)

    def multiplier_for(self, user: User) -> float:
        return self.groups.get(user.group, 1.0)

    def cost_of(self, user: User, tokens_in: int, tokens_out: int) -> int:
        """按 tokens 折点 × 分组倍率，向上取整。额度 -1（不限量）不参与计费。"""
        if user.quota < 0:
            return 0
        base = tokens_in / 1000.0 * self.price_in_per_1k + tokens_out / 1000.0 * self.price_out_per_1k
        if base <= 0:
            return 0
        return max(1, math.ceil(base * self.multiplier_for(user)))

    # -- 增删改（调用方负责持锁与落盘） -----------------------------------

    def register(self, username: str, password: str, *, role: str = "user") -> User:
        """开放注册走这里（受 allow_register 门控的判断在调用方）。"""
        username = username.strip()
        if not 3 <= len(username) <= 32:
            raise UserError("用户名长度 3-32")
        if len(password) < 8:
            raise UserError("密码至少 8 位")
        if self.find_by_name(username):
            raise UserError(f"用户名已存在：{username}")
        user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            password_hash=hash_password(password),
            role=role,
            quota=self.default_quota,
        )
        self.users.append(user)
        return user

    def verify(self, username: str, password: str) -> User | None:
        user = self.find_by_name(username.strip())
        if user is None or not user.enabled:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    def deduct(self, user_id: str, cost: int) -> bool:
        """直接扣减。额度 -1 = 不限量恒通过；余额不足返回 False（不透支）。"""
        user = self.get(user_id)
        if user is None:
            return False
        if user.quota < 0:
            user.used += max(0, cost)
            return True
        if user.quota < cost:
            return False
        user.quota -= cost
        user.used += cost
        return True

    def pre_consume(self, user_id: str, estimated: int) -> bool:
        """预扣（对标 new-api 的 input pre-consume）：relay 前先冻结节Estimated 点。

        防「发大 prompt 中途断开白嫖上游」——成功后由 settle 多退少补，
        失败全额退还。额度 -1 = 不限量，不参与预扣。
        """
        if estimated <= 0:
            return True
        user = self.get(user_id)
        if user is None or user.quota < 0:
            return True
        if user.quota < estimated:
            return False
        user.quota -= estimated
        user.used += estimated
        return True

    def settle(self, user_id: str, pre: int, actual: int) -> None:
        """结算：把预扣的 pre 调整为实际 actual（多退少补）。用户不存在则静默跳过。"""
        user = self.get(user_id)
        if user is None:
            return
        delta = max(0, pre) - max(0, actual)
        if user.quota >= 0:
            user.quota += delta
        user.used = max(0, user.used - delta)


class UserStore:
    """包住 UserPool：users.json 被外部改动（管理面加用户/发额度）就重载。

    与 TokenStore 同一套指纹+锁思路。deduct 在锁内改内存+落盘，
    多线程扣费不会超卖。"""
    _NO_USERS = object()

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._fingerprint = _fingerprint(self.path)
        self._pool = UserPool.load(self.path)

    @property
    def pool(self) -> UserPool:
        return self._current()

    def _current(self) -> UserPool:
        fingerprint = _fingerprint(self.path)
        if fingerprint != self._fingerprint:
            with self._lock:
                fingerprint = _fingerprint(self.path)
                if fingerprint != self._fingerprint:
                    self._pool = UserPool.load(self.path)
                    self._fingerprint = fingerprint
        return self._pool

    def mutate(self, change) -> None:
        """锁内改内存再落盘（change(pool) 可以抛 UserError，落盘前不生效）。"""
        with self._lock:
            change(self._pool)
            self._pool.save(self.path)

    def _reload_locked(self) -> None:
        """锁内的指纹检查+重载（_current 的锁不可重入，这里手动展开——
        与 TokenStore.add 的处理同源，否则 register/deduct 里调用 _current 会自锁死）。"""
        fingerprint = _fingerprint(self.path)
        if fingerprint != self._fingerprint:
            self._pool = UserPool.load(self.path)
            self._fingerprint = fingerprint

    def register(self, username: str, password: str) -> User:
        with self._lock:
            self._reload_locked()
            pool = self._pool
            if not pool.allow_register:
                raise UserError("本站未开放注册")
            user = pool.register(username, password)
            pool.save(self.path)
            return user

    def verify(self, username: str, password: str) -> User | None:
        return self._current().verify(username, password)

    def deduct(self, user_id: str, cost: int) -> bool:
        if cost <= 0:
            return True
        with self._lock:
            self._reload_locked()
            ok = self._pool.deduct(user_id, cost)
            if ok:
                self._pool.save(self.path)
            return ok

    def pre_consume(self, user_id: str, estimated: int) -> bool:
        """预扣（锁内检查+扣+落盘）。失败（余额不足）返回 False。"""
        if estimated <= 0:
            return True
        with self._lock:
            self._reload_locked()
            ok = self._pool.pre_consume(user_id, estimated)
            if ok:
                self._pool.save(self.path)
            return ok

    def settle(self, user_id: str, pre: int, actual: int) -> None:
        """结算（锁内多退少补+落盘）。"""
        with self._lock:
            self._reload_locked()
            self._pool.settle(user_id, pre, actual)
            self._pool.save(self.path)


@dataclass
class RedeemCode:
    code: str
    credits: int
    created_at: float = field(default_factory=time.time)
    used_by: str = ""
    used_at: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "RedeemCode":
        return cls(
            code=str(raw.get("code") or ""),
            credits=int(raw.get("credits", 0) or 0),
            created_at=float(raw.get("created_at", 0.0) or 0.0),
            used_by=str(raw.get("used_by") or ""),
            used_at=float(raw.get("used_at", 0.0) or 0.0),
        )


class RedeemStore:
    """兑换码：一次性核销。codes.json 与 users.json 同目录。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def _load(self) -> list[RedeemCode]:
        if not self.path.is_file():
            return []
        return [RedeemCode.from_dict(i) for i in json.loads(self.path.read_text(encoding="utf-8")).get("codes", [])]

    def _save(self, codes: list[RedeemCode]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"schemaVersion": 1, "codes": [c.to_dict() for c in codes]}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def generate(self, count: int, credits: int, *, prefix: str = "rhx") -> list[RedeemCode]:
        with self._lock:
            codes = self._load()
            fresh = [
                RedeemCode(code=f"{prefix}-{secrets.token_hex(8)}", credits=max(1, int(credits)))
                for _ in range(max(1, min(count, 100)))
            ]
            codes.extend(fresh)
            self._save(codes)
            return fresh

    def list(self) -> list[RedeemCode]:
        with self._lock:
            return self._load()

    def redeem(self, code: str, user_id: str) -> int:
        """核销：一次性。成功返回点数；无效/已用抛 UserError。"""
        with self._lock:
            codes = self._load()
            found = next((c for c in codes if secrets.compare_digest(c.code, code.strip())), None)
            if found is None:
                raise UserError("兑换码不存在")
            if found.used_by:
                raise UserError("兑换码已被使用")
            found.used_by = user_id
            found.used_at = time.time()
            self._save(codes)
            return found.credits
