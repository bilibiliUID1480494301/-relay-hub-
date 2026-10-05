"""下游令牌：发给每个客户端设备的独立凭证（对标 one-api 的「令牌/Tokens」）。

one-api 里「渠道(channel)」对应本项目的号池，「令牌(token)」对应本文件——
发给每台客户端设备一个、可单独吊销的下游凭证。

为什么是独立的文件与模块，而不是塞进 `pool.py`：

1. **轮换语义相反**。上游 Key 换掉对客户端无感（网关自己消化）；
   下游令牌换掉必须重新推一次客户端配置——客户端不会自己发现凭证失效。
   混在一个文件里，很容易顺手把「加一个上游渠道」和「吊销一台设备」当成同一种操作。
2. **暴露面相反**。号池文件含上游 Key 明文，泄露 = 渠道被人白嫖；
   令牌文件里的每个 token 都发给过一台设备，泄露面天然更大，吊销必须按台操作。
3. **记账维度不同**。上游按渠道算成本，下游按设备/客户端算用量。

安全约定（与 `pool.py` 同级）：
  * token 明文存 JSON（与上游 Key 同级处理，磁盘加密属后续「加密套件」）。
  * 比对用 `hmac.compare_digest`；列表页只露尾 4 位，全文只在创建时打印一次。
  * 用量记账后整体落盘——与号池同样的「每请求一次整文件写」权衡，
    规模上去之后再做增量。

热加载指纹刻意排除用量字段：否则每服务一个请求指纹就变一次，
`serve` 进程里表现为「每请求 reload 一次」。坑与 `router.config_fingerprint` 完全同源。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Sequence

# 令牌前缀：让它在一堆 sk-/ak- 里一眼认出是本网关发的，也方便在日志里 grep。
TOKEN_PREFIX = "rht_"

# 令牌作用域：normal=正常走号池路由；test=本地合成应答（公网性能测试用，
# 绝不触达真实上游，也不烧渠道配额）。
SCOPE_NORMAL = "normal"
SCOPE_TEST = "test"
SCOPES = (SCOPE_NORMAL, SCOPE_TEST)

# 令牌安全（对标 new-api 的 SHA-256 存储）：
#   * 落盘只存 SHA-256 哈希 + 尾 4 位提示，**明文永不写盘**；
#   * 明文只在生成那一刻返回给创建者；
#   * 旧文件里的明文令牌在首次加载时自动迁移（算哈希、落 hint、清明文）。


def hash_token(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def token_hint_of(secret: str) -> str:
    return f"…{secret[-4:]}" if len(secret) > 4 else "…"


SCHEMA_VERSION = 1
# 这些字段是「服务过程中产生的状态」，不参与鉴权配置，指纹必须排除。
_RUNTIME_ONLY_FIELDS = ("usage",)


class TokenError(RuntimeError):
    """下游令牌的配置或使用错误。"""


@dataclass
class TokenUsage:
    requests: int = 0
    ok: int = 0
    failed: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    last_used: float = 0.0
    # 日配额记账：day=本地日期字符串，day_requests=当天已受理请求数。
    # 放在 usage 里是因为它们是运行时状态——指纹必须排除（否则每次请求都触发重载）。
    day: str = ""
    day_requests: int = 0
    # 客户端身份最近一次的样子：管理页「这台设备是谁」一眼可见。
    # 只存最近一次（不是历史）：历史在 reqlog 里，这里只是速览。
    last_ip: str = ""
    last_user: str = ""
    last_ver: str = ""
    last_device: str = ""
    last_device_id: str = ""

    def merge(self, tokens_in: int, tokens_out: int) -> None:
        self.tokens_in += max(0, int(tokens_in))
        self.tokens_out += max(0, int(tokens_out))


@dataclass
class DownstreamToken:
    token_id: str
    name: str
    token: str
    enabled: bool = True
    # 允许使用的模型；空 = 不限制。对标 one-api 令牌的「可用模型」范围。
    models: tuple[str, ...] = ()
    # 作用域（SCOPE_NORMAL / SCOPE_TEST）。test=合成应答，见 service.TestRouter。
    scope: str = SCOPE_NORMAL
    # 限额。0 = 不限。rpm=每分钟请求数（滑动窗口，进程内计数）；
    # daily_requests=每自然日请求数（随 usage 落盘，重启不清零）。
    rpm: int = 0
    daily_requests: int = 0
    # 有效期：epoch 秒；0 = 永不过期（对标 new-api 令牌默认 30 天过期的可配版）。
    expires_at: float = 0.0
    # 所属用户（users.py 的 user_id）。空 = 无主设备令牌，不参与用户计费。
    user_id: str = ""
    # 分组标签（用户分组）：同一批设备/同一个人可归同组，管理台按组筛选与汇总。
    # 归一化：空白→default；长度≤32；非法字符折叠为 -。
    group: str = "default"
    # SHA-256 哈希（落盘的唯一凭证形态）与尾 4 位提示。
    # token 字段是遗留明文：旧文件加载后内存里保留以兼容，**save 时一律清空**。
    token_hash: str = ""
    token_hint: str = ""
    note: str = ""
    created_at: float = field(default_factory=time.time)
    usage: TokenUsage = field(default_factory=TokenUsage)

    def __post_init__(self) -> None:
        if self.scope not in SCOPES:
            raise TokenError(f"未知 scope {self.scope!r}，可选 {SCOPES}")
        if self.rpm < 0 or self.daily_requests < 0:
            raise TokenError("限额不能为负数（0 = 不限）")
        self.group = _normalize_group(self.group)
        # 自动补哈希与提示（新建 / 旧文件迁移都在这里收口）
        if self.token and not self.token_hash:
            self.token_hash = hash_token(self.token)
        if self.token and not self.token_hint:
            self.token_hint = token_hint_of(self.token)

    def is_expired(self, now: float | None = None) -> bool:
        return bool(self.expires_at) and (now or time.time()) > self.expires_at

    def allows(self, model: str) -> bool:
        return not self.models or model in self.models

    def to_dict(self) -> dict:
        data = asdict(self)
        data["models"] = list(self.models)
        data["token"] = ""  # 明文永不落盘（对标 new-api 的 SHA-256 存储）
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "DownstreamToken":
        usage = raw.get("usage") or {}
        return cls(
            token_id=str(raw.get("token_id") or uuid.uuid4()),
            name=str(raw.get("name") or raw.get("token_id") or "unnamed"),
            token=str(raw.get("token", "")),
            enabled=bool(raw.get("enabled", True)),
            models=tuple(str(m) for m in (raw.get("models") or ())),
            # 未知 scope（旧文件/手改坏）回退 normal，别让一份脏文件卡死整个网关
            scope=str(raw.get("scope")) if raw.get("scope") in SCOPES else SCOPE_NORMAL,
            rpm=int(raw.get("rpm", 0) or 0),
            daily_requests=int(raw.get("daily_requests", 0) or 0),
            expires_at=float(raw.get("expires_at", 0.0) or 0.0),
            user_id=str(raw.get("user_id") or ""),
            group=str(raw.get("group") or "default"),
            token_hash=str(raw.get("token_hash", "")),
            token_hint=str(raw.get("token_hint", "")),
            note=str(raw.get("note", "")),
            created_at=float(raw.get("created_at", 0.0) or 0.0),
            usage=TokenUsage(
                requests=int(usage.get("requests", 0)),
                ok=int(usage.get("ok", 0)),
                failed=int(usage.get("failed", 0)),
                tokens_in=int(usage.get("tokens_in", 0)),
                tokens_out=int(usage.get("tokens_out", 0)),
                last_used=float(usage.get("last_used", 0.0) or 0.0),
                day=str(usage.get("day", "")),
                day_requests=int(usage.get("day_requests", 0) or 0),
                last_ip=str(usage.get("last_ip", "")),
                last_user=str(usage.get("last_user", "")),
                last_ver=str(usage.get("last_ver", "")),
                last_device=str(usage.get("last_device", "")),
                last_device_id=str(usage.get("last_device_id", "")),
            ),
        )


def generate_token() -> str:
    """生成一个下游令牌。24 字节十六进制 + 前缀，全程不落日志。"""
    return f"{TOKEN_PREFIX}{secrets.token_hex(24)}"


def _normalize_group(raw: str) -> str:
    """分组标签归一化：空→default；去首尾空白；超长截断；非法字符折叠为 -。"""
    text = str(raw or "").strip() or "default"
    text = re.sub(r"[^\w.-]+", "-", text, flags=re.UNICODE)
    return text[:32] or "default"


def _fingerprint(path: Path) -> str | None:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    stripped = {
        k: v for k, v in raw.items() if k != "tokens"
    }
    stripped["tokens"] = [
        {k: v for k, v in item.items() if k not in _RUNTIME_ONLY_FIELDS}
        for item in raw.get("tokens") or []
        if isinstance(item, dict)
    ]
    blob = json.dumps(stripped, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class TokenPool:
    """一组下游令牌 + 鉴权判定 + 按令牌记账。纯数据，不做热加载（那是 TokenStore 的事）。"""

    def __init__(self, tokens: Sequence[DownstreamToken] = ()) -> None:
        self.tokens: list[DownstreamToken] = list(tokens)

    # -- 存取 ------------------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "TokenPool":
        """文件不存在返回空池而不是报错：首次启用前 serve 不该被令牌文件卡住。"""
        path = Path(path)
        if not path.is_file():
            return cls([])
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls([DownstreamToken.from_dict(item) for item in raw.get("tokens", [])])

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schemaVersion": SCHEMA_VERSION,
            "tokens": [t.to_dict() for t in self.tokens],
        }
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # -- 增删改 ----------------------------------------------------------

    def get(self, token_id: str) -> DownstreamToken | None:
        for token in self.tokens:
            if token.token_id == token_id:
                return token
        return None

    def find_by_name(self, name: str) -> DownstreamToken | None:
        for token in self.tokens:
            if token.name == name:
                return token
        return None

    def add(self, token: DownstreamToken) -> DownstreamToken:
        if not token.token.strip():
            raise TokenError("token 不能为空")
        if not token.name.strip():
            raise TokenError("name 不能为空（设备名，吊销时按它找）")
        if self.get(token.token_id) or self.find_by_name(token.name):
            raise TokenError(f"token_id 或 name 已存在：{token.token_id} / {token.name}")
        self.tokens.append(token)
        return token

    def remove(self, identifier: str) -> bool:
        """按 token_id / name / token 全文三选一删除。吊销场景往往只拿得到其中一个。"""
        for index, token in enumerate(self.tokens):
            if token.token_id == identifier or token.name == identifier or token.token == identifier:
                del self.tokens[index]
                return True
        return False

    def set_enabled(self, identifier: str, enabled: bool) -> bool:
        found = (
            self.get(identifier)
            or self.find_by_name(identifier)
            or next((t for t in self.tokens if t.token == identifier), None)
        )
        if found is None:
            return False
        found.enabled = enabled
        return True

    # -- 鉴权与记账 ------------------------------------------------------

    def find(self, secret: str) -> DownstreamToken | None:
        """按凭证全文找令牌：先比对 SHA-256（哈希存储），再兼容遗留明文。
        恒定时间比较，逐个比——令牌数量级是「设备数」，不是千级。"""
        if not secret:
            return None
        secret_hash = hash_token(secret)
        for token in self.tokens:
            if token.token_hash and hmac.compare_digest(token.token_hash, secret_hash):
                return token
            if token.token and hmac.compare_digest(token.token, secret):
                return token
        return None

    def report(
        self, token: DownstreamToken, ok: bool, tokens_in: int = 0, tokens_out: int = 0
    ) -> None:
        token.usage.requests += 1
        if ok:
            token.usage.ok += 1
        else:
            token.usage.failed += 1
        token.usage.merge(tokens_in, tokens_out)
        token.usage.last_used = time.time()

    def admit(self, token: DownstreamToken) -> tuple[bool, str]:
        """日配额准入：跨天先清零，再检查并预扣一个名额。

        必须在 TokenStore 的锁内调用（与 report 同一把锁），否则并发请求会超卖。
        「预扣」意味着配额按受理计数，失败的请求也占额——与 one-api 的语义一致，
        且省掉了「请求失败再退还」的复杂性。

        返回 (是否放行, 拒绝原因)。rpm 不在这里管——它是进程内滑动窗口，
        由网关的 RateLimiter 负责，不需要落盘。
        """
        today = time.strftime("%Y-%m-%d")
        usage = token.usage
        if usage.day != today:
            usage.day = today
            usage.day_requests = 0
        if token.daily_requests and usage.day_requests >= token.daily_requests:
            return False, f"已达日配额 {token.daily_requests} 请求/天"
        usage.day_requests += 1
        return True, ""

    def stats(self) -> dict:
        return {
            "token_count": len(self.tokens),
            "enabled_count": len([t for t in self.tokens if t.enabled]),
            "tokens": [
                {
                    "token_id": t.token_id,
                    "name": t.name,
                    "enabled": t.enabled,
                    "group": t.group,
                    "token_hint": t.token_hint or token_hint_of(t.token),
                    "models": list(t.models),
                    "scope": t.scope,
                    "rpm": t.rpm,
                    "daily_requests": t.daily_requests,
                    "day_requests": t.usage.day_requests,
                    "expires_at": t.expires_at,
                    "expired": t.is_expired(),
                    "note": t.note,
                    "usage": asdict(t.usage),
                }
                for t in self.tokens
            ],
        }


class TokenStore:
    """包住 TokenPool：tokens.json 被外部改动（比如刚跑了一次 `token add`）就重新加载。

    与 `router.ReloadingRouter` 同一套指纹思路，但锁在这里：
    每个请求线程都要过鉴权 + 记账，读写必须串行化。
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        # 先记指纹再加载：与 ReloadingRouter 相同的顺序理由——
        # 反过来会出现「内存里是旧令牌、指纹却是新文件的」，从此永不刷新。
        self._fingerprint = _fingerprint(self.path)
        self._pool = TokenPool.load(self.path)

    @property
    def pool(self) -> TokenPool:
        return self._current()

    def _current(self) -> TokenPool:
        fingerprint = _fingerprint(self.path)
        if fingerprint != self._fingerprint:
            with self._lock:
                fingerprint = _fingerprint(self.path)
                if fingerprint != self._fingerprint:
                    self._pool = TokenPool.load(self.path)
                    self._fingerprint = fingerprint
        return self._pool

    # -- 与 TokenPool 同形（每次都走热加载检查） ---------------------------

    def find(self, secret: str) -> DownstreamToken | None:
        return self._current().find(secret)

    def by_id(self, token_id: str) -> DownstreamToken | None:
        """按 token_id 取令牌。

        与 `find(明文)` 的区别是它不需要明文——TOIP 轮换会话令牌时，通行证
        里只记着上一次发出的 token_id，靠它找回旧令牌好作废（明文落盘只存
        哈希，拿不回原文，轮换是唯一诚实的「再来一次」）。
        """
        if not token_id:
            return None
        return self._current().get(token_id)

    def add(self, token: DownstreamToken) -> DownstreamToken:
        """发放一枚令牌（配对流程用）。

        必须复用锁内的内存池而不是重新 load：池里带着每请求累积的用量，
        重新 load 会把「加令牌前最后一个请求」的记账抹掉。

        指纹检查在这里手动展开、不能调 `_current()`：那把锁不可重入，
        `_current()` 在指纹变化时会再抢一次锁，锁内调它就是自锁死。
        """
        with self._lock:
            fingerprint = _fingerprint(self.path)
            if fingerprint != self._fingerprint:
                self._pool = TokenPool.load(self.path)
                self._fingerprint = fingerprint
            self._pool.add(token)
            self._pool.save(self.path)
            return token

    def report(
        self, token: DownstreamToken, ok: bool, tokens_in: int = 0, tokens_out: int = 0
    ) -> None:
        with self._lock:
            self._pool.report(token, ok, tokens_in, tokens_out)
            self._pool.save(self.path)

    def admit(self, token: DownstreamToken) -> tuple[bool, str]:
        """日配额准入（锁内检查+预扣+落盘）。拒绝时也要落盘：跨天清零的改动不能丢。

        每次 admit 多一次整文件写（与 report 同级代价）——当前「设备数」量级下
        可接受，规模上去后与 report 一起改增量。
        """
        with self._lock:
            ok, reason = self._pool.admit(token)
            self._pool.save(self.path)
            return ok, reason

    def mutate(self, change) -> None:
        """锁内对内存池做任意修改再落盘（change(pool) 抛异常则不落盘）。

        用户面板发/换 API Key 用：先删同 user_id 的旧令牌再 add，
        两步必须同锁完成，否则并发窗口里能出现「同一个用户两枚钥匙」。
        """
        with self._lock:
            change(self._pool)
            self._pool.save(self.path)

    def stats(self) -> dict:
        return self._current().stats()
