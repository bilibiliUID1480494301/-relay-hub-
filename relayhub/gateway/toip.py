"""TOIP：中转站动态口令接入协议（Time-based One-time password Ingestion Protocol）。

TOIP 解决的是 `pairing.py` 留下的那个缺口。配对码的三条约束让它天生不能
给「插件」用：

  * **手动**：必须在网关控制台执行 `pair begin` 才有码，没人开窗就接不进来；
  * **一次性**：成功即焚，插件换机/重装/清配置就得再找管理员要一枚；
  * **不认品牌**：码对所有人一样，网关事后分不清「这个请求来自哪个插件」。

TOIP 把接入凭证从「一次性事件」改成「**可轮转的口令**」，于是插件只需要
一个网址 + 一个动态口令就能自助接入，网关侧始终知道对方是谁：

    管理员一次：hubrelay toip ticket --name dsh-laptop --plugins dsh-relayhub-bridge
                → 产出 station id、口令种子（base32）、**登记口令**（TOTP 当前值）
    插件一次  ：填网址（局域网可自动发现）+ 登记口令 → POST /v1/toip/join
                → 换回长效会话令牌 rht_… + base_url + 可选模型清单
    插件常驻  ：带着会话令牌请求 /v1/messages，并附插件身份头

三条设计红线（与 `pool.py`/`tokens.py`/`audit.py` 同级）：

1. **零依赖**。TOTP 只用 stdlib 的 hmac/hashlib/base64——`wbtoken.py` 已经
   证明这条路走得通（那里给厂商接口算口令签名）。引 pyotp 会把「pip install
   hubrelay 就完事」变成「还要拖一棵依赖树」，中转站不吃这个。
2. **口令种子落盘存哈希**。与 `tokens.py` 的令牌同纪律：磁盘上只有
   SHA-256 与尾 4 位提示，明文只在 `toip ticket` 打印那一次。种子泄露 =
   谁能算出下一枚口令，这个暴露面和令牌明文完全等价。
3. **拒绝不留盲区**。每一次拒绝都写 `toip.reject` 审计并计入尝试次数，
   与 `pairing.py` 的 `pair.reject` 同构——能被爆破的口令必须留下痕迹。

诚实的安全边界（不假装做到了没做到的事）：

  * 走 HTTP 明文时，口令与会话令牌都在同网段可见——与配对码相同的残余风险，
    README 的「加密套件」一步才能真正关掉。TTL 与窗口滚动是现阶段的风险控制。
  * **不含重放防护**：同一个 30 秒窗口内，同一枚口令可被重复提交。理由是
    接入动作本身不产生副作用（重复 join 幂等轮换同一枚令牌），而做严格
    一次性会让「插件重装后同窗口内重试」直接失败——可用性亏得比安全多。
    真要跟重放较劲，请上 HTTPS，那里的窗口只有攻击者拿不到种子才安全。
  * 口令窗口 30 秒、默认容错 ±1 个窗口（±30s 时钟漂移）。网关与插件
    时钟差超过 30 秒会接入失败——这是 TOTP 的固有约束，报错里明写。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import secretbox
from .atomicio import write_json_atomic
from .tokens import DownstreamToken, TokenStore, generate_token, token_hint_of

# ---------------------------------------------------------------- 协议常量

# 协议版本：出现在每一个 TOIP 响应的 protocol 字段里，客户端据此判断兼容性。
PROTOCOL = "toip"
PROTOCOL_VERSION = 1

# 时间步长（秒）。30 秒是 RFC 6238 的通行值，也是各家验证器 App 的默认值——
# 选它意味着管理员可以用手机上的验证器直接读出口令，不必跑 hubrelay。
TOTP_STEP = 30.0
TOTP_DIGITS = 6
# TOTP 哈希算法。SHA-1 是 RFC 6238 的默认值，也是各家验证器 App 唯一
# 普遍支持的算法；这里没有「换个更强的哈希」的余地，兼容性压过洁癖。
TOTP_ALGORITHM = "sha1"

# 时钟容错：接受 ±1 个窗口。网关与插件时钟漂移超过 30 秒即拒绝——
# 这类失败必须给出「是不是时钟不对」的提示，否则排查方向会被带到密钥上。
TOTP_WINDOW = 1

# 会话令牌默认有效期（秒）。90 天是「一次接入管一季」的工程取舍：
# 比令牌默认永不过期保守，又不至于让插件每周重新填一次口令。
SESSION_TTL = 90 * 24 * 3600.0

# join 的尝试上限（每个来源 IP 在一个窗口内）。动态口令可以被在线爆破，
# 上限把它锁死；与 pairing.py 的 max_attempts 同思路但按 IP 独立计数。
JOIN_MAX_ATTEMPTS = 8
JOIN_ATTEMPT_WINDOW = 300.0

# 登记口令（管理员用口令本身换一枚一次性 join 凭据）的有效期。
ENROLL_TICKET_TTL = 900.0

# 会话令牌前缀。复用下游令牌的 rht_ 词表：它就是一枚普通下游令牌，
# 落在同一个 tokens.json 里，沿用同一套限流/记账/吊销路径。
SESSION_TOKEN_PREFIX = "rht_"

# 插件身份头。网关只认这几个头，且只用于「分流日志」，不参与鉴权——
# 鉴权永远只看下游令牌（会话令牌）。头名与 DSH 官方的
# x-deepseek-harness-session-id 并列而不冲突，两边都能被上游单独识别。
#
# 两个插件 id 头是**同一语义的两个名字**：DSH 插件按自己的品牌发
# `X-DSH-Plugin-Id`，其他宿主（将来的别的客户端）发中性名。网关先认前者，
# 再认后者，最后回退到会话令牌上的 TOIP 绑定。
PLUGIN_ID_HEADER = "X-DSH-Plugin-Id"
PLUGIN_ID_HEADER_GENERIC = "X-Relayhub-Plugin-Id"
PLUGIN_VERSION_HEADER = "X-DSH-Plugin-Version"
STATION_ID_HEADER = "X-Relayhub-Station-Id"

# 插件 id 与站点 id 的字符集：够宽松（kebab-case、点分命名空间），
# 又要能安全地当目录名用——不含路径分隔符与 ..，日志按 id 建目录才不会逃逸。
_SAFE_LABEL = "abcdefghijklmnopqrstuvwxyz0123456789._-"


class ToipError(RuntimeError):
    """TOIP 接入被拒。message 会直接回给客户端（中文，附带排查方向）。"""


# ---------------------------------------------------------------- TOTP 内核


def b32encode(secret: bytes) -> str:
    """把口令种子编成 base32（去掉 = 填充），管理员抄写/喂验证器 App 用。"""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def b32decode(text: str) -> bytes:
    """解 base32 种子，宽容大小写、空格、连字符与缺失的填充。"""
    cleaned = "".join(ch for ch in str(text).strip().upper() if ch not in " -_")
    if not cleaned:
        raise ToipError("口令种子为空")
    padding = "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        return base64.b32decode(cleaned + padding, casefold=True)
    except Exception as exc:  # binascii.Error / ValueError
        raise ToipError("口令种子不是合法的 base32（请检查是否抄漏了字符）") from exc


def new_secret() -> bytes:
    """生成 20 字节（160 bit）种子——RFC 4226 建议的 HMAC-SHA1 密钥长度。"""
    return secrets.token_bytes(20)


def totp_at(secret: bytes, *, at: float, step: float = TOTP_STEP, digits: int = TOTP_DIGITS) -> str:
    """按 RFC 6238 算某个时刻的动态口令（HOTP 截断）。"""
    counter = int(at // step)
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % (10 ** digits):0{digits}d}"


def totp_now(secret: bytes, *, clock: Callable[[], float] = time.time) -> str:
    """当前窗口的动态口令。"""
    return totp_at(secret, at=clock())


def totp_seconds_left(*, clock: Callable[[], float] = time.time) -> float:
    """当前窗口还剩几秒。插件可以在录入界面显示它，减少「刚好跨窗」的失败。"""
    return TOTP_STEP - (clock() % TOTP_STEP)


def verify_totp(
    secret: bytes,
    code: str,
    *,
    clock: Callable[[], float] = time.time,
    window: int = TOTP_WINDOW,
) -> bool:
    """校验动态口令，允许 ±window 个窗口的时钟漂移。常数时间比较。"""
    supplied = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(supplied) != TOTP_DIGITS:
        return False
    now = clock()
    for shift in range(-window, window + 1):
        expected = totp_at(secret, at=now + shift * TOTP_STEP)
        if hmac.compare_digest(supplied, expected):
            return True
    return False


def otpauth_uri(secret_text: str, *, label: str, issuer: str = "relayhub") -> str:
    """给验证器 App 扫的标准 otpauth:// URI（管理员不想跑 hubrelay 时用）。"""
    from urllib.parse import quote

    return (
        f"otpauth://totp/{quote(issuer)}:{quote(label)}"
        f"?secret={secret_text}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={int(TOTP_STEP)}"
    )


# ---------------------------------------------------------------- 站点身份

STATION_SCHEMA_VERSION = 1


@dataclass
class StationIdentity:
    """本站的 TOIP 身份（station id + 口令种子）。管理员 `toip station` 时建。"""

    schemaVersion: int = STATION_SCHEMA_VERSION
    station_id: str = ""
    # 口令种子明文。**只在内存与本文件里存在**——文件权限由原子写入保证，
    # 且这是网关自己算口令用的，不过网。
    secret: str = ""
    name: str = "relay-hub"
    created_at: float = 0.0
    base_url: str = ""

    @staticmethod
    def create(*, name: str, base_url: str = "", clock: Callable[[], float] = time.time) -> "StationIdentity":
        return StationIdentity(
            station_id=f"rst_{secrets.token_hex(8)}",
            secret=b32encode(new_secret()),
            name=name.strip() or "relay-hub",
            created_at=clock(),
            base_url=base_url.strip(),
        )

    @property
    def secret_bytes(self) -> bytes:
        return b32decode(self.secret)


def load_station(path: Path) -> StationIdentity | None:
    """读站点身份文件。不存在/损坏/解不开都返回 None（TOIP 视为未启用）。

    secretbox 兼容历史明文文档；DPAPI 解密失败（文件被拷到别的机器）按
    「站点不存在」处理，绝不把密文当明文猜。"""
    raw = secretbox.unseal(Path(path))
    if not isinstance(raw, dict) or not raw.get("secret"):
        return None
    known = {f for f in StationIdentity.__dataclass_fields__}
    return StationIdentity(**{k: v for k, v in raw.items() if k in known})


def save_station(path: Path, station: StationIdentity) -> None:
    """站点身份加密落盘（secretbox：Windows DPAPI / 其余平台明文 0600 降级）。

    口令种子等于「该站点全部接入能力」，只允许以本机账户可解的密文躺在
    磁盘上——toip.json 被拷到任何别的机器都算不出本站动态口令。
    """
    path = Path(path)
    secretbox.seal(asdict(station), path=path)


def _harden(path: Path) -> None:
    """把权限收到 0600（Windows 上 os.chmod 语义有限，失败不阻断）。

    口令种子是「等于该站点全部接入能力」的凭证，多用户机器上不能让同机
    其他账号顺手读到。这里只做到最好努力的收权，真正的隔离靠 OS 账号边界。
    """
    try:
        import os
        import stat

        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, ImportError):  # pragma: no cover - 平台相关
        pass


# ---------------------------------------------------------------- 通行证（ticket）


TICKET_SCHEMA_VERSION = 1
TICKET_PREFIX = "rhe_"


@dataclass
class Ticket:
    """一枚 TOIP 通行证：把「某插件 + 某设备」绑到一条可吊销的接入记录上。

    落盘形态与 `tokens.py` 的 DownstreamToken 对齐（哈希 + 提示，无明文），
    但它是**接入凭据**而不是**推理凭据**：ticket 换令牌，令牌才是长期凭证。
    两者分开的好处是 ticket 可以随便重发，令牌的吊销面不被搅动。
    """

    ticket_id: str
    ticket_hash: str
    ticket_hint: str
    name: str
    # 允许的插件 id 白名单。空 = 不限制（任何插件都能用这枚 ticket 接入）。
    plugins: tuple[str, ...] = ()
    enabled: bool = True
    created_at: float = 0.0
    expires_at: float = 0.0
    # 该 ticket 换出去的会话令牌 id（tokens.json 里的 token_id）。
    # 存它是为了「吊销插件」能一把收回令牌，而不是让管理员自己去猜哪枚。
    token_id: str = ""
    used_count: int = 0
    last_used: float = 0.0
    last_ip: str = ""
    note: str = ""

    def is_expired(self, *, clock: Callable[[], float] = time.time) -> bool:
        return bool(self.expires_at) and clock() >= float(self.expires_at)


def generate_ticket() -> str:
    """生成通行证明文。前缀让它在一堆 sk-/rht_ 里一眼认出是接入凭据。"""
    return f"{TICKET_PREFIX}{secrets.token_urlsafe(32)}"


def make_ticket(
    *,
    name: str,
    plugins: Iterable[str] = (),
    ttl: float = 0.0,
    note: str = "",
    clock: Callable[[], float] = time.time,
) -> tuple[Ticket, str]:
    """造一枚 ticket，返回 (记录, 明文)。明文只在这一刻存在。"""
    secret = generate_ticket()
    clean_name = _sanitize_label(name, what="通行证名")
    record = Ticket(
        ticket_id=str(uuid.uuid4()),
        ticket_hash=hashlib.sha256(secret.encode("utf-8")).hexdigest(),
        ticket_hint=token_hint_of(secret),
        name=clean_name,
        plugins=tuple(sanitize_plugin_id(p) for p in plugins),
        created_at=clock(),
        expires_at=(clock() + ttl) if ttl else 0.0,
        note=note.strip(),
    )
    return record, secret


def _sanitize_label(raw: str, *, what: str, limit: int = 40) -> str:
    """标签归一化：空白折叠、长度封顶、危险字符挡掉（会进文件名/日志）。"""
    text = " ".join(str(raw or "").split())
    if not text:
        raise ToipError(f"缺少{what}")
    if len(text) > limit:
        raise ToipError(f"{what}过长（<= {limit} 字符）")
    return text


def sanitize_plugin_id(raw: str) -> str:
    """插件 id 归一化。它是**目录名**，必须挡掉路径穿越与空值。

    存疑即拒而不是「清洗成安全的」：插件 id 会出现在 API 与日志目录里，
    静默改写会让「插件自己报的 id」和「管理员看到的 id」对不上，
    接入类协议里这种不一致比直接报错更难排查。
    """
    text = str(raw or "").strip().lower()
    if not text:
        raise ToipError("插件 id 不能为空")
    if len(text) > 64:
        raise ToipError(f"插件 id 过长（<= 64 字符）：{text[:32]}…")
    bad = [ch for ch in text if ch not in _SAFE_LABEL]
    if bad or ".." in text or text.startswith(".") or text.endswith("."):
        raise ToipError(
            f"插件 id 只允许小写字母/数字/./_/-，且不能以点开头结尾或含 '..'：{text!r}"
        )
    return text


class TicketStore:
    """通行证文件（tickets.json）的读写门面。

    与 `TokenStore` 同一套规矩：整文件读写 + 一把锁 + 原子落盘 + **指纹热加载**。

    热加载不是可选项：`toip ticket` 是在**控制面进程**里跑的，签完写文件就退出；
    数据面的 `serve` 早就在跑了。没有指纹检查的话，管理员签发的通行证要等到
    网关重启才生效——而 TOIP 的全部卖点就是「签一枚口令就能自助接入」，
    这条链断在这里会让功能看起来「时灵时不灵」（实际上是「灵不灵看重启」）。
    坑与 `tokens.py` / `router.ReloadingRouter` 完全同源。
    """

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        self._lock = threading.RLock()
        self.tickets: list[Ticket] = []
        # 先记指纹再加载：反过来会出现「内存里是旧文件、指纹却是新文件的」，
        # 从此永不刷新（与 TokenStore 相同的顺序理由）。
        self._fingerprint = _fingerprint(self.path)
        self.load()

    # -- 加载/落盘 ------------------------------------------------------

    def load(self) -> None:
        records = _read_tickets(self.path)
        with self._lock:
            self.tickets = records
            self._fingerprint = _fingerprint(self.path)

    def _refresh(self) -> None:
        """指纹变了就重新读盘（锁内调用）。"""
        fingerprint = _fingerprint(self.path)
        if fingerprint != self._fingerprint:
            self.tickets = _read_tickets(self.path)
            self._fingerprint = fingerprint

    def save(self) -> None:
        with self._lock:
            payload = {
                "schemaVersion": TICKET_SCHEMA_VERSION,
                "tickets": [asdict(t) for t in self.tickets],
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            write_json_atomic(self.path, payload)
            self._fingerprint = _fingerprint(self.path)

    # -- 变更 -----------------------------------------------------------

    def add(self, record: Ticket) -> None:
        with self._lock:
            self._refresh()
            if any(t.name == record.name for t in self.tickets):
                raise ToipError(f"同名通行证已存在：{record.name}")
            self.tickets.append(record)
        self.save()

    def remove(self, ticket_id: str) -> bool:
        with self._lock:
            self._refresh()
            before = len(self.tickets)
            self.tickets = [t for t in self.tickets if t.ticket_id != ticket_id]
            removed = len(self.tickets) != before
        if removed:
            self.save()
        return removed

    def mutate(self, change: Callable[[list[Ticket]], None]) -> None:
        """在一把锁里改完再落盘（改多个字段时避免两次写盘之间的中间态）。"""
        with self._lock:
            self._refresh()
            change(self.tickets)
        self.save()

    # -- 查询 -----------------------------------------------------------

    def find(self, secret: str) -> Ticket | None:
        """按明文查 ticket。常数时间比较——虽然比对的是哈希，纪律不破。"""
        digest = hashlib.sha256(str(secret or "").encode("utf-8")).hexdigest()
        with self._lock:
            self._refresh()
            for record in self.tickets:
                if hmac.compare_digest(record.ticket_hash, digest):
                    return record
        return None

    def by_id(self, ticket_id: str) -> Ticket | None:
        with self._lock:
            self._refresh()
            for record in self.tickets:
                if record.ticket_id == ticket_id:
                    return record
        return None

    def list(self) -> list[Ticket]:
        with self._lock:
            self._refresh()
            return list(self.tickets)


def _fingerprint(path: Path) -> str | None:
    """文件指纹（mtime_ns + size）。不存在返回 None。

    与 `tokens._fingerprint` 同构：用 mtime_ns 而不是 mtime，因为 NTFS 的
    mtime 分辨率在快速连写下会让「签完立刻接」读到旧内容。
    """
    try:
        stat = Path(path).stat()
    except OSError:
        return None
    return f"{stat.st_mtime_ns}:{stat.st_size}"


def _read_tickets(path: Path) -> list[Ticket]:
    """读 tickets.json，坏行/坏字段跳过而不炸（一个坏条目不该废掉整份通行证表）。"""
    try:
        raw: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if not isinstance(raw, dict):
        return []
    items = raw.get("tickets")
    if not isinstance(items, list):
        return []
    known = {f for f in Ticket.__dataclass_fields__}
    records: list[Ticket] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        data = {k: v for k, v in item.items() if k in known}
        if "plugins" in data:
            data["plugins"] = tuple(data["plugins"] or ())
        try:
            records.append(Ticket(**data))
        except TypeError:
            continue
    return records


# ---------------------------------------------------------------- 接入服务


@dataclass
class JoinResult:
    """一次成功 join 的结果：令牌 + 给插件自填的接入载荷。"""

    ticket: Ticket
    token: DownstreamToken
    token_plain: str
    plugin_id: str
    returned_session: bool  # True = 复用旧令牌（轮换），False = 新发
    fields: dict[str, Any] = field(default_factory=dict)


class ToipService:
    """数据面侧的 TOIP 兑换器。挂在 serve 上，处理 /v1/toip/*。

    与控制面（admin/CLI）共享的就是那两个文件：station.json（口令种子）与
    tickets.json（通行证）。与 `pairing.py` 同构——开窗在控制面、兑换在数据面，
    唯一可靠的共享物是文件。
    """

    def __init__(
        self,
        tickets: TicketStore,
        tokens: TokenStore,
        station_path: Path,
        *,
        session_ttl: float = SESSION_TTL,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.tickets = tickets
        self.tokens = tokens
        self.station_path = Path(station_path)
        self.session_ttl = session_ttl
        self._clock = clock
        # 每来源 IP 的失败计数：(ip) -> [window_start, attempts]。进程内，
        # 重启清零——与 RateLimiter 同权衡：暴力破解是持续行为，重启不洗白。
        self._attempts: dict[str, list[float]] = {}
        self._attempt_lock = threading.Lock()

    # -- 站点身份 -------------------------------------------------------

    def station(self) -> StationIdentity | None:
        return load_station(self.station_path)

    def enabled(self) -> bool:
        return self.station() is not None

    def station_public(self) -> dict[str, Any]:
        """给未认证客户端的站点元数据：**不含种子、不含口令、不含令牌**。

        发现阶段的信息按「探测成本与 404 相同」原则给：客户端据此知道
        「这里支持 TOIP、该用什么口径发口令」，拿不到任何可用凭证。
        """
        station = self.station()
        if station is None:
            return {
                "protocol": PROTOCOL,
                "version": PROTOCOL_VERSION,
                "enabled": False,
            }
        return {
            "protocol": PROTOCOL,
            "version": PROTOCOL_VERSION,
            "enabled": True,
            "station_id": station.station_id,
            "name": station.name,
            "base_url": station.base_url,
            # 口令参数：插件据此本地算 TOTP，不需要任何额外约定。
            "otp": {
                "algorithm": TOTP_ALGORITHM.upper(),
                "digits": TOTP_DIGITS,
                "period": int(TOTP_STEP),
                "window": TOTP_WINDOW,
            },
            "session_ttl": int(self.session_ttl),
            "endpoints": {
                "station": "/v1/toip/station",
                "enroll": "/v1/toip/enroll",
                "join": "/v1/toip/join",
                "session": "/v1/toip/session",
                "messages": "/v1/messages",
                "chat": "/v1/chat/completions",
                "models": "/v1/models",
            },
        }

    # -- 爆破闸门 -------------------------------------------------------

    def _register_failure(self, ip: str) -> int:
        """记一次失败，返回本窗口内**剩余**尝试次数（0 = 这一次用掉了最后一次）。"""
        now = self._clock()
        with self._attempt_lock:
            slot = self._attempts.get(ip)
            if slot is None or now - slot[0] >= JOIN_ATTEMPT_WINDOW:
                slot = [now, 0.0]
                self._attempts[ip] = slot
            slot[1] += 1
            # 剩余 = 上限 - 已用；用掉最后一次时返回 0（而不是 -1）。
            # 之前写的 int(上限 - 已用) 没算这一步，报「剩余 1 次」时其实已经用完了。
            return max(0, int(JOIN_MAX_ATTEMPTS - slot[1]))

    def _register_success(self, ip: str) -> None:
        with self._attempt_lock:
            self._attempts.pop(ip, None)

    def locked_out(self, ip: str) -> bool:
        now = self._clock()
        with self._attempt_lock:
            slot = self._attempts.get(ip)
            if slot is None or now - slot[0] >= JOIN_ATTEMPT_WINDOW:
                return False
            return slot[1] >= JOIN_MAX_ATTEMPTS

    # -- 兑换 -----------------------------------------------------------

    def join(
        self,
        *,
        code: str = "",
        ticket: str = "",
        name: str,
        plugin_id: str,
        ip: str,
        client_id: str = "dsh",
    ) -> JoinResult:
        """用动态口令或登记口令换一枚会话令牌。

        两条口径：
          * `ticket`：登记口令（管理员 `toip ticket` 打印的那串）→ 首接；
          * `code` ：动态口令（TOTP，每 30 秒滚一次）→ 重接/轮换。

        任一口径成功都走同一条发放路径：同 ticket 的旧会话令牌作废，
        发新枚（明文令牌落盘只存哈希，拿不回原文，轮换是唯一诚实的「再来一次」）。
        """
        station = self.station()
        if station is None:
            raise ToipError("本站未启用 TOIP 接入（管理员需先执行 `hubrelay toip station`）")
        if self.locked_out(ip):
            raise ToipError(
                f"来源 {ip} 尝试次数过多，已锁 {int(JOIN_ATTEMPT_WINDOW)} 秒"
            )

        plugin = sanitize_plugin_id(plugin_id)
        supplied_ticket = str(ticket or "").strip()
        supplied_code = str(code or "").strip()

        if supplied_ticket:
            record = self.tickets.find(supplied_ticket)
            if record is None:
                self._fail(ip, "toip.reject", reason="登记口令无效", plugin=plugin)
                raise ToipError("登记口令无效或已吊销")
            if not record.enabled:
                self._fail(ip, "toip.reject", reason="通行证已停用", plugin=plugin)
                raise ToipError(f"通行证 {record.name} 已停用")
            if record.is_expired(clock=self._clock):
                self._fail(ip, "toip.reject", reason="通行证已过期", plugin=plugin)
                raise ToipError(f"通行证 {record.name} 已过期，请让管理员重新签发")
            if record.plugins and plugin not in record.plugins:
                self._fail(
                    ip,
                    "toip.reject",
                    reason="插件不在通行证白名单",
                    plugin=plugin,
                    allowed=list(record.plugins),
                )
                raise ToipError(
                    f"通行证 {record.name} 只允许插件 {', '.join(record.plugins)}，收到 {plugin}"
                )
        elif supplied_code:
            if not verify_totp(station.secret_bytes, supplied_code, clock=self._clock):
                remaining = self._register_failure(ip)
                self._fail(
                    ip,
                    "toip.reject",
                    reason="动态口令不正确或已过期",
                    plugin=plugin,
                    remaining=remaining,
                )
                raise ToipError(
                    "动态口令不正确或已过期（口令 30 秒滚动一次；"
                    "若确认抄对了，请检查网关与本机时钟是否相差超过 30 秒）"
                )
            # 口令通过后仍要落到一枚通行证上：令牌必须有主，才能被单独吊销。
            record = self._ticket_for_plugin(plugin)
            if record is None:
                self._fail(
                    ip, "toip.reject", reason="没有可用的通行证", plugin=plugin
                )
                raise ToipError(
                    f"动态口令正确，但没有为插件 {plugin} 签发过通行证；"
                    "请让管理员执行 `hubrelay toip ticket --name <设备> "
                    f"--plugins {plugin}`"
                )
        else:
            self._fail(ip, "toip.reject", reason="既没有登记口令也没有动态口令", plugin=plugin)
            raise ToipError("请提供登记口令（ticket）或动态口令（code）")

        self._register_success(ip)
        return self._grant(record, plugin=plugin, ip=ip, client_id=client_id, name=name)

    def _ticket_for_plugin(self, plugin_id: str) -> Ticket | None:
        """挑一枚可用的通行证给这个插件：白名单匹配 + 启用 + 未过期。

        优先选已经给这个插件发过令牌的那一枚——轮换语义下「同一台设备
        换新钥匙」比「新开一个令牌位」更符合管理员的预期。
        """
        candidates = [
            t
            for t in self.tickets.list()
            if t.enabled
            and not t.is_expired(clock=self._clock)
            and (not t.plugins or plugin_id in t.plugins)
        ]
        if not candidates:
            return None
        bound = [t for t in candidates if t.token_id]
        pool = bound or candidates
        return sorted(pool, key=lambda t: t.last_used, reverse=True)[0]

    def _grant(
        self, record: Ticket, *, plugin: str, ip: str, client_id: str, name: str
    ) -> JoinResult:
        """发放/轮换会话令牌。删旧 + 加新必须在同一把锁里完成（并发窗口）。

        设备名解析优先级：显式传入的 name → 旧令牌的名字 → 通行证名。
        中间那一档是为**动态口令路径**准备的：那条路上插件只发口令，不会
        再报一次设备名；若直接用通行证名，同一台设备重新接入后会在
        `tokens.json` 里改名（用量/日志的 `token` 列跟着变，历史对不上）。
        """
        rotated = self.tokens.by_id(record.token_id) if record.token_id else None
        device = " ".join(str(name or "").split())
        if not device and rotated is not None:
            device = rotated.name
        if not device:
            device = record.name
        if len(device) > 40:
            device = device[:40]
        token_plain = generate_token()
        new_token = DownstreamToken(
            token_id=str(uuid.uuid4()),
            name=device,
            token=token_plain,
            note=f"toip:{plugin}",
            expires_at=(self._clock() + self.session_ttl) if self.session_ttl else 0.0,
        )

        def _rotate(pool: Any) -> None:
            if rotated is not None:
                pool.remove(rotated.token_id)
            pool.add(new_token)

        try:
            self.tokens.mutate(_rotate)
        except Exception as exc:  # TokenError（重名等）——通行证不焚，让设备改名重试
            self._fail(ip, "toip.reject", reason=f"令牌发放失败：{exc}", plugin=plugin)
            raise ToipError(f"会话令牌发放失败：{exc}") from exc

        def _bind(tickets: list[Ticket]) -> None:
            for item in tickets:
                if item.ticket_id == record.ticket_id:
                    item.token_id = new_token.token_id
                    item.used_count += 1
                    item.last_used = self._clock()
                    item.last_ip = ip

        self.tickets.mutate(_bind)
        from . import audit

        audit.record(
            "toip.join",
            plugin=plugin,
            device=device,
            ticket=record.name,
            token_hint=token_hint_of(token_plain),
            rotated=rotated is not None,
            ip=ip,
        )
        return JoinResult(
            ticket=record,
            token=new_token,
            token_plain=token_plain,
            plugin_id=plugin,
            returned_session=rotated is not None,
            fields={"client": client_id, "device": device},
        )

    # -- 会话查询 -------------------------------------------------------

    def describe_session(self, token: DownstreamToken) -> dict[str, Any]:
        """给已接入插件回一份「你自己是谁、还剩多久」。纯读，不产生副作用。"""
        station = self.station()
        return {
            "protocol": PROTOCOL,
            "version": PROTOCOL_VERSION,
            "station_id": station.station_id if station else "",
            "token_name": token.name,
            "plugin_id": plugin_of_note(token.note),
            "expires_at": float(token.expires_at or 0.0),
            "expires_in": max(0.0, float(token.expires_at or 0.0) - self._clock())
            if token.expires_at
            else 0.0,
            "models": list(token.models),
            "usage": {
                "requests": token.usage.requests,
                "ok": token.usage.ok,
                "failed": token.usage.failed,
                "tokens_in": token.usage.tokens_in,
                "tokens_out": token.usage.tokens_out,
            },
        }

    # -- 反面 -----------------------------------------------------------

    def _fail(self, ip: str, event: str, **detail: Any) -> None:
        from . import audit

        audit.record(event, ip=ip, **detail)


def plugin_of_note(note: str) -> str:
    """从令牌 note（toip:<plugin>）里取回插件 id。取不到就返回空串。"""
    text = str(note or "")
    return text[len("toip:") :] if text.startswith("toip:") else ""


def rotate_secret(
    path: Path, station: StationIdentity, *, clock: Callable[[], float] = time.time
) -> StationIdentity:
    """轮换站点口令种子（所有动态口令立刻失效，已发的会话令牌不受影响）。

    这是 TOIP 相对配对码最大的运维优势：**口令泄露不需要重发令牌**。
    种子换掉，旧口令马上作废，而正在跑的插件带着会话令牌照常工作——
    下次重接时才需要新口令。
    """
    station.secret = b32encode(new_secret())
    save_station(path, station)
    from . import audit

    audit.record("toip.rotate", station_id=station.station_id)
    return station
