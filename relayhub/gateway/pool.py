"""上游号池：Key 存储、候选排序、熔断冷却、用量记账。

与 `service.py` 里的 `ChannelPool` 的区别：那个只是轮询索引 + 失败计数的演示骨架，
渠道是写死的假对象；这里的 Key 是真能发上游请求的，且带熔断与用量。

安全边界（刻意为之，别误解）：
  * 本文件只解决「多个上游 Key 怎么轮、坏了怎么切、用了多少」。
  * 上游 Key 目前以明文存 JSON（与不少客户端把 apiKey 明文写进本地配置文件同级），
    磁盘加密属于后续「加密套件」那一步，不在这里假装做了。
  * **下游凭证（发给客户端的 per-device token）不在本文件**，那是另一层，
    轮换语义完全不同（下游轮换必须重推配置，客户端不会自己发现）。
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from .atomicio import write_json_atomic

PROTOCOL_ANTHROPIC = "anthropic-messages"
PROTOCOL_OPENAI_CHAT = "openai-chat"
SUPPORTED_PROTOCOLS = (PROTOCOL_ANTHROPIC, PROTOCOL_OPENAI_CHAT)
# [OSS-EXCLUDE-START] 订阅凭据反代协议：仅限内部使用，协议常量与说明一并内置
# Gemini 订阅（AI Pro）：gemini-cli 的 OAuth 凭据 → Code Assist API（v1internal）。
# 渠道 api_key 存的是 refresh_token，访问令牌由 upstream 层刷新缓存。
PROTOCOL_GEMINI = "gemini-codeassist"
SUPPORTED_PROTOCOLS = (PROTOCOL_ANTHROPIC, PROTOCOL_OPENAI_CHAT, PROTOCOL_GEMINI)
# [OSS-EXCLUDE-END]

# 鉴权头模式：auto=按协议默认（anthropic→x-api-key，openai→Bearer）；
# bearer=强制 Authorization: Bearer（部分上游要求 Bearer 而不是 x-api-key）。
AUTH_MODE_AUTO = "auto"
AUTH_MODE_BEARER = "bearer"
AUTH_MODES = (AUTH_MODE_AUTO, AUTH_MODE_BEARER)

STRATEGY_ROUND_ROBIN = "round_robin"
STRATEGY_LEAST_FAILURES = "least_failures"
# credit 感知调度：额度多的账号优先
STRATEGY_MOST_CREDITS = "most_credits"
STRATEGIES = (STRATEGY_ROUND_ROBIN, STRATEGY_LEAST_FAILURES, STRATEGY_MOST_CREDITS)

# ---------------------------------------------------------------- 分级冷却
# 四档 cooldown 状态机（plan 12h / soft 60s / err 10m / disable 人工）。
# 四个档位要分开，因为它们的恢复路径完全不同：
# plan 等次日额度刷新、soft 等一分钟、err 等十分钟、disable 必须人工处理
# （重新登录/换 token 后 `pool enable`）。把「限流」和「额度耗尽」显示成同一种
# 冷却，会让人对着前者的倒计时白等一小时。

TIER_PLAN = "plan"  # 额度/套餐耗尽（配额码/余额文案）→ 默认 12h
TIER_SOFT = "soft"  # 429 限流 → 默认 60s
TIER_ERR = "err"  # 5xx / 连不上 / 超时 → 默认 10m
TIER_DISABLE = "disable"  # 401/403 鉴权失效 → 立即禁用，人工 `pool enable` 才恢复

DEFAULT_TIER_DURATIONS = {TIER_PLAN: 43200.0, TIER_SOFT: 60.0, TIER_ERR: 600.0}

# 判定「额度耗尽」的响应文案标记（含实测配额码 1005）
_QUOTA_MARKERS = ("1005", "credit", "quota", "insufficient", "balance", "额度", "配额", "余额")


def classify_failure(status: int, message: str) -> str | None:
    """把上游失败归入冷却档位。返回 None 表示不该熔断（请求本身的问题）。"""
    if status in (401, 403):
        return TIER_DISABLE
    if status == 429:
        return TIER_SOFT
    if status == 0 or status >= 500:
        return TIER_ERR
    # 其余 4xx 默认是请求写错了（400/404），不算渠道故障；
    # 但带额度语义的例外——那是账号的事，不是请求的事。
    lowered = message.lower()
    if any(marker in lowered for marker in _QUOTA_MARKERS):
        return TIER_PLAN
    return None


# 默认熔断参数：连续失败 3 次才进入冷却（档位时长见 DEFAULT_TIER_DURATIONS）
DEFAULT_FAILURE_THRESHOLD = 3


class PoolError(RuntimeError):
    """号池配置或使用错误。"""


def is_self_reference(base_url: str, own_ports: Sequence[int] = (8799,)) -> bool:
    """判断 base_url 是否指向本网关自己（回环地址 + 自身端口）。

    防呆：把自己的公网/本地地址配成自己的上游。运行期还有内容指纹的
    LoopGuard 兜底，这里是配置期直接拒绝，错误更早更直白。
    """
    from urllib.parse import urlsplit

    parts = urlsplit(base_url.strip())
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    loopback = host in ("127.0.0.1", "localhost", "::1", "0.0.0.0")
    return loopback and port in own_ports


class _HealthProbeError:
    """健康探测失败的轻量错误壳。绕开 pool→upstream 的循环导入，
    只实现 report_failure 需要的最小接口（status / retryable / __str__）。"""

    status = 0
    retryable = True

    def __init__(self, message: str) -> None:
        self.message = message

    def __str__(self) -> str:
        return self.message


@dataclass
class Usage:
    requests: int = 0
    ok: int = 0
    failed: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    # 缓存命中记账（对标 new-api 的 cache accounting）
    cache_read: int = 0
    cache_creation: int = 0

    def merge(self, tokens_in: int, tokens_out: int) -> None:
        self.tokens_in += max(0, int(tokens_in))
        self.tokens_out += max(0, int(tokens_out))


@dataclass
class UpstreamKey:
    key_id: str
    label: str
    base_url: str
    api_key: str
    protocol: str = PROTOCOL_ANTHROPIC
    models: tuple[str, ...] = ()
    model_windows: dict[str, int] = field(default_factory=dict)
    # 模型映射（对标 new-api channel model_mapping）：对外名 → 上游真名。
    # 有映射时客户端只见对外名（干净名），请求进渠前改写成上游名；
    # 无映射时对外名 = models 里的名字。
    model_mapping: dict[str, str] = field(default_factory=dict)
    # 调度优先级（对标 new-api channel priority）：数值越大越优先。
    # 同优先级内按策略（round_robin 等）分配；高优先级全部冷却/失败后
    # 才落到低优先级——「主/备」语义。
    priority: int = 0
    weight: int = 1
    enabled: bool = True
    note: str = ""
    auth_mode: str = AUTH_MODE_AUTO
    # 额外请求头（如部分上游需要的 anthropic-beta）。
    # dict 以 JSON 形式随号池落盘，出站时原样合并进请求头。
    extra_headers: dict[str, str] = field(default_factory=dict)
    # [OSS-EXCLUDE-START] 订阅凭据反代专用字段：仅限内部使用
    # Gemini OAuth 覆写：默认用内置的公共 client 凭据，
    # Google 轮换或企业租户时按渠道覆盖。
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    # [OSS-EXCLUDE-END]
    # 剩余额度（credit 感知调度用）。-1 = 未知：未知的不参与 most_credits 排序，
    # 也不要当成 0 展示——「没记录过」和「用光了」是两回事。
    credits: int = -1
    credits_updated_at: float = 0.0
    # [OSS-EXCLUDE-START] 代签到配置字段：仅限内部使用
    # 签到/领取配置（jobs.py 执行）。结构：
    # {"url": ..., "method": "POST", "headers": {...}, "body": ...}
    # 端点各家不同，网关只做通用执行，不做协议假设。
    checkin: dict = field(default_factory=dict)
    # [OSS-EXCLUDE-END]
    # 运行时状态（持久化，用于熔断与用量统计）
    cooldown_tier: str = ""  # 当前生效的冷却档位；"" = 未在冷却
    consecutive_failures: int = 0
    disabled_until: float = 0.0
    # [OSS-EXCLUDE-START] 代签到运行时字段
    last_checkin: float = 0.0
    # [OSS-EXCLUDE-END]
    last_error: str = ""
    usage: Usage = field(default_factory=Usage)

    def __post_init__(self) -> None:
        if self.protocol not in SUPPORTED_PROTOCOLS:
            raise PoolError(f"不支持的协议 {self.protocol}，可选 {SUPPORTED_PROTOCOLS}")
        if not self.base_url.strip():
            raise PoolError("base_url 不能为空")
        if self.weight < 1:
            raise PoolError("weight 必须 >= 1")

    # -- 查询 ------------------------------------------------------------

    def public_models(self) -> tuple[str, ...]:
        """对外可见的模型名：有映射用映射键，否则就是 models 本身。"""
        if self.model_mapping:
            return tuple(self.model_mapping)
        return self.models

    def map_to_upstream(self, model: str) -> str:
        """对外名 → 上游真名。没配映射就原样透传。"""
        return self.model_mapping.get(model, model)

    def supports(self, model: str) -> bool:
        """models 为空表示该 Key 对全部模型开放；有映射时按对外名匹配。"""
        public = self.public_models()
        return not public or model in public

    def is_available(self, now: float) -> bool:
        return self.enabled and now >= self.disabled_until

    def cooling_down_for(self, now: float) -> float:
        return max(0.0, self.disabled_until - now)

    # -- 序列化 ----------------------------------------------------------

    def to_dict(self) -> dict:
        data = asdict(self)
        data["models"] = list(self.models)
        return data

    @classmethod
    def from_dict(cls, raw: dict) -> "UpstreamKey":
        usage = raw.get("usage") or {}
        return cls(
            key_id=str(raw.get("key_id") or uuid.uuid4()),
            label=str(raw.get("label") or raw.get("key_id") or "unnamed"),
            base_url=str(raw["base_url"]),
            api_key=str(raw.get("api_key", "")),
            protocol=str(raw.get("protocol", PROTOCOL_ANTHROPIC)),
            models=tuple(raw.get("models") or ()),
            model_mapping={
                str(k): str(v) for k, v in (raw.get("model_mapping") or {}).items()
            },
            priority=int(raw.get("priority", 0) or 0),
            model_windows={
                str(k): int(v) for k, v in (raw.get("model_windows") or {}).items()
            },
            weight=int(raw.get("weight", 1)),
            enabled=bool(raw.get("enabled", True)),
            note=str(raw.get("note", "")),
            auth_mode=str(raw.get("auth_mode") or AUTH_MODE_AUTO),
            extra_headers={
                str(k): str(v) for k, v in (raw.get("extra_headers") or {}).items()
            },
            # [OSS-EXCLUDE-START] 订阅凭据反代字段
            oauth_client_id=str(raw.get("oauth_client_id") or ""),
            oauth_client_secret=str(raw.get("oauth_client_secret") or ""),
            # [OSS-EXCLUDE-END]
            credits=int(raw.get("credits", -1)),
            credits_updated_at=float(raw.get("credits_updated_at", 0.0) or 0.0),
            # [OSS-EXCLUDE-START] 代签到字段
            checkin=dict(raw.get("checkin") or {}),
            # [OSS-EXCLUDE-END]
            cooldown_tier=str(raw.get("cooldown_tier", "")),
            consecutive_failures=int(raw.get("consecutive_failures", 0)),
            disabled_until=float(raw.get("disabled_until", 0.0) or 0.0),
            # [OSS-EXCLUDE-START] 代签到运行时字段
            last_checkin=float(raw.get("last_checkin", 0.0) or 0.0),
            # [OSS-EXCLUDE-END]
            last_error=str(raw.get("last_error", "")),
            usage=Usage(
                requests=int(usage.get("requests", 0)),
                ok=int(usage.get("ok", 0)),
                failed=int(usage.get("failed", 0)),
                tokens_in=int(usage.get("tokens_in", 0)),
                tokens_out=int(usage.get("tokens_out", 0)),
            ),
        )


class KeyPool:
    """一组上游 Key。候选排序 + 熔断 + 用量记账。

    clock 可注入，便于测试冷却窗口而不真的 sleep。
    """

    def __init__(
        self,
        keys: Sequence[UpstreamKey],
        *,
        strategy: str = STRATEGY_ROUND_ROBIN,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        cooldown_tiers: dict[str, float] | None = None,
        retries: int = 1,
        config_epoch: int = 0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if strategy not in STRATEGIES:
            raise PoolError(f"不支持的策略 {strategy}，可选 {STRATEGIES}")
        if retries < 1:
            raise PoolError("retries 必须 >= 1（每个渠道的尝试次数）")
        tiers = dict(DEFAULT_TIER_DURATIONS)
        for name, seconds in (cooldown_tiers or {}).items():
            if name not in tiers:
                raise PoolError(f"未知冷却档位 {name}，可选 {sorted(tiers)}")
            tiers[name] = float(seconds)
        self.keys: list[UpstreamKey] = list(keys)
        self.strategy = strategy
        self.failure_threshold = failure_threshold
        self.cooldown_tiers = tiers
        self.retries = int(retries)
        # 配置级代数：enable/复位熔断这类「必须让运行中的网关看见」的操作自增它。
        # 冷却本身是运行时字段（指纹排除），但人工清除冷却必须能触发 reload——
        # 否则 CLI/管理面写文件清了冷却，serve 内存里还在冷。
        self.config_epoch = int(config_epoch)
        self._clock = clock
        self._cursor = 0

    # -- 存取 ------------------------------------------------------------

    def now(self) -> float:
        """号池自己的时钟（可注入，便于测试冷却窗口而不真的 sleep）。"""
        return self._clock()

    @classmethod
    def load(cls, path: Path, **kwargs: object) -> "KeyPool":
        if not Path(path).is_file():
            return cls([], **kwargs)  # type: ignore[arg-type]
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        keys = [UpstreamKey.from_dict(item) for item in raw.get("keys", [])]
        merged = {
            "strategy": raw.get("strategy", STRATEGY_ROUND_ROBIN),
            "failure_threshold": raw.get("failure_threshold", DEFAULT_FAILURE_THRESHOLD),
            "cooldown_tiers": raw.get("cooldown_tiers") or {},
            "retries": int(raw.get("retries", 1) or 1),
            "config_epoch": int(raw.get("config_epoch") or 0),
        }
        merged.update(kwargs)  # 显式传参优先
        return cls(keys, **merged)  # type: ignore[arg-type]

    def save(self, path: Path) -> None:
        path = Path(path)
        payload = {
            "schemaVersion": 1,
            "strategy": self.strategy,
            "failure_threshold": self.failure_threshold,
            "cooldown_tiers": self.cooldown_tiers,
            "retries": self.retries,
            "config_epoch": self.config_epoch,
            "keys": [key.to_dict() for key in self.keys],
        }
        write_json_atomic(path, payload)

    # -- 增删改 ----------------------------------------------------------

    def get(self, key_id: str) -> UpstreamKey | None:
        for key in self.keys:
            if key.key_id == key_id:
                return key
        return None

    def find_by_label(self, label: str) -> UpstreamKey | None:
        for key in self.keys:
            if key.label == label:
                return key
        return None

    def add(self, key: UpstreamKey) -> UpstreamKey:
        if self.get(key.key_id) or self.find_by_label(key.label):
            raise PoolError(f"key_id 或 label 已存在：{key.key_id} / {key.label}")
        self.keys.append(key)
        return key

    def remove(self, identifier: str) -> bool:
        for index, key in enumerate(self.keys):
            if key.key_id == identifier or key.label == identifier:
                del self.keys[index]
                return True
        return False

    def set_enabled(self, identifier: str, enabled: bool) -> bool:
        key = self.get(identifier) or self.find_by_label(identifier)
        if key is None:
            return False
        key.enabled = enabled
        if enabled:
            # 人工启用要连冷却状态一起清：disable 档没有倒计时，
            # 不清的话 is_available 的判断会对不上人看到的「已启用」。
            key.consecutive_failures = 0
            key.disabled_until = 0.0
            key.cooldown_tier = ""
            # 人工清除冷却必须触发热加载（config_epoch 在指纹里），
            # 否则 serve 内存里还在冷，文件写了也白写。
            self.config_epoch += 1
        return True

    # -- 候选排序 --------------------------------------------------------

    def candidates(self, model: str, strategy: str | None = None) -> list[UpstreamKey]:
        """返回可用候选。语义对标 new-api：
        先按 priority 从高到低分组（高优先级全灭才轮到低优先级），
        组内再按策略（round_robin / least_failures / most_credits）排序。
        """
        now = self._clock()
        usable = [k for k in self.keys if k.supports(model) and k.is_available(now)]
        if not usable:
            return []
        chosen = strategy or self.strategy

        def order_group(group: list[UpstreamKey]) -> list[UpstreamKey]:
            if chosen == STRATEGY_LEAST_FAILURES:
                return sorted(
                    group,
                    key=lambda k: (
                        k.consecutive_failures,
                        k.usage.failed / max(1, k.usage.requests),
                        k.label,
                    ),
                )
            if chosen == STRATEGY_MOST_CREDITS:
                def credit_rank(key: UpstreamKey) -> tuple[int, int, int, str]:
                    if key.credits < 0:
                        return (1, 0, key.consecutive_failures, key.label)
                    return (0, -key.credits, key.consecutive_failures, key.label)

                return sorted(group, key=credit_rank)
            # round_robin：全局游标在组内旋转
            start = self._cursor % len(group)
            self._cursor = (self._cursor + 1) % len(group)
            return group[start:] + group[:start]

        priorities = sorted({k.priority for k in usable}, reverse=True)
        ordered: list[UpstreamKey] = []
        for rank in priorities:
            group = [k for k in usable if k.priority == rank]
            if len(group) == 1:
                ordered.append(group[0])
            else:
                ordered.extend(order_group(group))
        return ordered

    def all_models(self) -> list[str]:
        """启用中的 Key 的模型并集（去重、保持顺序）。

        已禁用的 Key 不进清单：/v1/models 是给客户端拉模型用的，
        列出一个必然 503 的模型只会误导客户端。冷却中的 Key 仍算启用
        （冷却会恢复，不该让模型清单来回抖动）。
        """
        seen: list[str] = []
        for key in self.keys:
            if not key.enabled:
                continue
            for model in key.public_models():
                if model not in seen:
                    seen.append(model)
        return seen

    def model_windows(self) -> dict[str, int]:
        """合并各 Key 声明的上下文长度，键为对外名（映射时翻回对外侧）。"""
        merged: dict[str, int] = {}
        for key in self.keys:
            if not key.enabled:
                continue
            reverse = {up: pub for pub, up in key.model_mapping.items()} if key.model_mapping else {}
            for model, window in key.model_windows.items():
                public = reverse.get(model, model)
                merged[public] = max(merged.get(public, 0), int(window))
        return merged

    # -- 健康探测（内置，对标外部 watchdog 的收编版） ----------------------

    def report_health(self, key: UpstreamKey, ok: bool) -> None:
        """TCP 层健康探测结果。

        失败：按通用错误计连败（trip=True）——连续超过阈值自然进入 err 冷却。
        成功：只清 err 档冷却（「机器又开机了」），**不碰 disable 档**——
        鉴权失效（403 配额耗尽/换 token）不该被一次 TCP 握手洗白。
        """
        if not ok:
            self.report_failure(key, _HealthProbeError("健康探测失败：上游端口不可达"), trip=True)
            return
        if key.cooldown_tier == TIER_ERR:
            key.consecutive_failures = 0
            key.disabled_until = 0.0
            key.cooldown_tier = ""
            key.last_error = ""

    # -- 反馈 ------------------------------------------------------------

    def report_success(
        self,
        key: UpstreamKey,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cache_read: int = 0,
        cache_creation: int = 0,
    ) -> None:
        key.consecutive_failures = 0
        key.disabled_until = 0.0
        key.cooldown_tier = ""
        key.last_error = ""
        key.usage.requests += 1
        key.usage.ok += 1
        key.usage.merge(tokens_in, tokens_out)
        key.usage.cache_read += max(0, int(cache_read))
        key.usage.cache_creation += max(0, int(cache_creation))

    def report_failure(self, key: UpstreamKey, error: object, *, trip: bool = True) -> None:
        key.usage.requests += 1
        key.usage.failed += 1
        key.last_error = str(error)[:400]
        if not trip:
            # 400/404 这类是「请求本身有问题」，不是渠道坏了，不该计入熔断
            return
        status = int(getattr(error, "status", 0) or 0)
        tier = classify_failure(status, str(error))
        if tier is None:
            # trip=True 但归不出档位（防御）：按通用错误处理，别让故障渠道装健康
            tier = TIER_ERR
        if tier == TIER_DISABLE:
            # 鉴权失效：没有「等一会儿就好」的恢复路径，立即禁用等人工处理
            # （重新登录/换 token 后 `pool enable`）。
            key.enabled = False
            key.cooldown_tier = TIER_DISABLE
            key.disabled_until = 0.0
            key.consecutive_failures = 0
            return
        # 时间档位仍受阈值门控：偶发一次 5xx 不该立刻冷却整个渠道
        key.consecutive_failures += 1
        if key.consecutive_failures >= self.failure_threshold:
            key.cooldown_tier = tier
            key.disabled_until = self._clock() + self.cooldown_tiers[tier]

    def totals(self) -> Usage:
        total = Usage()
        for key in self.keys:
            total.requests += key.usage.requests
            total.ok += key.usage.ok
            total.failed += key.usage.failed
            total.tokens_in += key.usage.tokens_in
            total.tokens_out += key.usage.tokens_out
            total.cache_read += key.usage.cache_read
            total.cache_creation += key.usage.cache_creation
        return total

    def stats(self) -> dict:
        now = self._clock()
        return {
            "strategy": self.strategy,
            "failure_threshold": self.failure_threshold,
            "cooldown_tiers": self.cooldown_tiers,
            "key_count": len(self.keys),
            "usable_count": len([k for k in self.keys if k.is_available(now)]),
            "keys": [
                {
                    "key_id": key.key_id,
                    "label": key.label,
                    "protocol": key.protocol,
                    "enabled": key.enabled,
                    "available": key.is_available(now),
                    "cooling_down_for": round(key.cooling_down_for(now), 1),
                    "cooldown_tier": key.cooldown_tier,
                    "credits": key.credits,
                    "credits_updated_at": key.credits_updated_at,
                    # [OSS-EXCLUDE-START] 代签到运行时状态
                    "last_checkin": key.last_checkin,
                    "has_checkin": bool(key.checkin.get("url")),
                    # [OSS-EXCLUDE-END]
                    "models": list(key.models),
                    "consecutive_failures": key.consecutive_failures,
                    "last_error": key.last_error,
                    "usage": asdict(key.usage),
                }
                for key in self.keys
            ],
            "totals": asdict(self.totals()),
        }


def key_from_spec(raw: dict) -> UpstreamKey:
    """从 CLI/配置文件的一段 dict 造 Key；label 缺省时由 host + key 尾号生成。"""
    base_url = str(raw.get("base_url", "")).strip()
    if not base_url:
        raise PoolError("缺少 base_url")
    api_key = str(raw.get("api_key", ""))
    label = str(raw.get("label") or "").strip()
    if not label:
        host = base_url.split("//", 1)[-1].split("/", 1)[0]
        label = f"{host}#{api_key[-4:] if api_key else 'nokey'}"
    return UpstreamKey(
        key_id=str(raw.get("key_id") or uuid.uuid4()),
        label=label,
        base_url=base_url,
        api_key=api_key,
        protocol=str(raw.get("protocol", PROTOCOL_ANTHROPIC)),
        models=tuple(raw.get("models") or ()),
        model_mapping=dict(raw.get("model_mapping") or {}),
        priority=int(raw.get("priority", 0) or 0),
        model_windows={str(k): int(v) for k, v in (raw.get("model_windows") or {}).items()},
        weight=int(raw.get("weight", 1)),
        credits=int(raw.get("credits", -1)),
        # [OSS-EXCLUDE-START] 代签到字段
        checkin=dict(raw.get("checkin") or {}),
        # [OSS-EXCLUDE-END]
        auth_mode=str(raw.get("auth_mode") or AUTH_MODE_AUTO),
        extra_headers={
            str(k): str(v) for k, v in (raw.get("extra_headers") or {}).items()
        },
        # [OSS-EXCLUDE-START] 订阅凭据反代字段
        oauth_client_id=str(raw.get("oauth_client_id") or ""),
        oauth_client_secret=str(raw.get("oauth_client_secret") or ""),
        # [OSS-EXCLUDE-END]
        note=str(raw.get("note", "")),
    )
