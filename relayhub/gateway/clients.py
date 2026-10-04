"""客户端反代理档案：描述各类下游客户端怎么把 base_url 指到 relay-hub。

对标 one-api 的「渠道类型适配器」概念，但方向相反：one-api 的适配器解决
「上游各家说什么协议」，这里的档案解决「下游各家客户端说什么协议、
怎么把它的 base_url 指到本网关、凭证怎么带」。

内置一个通用档案（app：OpenAI 兼容客户端）；其他客户端的档案由扩展包在
启动时注册（见 `register_profile`）——接入方式千差万别（有的配置在本地
JSON 可以确定性注入，有的配置在服务端只能引导式手配，有的契约还没实测），
所以档案不写死在网关里，实测一个、注册一个。

网关侧对所有客户端是同一套资源：两个入站口（`/v1/messages`、`/v1/chat/completions`）
+ 每设备一个下游令牌（`tokens.py`）。新客户端接入时只需要补档案 + 发令牌，
不用动网关——接入路径已铺好，每个客户端只差它自己的实测。

onboarding() 是纯函数：模型列表由调用方解析好传进来，本模块不做网络 I/O。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

# 客户端接入状态
STATUS_SUPPORTED = "supported"  # 已实现自动接入
STATUS_GUIDED = "guided"        # 引导式：客户端里手动配一次（配置由服务端同步）
STATUS_RESERVED = "reserved"    # 预留：契约未实测，先占位并写清待验证项

# 入站协议取值与 pool.py 的上游协议字段同词表，但方向相反（这是客户端说的协议）
INBOUND_ANTHROPIC = "anthropic-messages"
INBOUND_OPENAI_CHAT = "openai-chat"
INBOUND_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ClientProfile:
    """一个客户端的反代理契约。

    每个字段都是「接这个客户端时会被问到的第一个问题」：
    打哪个路径、凭证放哪个头、base_url 要不要补路径、现在能不能自动接。
    """

    client_id: str
    display_name: str
    inbound: str
    # 客户端最终请求的完整路径。注意有的客户端要写全路径，它不自己拼。
    endpoint: str
    endpoint_note: str
    # 该客户端实际用什么头带凭证（网关两个头都认，这里记录的是它的习惯）
    auth_header: str
    base_url_rule: str
    status: str
    how_to: str
    # 上游侧建议：这个客户端生态里常见的「账号池 → 标准 API」包装项目，
    # 可作为 relay-hub 的上游渠道。由各档案自己填写。
    upstream_hint: str = ""
    # 状态为 reserved/guided 时，列出接入前必须实测/必须手动做的事
    open_questions: tuple[str, ...] = ()
    references: tuple[str, ...] = field(default_factory=tuple)


APP = ClientProfile(
    client_id="app",
    display_name="客户端应用（App）",
    inbound=INBOUND_OPENAI_CHAT,
    endpoint="/v1/chat/completions",
    endpoint_note="App 填根地址即可，客户端自动补 /v1/chat/completions",
    auth_header="Authorization: Bearer（配对发放的下游令牌 rht_…）",
    base_url_rule="App 只填网址：根地址，自动补 /v1",
    status=STATUS_SUPPORTED,
    how_to=(
        "App 侧：`pair begin` 开 5 分钟配对窗（或 auto-lan 免码直连），"
        "应用设置页填中转站网址 + 配对码一键绑定；绑定后按令牌记账"
    ),
)


_BUILTIN_PROFILES = (
    APP,
)

_PROFILES: dict[str, ClientProfile] = {
    p.client_id: p for p in _BUILTIN_PROFILES
}

# 可选客户端包注册自己的档案与 onboarding 钩子。
# 没装扩展包时注册自然跳过，档案表与配对端点里就没有对应档案。
_ONBOARDING_HOOKS: dict[str, Any] = {}


def register_profile(profile: ClientProfile) -> None:
    """外部包注册客户端档案（幂等，后注册覆盖同名）。"""
    _PROFILES[profile.client_id] = profile


def register_onboarding(client_id: str, hook: Any) -> None:
    """注册 onboarding 载荷扩展钩子：hook(payload, base_url=, api_key=) → payload。"""
    _ONBOARDING_HOOKS[client_id] = hook


def profiles() -> list[ClientProfile]:
    return list(_PROFILES.values())


def get(client_id: str) -> ClientProfile:
    profile = _PROFILES.get(client_id.strip().lower())
    if profile is None:
        raise KeyError(f"未知客户端 {client_id!r}，已知：{sorted(_PROFILES)}")
    return profile




# ---------------------------------------------------------------- onboarding


def _model_entries(models: Sequence[Any]) -> list[dict[str, Any]]:
    """接受 ModelSpec、dict（JSON 载荷）或纯字符串，统一成 onboarding 里的模型条目。"""
    entries: list[dict[str, Any]] = []
    for model in models:
        if isinstance(model, str):
            entries.append({"model_id": model, "context_window": None})
            continue
        if isinstance(model, dict):
            entries.append(
                {
                    "model_id": str(model.get("model_id") or model.get("id") or ""),
                    "context_window": model.get("context_window"),
                }
            )
            continue
        entries.append(
            {
                "model_id": model.model_id,
                "context_window": getattr(model, "context_window", None),
            }
        )
    return entries


def onboarding(
    client_id: str,
    *,
    base_url: str,
    api_key: str,
    models: Sequence[Any] = (),
    spec_name: str = "Relay Hub",
) -> dict[str, Any]:
    """生成把某客户端指到 relay-hub 的接入载荷。纯函数，不发网络请求。

    models 由调用方解析（CLI 里是 `fetch_models()` 的结果或 --model 参数），
    本模块保持无 I/O，才能对三种客户端的载荷做确定性测试。
    """
    profile = get(client_id)
    payload: dict[str, Any] = {
        "client": profile.client_id,
        "display_name": profile.display_name,
        "status": profile.status,
        "inbound": profile.inbound,
        "endpoint": profile.endpoint,
        "base_url": base_url.rstrip("/"),
        "api_key": api_key,
        "models": _model_entries(models),
    }
    hook = _ONBOARDING_HOOKS.get(profile.client_id)
    if hook is not None:
        # 外部客户端包的载荷扩展（fields/identity 自描述）
        payload = hook(payload, base_url=base_url, api_key=api_key)
    if profile.open_questions:
        payload["open_questions"] = list(profile.open_questions)
    return payload
