"""上游渠道预设 / Upstream provider presets.

中文：
    one-api、new-api 这类优秀的前辈项目用渠道模板的思路覆盖了大量上游，
    这里沿用同样的思路：绝大多数大模型厂商都提供 OpenAI 兼容接口，接入
    参数差异主要在 base_url 和模型名。本字典内置主流渠道的接入参数，
    `add_upstream(provider="deepseek", api_key=…)` 一行接入；
    想加新渠道 = 往这个字典加一行。

English:
    Following the channel-template approach popularized by projects like
    one-api and new-api: most LLM vendors expose OpenAI-compatible endpoints,
    and the wiring differences come down to base_url and model names. This
    dict holds connection params for mainstream providers; adding one more
    provider is one dict entry.
"""

from __future__ import annotations

PROVIDERS: dict[str, dict[str, str]] = {
    # ---- 海外云厂商 / international ----
    "openai": {"base_url": "https://api.openai.com/v1"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1"},
    "groq": {"base_url": "https://api.groq.com/openai/v1"},
    "mistral": {"base_url": "https://api.mistral.ai/v1"},
    "together": {"base_url": "https://api.together.xyz/v1"},
    "fireworks": {"base_url": "https://api.fireworks.ai/inference/v1"},
    "xai": {"base_url": "https://api.x.ai/v1"},
    "deepseek": {"base_url": "https://api.deepseek.com/v1"},
    "moonshot": {"base_url": "https://api.moonshot.cn/v1", "alias": "kimi"},
    # ---- 国内云厂商 / China ----
    "zhipu": {"base_url": "https://open.bigmodel.cn/api/paas/v4", "alias": "glm"},
    "dashscope": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "alias": "qwen",
    },
    "siliconflow": {"base_url": "https://api.siliconflow.cn/v1"},
    # ---- 本机推理 / local inference ----
    "ollama": {"base_url": "http://127.0.0.1:11434/v1"},
    "lmstudio": {"base_url": "http://127.0.0.1:1234/v1"},
    "vllm": {"base_url": "http://127.0.0.1:8000/v1"},
    "llamacpp": {"base_url": "http://127.0.0.1:8080/v1"},
}

_ALIASES = {
    info.get("alias", ""): name for name, info in PROVIDERS.items() if info.get("alias")
}


def resolve_provider(name: str) -> tuple[str, str]:
    """渠道名 → (base_url, 规范名)。/ provider name → (base_url, canonical name).

    支持别名（kimi→moonshot、glm→zhipu、qwen→dashscope）。未知渠道抛 KeyError。
    """
    key = name.strip().lower()
    key = _ALIASES.get(key, key)
    if key not in PROVIDERS:
        raise KeyError(
            f"未知渠道 / unknown provider: {name!r}；可选 / available: {sorted(PROVIDERS)}"
        )
    return PROVIDERS[key]["base_url"], key


def list_providers() -> dict[str, str]:
    """全部内置渠道及其 base_url（供 UI/文档展示）。/ all presets for display."""
    return {name: info["base_url"] for name, info in sorted(PROVIDERS.items())}
