"""多模态与联网搜索的方言互译测试（upstream 的图片/搜索透传）。

搜题场景的核心链路：App 发带图消息 → 网关翻成上游方言 → 上游识图/搜索。
任何一侧把图片块弄丢或翻错，表现出来都是「模型看不到图」这类静默错误，
所以这里全部做结构级断言。
"""

from __future__ import annotations

import pytest

from relayhub.gateway import upstream

ANTHROPIC_IMAGE = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "aGk="}}
OPENAI_IMAGE_URL = {"type": "image_url", "image_url": {"url": "data:image/png;base64,aGk="}}


# ---------------------------------------------------------------- Anthropic → OpenAI


def test_anthropic_image_block_becomes_openai_image_url() -> None:
    out = upstream.to_openai_request(
        {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": [{"type": "text", "text": "看图答题"}, ANTHROPIC_IMAGE]}]}
    )
    (msg,) = out["messages"]
    assert isinstance(msg["content"], list)
    kinds = [p["type"] for p in msg["content"]]
    assert kinds == ["text", "image_url"]
    assert msg["content"][1]["image_url"]["url"] == "data:image/png;base64,aGk="


def test_anthropic_url_image_source_passes_through_as_url() -> None:
    out = upstream.to_openai_request(
        {
            "model": "m",
            "max_tokens": 8,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "image", "source": {"type": "url", "url": "https://x/y.png"}}
                    ],
                }
            ],
        }
    )
    (msg,) = out["messages"]
    assert msg["content"][0]["image_url"]["url"] == "https://x/y.png"


def test_anthropic_web_search_tool_maps_to_openai_options() -> None:
    out = upstream.to_openai_request(
        {
            "model": "m",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "查一下"}],
            "tools": [{"type": "web_search_20250305", "name": "web_search", "max_uses": 3}],
        }
    )
    # 服务端工具不翻成假 function，映射成原生搜索开关
    assert "tools" not in out
    assert out["web_search_options"] == {}


# ---------------------------------------------------------------- OpenAI → Anthropic


def test_openai_data_url_image_becomes_base64_block() -> None:
    out = upstream.to_anthropic_request(
        {
            "model": "m",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": [{"type": "text", "text": "看图"}, OPENAI_IMAGE_URL]}],
        }
    )
    (msg,) = out["messages"]
    assert isinstance(msg["content"], list)
    assert msg["content"][0] == {"type": "text", "text": "看图"}
    assert msg["content"][1]["source"] == {"type": "base64", "media_type": "image/png", "data": "aGk="}


def test_openai_http_image_becomes_url_source() -> None:
    out = upstream.to_anthropic_request(
        {
            "model": "m",
            "max_tokens": 8,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "image_url", "image_url": {"url": "https://x/y.jpg"}}
                    ],
                }
            ],
        }
    )
    (msg,) = out["messages"]
    assert isinstance(msg["content"], list)
    assert msg["content"][0] == {"type": "text", "text": ""}  # 自动补前导空文本
    assert msg["content"][1]["source"] == {"type": "url", "url": "https://x/y.jpg"}


def test_openai_plain_text_user_message_stays_string() -> None:
    out = upstream.to_anthropic_request(
        {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "纯文本"}]}
    )
    assert out["messages"][0]["content"] == "纯文本"


def test_openai_web_search_options_maps_to_server_tool() -> None:
    out = upstream.to_anthropic_request(
        {
            "model": "m",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": "查一下"}],
            "web_search_options": {"max_uses": 2},
        }
    )
    tools = out["tools"]
    assert tools[-1]["type"].startswith("web_search")
    assert tools[-1]["max_uses"] == 2


def test_openai_audio_still_rejected() -> None:
    with pytest.raises(upstream.UpstreamError):
        upstream.to_anthropic_request(
            {
                "model": "m",
                "max_tokens": 8,
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "input_audio", "input_audio": {"data": "x", "format": "wav"}}],
                    }
                ],
            }
        )
