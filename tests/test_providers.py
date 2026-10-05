# -*- coding: utf-8 -*-
"""v0.2.12：渠道预设、显式版本路径、stats/request_logs/usage_summary。"""

from __future__ import annotations

import json
import urllib.request

import pytest

import relayhub.api as api
from relayhub.gateway.upstream import _open
from relayhub.providers import resolve_provider

from test_api import fake_upstream  # noqa: F401  复用 test_api 的假上游 fixture


def test_providers_presets():
    base, canon = resolve_provider("deepseek")
    assert base == "https://api.deepseek.com/v1" and canon == "deepseek"
    assert resolve_provider("kimi")[1] == "moonshot"      # 别名
    assert resolve_provider("qwen")[1] == "dashscope"
    with pytest.raises(KeyError):
        resolve_provider("not-a-vendor")
    listing = api.list_providers()
    assert "deepseek" in listing and "ollama" in listing


def test_add_upstream_by_provider(tmp_path):
    st = api.Station(port=18701, home=tmp_path / "p1")
    added = st.add_upstream(provider="deepseek", api_key="sk-x")
    assert added.base_url == "https://api.deepseek.com/v1"
    assert added.label == "deepseek"  # 预设名自动做 label
    ups = st.list_upstreams()
    assert ups[0]["label"] == "deepseek" and ups[0]["enabled"] is True
    # provider 与 base_url 互斥
    with pytest.raises(ValueError):
        st.add_upstream(provider="groq", base_url="https://x/v1")
    # 完全不传报错
    with pytest.raises(ValueError):
        st.add_upstream(api_key="sk-x")


def test_explicit_version_path_respected():
    """智谱 /api/paas/v4 这类显式版本路径不能再被强补 /v1。"""
    from relayhub.gateway.pool import UpstreamKey

    key = UpstreamKey(key_id="1", label="glm", protocol="openai-chat",
                      base_url="https://open.bigmodel.cn/api/paas/v4", api_key="k")
    conn, target = _open(key, "/chat/completions", 5.0)
    conn.close()
    assert target.startswith("/api/paas/v4/chat/completions"), target
    # 无路径的 base_url 仍自动补 /v1
    key2 = UpstreamKey(key_id="2", label="plain", protocol="openai-chat",
                       base_url="http://127.0.0.1:8000", api_key="")
    conn, target2 = _open(key2, "/chat/completions", 5.0)
    conn.close()
    assert target2.startswith("/v1/chat/completions"), target2


def test_stats_and_logs(tmp_path, fake_upstream):
    port = 18702
    st = api.Station(port=port, home=tmp_path / "p2")
    st.add_upstream(fake_upstream, api_key="sk-f", models=["fake-model"],
                    protocol="openai-chat", label="fake")
    tok = st.create_token("logger", scope="test")
    url = st.serve(background=True)
    try:
        # 打一次流量（test 令牌 → 合成应答），产生请求日志
        req = urllib.request.Request(
            url + "/v1/chat/completions",
            data=json.dumps({"model": "any",
                             "messages": [{"role": "user", "content": "hi"}]}).encode(),
            headers={"Authorization": f"Bearer {tok.plaintext}",
                     "Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=10).read()

        stats = st.stats()
        assert stats["key_count"] == 1 and stats["keys"][0]["label"] == "fake"

        logs = st.request_logs(limit=10)
        assert len(logs) >= 1 and logs[-1].get("ok") is True

        summary = st.usage_summary()
        assert isinstance(summary, dict) and summary
    finally:
        st.stop()
