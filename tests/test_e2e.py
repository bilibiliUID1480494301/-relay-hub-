# -*- coding: utf-8 -*-
"""E2E 信封加密测试：roundtrip、重放拒绝、凭证绑定、明文兼容。"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from relayhub.gateway import e2e as e2e_module
from tests.test_relay_chain import relay_server
from tests.support import FakeUpstream, make_key

API_KEY = "rh_e2e_down"


def _params(base: str) -> dict:
    with urllib.request.urlopen(f"{base}/v1/e2e/params", timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def _seal(params: dict, credential: str, payload: dict, *, ts: int | None = None,
          nonce: bytes | None = None) -> tuple[dict[str, object], bytes, bytes]:
    """客户端侧信封构造（与服务端互为镜像，协议正确性两边各自实现）。"""
    eph = X25519PrivateKey.generate()
    server_pub = base64.b64decode(params["server_public"])
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    shared = eph.exchange(X25519PublicKey.from_public_bytes(server_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32,
               salt=credential.encode("utf-8"), info=b"relayhub-e2e-v1").derive(shared)
    eph_pub = eph.public_key().public_bytes_raw()
    nonce = nonce or eph.public_key().public_bytes_raw()[:12]  # 占位；调用方一般另给
    nonce = nonce if len(nonce) == 12 else nonce[:12]
    ts = int(time.time()) if ts is None else ts
    aad = json.dumps(
        {"v": 1, "key_id": params["key_id"], "eph": base64.b64encode(eph_pub).decode(),
         "nonce": base64.b64encode(nonce).decode(), "ts": ts},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload).encode("utf-8"), aad)
    envelope = {
        "v": 1, "key_id": params["key_id"],
        "eph": base64.b64encode(eph_pub).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ts": ts, "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return envelope, eph_pub, nonce


def _post_envelope(base: str, credential: str, envelope: dict) -> tuple[int, str]:
    request = urllib.request.Request(
        f"{base}/v1/messages", data=json.dumps(envelope).encode("utf-8"), method="POST"
    )
    request.add_header("Content-Type", e2e_module.ENVELOPE_CONTENT_TYPE)
    request.add_header("x-api-key", credential)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # noqa: TID251
        return exc.code, exc.read().decode("utf-8")


def test_params_exposes_public_key() -> None:
    with FakeUpstream() as upstream:
        router = __import__("relayhub.gateway.router", fromlist=["KeyPoolRouter"]).KeyPoolRouter(
            __import__("relayhub.gateway.pool", fromlist=["KeyPool"]).KeyPool([make_key("real", upstream.base_url)])
        )
        with relay_server(router, api_key=API_KEY) as server:
            base = server.base_url
            params = _params(base)
            assert params["scheme"] == e2e_module.SCHEME
            assert len(base64.b64decode(params["server_public"])) == 32
            assert params["key_id"]


def test_envelope_roundtrip(tmp_path: Path) -> None:
    """信封请求 → 服务端解密 → 正常走上游链路 → 200 明文应答。"""
    import secrets as _secrets

    with FakeUpstream() as upstream:
        from relayhub.gateway.pool import KeyPool
        from relayhub.gateway.router import KeyPoolRouter

        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            base = server.base_url
            params = _params(base)
            envelope, _, _ = _seal(
                params, API_KEY,
                {"model": "glm-5.2", "max_tokens": 8,
                 "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]},
                nonce=_secrets.token_bytes(12),
            )
            status, raw = _post_envelope(base, API_KEY, envelope)
            assert status == 200, raw
            assert "pong-from-upstream" in raw


def test_replay_is_rejected(tmp_path: Path) -> None:
    import secrets as _secrets

    with FakeUpstream() as upstream:
        from relayhub.gateway.pool import KeyPool
        from relayhub.gateway.router import KeyPoolRouter

        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            base = server.base_url
            params = _params(base)
            envelope, _, _ = _seal(
                params, API_KEY,
                {"model": "glm-5.2", "max_tokens": 8, "messages": []},
                nonce=_secrets.token_bytes(12),
            )
            status, _ = _post_envelope(base, API_KEY, envelope)
            assert status == 200
            status, raw = _post_envelope(base, API_KEY, envelope)
            assert status == 400
            assert "重放" in raw


def test_wrong_credential_cannot_decrypt(tmp_path: Path) -> None:
    """盐绑定凭证：用别的令牌构造的密文解不开（信封与身份绑定）。"""
    import secrets as _secrets

    with FakeUpstream() as upstream:
        from relayhub.gateway.pool import KeyPool
        from relayhub.gateway.router import KeyPoolRouter

        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            base = server.base_url
            params = _params(base)
            envelope, _, _ = _seal(
                params, "rh_wrong_credential",
                {"model": "glm-5.2", "max_tokens": 8, "messages": []},
                nonce=_secrets.token_bytes(12),
            )
            status, raw = _post_envelope(base, API_KEY, envelope)
            assert status == 400
            assert "解密失败" in raw


def test_stale_timestamp_rejected(tmp_path: Path) -> None:
    with FakeUpstream() as upstream:
        from relayhub.gateway.pool import KeyPool
        from relayhub.gateway.router import KeyPoolRouter

        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            base = server.base_url
            params = _params(base)
            envelope, _, _ = _seal(
                params, API_KEY,
                {"model": "glm-5.2", "max_tokens": 8, "messages": []},
                ts=int(time.time()) - 3600,
            )
            status, raw = _post_envelope(base, API_KEY, envelope)
            assert status == 400
            assert "时间戳" in raw


def test_plain_json_still_works(tmp_path: Path) -> None:
    """信封是可选升级：明文流量完全不受影响（向后兼容承诺）。"""
    with FakeUpstream() as upstream:
        from relayhub.gateway.pool import KeyPool
        from relayhub.gateway.router import KeyPoolRouter

        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            base = server.base_url
            request = urllib.request.Request(
                f"{base}/v1/messages",
                data=json.dumps({"model": "glm-5.2", "max_tokens": 8, "messages": []}).encode(),
                method="POST",
            )
            request.add_header("Content-Type", "application/json")
            request.add_header("x-api-key", API_KEY)
            with urllib.request.urlopen(request, timeout=15) as response:
                assert response.status == 200
