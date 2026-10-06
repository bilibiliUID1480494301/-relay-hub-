# -*- coding: utf-8 -*-
"""E2E 信封加密（站点侧）：插件↔中转站的线上载荷机密性与重放防护。

协议（与 docs/E2E-ENCRYPTION.md 一致，每请求信封、服务端零会话状态）：

  1. 站点启动时生成一次 X25519 静态密钥对，私钥经 secretbox 加密落盘
     （e2e.json——与口令种子同一条纪律：拷到别的机器解不开）。
  2. 客户端 `GET /v1/e2e/params` 拿公钥（公开材料，不鉴权）。
  3. 每个请求：客户端生成一次性 X25519 密钥对，
     shared = X25519(eph_priv, server_pub)
     key    = HKDF-SHA256(shared, salt=<本次供应的凭证串>, info="relayhub-e2e-v1")
     POST body = {"v":1,"key_id","eph","nonce","ts","ciphertext"}
     ciphertext = AES-256-GCM(key, nonce, 原始 JSON body, aad=<绑定串>)
     AAD 绑定 key_id+eph+nonce+ts——密文与它的信封字段不可拆分。
  4. 服务端：X25519(server_priv, eph_pub) → 同一 key → 解密 → 原链路处理。
     重放防护：ts 窗口（默认 ±120s）+ (credential, key_id, nonce) 短期去重。

盐取「本次供应的凭证串」：同一密文换个令牌就解不开，信封与身份绑定。
cryptography 是可选依赖（hubrelay[e2e]）——没装时信封请求回 501 并指路，
普通明文流量完全不受影响；我们不上自研密码学，装不上就诚实说不支持。
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from pathlib import Path
from typing import Any

SCHEME = "x25519-hkdf-sha256-aesgcm"
INFO = b"relayhub-e2e-v1"
TS_WINDOW = 120.0  # 信封时间戳容差（秒）；NTP 偏差 + 一点网络余量

ENVELOPE_CONTENT_TYPE = "application/x-relayhub-envelope+json"


class E2eError(RuntimeError):
    """信封不可用/不合法。message 面向客户端，可直接回 4xx。"""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise E2eError(f"信封字段不是合法 base64：{exc}") from exc


def _crypto():
    """懒加载 cryptography；缺失时返回 None（调用方回 501）。"""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        return X25519PrivateKey, X25519PublicKey, AESGCM, HKDF, hashes
    except ImportError:
        return None


class E2eIdentity:
    """站点的 X25519 静态身份。私钥只在内存，落盘走 secretbox。"""

    def __init__(self, key_id: str, private: Any, public: bytes) -> None:
        self.key_id = key_id
        self._private = private
        self.public = public

    @classmethod
    def create(cls) -> "E2eIdentity":
        mod = _crypto()
        if mod is None:
            raise E2eError("未安装 cryptography（pip install \"hubrelay[e2e]\"）")
        X25519PrivateKey, _, _, _, _ = mod
        private = X25519PrivateKey.generate()
        public = private.public_key().public_bytes_raw()
        return cls(key_id=secrets.token_hex(4), private=private, public=public)

    def public_b64(self) -> str:
        return _b64e(self.public)


def load_or_create(path: Path) -> E2eIdentity:
    """读站点 E2E 身份；不存在则生成并落盘。解不开（换机器）就重建——
    旧信封请求会因 key_id 不匹配被客户端拒绝后重新拉参数，损失为零。"""
    from . import secretbox

    mod = _crypto()
    if mod is None:
        raise E2eError("未安装 cryptography（pip install \"hubrelay[e2e]\"）")
    raw = secretbox.unseal(Path(path))
    if isinstance(raw, dict) and raw.get("private") and raw.get("key_id"):
        X25519PrivateKey, X25519PublicKey, _, _, _ = mod
        try:
            private = X25519PrivateKey.from_private_bytes(_b64d(str(raw["private"])))
            return E2eIdentity(str(raw["key_id"]), private, private.public_key().public_bytes_raw())
        except Exception:  # 密钥损坏：重建（key_id 变了，客户端会自适应）
            pass
    identity = E2eIdentity.create()
    secretbox.seal(
        {"key_id": identity.key_id, "private": _b64e(identity._private.private_bytes_raw())},
        path=Path(path),
    )
    return identity


def derive_key(shared: bytes, credential: str) -> bytes:
    _, _, _, HKDF, hashes = _crypto()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=credential.encode("utf-8"),
        info=INFO,
    ).derive(shared)


def _aad(key_id: str, eph: bytes, nonce: bytes, ts: int) -> bytes:
    return json.dumps(
        {"v": 1, "key_id": key_id, "eph": _b64e(eph), "nonce": _b64e(nonce), "ts": ts},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class ReplayGuard:
    """(credential, key_id, nonce) 短期去重。进程内存态：重启清零，
    窗口外时间戳已在 ts 校验挡住，所以内存态重启不构成重放窗口。"""

    def __init__(self, window: float = TS_WINDOW) -> None:
        self._window = window
        self._seen: dict[str, float] = {}

    def check(self, credential: str, key_id: str, nonce: bytes, now: float | None = None) -> bool:
        """True = 首见放行；False = 窗口内重放。"""
        now = time.monotonic() if now is None else now
        key = hashlib.sha256(
            credential.encode("utf-8") + b"\0" + key_id.encode() + b"\0" + nonce
        ).digest()
        for k, t in list(self._seen.items()):
            if now - t > self._window:
                del self._seen[k]
        if key in self._seen:
            return False
        self._seen[key] = now
        if len(self._seen) > 65536:  # 硬上限：防内存被撑爆
            oldest = sorted(self._seen.items(), key=lambda kv: kv[1])[:4096]
            for k, _ in oldest:
                del self._seen[k]
        return True


def open_envelope(
    identity: E2eIdentity,
    envelope: dict[str, Any],
    credential: str,
    replay: ReplayGuard,
) -> dict[str, Any]:
    """解一个信封，返回原始 JSON 请求（dict）。任何不合法都抛 E2eError。"""
    mod = _crypto()
    if mod is None:
        raise E2eError("服务端未安装 cryptography（pip install \"hubrelay[e2e]\"）")
    X25519PrivateKey, X25519PublicKey, AESGCM, _, _ = mod

    if int(envelope.get("v") or 0) != 1:
        raise E2eError("信封版本不支持（本站只认 v=1）")
    if str(envelope.get("key_id") or "") != identity.key_id:
        raise E2eError(
            f"key_id 不匹配（站点公钥已轮换？重新 GET /v1/e2e/params）"
        )
    try:
        ts = int(envelope.get("ts") or 0)
    except (TypeError, ValueError):
        raise E2eError("ts 必须是整数秒级时间戳")
    skew = abs(time.time() - ts)
    if skew > TS_WINDOW:
        raise E2eError(f"信封时间戳偏差 {skew:.0f}s 超出 ±{int(TS_WINDOW)}s 窗口（校对本机时钟）")

    eph_raw = _b64d(str(envelope.get("eph") or ""))
    nonce = _b64d(str(envelope.get("nonce") or ""))
    ciphertext = _b64d(str(envelope.get("ciphertext") or ""))
    if len(eph_raw) != 32:
        raise E2eError("eph 必须是 32 字节 X25519 公钥")
    if len(nonce) != 12:
        raise E2eError("nonce 必须是 12 字节")

    if not replay.check(credential, identity.key_id, nonce):
        raise E2eError("检测到重放：同一信封 nonce 已被使用")

    try:
        shared = identity._private.exchange(X25519PublicKey.from_public_bytes(eph_raw))
        key = derive_key(shared, credential)
        plain = AESGCM(key).decrypt(nonce, ciphertext, _aad(identity.key_id, eph_raw, nonce, ts))
    except E2eError:
        raise
    except Exception:
        # 解密失败的具体原因（密钥不匹配/GCM 校验失败）对攻击者也是信息，统一口径
        raise E2eError("信封解密失败：确认凭证、key_id 与参数接口返回一致")

    try:
        payload = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise E2eError("信封明文不是合法 JSON")
    if not isinstance(payload, dict):
        raise E2eError("信封明文必须是 JSON 对象")
    return payload
