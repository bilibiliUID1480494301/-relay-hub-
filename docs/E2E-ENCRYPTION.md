# E2E Encryption Design / 端到端加密设计

**Status / 状态**: design approved, implementation scheduled (0.5.x) · 设计已定，实现排期 0.5.x
**Scope / 范围**: client (DeepSeek Harness plugin) ↔ relay-hub station wire protocol · 插件 ↔ 中转站线上协议

## Why / 为什么

The wire between a plugin and a relay-hub station is currently HTTP + bearer
token. On a LAN that means anyone sniffing the wire sees model traffic and
replays the token. Our stated threat model treats **the local environment as
untrusted**, so transport must be end-to-end encrypted — TLS at a reverse
proxy is deployment-dependent and does not cover plain-LAN HTTP.

当前插件与中转站之间是 HTTP + bearer token。局域网上抓包即可看到全部模型
流量并重放令牌。我们的威胁模型是**本地环境默认不可信**，所以传输必须端到
端加密——反代上的 TLS 依赖部署形态，覆盖不了纯局域网 HTTP。

## Design / 设计

Handshake piggybacks on the existing TOIP join; traffic keys are derived from
materials **both sides already hold**, so no extra round trip:

握手搭在既有 TOIP join 上，流量密钥从**双方已持有**的材料派生，零额外往返：

```
join (existing / TOIP)                    join（现有 TOIP 流程）
  station → client: session token            站点 → 客户端：会话令牌
             + server_public (X25519)                   + 服务端公钥
  client: eph_keypair → shared = X25519(eph, server_public)
          key = HKDF(shared, salt=token_id, info="relayhub-e2e-v1")
  subsequent calls: POST /v1/messages
    Content-Type: application/x-relayhub-envelope+json
    body: { "v":1, "token_id", "nonce", "ciphertext" }   # AES-256-GCM
  station: X25519(server_static, client_eph) → same key → decrypt → dispatch
```

- **Crypto stack / 加密栈**: X25519 + HKDF-SHA256 + AES-256-GCM.
  Station side: `cryptography` as an **optional dependency**
  (`pip install "hubrelay[e2e]"`) — the core stays stdlib-only and plain
  HTTP keeps working. Plugin side: Web Crypto / Node crypto, zero deps.
  站点侧把 `cryptography` 做成**可选依赖**（`hubrelay[e2e]`），核心仍零依
  赖、明文通道继续可用；插件侧走 Web Crypto / Node crypto，零新增依赖。
- **Replay / 重放**: `nonce` is monotonic per session; the station rejects
  replays and records the offender. 每会话单调递增，站点拒绝重放并记录来源。
- **Fallback / 降级**: clients that do not implement the envelope keep using
  plain JSON; the admin console shows which sessions are encrypted.
  未实现信封的客户端继续明文；管理台标注每个会话是否已加密。
- **What TLS still adds / TLS 仍有的价值**: E2E here protects the payload;
  it does not authenticate the *station* to the client beyond the TOIP join.
  TOIP 的站点指纹（station id）承担这个角色。站点身份认证由 TOIP 的
  station id 承担。

## Relationship to the TOTP secret / 与 TOTP 种子的关系

The TOTP seed never crosses the wire (join proves possession of the rolling
code, not the seed). E2E traffic keys are derived from the session token and
ephemeral X25519 keys — the seed is not an input, so a compromised session
key says nothing about the seed.

TOTP 种子从不过网（join 只证明「持有滚动口令」，不是持有种子）。E2E 流量
密钥由会话令牌与一次性 X25519 密钥派生——种子不是输入，会话密钥泄露推不
出种子。

## Secrets at rest / 落盘凭证（已在 0.4.0 落地）

Upstream keys (`pool.json`) and the TOTP seed (`toip.json`) are encrypted at
rest with Windows DPAPI (CurrentUser scope): copying the file to another
machine or account yields nothing. Non-Windows platforms fall back to
plaintext + 0600 with a startup warning — we do not ship home-rolled crypto.

上游密钥（pool.json）与 TOTP 种子（toip.json）已用 Windows DPAPI（当前用户
域）加密落盘：文件被拷到别的机器或别的账户都解不开。非 Windows 平台诚实
降级为明文 + 0600 + 启动警告——不上自研密码学。
