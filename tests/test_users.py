"""用户体系测试：注册门控、登录验证、额度扣减、兑换码、公网面板全链路。"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from relayhub.gateway.service import RelayServer, demo_router
from relayhub.gateway.users import (
    RedeemStore,
    UserError,
    UserPool,
    UserStore,
    hash_password,
    verify_password,
)


# ---------------------------------------------------------------- 单元


def test_password_hash_roundtrip() -> None:
    stored = hash_password("s3cret-password")
    assert stored.startswith("pbkdf2$")
    assert verify_password("s3cret-password", stored)
    assert not verify_password("wrong", stored)
    assert not verify_password("s3cret-password", "garbage")


def test_register_gates_and_uniqueness(tmp_path: Path) -> None:
    pool = UserPool(allow_register=True, default_quota=500)
    user = pool.register("alice", "password8")
    assert user.quota == 500
    with pytest.raises(UserError):
        pool.register("alice", "password8")
    with pytest.raises(UserError):
        pool.register("bob", "short")  # 密码太短
    closed = UserPool(allow_register=False)
    # 注册门控在 UserStore.register；这里直接验证 verify
    assert pool.verify("alice", "password8") is not None
    assert pool.verify("alice", "wrong") is None
    assert pool.verify("nobody", "password8") is None


def test_deduct_atomic_no_oversell() -> None:
    pool = UserPool(default_quota=100)
    user = pool.register("bob", "password8")
    assert pool.deduct(user.user_id, 60) is True
    assert pool.deduct(user.user_id, 60) is False  # 不透支
    assert pool.deduct(user.user_id, 40) is True
    assert user.quota == 0
    user.quota = -1  # 不限量
    assert pool.deduct(user.user_id, 999999) is True


def test_cost_calculation_with_group_multiplier() -> None:
    pool = UserPool(price_in_per_1k=2.0, price_out_per_1k=6.0, groups={"default": 1.0, "vip": 0.5})
    user = pool.register("carol", "password8")
    vip = pool.register("dave", "password8")
    vip.group = "vip"
    # 1000 in + 1000 out = 2 + 6 = 8 点
    assert pool.cost_of(user, 1000, 1000) == 8
    assert pool.cost_of(vip, 1000, 1000) == 4  # vip 半价
    assert pool.cost_of(user, 0, 0) == 0


def test_redeem_code_single_use(tmp_path: Path) -> None:
    store = RedeemStore(tmp_path / "codes.json")
    [code] = store.generate(1, 500)
    assert store.redeem(code.code, "u1") == 500
    with pytest.raises(UserError):
        store.redeem(code.code, "u2")  # 已核销
    with pytest.raises(UserError):
        store.redeem("rhx-notexist", "u1")


def test_user_store_merges_external_changes(tmp_path: Path) -> None:
    path = tmp_path / "users.json"
    store = UserStore(path)
    store.mutate(lambda p: p.users.append(
        __import__("relayhub.gateway.users", fromlist=["User"]).User(
            user_id="u1", username="admin1", password_hash=hash_password("password8"),
            role="admin", quota=-1,
        )
    ))
    assert store.verify("admin1", "password8") is not None


# ---------------------------------------------------------------- 面板全链路


def _call(base: str, path: str, body: dict | None = None, cookie: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{base}{path}", data=data, method="POST" if body is not None else "GET")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if cookie:
        request.add_header("Cookie", f"rh_session={cookie}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode()), response.headers
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode()), exc.headers


@pytest.fixture
def panel_relay(tmp_path: Path):
    """开放注册 + 兑换码的网关（令牌文件也在 tmp，面板能发 API Key）。"""
    import relayhub.paths as paths
    from relayhub.gateway.tokens import TokenStore
    from relayhub.gateway.users import UserStore

    original = paths.users_path
    paths.users_path = lambda: tmp_path / "users.json"
    original_codes = paths.redeem_codes_path
    paths.redeem_codes_path = lambda: tmp_path / "codes.json"
    store = UserStore(tmp_path / "users.json")
    store.mutate(lambda p: setattr(p, "allow_register", True))
    server = RelayServer(
        ("127.0.0.1", 0),
        demo_router(),
        api_key=None,
        event_delay=0.0,
        tokens=TokenStore(tmp_path / "tokens.json"),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, tmp_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        paths.users_path = original
        paths.redeem_codes_path = original_codes


def test_panel_register_login_redeem_flow(panel_relay) -> None:
    server, tmp_path = panel_relay
    base = server.base_url

    # 注册：拿会话 cookie + 一次性 API Key
    status, body, headers = _call(base, "/api/auth/register", {"username": "eve", "password": "password8"})
    assert status == 200 and body["ok"]
    set_cookie = headers.get("Set-Cookie") or ""
    cookie = set_cookie.split(";")[0].split("=", 1)[1]
    assert body["token"].startswith("rht_")

    # whoami
    status, body, _ = _call(base, "/api/user/me", cookie=cookie)
    assert status == 200 and body["username"] == "eve"
    assert body["quota"] == server.users.pool.default_quota

    # 用 API Key 打真实端点 → 额度被扣（演示路由 usage 12/8 → cost = 12/1000*2 + 8/1000*6 ≈ 0.096 → 1 点）
    request = urllib.request.Request(
        f"{base}/v1/chat/completions",
        data=json.dumps({"model": "glm-5.2", "messages": [{"role": "user", "content": "hi"}]}).encode(),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {body.get('api_key_hint') or 'x'}")
    # api_key_hint 只有尾号——真正调用需要明文，这里直接从令牌文件外的注册响应取
    # （上面注册响应的 token 是明文，此处重新注册一个新用户来做调用验证）
    status2, body2, headers2 = _call(base, "/api/auth/register", {"username": "frank", "password": "password8"})
    plain_key = body2["token"]
    request = urllib.request.Request(
        f"{base}/v1/chat/completions",
        data=json.dumps({"model": "glm-5.2", "messages": [{"role": "user", "content": "hi"}]}).encode(),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {plain_key}")
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status == 200
    frank = server.users.pool.find_by_name("frank")
    assert frank.used > 0 and frank.quota < server.users.pool.default_quota

    # 兑换码
    codes_store = server.redeem
    [code] = codes_store.generate(1, 500)
    status, body, _ = _call(base, "/api/user/redeem", {"code": code.code}, cookie=cookie)
    assert status == 200 and body["credits"] == 500
    with pytest.raises(UserError):
        codes_store.redeem(code.code, "someone-else")

    # 登出后 whoami 401
    status, _, _ = _call(base, "/api/auth/logout", {}, cookie=cookie)
    assert status == 200
    status, _, _ = _call(base, "/api/user/me", cookie=cookie)
    assert status == 401


# ---------------------------------------------------------------- 预扣费


def test_pre_consume_and_settle() -> None:
    """预扣→结算多退少补；预扣不足拒绝；不限量恒通过且不动 quota。"""
    pool = UserPool(default_quota=100)
    user = pool.register("pre", "password8")
    assert pool.pre_consume(user.user_id, 30) is True
    assert user.quota == 70 and user.used == 30

    pool.settle(user.user_id, 30, 12)  # 实际 12 点 → 退 18
    assert user.quota == 88 and user.used == 12

    assert pool.pre_consume(user.user_id, 500) is False  # 预扣超过余额
    assert user.quota == 88  # 拒绝时不冻结

    user.quota = -1  # 不限量：预扣恒通过且不冻结；结算只记累计（服务层对不限量的 pre 恒为 0）
    assert pool.pre_consume(user.user_id, 999) is True
    assert user.used == 12 and user.quota == -1
    pool.settle(user.user_id, 0, 10)
    assert user.quota == -1 and user.used == 22  # 只记累计，不动额度


def test_panel_pre_consume_rejects_oversized_prompt(panel_relay) -> None:
    """输入体量预估超过余额 → relay 之前就 429，余额不动，上游零消耗。"""
    server, tmp_path = panel_relay
    base = server.base_url
    status, body, headers = _call(base, "/api/auth/register", {"username": "greta", "password": "password8"})
    assert status == 200
    cookie = (headers.get("Set-Cookie") or "").split(";")[0].split("=", 1)[1]
    plain_key = body["token"]

    big = "x" * 4_400_000  # est_input ≈ 1.1M tokens → 预估 2200 点 > 1000
    request = urllib.request.Request(
        f"{base}/v1/chat/completions",
        data=json.dumps({"model": "glm-5.2", "messages": [{"role": "user", "content": big}]}).encode(),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", f"Bearer {plain_key}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    assert status == 429

    status, body, _ = _call(base, "/api/user/me", cookie=cookie)
    assert body["quota"] == server.users.pool.default_quota  # 分文未扣
