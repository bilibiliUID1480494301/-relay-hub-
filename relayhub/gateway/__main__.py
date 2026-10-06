"""`python -m relayhub.gateway <serve|admin|pool|token|clients|pair|audit|check>` 入口。

    serve   起中转站。`--pool` 指定号池（连真实上游）；不传则用返回固定文本的演示池。
    admin   中转站控制台（本地网页，独立进程 + 独立端口）
    pool    管理上游号池：add / ls / rm / enable / disable / credit / stats
    token   管理下游令牌（对标 one-api 的「令牌」）：add / ls / rm / enable / disable
    clients 客户端反代理档案：ls / spec（生成下游客户端接入配置）
    pair    带外配对：begin / cancel（网关侧）、request（设备侧）
    audit   控制面操作审计查看
    check   对着任意网关跑一致性探测（也可指向 New API 这类现成网关）

术语分清楚，别混：
  * **上游 Key**（`pool` 与 `admin` 管的东西）：你手上的官方/自建渠道凭证，存在号池文件里。
  * **下游令牌**（`token` 管的东西 / `serve --api-key` 的 master 凭证）：发给客户端设备的
    凭证，与上游 Key 完全是两回事——轮换方向相反（下游换 Key 必须重推客户端配置）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .. import paths
from . import admin as admin_module
appconfig_module = None  # 未安装客户端扩展包时的占位
from . import audit as audit_module
from . import clients as clients_module
from . import discovery as discovery_module
from .doctor_api import cmd_doctor as _cmd_doctor
from . import localscan as localscan_module
from . import pairing as pairing_module
from . import pluginlogs as pluginlogs_module
from . import policy as policy_module
from . import reqlog as reqlog_module
from . import toip as toip_module
from .conformance import main as conformance_main, Probe
from .pool import (
    PROTOCOL_ANTHROPIC,
    PROTOCOL_OPENAI_CHAT,
    KeyPool,
    PoolError,
    is_self_reference,
    key_from_spec,
)
from .router import KeyPoolRouter, ReloadingRouter
from .service import DemoRouter, RelayServer, demo_pool
from .tokens import (
    SCOPE_TEST,
    DownstreamToken,
    TokenError,
    TokenPool,
    TokenStore,
    generate_token,
)
from .admin import is_loopback


def _public_safety_error(api_key: str | None, enabled_tokens: int) -> str | None:
    """公网绑定的安全闸。返回错误文案 = 拒绝启动；None = 放行。

    「有凭证」的定义：master 凭证或至少一枚启用中的下游令牌。
    测试密钥也算凭证——它只能打到本地合成应答器，公网性能测试正是它的本职。
    """
    if api_key or enabled_tokens > 0:
        return None
    return (
        "公网模式必须先配凭证：--api-key 或至少一枚启用中的下游令牌"
        "（`token add`）。无凭证上公网等于把网关白送给全网。"
    )


def _safe_stdout() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass


def _mask(secret: str) -> str:
    """上游 Key 只露尾 4 位：终端里的东西经常被截图、贴进群里。"""
    if not secret:
        return "<无>"
    return f"…{secret[-4:]}" if len(secret) > 4 else "…"


def _parse_model_tokens(tokens: list[str] | None) -> tuple[list[str], dict[str, int]]:
    """支持 "glm-5.2" 或 "glm-5.2:1000000"（后者声明上下文长度）。"""
    models: list[str] = []
    windows: dict[str, int] = {}
    for token in tokens or ():
        model_id, _, ctx = token.partition(":")
        model_id = model_id.strip()
        if not model_id:
            continue
        models.append(model_id)
        if ctx.strip():
            windows[model_id] = int(ctx)
    return models, windows


def _pool_file(args: argparse.Namespace) -> Path:
    return Path(args.pool) if args.pool else paths.pool_path()


# ---------------------------------------------------------------- serve


def _cmd_serve(argv: list[str]) -> int:
    if argv and argv[0] in ("help", "-h") and "--help" not in argv:
        # 「serve help」这种写法直接映射到 --help，别让人吃 argparse 报错
        argv = ["--help"]
    parser = argparse.ArgumentParser(prog="relayhub.gateway serve", description="起中转站")
    parser.add_argument(
        "--pool", type=Path, default=None, help="号池文件；不传则用演示池"
    )
    parser.add_argument(
        "--tokens",
        type=Path,
        default=None,
        dest="tokens",
        help="下游令牌文件；不传则用默认路径（默认 %%LOCALAPPDATA%%\\relay-hub\\tokens.json）",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        dest="discover",
        help="开启局域网发现（UDP 广播应答，见 README §十；首次会弹防火墙授权）",
    )
    parser.add_argument(
        "--discovery-port",
        type=int,
        default=discovery_module.DISCOVERY_PORT,
        dest="discovery_port",
        help="发现服务 UDP 端口（默认 8795）",
    )
    parser.add_argument(
        "--name",
        default="relay-hub",
        help="实例名（发现应答与管理面展示用）",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument(
        "--public",
        action="store_true",
        dest="public",
        help="公网模式：绑定 0.0.0.0 对外提供服务。必须先配凭证（--api-key 或下游令牌），"
        "否则拒绝启动——公网无凭证等于把网关白送给全网。建议只发测试密钥（token add --scope test）。",
    )
    parser.add_argument(
        "--api-key",
        default="rh_local_dev",
        help="发给客户端的下游凭证（与上游 Key 无关）；传空字符串则关闭鉴权",
    )
    parser.add_argument(
        "--event-delay",
        type=float,
        default=0.0,
        dest="event_delay",
        help="每个 SSE 事件之间额外 sleep 的秒数（验证真增量时用 0.03）",
    )
    parser.add_argument("--timeout", type=float, default=120.0, help="非流式请求的上游超时")
    parser.add_argument(
        "--health-interval",
        type=float,
        default=300.0,
        dest="health_interval",
        help="内置健康探测间隔秒数（TCP 探测各渠道 base_url；0=关闭）。"
        "探测失败计入连败（到阈值进 err 冷却），恢复只清 err 档、不碰 disable 档。",
    )
    parser.add_argument("--stream-timeout", type=float, default=300.0, dest="stream_timeout")
    parser.add_argument(
        "--no-watch",
        action="store_true",
        dest="no_watch",
        help="不监听号池文件变化（默认热加载，加 Key 不用重启）",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        dest="scan",
        help="启动前自动扫描本机推理服务并导入号池（需配合 --pool）",
    )
    parser.add_argument(
        "--no-request-log",
        action="store_true",
        dest="no_request_log",
        help="不写请求明细日志（默认写到 RELAYHUB_HOME\\requests.jsonl）",
    )
    parser.add_argument(
        "--log-retention-days",
        type=int,
        default=30,
        dest="log_retention_days",
        help="请求明细保留天数（按日文件自动清理；0=永久保留，默认 30）",
    )
    parser.add_argument(
        "--ip-rpm",
        type=int,
        default=60,
        dest="ip_rpm",
        help="单 IP 每分钟请求上限（对 /v1 推理端点生效，鉴权前拦截；0=关闭）。"
        "公网/教室 NAT 场景防单出口刷请求",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=4,
        dest="max_concurrency",
        help="同时在处理的推理请求数上限（0=不限制）。超出进排队",
    )
    parser.add_argument(
        "--queue-size",
        type=int,
        default=16,
        dest="queue_size",
        help="并发满员时的排队席位（排队而非硬拒）",
    )
    parser.add_argument(
        "--queue-wait",
        type=float,
        default=30.0,
        dest="queue_wait",
        help="排队最久等待秒数，超时回 429（0=满员即拒，不排队）",
    )
    parser.add_argument(
        "--pair-mode",
        choices=("code", "auto-lan"),
        default="code",
        dest="pair_mode",
        help=(
            "配对模式：code=带外配对码（默认）；"
            "auto-lan=局域网免码自动配对（回环/私有来源直接发令牌，"
            "同设备幂等复用；公网来源仍要求配对码）"
        ),
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)


    if args.pool:
        path = Path(args.pool)
        if not path.is_file():
            print(f"号池文件不存在：{path}", file=sys.stderr)
            print("用 `python -m relayhub.gateway pool add --help` 建一个。", file=sys.stderr)
            return 2
        if args.scan:
            servers = localscan_module.scan()
            if servers:
                imported, _skipped = localscan_module.import_to_pool(path, servers)
                for key in imported:
                    print(f"本机扫描：已导入 {key.label}  模型 {list(key.models)}")
            else:
                print("本机扫描：未发现推理服务。")
        timeouts = {"timeout": args.timeout, "stream_timeout": args.stream_timeout}
        router = (
            KeyPoolRouter(KeyPool.load(path), persist_path=path, **timeouts)
            if args.no_watch
            else ReloadingRouter(path, **timeouts)
        )
        models = router.models()
        watch = "关" if args.no_watch else "开"
        print(f"号池：{path}（{len(models)} 个模型声明，热加载{watch}）")
        if not models:
            print(
                "警告：没有任何 Key 声明模型，/v1/models 会是空列表，客户端拉不到模型。",
                file=sys.stderr,
            )
    else:
        if args.scan:
            print("--scan 需要配合 --pool（演示池没有可导入的号池）。", file=sys.stderr)
            return 2
        router = DemoRouter(demo_pool())
        print("号池：演示池（返回固定文本，只用于验证契约；要连真实上游请加 --pool）")
        models = router.models()

    # 下游令牌：显式给了路径就必须存在（打错路径静默退回 master-only 会让人以为
    # 令牌生效了）；没给则默认路径常驻——配对发放需要它，空池时鉴权仍是 master-only。
    if args.tokens:
        if not Path(args.tokens).is_file():
            print(f"令牌文件不存在：{args.tokens}", file=sys.stderr)
            print("用 `python -m relayhub.gateway token add --help` 建第一个令牌。", file=sys.stderr)
            return 2
        token_store: TokenStore | None = TokenStore(Path(args.tokens))
        token_path = Path(args.tokens)
    else:
        token_path = paths.tokens_path()
        token_store = TokenStore(token_path)

    # 配对服务：端点常在，但窗口关闭时 /v1/pair 直接拒绝（零常态暴露）。
    # TOIP 接入服务：站点身份文件不存在时它自己报「未启用」，端点全 404。
    # 构造它不需要任何开关——「启用 TOIP」这件事由 `hubrelay toip station`
    # 创建一个文件来表达，而不是由 serve 的某个 flag 表达。少一个 flag
    # 少一处「管理员以为开了其实没开」的可能。
    toip_service = toip_module.ToipService(
        toip_module.TicketStore(paths.toip_tickets_path()),
        token_store,
        paths.toip_station_path(),
    )
    pairing_service = pairing_module.PairingService(
        tokens=token_store, path=paths.pairing_path()
    )

    # 公网开关：绑 0.0.0.0 前必须过安全闸——没有任何凭证就上公网是事故不是配置。
    host = args.host
    if args.public and is_loopback(host):
        host = "0.0.0.0"
    if not is_loopback(host):
        guard_error = _public_safety_error(
            args.api_key, token_store.stats()["enabled_count"] if token_store else 0
        )
        if guard_error:
            print(f"错误：{guard_error}", file=sys.stderr)
            return 2

    server = RelayServer(
        (host, args.port),
        router,
        api_key=args.api_key or None,
        event_delay=args.event_delay,
        verbose=args.verbose,
        tokens=token_store,
        pairing=pairing_service,
        request_log=None if args.no_request_log else paths.requests_log_path(),
        ip_rpm=args.ip_rpm,
        max_concurrency=args.max_concurrency,
        queue_size=args.queue_size,
        queue_wait=args.queue_wait,
        policy=policy_module.PolicyStore(paths.policy_path()),
        pair_mode=args.pair_mode,
    )
    responder = None
    if args.discover:
        responder = discovery_module.DiscoveryResponder(
            name=args.name,
            data_port=args.port,
            models_count=lambda: len(router.models()),
            pairing_open=pairing_service.window_open,
            port=args.discovery_port,
        )
        responder.start()
    print(f"监听：{server.base_url}（实例名 {args.name}）")
    if not is_loopback(host):
        print(
            "⚠ 公网模式：网关绑定在非回环地址上，所有流量都必须带凭证。\n"
            "  强烈建议只发测试密钥（`token add --scope test`）给第三方，"
            "正常令牌不要外发。",
        )
    enabled = token_store.stats()["enabled_count"]
    if enabled:
        print(f"下游凭证：master {_mask(args.api_key or '')} + 令牌文件 {token_path}（{enabled} 个启用中）")
    else:
        print(
            f"下游凭证：master {_mask(args.api_key or '')}"
            f"（令牌文件空；设备可经 `pair begin` 配对领取）"
        )
    print("路由：GET /v1/models, POST /v1/messages, POST /v1/chat/completions, POST /v1/pair")
    print(
        f"防护：单 IP {args.ip_rpm or '∞'} 请求/分钟；并发 {args.max_concurrency or '∞'}"
        + (f" + 排队 {args.queue_size} 席（最长等 {args.queue_wait:g}s）" if args.max_concurrency else "")
    )
    print(
        "客户端接入："
        + ", ".join(f"{p.client_id}={p.status}" for p in clients_module.profiles())
        + "（`clients ls` 看档案）"
    )
    if responder is not None:
        print(f"发现服务：UDP {responder.port} 广播应答中。")
    reqlog_module.set_retention(args.log_retention_days)
    if args.no_request_log:
        print("请求明细：已关闭（--no-request-log）。")
    else:
        print(f"请求明细：{paths.requests_log_path()}（`requests` / `usage` 查看）")
    if models:
        print(f"模型：{', '.join(sorted(models)[:8])}" + (" …" if len(models) > 8 else ""))
    print("Ctrl+C 停止。")
    if args.health_interval > 0:
        health_thread = threading.Thread(
            target=_health_loop,
            args=(router, args.health_interval),
            daemon=True,
            name="health-probe",
        )
        health_thread.start()
        print(f"健康探测：每 {args.health_interval:g}s TCP 探测各渠道（失败计连败，恢复清 err 冷却）。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        if responder is not None:
            responder.stop()
        server.server_close()
    return 0


def _health_loop(router: Any, interval: float) -> None:
    """内置健康探测线程：TCP 探测各启用渠道，失败计连败、恢复清 err 冷却。

    与外部 watchdog 的区别：探活在网关进程内，禁用状态由号池自己的
    冷却语义管理——disable 档（鉴权失效）绝不会被 TCP 握手洗白。
    """
    import socket
    from urllib.parse import urlparse

    while True:
        time.sleep(interval)
        pool = getattr(router, "pool", None)
        if pool is None:
            continue
        for key in list(pool.keys):
            if not key.enabled:
                continue
            parsed = urlparse(key.base_url)
            host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
            ok = False
            if host and port:
                try:
                    with socket.create_connection((host, port), timeout=3.0):
                        ok = True
                except OSError:
                    ok = False
            pool.report_health(key, ok)
        if getattr(router, "persist_path", None):
            pool.save(router.persist_path)


# ---------------------------------------------------------------- pool


def _cmd_pool_add(args: argparse.Namespace) -> int:
    path = _pool_file(args)
    pool = KeyPool.load(path)
    models, windows = _parse_model_tokens(args.model)
    checkin: dict = {}
    try:
        mapping: dict[str, str] = {}
        if args.mapping:
            for pair in str(args.mapping).split(","):
                name, _, up = pair.partition("=")
                if not name.strip() or not up.strip():
                    print(f"错误：--mapping 期望 '对外名=上游名'，收到 {pair!r}", file=sys.stderr)
                    return 2
                mapping[name.strip()] = up.strip()
        if is_self_reference(args.base_url):
            print(
                f"错误：base_url 指向本网关自己（{args.base_url}）——这会构成转发自环。"
                "上游应该是别的服务，不是本站。",
                file=sys.stderr,
            )
            return 2
        key = key_from_spec(
            {
                "base_url": args.base_url,
                "api_key": args.api_key,
                "protocol": args.protocol,
                "label": args.label,
                "models": models,
                "model_windows": windows,
                "model_mapping": mapping,
                "priority": args.priority,
                "weight": args.weight,
                "credits": args.credit,
                "auth_mode": args.auth_mode,
                "note": args.note or "",
            }
        )
    except PoolError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    if pool.get(key.key_id) or pool.find_by_label(key.label):
        if not args.replace:
            print(f"错误：label 已存在：{key.label}（要覆盖请加 --replace）", file=sys.stderr)
            return 1
        pool.remove(key.label)

    pool.add(key)
    pool.save(path)
    print(f"已写入 {path}")
    print(f"  {key.label}  {key.protocol}  {key.base_url}  上游 Key={_mask(key.api_key)}")
    if key.auth_mode != "auto":
        print(f"  鉴权模式：{key.auth_mode}")
    print(f"  模型：{list(key.models) or '（未声明 → 对全部模型开放）'}")
    if key.model_mapping:
        print(f"  模型映射：{key.model_mapping}")
    if key.priority:
        print(f"  优先级：{key.priority}")
    if key.credits >= 0:
        print(f"  额度：{key.credits}")
    if windows:
        print(f"  上下文：{windows}")
    return 0


def _cmd_pool_ls(args: argparse.Namespace) -> int:
    path = _pool_file(args)
    if not path.is_file():
        print(f"{path} 不存在（号池为空）。用 `pool add` 添加第一个 Key。")
        return 0
    pool = KeyPool.load(path)
    now = time.time()
    tier_text = "/".join(f"{n}:{s:g}s" for n, s in pool.cooldown_tiers.items())
    print(f"号池：{path}")
    print(
        f"策略={pool.strategy}  熔断阈值={pool.failure_threshold}  "
        f"冷却档位={tier_text}  共 {len(pool.keys)} 个 Key"
    )
    if not pool.keys:
        print("（没有 Key）")
        return 0
    for key in pool.keys:
        state = "可用" if key.is_available(now) else f"冷却 {key.cooling_down_for(now):.0f}s"
        if key.cooldown_tier:
            state = f"{state}[{key.cooldown_tier}]"
        if not key.enabled:
            state = "已禁用(鉴权)" if key.cooldown_tier == "disable" else "已禁用"
        credits = "未记录" if key.credits < 0 else str(key.credits)
        seg_checkin = ""
        usage = key.usage
        print(
            f"  {key.label:<24} {key.protocol:<17} {state:<16} "
            f"额度 {credits:>8}  {seg_checkin}"
            f"模型 {len(key.models) or '全部'} 个  "
            f"请求 {usage.requests}（成功 {usage.ok} / 失败 {usage.failed}）  "
            f"tokens {usage.tokens_in}→{usage.tokens_out}  key={_mask(key.api_key)}"
        )
        if key.last_error:
            print(f"      最近错误：{key.last_error}")
    totals = pool.totals()
    print(
        f"  合计：请求 {totals.requests}（成功 {totals.ok} / 失败 {totals.failed}）  "
        f"tokens {totals.tokens_in}→{totals.tokens_out}"
    )
    return 0


def _cmd_pool_stats(args: argparse.Namespace) -> int:
    path = _pool_file(args)
    if not path.is_file():
        print(f"{path} 不存在（号池为空）。", file=sys.stderr)
        return 1
    stats = KeyPool.load(path).stats()
    if args.json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return 0
    print(
        f"共 {stats['key_count']} 个 Key，可用 {stats['usable_count']} 个"
        f"（策略 {stats['strategy']}）"
    )
    for item in stats["keys"]:
        state = "可用" if item["available"] else f"冷却 {item['cooling_down_for']}s"
        print(
            f"  {item['label']:<24} {state:<12}  连续失败 {item['consecutive_failures']}  "
            f"{item['usage']}"
        )
    print(f"合计：{stats['totals']}")
    return 0


def _cmd_pool_toggle(args: argparse.Namespace, enabled: bool) -> int:
    path = _pool_file(args)
    pool = KeyPool.load(path)
    if not pool.set_enabled(args.key, enabled):
        print(f"错误：找不到 Key {args.key}", file=sys.stderr)
        return 1
    pool.save(path)
    print(f"{'已启用' if enabled else '已禁用'}：{args.key}")
    return 0


def _cmd_pool_rm(args: argparse.Namespace) -> int:
    path = _pool_file(args)
    pool = KeyPool.load(path)
    if not pool.remove(args.key):
        print(f"错误：找不到 Key {args.key}", file=sys.stderr)
        return 1
    pool.save(path)
    print(f"已移除：{args.key}")
    return 0


def _cmd_pool_credit(args: argparse.Namespace) -> int:
    """记录渠道剩余额度（credit 感知调度的输入）。

    手动记录是有意的：各上游的额度查询端点互不相同，通用网关不假装会读；
    真实来源可以由包装项目的状态页、人工观察或后续的 per-project 适配器回填。
    """
    path = _pool_file(args)
    pool = KeyPool.load(path)
    key = pool.get(args.key) or pool.find_by_label(args.key)
    if key is None:
        print(f"错误：找不到 Key {args.key}", file=sys.stderr)
        return 1
    key.credits = int(args.value)
    key.credits_updated_at = time.time()
    pool.save(path)
    print(f"已记录：{key.label} 剩余额度 {key.credits}")
    return 0


def _cmd_pool_init(args: argparse.Namespace) -> int:
    path = _pool_file(args)
    if path.is_file() and not args.force:
        print(f"{path} 已存在（要重建请加 --force）")
        return 0
    KeyPool([]).save(path)
    print(f"已创建空号池：{path}")
    return 0


def _cmd_pool(argv: list[str]) -> int:
    # `--pool` 只挂在各动作上（`pool add --pool X`）。
    # 不能同时挂在组上：argparse 的子命令会用一个全新 namespace 解析再把全部字段
    # 拷回来，子命令的默认值会把组上刚设好的值覆盖成 None——表现是「静默写到了
    # 默认路径」，比报错难查得多。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--pool",
        type=Path,
        default=None,
        help="号池文件（默认 %%LOCALAPPDATA%%\\relay-hub\\pool.json）",
    )

    parser = argparse.ArgumentParser(prog="relayhub.gateway pool", description="管理上游号池")
    sub = parser.add_subparsers(dest="action", required=True)

    p_add = sub.add_parser("add", parents=[common], help="添加一个上游 Key")
    p_add.add_argument("--base-url", dest="base_url", required=True, help="上游 Base URL")
    p_add.add_argument("--api-key", dest="api_key", default="", help="上游 Key（默认空，自建无鉴权时用）")
    p_add.add_argument(
        "--protocol",
        default=PROTOCOL_ANTHROPIC,
        choices=[
            PROTOCOL_ANTHROPIC,
            PROTOCOL_OPENAI_CHAT,
        ],
    )
    p_add.add_argument(
        "--auth-mode",
        dest="auth_mode",
        default="auto",
        choices=["auto", "bearer"],
        help="bearer=强制 Authorization: Bearer（部分上游要求 Bearer 而不是 x-api-key）",
    )
    p_add.add_argument("--label", default=None, help="显示名；默认由 host + Key 尾号生成")
    p_add.add_argument(
        "--model",
        action="append",
        help="可重复；格式 id 或 id:contextWindow。省略=对全部模型开放",
    )
    p_add.add_argument("--note", default="")
    p_add.add_argument("--weight", type=int, default=1, help="同优先级内的权重（预留，当前组内按策略）")
    p_add.add_argument(
        "--mapping",
        dest="mapping",
        default=None,
        help="模型映射，格式 '对外名=上游名'，逗号分隔（如 'glm-5.2=[满血]GLM-5.2'）。客户端只见对外名",
    )
    p_add.add_argument(
        "--priority",
        type=int,
        default=0,
        dest="priority",
        help="调度优先级，越大越优先；高优先级全灭才落到低优先级（主/备语义）",
    )
    p_add.add_argument(
        "--credit",
        type=int,
        default=-1,
        dest="credit",
        help="剩余额度（most_credits 策略用）；省略=未记录",
    )
    p_add.add_argument("--replace", action="store_true", help="同 label 时覆盖而不是报错")
    p_add.set_defaults(func=_cmd_pool_add)

    sub.add_parser("ls", parents=[common], help="列出全部 Key 与用量").set_defaults(
        func=_cmd_pool_ls
    )

    p_stats = sub.add_parser("stats", parents=[common], help="用量与熔断状态")
    p_stats.add_argument("--json", action="store_true")
    p_stats.set_defaults(func=_cmd_pool_stats)

    p_rm = sub.add_parser("rm", parents=[common], help="移除一个 Key（按 label 或 key_id）")
    p_rm.add_argument("key")
    p_rm.set_defaults(func=_cmd_pool_rm)

    p_en = sub.add_parser("enable", parents=[common], help="启用一个 Key 并清掉熔断冷却")
    p_en.add_argument("key")
    p_en.set_defaults(func=lambda a: _cmd_pool_toggle(a, True))

    p_dis = sub.add_parser("disable", parents=[common], help="禁用一个 Key（不删配置）")
    p_dis.add_argument("key")
    p_dis.set_defaults(func=lambda a: _cmd_pool_toggle(a, False))

    p_credit = sub.add_parser(
        "credit", parents=[common], help="记录一个 Key 的剩余额度（most_credits 策略的输入）"
    )
    p_credit.add_argument("key")
    p_credit.add_argument("value", type=int, help="剩余额度数值；来源见帮助外说明")
    p_credit.set_defaults(func=_cmd_pool_credit)

    p_init = sub.add_parser("init", parents=[common], help="创建空号池文件")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=_cmd_pool_init)

    args = parser.parse_args(argv)
    return int(args.func(args))


# ---------------------------------------------------------------- token


def _tokens_file(args: argparse.Namespace) -> Path:
    return Path(args.tokens) if args.tokens else paths.tokens_path()


def _cmd_token_add(args: argparse.Namespace) -> int:
    path = _tokens_file(args)
    pool = TokenPool.load(path)
    secret = args.token or generate_token()
    try:
        record = DownstreamToken(
            token_id=str(uuid.uuid4()),
            name=args.name,
            token=secret,
            models=args.model or (),
            scope=args.scope,
            rpm=args.rpm,
            daily_requests=args.daily,
            expires_at=(time.time() + args.days * 86400) if args.days > 0 else 0.0,
            note=args.note or "",
            group=args.group,
        )
        pool.add(record)
    except TokenError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    pool.save(path)
    print(f"已写入 {path}")
    print(f"  {record.name}  分组：{record.group}  模型限制：{list(record.models) or '（不限制）'}")
    if record.scope == SCOPE_TEST:
        print("  作用域：test（合成应答——不触达真实上游，不消耗渠道配额）")
    limits = []
    if record.rpm:
        limits.append(f"{record.rpm} 请求/分钟")
    if record.daily_requests:
        limits.append(f"{record.daily_requests} 请求/天")
    if record.expires_at:
        limits.append(f"有效期至 {time.strftime('%Y-%m-%d', time.localtime(record.expires_at))}")
    print(f"  限额：{' + '.join(limits) if limits else '（不限）'}")
    print(f"  令牌（只显示这一次，客户端配置用它；落盘仅存 SHA-256）：{record.token}")
    if not args.token:
        print("  （找回不了这个值；丢了就 rm 后重新 add）")
    return 0


def _cmd_token_ls(args: argparse.Namespace) -> int:
    path = _tokens_file(args)
    if not path.is_file():
        print(f"{path} 不存在（还没有下游令牌）。用 `token add` 给第一台设备发一个。")
        return 0
    pool = TokenStore(path).pool
    print(f"下游令牌：{path}（{len(pool.tokens)} 个）")
    if not pool.tokens:
        print("（没有令牌）")
        return 0
    for record in pool.tokens:
        state = "启用" if record.enabled else "已禁用"
        usage = record.usage
        print(
            f"  {record.name:<24} {state:<6} 令牌={_mask(record.token)}  "
            f"模型 {list(record.models) or '全部'}  "
            f"请求 {usage.requests}（成功 {usage.ok} / 失败 {usage.failed}）  "
            f"tokens {usage.tokens_in}→{usage.tokens_out}"
        )
        if record.note:
            print(f"      备注：{record.note}")
    return 0


def _cmd_token_rm(args: argparse.Namespace) -> int:
    path = _tokens_file(args)
    pool = TokenStore(path).pool
    if not pool.remove(args.name):
        print(f"错误：找不到令牌 {args.name}（按 name / token_id / 令牌全文匹配）", file=sys.stderr)
        return 1
    pool.save(path)
    print(f"已吊销：{args.name}（该设备的配置会开始 401，要恢复就重新 add 一枚并重推配置）")
    return 0


def _cmd_token_toggle(args: argparse.Namespace, enabled: bool) -> int:
    path = _tokens_file(args)
    pool = TokenStore(path).pool
    if not pool.set_enabled(args.name, enabled):
        print(f"错误：找不到令牌 {args.name}", file=sys.stderr)
        return 1
    pool.save(path)
    print(f"{'已启用' if enabled else '已禁用'}：{args.name}")
    return 0


def _cmd_token(argv: list[str]) -> int:
    # 与 `pool` 同一个 argparse 陷阱：`--tokens` 只挂各子命令，不挂组。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--tokens",
        type=Path,
        default=None,
        dest="tokens",
        help="令牌文件（默认 %%LOCALAPPDATA%%\\relay-hub\\tokens.json）",
    )

    parser = argparse.ArgumentParser(
        prog="relayhub.gateway token", description="管理下游令牌（每台设备一个的客户端凭证）"
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_add = sub.add_parser("add", parents=[common], help="发一枚新令牌（如 pad-classroom-3）")
    p_add.add_argument("--name", required=True, help="设备/客户端名，吊销时按它找")
    p_add.add_argument(
        "--group",
        default="default",
        help="分组标签（如 class-2 / vip），管理台可按组筛选与汇总；默认 default",
    )
    p_add.add_argument(
        "--model",
        action="append",
        dest="model",
        help="可重复；限制该令牌可用的模型。省略=不限制",
    )
    p_add.add_argument(
        "--scope",
        default="normal",
        choices=("normal", "test"),
        help="normal=正常走号池路由；test=本地合成应答（公网性能测试用，不碰真实上游）",
    )
    p_add.add_argument(
        "--rpm",
        type=int,
        default=0,
        help="每分钟请求上限；0=不限。公网令牌强烈建议设置（如 --rpm 30）",
    )
    p_add.add_argument(
        "--daily",
        type=int,
        default=0,
        dest="daily",
        help="每日请求上限；0=不限。随令牌文件落盘，重启不清零",
    )
    p_add.add_argument(
        "--days",
        type=int,
        default=0,
        dest="days",
        help="有效期天数；0=永不过期。公网令牌建议 30",
    )
    p_add.add_argument("--note", default="")
    p_add.add_argument(
        "--token",
        default=None,
        help="手动指定令牌值（测试/迁移用）；默认自动生成 rht_ 前缀随机值",
    )
    p_add.set_defaults(func=_cmd_token_add)

    sub.add_parser("ls", parents=[common], help="列出全部令牌与用量").set_defaults(
        func=_cmd_token_ls
    )

    p_rm = sub.add_parser("rm", parents=[common], help="吊销一枚令牌（该设备开始 401）")
    p_rm.add_argument("name")
    p_rm.set_defaults(func=_cmd_token_rm)

    p_en = sub.add_parser("enable", parents=[common], help="重新启用一枚令牌")
    p_en.add_argument("name")
    p_en.set_defaults(func=lambda a: _cmd_token_toggle(a, True))

    p_dis = sub.add_parser("disable", parents=[common], help="临时禁用一枚令牌（不删配置）")
    p_dis.add_argument("name")
    p_dis.set_defaults(func=lambda a: _cmd_token_toggle(a, False))

    args = parser.parse_args(argv)
    return int(args.func(args))




# ---------------------------------------------------------------- clients


def _cmd_clients_ls(args: argparse.Namespace) -> int:
    del args  # 无参数，占位保持签名一致
    print("客户端反代理档案（网关两个入站口对全体客户端通用，接入=补档案+发令牌）：")
    for profile in clients_module.profiles():
        status = {
            clients_module.STATUS_SUPPORTED: "已支持",
            clients_module.STATUS_GUIDED: "引导式",
            clients_module.STATUS_RESERVED: "预留",
        }[profile.status]
        print(f"  {profile.client_id:<10} [{status}] {profile.display_name}")
        print(f"    入站协议：{profile.inbound}    路径：{profile.endpoint}")
        print(f"    凭证头：{profile.auth_header}")
        print(f"    接入：{profile.how_to}")
        if profile.upstream_hint:
            print(f"    上游：{profile.upstream_hint}")
        for question in profile.open_questions:
            print(f"    待确认：{question}")
    return 0


def _cmd_clients_spec(args: argparse.Namespace) -> int:
    profile = clients_module.get(args.client)
    models: list = list(args.model or ())
    payload = clients_module.onboarding(
        args.client,
        base_url=args.base_url,
        api_key=args.api_key,
        models=models,
        spec_name=args.name,
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _cmd_clients(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="relayhub.gateway clients", description="客户端反代理档案（内置 + 扩展包注册）"
    )
    sub = parser.add_subparsers(dest="action", required=True)

    sub.add_parser("ls", help="列出全部客户端档案与接入方式").set_defaults(func=_cmd_clients_ls)

    p_spec = sub.add_parser(
        "spec", help="生成某客户端的接入配置（JSON）"
    )
    p_spec.add_argument("client", help="客户端 id（`clients ls` 查看可用值）")
    p_spec.add_argument("--base-url", dest="base_url", default="http://127.0.0.1:8799")
    p_spec.add_argument(
        "--api-key",
        dest="api_key",
        default="rh_local_dev",
        help="发给该设备的下游令牌（先用 token add 领一枚）",
    )
    p_spec.add_argument("--model", action="append", help="可重复；省略则尝试拉 /v1/models")
    p_spec.add_argument("--name", default="Relay Hub", help="注入 spec 的 provider 显示名")
    p_spec.set_defaults(func=_cmd_clients_spec)

    args = parser.parse_args(argv)
    return int(args.func(args))






# ---------------------------------------------------------------- pair


def _cmd_pair_begin(args: argparse.Namespace) -> int:
    window = pairing_module.open_window(
        args.pairing_file or paths.pairing_path(), client_id=args.client, ttl=args.ttl
    )
    print(f"配对窗口已开启（{args.ttl:.0f} 秒内有效，最多 5 次尝试，成功即焚）。")
    print(f"  配对码：{window['code']}")
    print(f"  客户端：{args.client}")
    print("  在设备上执行：relayhub.gateway pair request --code <配对码> --name <设备名>")
    print("  提前收回：relayhub.gateway pair cancel")
    if args.pairing_file:
        print(f"  窗口文件：{args.pairing_file}")
    return 0


def _cmd_pair_cancel(args: argparse.Namespace) -> int:
    if pairing_module.cancel_window(args.pairing_file or paths.pairing_path()):
        print("配对窗口已关闭。")
        return 0
    print("没有开启中的配对窗口。")
    return 0


def _cmd_pair_request(args: argparse.Namespace) -> int:
    base_url = args.base_url
    if not base_url:
        found = discovery_module.discover(timeout=args.discover_timeout)
        if not found:
            print("未发现网关。确认网关以 --discover 启动后重试，或直接给 --base-url。", file=sys.stderr)
            return 1
        if len(found) > 1:
            print("发现了多个网关，请用 --base-url 指定其一：", file=sys.stderr)
            for info in found:
                print(f"  http://{info.host}:{info.port}  {info.name}（{info.models} 个模型）", file=sys.stderr)
            return 1
        info = found[0]
        base_url = f"http://{info.host}:{info.port}"
        print(f"已发现网关：{info.name} @ {base_url}（{info.models} 个模型）")

    probe = Probe(base_url, timeout=args.timeout)
    response, _ = probe.post(
        "/v1/pair",
        {"code": args.code, "name": args.name, "client": args.client},
        with_auth=False,
    )
    if response.status != 200:
        print(f"配对失败（HTTP {response.status}）：{response.body.decode('utf-8', errors='replace')}", file=sys.stderr)
        return 1
    payload = json.loads(response.body.decode("utf-8"))
    token = str(payload.get("api_key") or "")
    print("配对成功！本设备的专属令牌（只显示这一次）：")
    print(f"  {token}")
    if payload.get("endpoint"):
        print(f"  接口路径：{payload['endpoint']}")
    if payload.get("models"):
        print(f"  可用模型：{[m['model_id'] for m in payload['models']]}")
    for step in payload.get("next") or []:
        print(f"  下一步：{step}")
    if args.out and payload.get("spec"):
        out = Path(args.out)
        out.write_text(json.dumps(payload["spec"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"  注入 spec 已写入：{out}")
        print("  按该客户端的接入指引把 spec 应用进去，即完成接入。")
    return 0


def _cmd_pair(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="relayhub.gateway pair", description="带外配对：新设备用 6 位码换取专属下游令牌"
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_begin = sub.add_parser("begin", help="开一个配对窗口（配对码打印在控制台）")
    p_begin.add_argument("--client", default="app", help="限定配对目标客户端（默认 app；可用 `clients ls` 查）")
    p_begin.add_argument("--ttl", type=float, default=pairing_module.PAIRING_TTL, help="窗口有效期秒数")
    p_begin.add_argument("--pairing-file", dest="pairing_file", type=Path, default=None, help=argparse.SUPPRESS)
    p_begin.set_defaults(func=_cmd_pair_begin)

    p_cancel = sub.add_parser("cancel", help="关闭配对窗口")
    p_cancel.add_argument("--pairing-file", dest="pairing_file", type=Path, default=None, help=argparse.SUPPRESS)
    p_cancel.set_defaults(func=_cmd_pair_cancel)

    p_req = sub.add_parser("request", help="设备侧：用配对码换令牌与接入配置")
    p_req.add_argument("--code", required=True, help="网关控制台显示的 6 位配对码")
    p_req.add_argument("--name", required=True, help="设备名（令牌名，吊销时按它找）")
    p_req.add_argument("--client", default="app", help="要接入的客户端类型")
    p_req.add_argument("--base-url", dest="base_url", default=None, help="跳过发现，直接指定网关地址")
    p_req.add_argument("--discover-timeout", dest="discover_timeout", type=float, default=3.0)
    p_req.add_argument("--timeout", type=float, default=15.0)
    p_req.add_argument("--out", default=None, help="把接入 spec 写到该文件")
    p_req.set_defaults(func=_cmd_pair_request)

    args = parser.parse_args(argv)
    return int(args.func(args))


# ---------------------------------------------------------------- toip


def _cmd_toip_station(args: argparse.Namespace) -> int:
    """建站点身份（幂等：已存在就只打印现状，除非 --force 轮换种子）。"""
    path = paths.toip_station_path()
    station = toip_module.load_station(path)
    if station is not None and not args.force:
        print(f"TOIP 站点已存在：{station.name}（station_id={station.station_id}）")
        print("  轮换口令种子（旧动态口令立刻作废，已发出的会话令牌不受影响）：")
        print("    relayhub.gateway toip station --force")
        _print_station_hint(station)
        return 0
    if station is None:
        station = toip_module.StationIdentity.create(name=args.name, base_url=args.base_url or "")
        toip_module.save_station(path, station)
        print(f"TOIP 站点已创建：{station.name}")
    else:
        station.name = args.name or station.name
        if args.base_url is not None:
            station.base_url = args.base_url
        toip_module.rotate_secret(path, station)
        print("口令种子已轮换（旧动态口令立刻作废）。")
    print(f"  站点 id：{station.station_id}")
    print(f"  身份文件：{path}")
    _print_station_hint(station)
    print("  下一步：为要接入的插件签一枚通行证")
    print("    relayhub.gateway toip ticket --name dsh-laptop --plugins dsh-relayhub-bridge")
    return 0


def _print_station_hint(station: "toip_module.StationIdentity") -> None:
    """打印当前动态口令与验证器 URI（管理员手抄或扫码都行）。"""
    code = toip_module.totp_now(station.secret_bytes)
    left = int(toip_module.totp_seconds_left())
    print(f"  当前动态口令：{code}（{left} 秒后滚动；口令种子只在身份文件里，不再打印）")
    print(f"  验证器 App：{toip_module.otpauth_uri(station.secret, label=station.name)}")


def _cmd_toip_qr(args: argparse.Namespace) -> int:
    """把 otpauth:// 登记二维码打到终端（验证器 App 直接扫屏）。

    装了 qr 扩展（pip install "hubrelay[qr]"）画 ASCII 二维码；没装退化为
    打印 otpauth URI 明文——验证器 App 手动添加效果一致。
    """
    station = toip_module.load_station(paths.toip_station_path())
    if station is None:
        print("尚未创建 TOIP 站点。先执行：relayhub.gateway toip station", file=sys.stderr)
        return 1
    uri = toip_module.otpauth_uri(station.secret, label=station.name)
    try:
        import qrcode  # 可选依赖
    except ImportError:
        print("otpauth URI（未装 qr 扩展，可手动添加到验证器）：")
        print(f"  {uri}")
        print('  想直接出二维码：pip install "hubrelay[qr]" 后重跑本命令。')
        return 0
    qr = qrcode.QRCode(border=2)
    qr.add_data(uri)
    qr.print_ascii(invert=True)
    print(f"站点：{station.name}（{station.station_id}）")
    print("用验证器 App 扫上方二维码；动态口令 30 秒滚动，插件接入时填当前口令。")
    return 0


def _cmd_toip_ticket(args: argparse.Namespace) -> int:
    """签一枚通行证：产出登记口令（一次性）并可立刻读出现行动态口令。"""
    station = toip_module.load_station(paths.toip_station_path())
    if station is None:
        print("尚未创建 TOIP 站点。先执行：relayhub.gateway toip station", file=sys.stderr)
        return 1
    plugins = [p.strip() for p in (args.plugins or "").split(",") if p.strip()]
    try:
        record, plain = toip_module.make_ticket(
            name=args.name, plugins=plugins, ttl=args.ttl, note=args.note or ""
        )
        toip_module.TicketStore(paths.toip_tickets_path()).add(record)
    except toip_module.ToipError as exc:
        print(f"签发失败：{exc}", file=sys.stderr)
        return 1
    print(f"通行证已签发：{record.name}")
    print(f"  登记口令（**只显示这一次**，插件首接用）：{plain}")
    print(f"  允许的插件：{', '.join(record.plugins) if record.plugins else '（不限制，任意插件都能用它接入）'}")
    if record.expires_at:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(record.expires_at))
        print(f"  有效期至：{stamp}")
    code = toip_module.totp_now(station.secret_bytes)
    print(f"  现行动态口令（重接用，30 秒滚动）：{code}")
    print("  插件侧：填中转站地址 + 上面任一凭证即可接入")
    return 0


def _cmd_toip_list(args: argparse.Namespace) -> int:
    station = toip_module.load_station(paths.toip_station_path())
    tickets = toip_module.TicketStore(paths.toip_tickets_path()).list()
    if args.json:
        print(
            json.dumps(
                {
                    "station": (
                        None
                        if station is None
                        else {
                            "station_id": station.station_id,
                            "name": station.name,
                            "base_url": station.base_url,
                        }
                    ),
                    "tickets": [
                        {
                            "ticket_id": t.ticket_id,
                            "name": t.name,
                            "hint": t.ticket_hint,
                            "plugins": list(t.plugins),
                            "enabled": t.enabled,
                            "used_count": t.used_count,
                            "last_used": t.last_used,
                            "last_ip": t.last_ip,
                            "expires_at": t.expires_at,
                            "token_id": t.token_id,
                        }
                        for t in tickets
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if station is None:
        print("（尚未启用 TOIP；`toip station` 创建站点身份）")
    else:
        print(f"站点：{station.name}  id={station.station_id}  base_url={station.base_url or '（按请求 Host 回填）'}")
    if not tickets:
        print("（还没有通行证）")
        return 0
    print(f"通行证（{len(tickets)} 枚）：")
    for t in tickets:
        state = "启用" if t.enabled else "停用"
        when = (
            time.strftime("%m-%d %H:%M", time.localtime(t.last_used)) if t.last_used else "从未"
        )
        print(
            f"  {t.name:<20} {t.ticket_hint}  {state}  用{t.used_count}次  最后{when}  "
            f"插件={','.join(t.plugins) or '*'}"
        )
    return 0


def _cmd_toip_revoke(args: argparse.Namespace) -> int:
    """吊销通行证：可选一并收回它换出去的会话令牌（默认收回）。"""
    store = toip_module.TicketStore(paths.toip_tickets_path())
    target = None
    for t in store.list():
        if t.name == args.name or t.ticket_id == args.name:
            target = t
            break
    if target is None:
        print(f"找不到通行证：{args.name}", file=sys.stderr)
        return 1
    token_id = target.token_id
    store.remove(target.ticket_id)
    print(f"通行证已吊销：{target.name}")
    if token_id and not args.keep_token:
        token_store = TokenStore(paths.tokens_path())
        token_store.mutate(lambda pool: pool.remove(token_id))
        print(f"  同时收回会话令牌 {token_id[:8]}…（插件下次请求会 401）")
    elif token_id:
        print("  保留了会话令牌（--keep-token）：插件仍能用到令牌过期")
    return 0


def _cmd_toip_logs(args: argparse.Namespace) -> int:
    """看插件日志：list / show / prune / forget。"""
    home = paths.relayhub_home()
    if args.action == "list":
        rows = pluginlogs_module.list_plugins(home)
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
            return 0
        if not rows:
            print("（还没有任何插件日志）")
            return 0
        for row in rows:
            seen = (
                time.strftime("%m-%d %H:%M", time.localtime(row["first_seen"]))
                if row["first_seen"]
                else "-"
            )
            last = (
                time.strftime("%m-%d %H:%M", time.localtime(row["last_activity"]))
                if row["last_activity"]
                else "-"
            )
            print(
                f"  {row['plugin_id']:<28} {row['files']:>3} 个文件  "
                f"{row['bytes']:>8} B  首次 {seen}  最后 {last}"
            )
        return 0
    if args.action == "show":
        rows = pluginlogs_module.tail(home, args.plugin, limit=args.limit)
        events = pluginlogs_module.events(home, args.plugin, limit=args.limit)
        if args.json:
            print(json.dumps({"events": events, "entries": rows}, ensure_ascii=False, indent=2))
            return 0
        if not rows and not events:
            print(f"（插件 {args.plugin} 没有任何日志）")
            return 0
        if events:
            print(f"接入事件（{len(events)} 条）：")
            for e in events:
                stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(float(e.get("ts") or 0)))
                detail = {k: v for k, v in e.items() if k not in ("ts", "schema")}
                print(f"  {stamp}  {detail}")
        summary = pluginlogs_module.summarize(rows)
        window = summary["window"]
        print(
            f"调用流水（{window['requests']} 条）：ok={window['ok']} failed={window['failed']} "
            f"tokens_in={window['tokens_in']} tokens_out={window['tokens_out']} "
            f"avg={window['avg_latency_ms']}ms"
        )
        for entry in rows:
            stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(float(entry.get("ts") or 0)))
            flag = "ok " if entry.get("ok") else "ERR"
            print(
                f"  {stamp}  {flag} {str(entry.get('model') or '-'):<24} "
                f"{str(entry.get('dialect') or '-'):<10} "
                f"in={entry.get('tokens_in', 0)} out={entry.get('tokens_out', 0)} "
                f"{entry.get('latency_ms', 0)}ms  {entry.get('reason', '')}"
            )
        return 0
    if args.action == "prune":
        removed = pluginlogs_module.prune(home, retention_days=args.days)
        print(f"已清理 {len(removed)} 个过期流水文件（保留期 {args.days} 天；接入事件不清理）。")
        for name in removed:
            print(f"  - {name}")
        return 0
    if args.action == "forget":
        if not args.yes:
            print(
                f"这会**永久删除**插件 {args.plugin} 的全部日志（含接入事件）。"
                "确认请加 --yes。",
                file=sys.stderr,
            )
            return 2
        if pluginlogs_module.forget(home, args.plugin):
            print(f"已删除插件 {args.plugin} 的全部日志。")
            return 0
        print(f"插件 {args.plugin} 没有日志目录。", file=sys.stderr)
        return 1
    return 2


def _cmd_toip(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="relayhub.gateway toip",
        description="TOIP 动态口令接入：插件用网址+口令自助接入，并按插件分账日志",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_station = sub.add_parser("station", help="创建/查看本站 TOIP 身份（--force 轮换口令种子）")
    p_station.add_argument("--name", default="relay-hub", help="站点显示名")
    p_station.add_argument("--base-url", dest="base_url", default=None, help="显式对外地址（跨网段/NAT 后无法从来源推断时用）")
    p_station.add_argument("--force", action="store_true", help="已存在时轮换口令种子")
    p_station.set_defaults(func=_cmd_toip_station)

    p_qr = sub.add_parser("qr", help="把 otpauth:// 登记二维码打到终端（验证器 App 扫码）")
    p_qr.set_defaults(func=_cmd_toip_qr)

    p_ticket = sub.add_parser("ticket", help="为一台设备/一个插件签一枚通行证（登记口令）")
    p_ticket.add_argument("--name", required=True, help="通行证名（设备名，吊销时按它找）")
    p_ticket.add_argument("--plugins", default="", help="允许的插件 id，逗号分隔；留空=不限制")
    p_ticket.add_argument("--ttl", type=float, default=0.0, help="登记口令有效期秒数（0=不过期）")
    p_ticket.add_argument("--note", default="", help="备注")
    p_ticket.set_defaults(func=_cmd_toip_ticket)

    p_list = sub.add_parser("list", help="列出站点与全部通行证")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=_cmd_toip_list)

    p_revoke = sub.add_parser("revoke", help="吊销通行证（默认一并收回会话令牌）")
    p_revoke.add_argument("name", help="通行证名或 ticket_id")
    p_revoke.add_argument("--keep-token", dest="keep_token", action="store_true", help="保留已发出的会话令牌")
    p_revoke.set_defaults(func=_cmd_toip_revoke)

    p_logs = sub.add_parser("logs", help="插件日志：list / show / prune / forget")
    logs_sub = p_logs.add_subparsers(dest="action", required=True)
    l_list = logs_sub.add_parser("list", help="列出所有有日志的插件")
    l_list.add_argument("--json", action="store_true")
    l_list.set_defaults(func=_cmd_toip_logs)
    l_show = logs_sub.add_parser("show", help="看某个插件的接入事件与调用流水")
    l_show.add_argument("plugin", help="插件 id")
    l_show.add_argument("--limit", type=int, default=50)
    l_show.add_argument("--json", action="store_true")
    l_show.set_defaults(func=_cmd_toip_logs)
    l_prune = logs_sub.add_parser("prune", help="按保留期清理过期流水（接入事件不清理）")
    l_prune.add_argument("--days", type=int, default=pluginlogs_module.DEFAULT_RETENTION_DAYS)
    l_prune.set_defaults(func=_cmd_toip_logs)
    l_forget = logs_sub.add_parser("forget", help="永久删除某个插件的全部日志")
    l_forget.add_argument("plugin")
    l_forget.add_argument("--yes", action="store_true", help="确认删除（不加则只提示）")
    l_forget.set_defaults(func=_cmd_toip_logs)

    args = parser.parse_args(argv)
    return int(args.func(args))


# ---------------------------------------------------------------- audit


def _cmd_audit(args: argparse.Namespace) -> int:
    entries = audit_module.tail(args.audit_file or paths.audit_path(), limit=args.limit)
    if args.event:
        entries = [e for e in entries if str(e.get("event", "")).startswith(args.event)]
    if args.json:
        print(json.dumps(entries, ensure_ascii=False, indent=2))
        return 0
    if not entries:
        print("（还没有审计记录）")
        return 0
    for entry in entries:
        stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(float(entry.get("ts") or 0)))
        detail = {k: v for k, v in entry.items() if k not in ("ts", "event")}
        print(f"  {stamp}  {entry.get('event'):<16} {detail or ''}")
    return 0


def _cmd_audit_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="relayhub.gateway audit", description="控制面操作审计（配对/令牌/号池管理动作）"
    )
    parser.add_argument("--limit", type=int, default=50, help="最多显示最近 N 条")
    parser.add_argument("--event", default=None, help="按事件前缀过滤（如 pair. / token. / pool.）")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--audit-file", dest="audit_file", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    return _cmd_audit(args)


# ---------------------------------------------------------------- scan


def _cmd_scan(args: argparse.Namespace) -> int:
    servers = localscan_module.scan(
        args.host, ports=args.port or None, timeout=args.timeout
    )
    if not servers:
        print(
            f"{args.host} 上未发现推理服务（试探端口："
            f"{[p for _, p in localscan_module.KNOWN_PORTS]}）。"
            "服务没起，或端口不在默认列表（用 --port 补）。",
            file=sys.stderr,
        )
        return 1
    for server in servers:
        names = ", ".join(server.models[:6]) + ("…" if len(server.models) > 6 else "")
        windows = sum(1 for _ in server.model_windows)
        print(
            f"  {server.label:<18} {server.base_url}  "
            f"{len(server.models)} 模型（{windows} 个带上下文）  via {server.source}"
        )
        print(f"    模型：{names}")
    if args.do_import:
        pool_path = Path(args.pool) if args.pool else paths.pool_path()
        imported, skipped = localscan_module.import_to_pool(pool_path, servers)
        for key in imported:
            print(f"  已导入号池：{key.label}  模型 {list(key.models)}")
        for reason in skipped:
            print(f"  跳过：{reason}")
        print(f"号池：{pool_path}（serve 热加载，无需重启）")
    return 0


def _cmd_scan_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="relayhub.gateway scan", description="扫描本机推理服务（Ollama / LM Studio / vLLM / llama.cpp…）"
    )
    parser.add_argument("--host", default="127.0.0.1", help="扫描目标主机（默认本机回环）")
    parser.add_argument("--port", action="append", type=int, help="可重复；补扫端口（默认扫已知端口集）")
    parser.add_argument("--timeout", type=float, default=localscan_module.SCAN_TIMEOUT)
    parser.add_argument(
        "--import",
        dest="do_import",
        action="store_true",
        help="把发现的服务导入号池（label=local-<kind>，重复导入=覆盖刷新）",
    )
    parser.add_argument("--pool", type=Path, default=None, help="导入目标号池文件")
    args = parser.parse_args(argv)
    return _cmd_scan(args)


# ---------------------------------------------------------------- requests


def _cmd_requests(args: argparse.Namespace) -> int:
    path = Path(args.file) if args.file else paths.requests_log_path()
    entries = reqlog_module.tail(path, limit=max(args.limit * 4, 200))
    if args.token:
        entries = [e for e in entries if e.get("token") == args.token]
    if args.model:
        entries = [e for e in entries if e.get("model") == args.model]
    entries = entries[-args.limit :]
    if args.json:
        print(json.dumps(entries, ensure_ascii=False, indent=2))
        return 0
    if not entries:
        print(f"（{path} 还没有请求记录）")
        return 0
    print(f"请求明细：{path}（最近 {len(entries)} 条；只记元数据，不含对话内容）")
    for e in entries:
        stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(float(e.get("ts") or 0)))
        mark = "✓" if e.get("ok") else "✗"
        stream = "流" if e.get("stream") else "  "
        reason = f"  ←{e['reason']}" if e.get("reason") else ""
        print(
            f"  {stamp}  {mark} {stream}  {str(e.get('token')):<16} "
            f"{str(e.get('model')):<22} {str(e.get('channel')) or '-':<16} "
            f"{e.get('tokens_in', 0):>6}→{e.get('tokens_out', 0):<6} "
            f"{e.get('latency_ms', 0):>8.1f}ms{reason}"
        )
    return 0


# ---------------------------------------------------------------- usage


def _cmd_usage(args: argparse.Namespace) -> int:
    """用量统计：三处数据源合成一个视图（号池渠道 / 下游令牌 / 请求明细）。"""
    pool_stats = KeyPool.load(_pool_file(args)).stats()
    token_store = TokenStore(Path(args.tokens) if args.tokens else paths.tokens_path())
    token_stats = token_store.stats()

    entries = reqlog_module.tail(
        Path(args.file) if args.file else paths.requests_log_path(), limit=200_000
    )
    if args.days:
        cutoff = time.time() - args.days * 86400
        entries = [e for e in entries if float(e.get("ts") or 0) >= cutoff]
    summary = reqlog_module.summarize(entries)

    if args.json:
        print(
            json.dumps(
                {"window_days": args.days, "requests": summary, "channels": pool_stats["totals"], "tokens": token_stats},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    window = summary["window"]
    print(f"请求窗口：{args.days or '全部'}天  共 {window['requests']} 次"
          f"（成功 {window['ok']} / 失败 {window['failed']}）  "
          f"tokens {window['tokens_in']}→{window['tokens_out']}  "
          f"平均 {window['avg_latency_ms']}ms")
    print()
    print("按令牌（谁在用）：")
    for name, slot in sorted(summary["by_token"].items(), key=lambda kv: -kv[1]["requests"]):
        print(f"  {name:<20} {slot['requests']:>6} 次（败 {slot['failed']}）  tokens {slot['tokens_in']}→{slot['tokens_out']}")
    print("按模型（用的什么）：")
    for name, slot in sorted(summary["by_model"].items(), key=lambda kv: -kv[1]["requests"]):
        print(f"  {name:<26} {slot['requests']:>6} 次  tokens {slot['tokens_in']}→{slot['tokens_out']}")
    print("按渠道（谁在扛）：")
    for name, slot in sorted(summary["by_channel"].items(), key=lambda kv: -kv[1]["requests"]):
        print(f"  {name:<20} {slot['requests']:>6} 次（败 {slot['failed']}）")
    print("按日：")
    for day, slot in summary["by_day"].items():
        print(f"  {day}  {slot['requests']:>6} 次（败 {slot['failed']}）  tokens {slot['tokens_in']}→{slot['tokens_out']}")
    totals = pool_stats["totals"]
    print(
        f"\n渠道侧累计（号池文件）：请求 {totals['requests']}（成功 {totals['ok']} / 失败 {totals['failed']}）  "
        f"tokens {totals['tokens_in']}→{totals['tokens_out']}"
    )
    return 0


def _cmd_requests_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="relayhub.gateway requests", description="请求明细查看")
    parser.add_argument("--limit", type=int, default=50, help="最多显示最近 N 条")
    parser.add_argument("--token", default=None, help="按下游令牌名过滤")
    parser.add_argument("--model", default=None, help="按模型过滤")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--file", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    return _cmd_requests(args)


def _cmd_usage_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="relayhub.gateway usage", description="用量统计（按令牌/模型/渠道/日）")
    parser.add_argument("--days", type=int, default=None, help="只统计最近 N 天（默认全部）")
    parser.add_argument("--pool", type=Path, default=None, help="号池文件")
    parser.add_argument("--tokens", type=Path, default=None, dest="tokens", help="令牌文件")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--file", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    return _cmd_usage(args)




# ---------------------------------------------------------------- 入口


def main(argv: list[str] | None = None) -> int:
    _safe_stdout()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        return _cmd_serve(argv[1:])
    if argv and argv[0] == "admin":
        return admin_module.main(argv[1:])
    if argv and argv[0] == "pool":
        return _cmd_pool(argv[1:])
    if argv and argv[0] == "scan":
        return _cmd_scan_main(argv[1:])
    if argv and argv[0] == "requests":
        return _cmd_requests_main(argv[1:])
    if argv and argv[0] == "usage":
        return _cmd_usage_main(argv[1:])
    if argv and argv[0] == "token":
        return _cmd_token(argv[1:])
    if argv and argv[0] == "clients":
        return _cmd_clients(argv[1:])
    if argv and argv[0] == "pair":
        return _cmd_pair(argv[1:])
    if argv and argv[0] == "toip":
        return _cmd_toip(argv[1:])
    if argv and argv[0] == "audit":
        return _cmd_audit_main(argv[1:])
    if argv and argv[0] == "doctor":
        return _cmd_doctor(argv[1:])
    if argv and argv[0] == "check":
        return conformance_main(argv[1:])
    if argv and argv[0] in ("--version", "-V"):
        from .. import __version__ as gw_version  # noqa: PLC0415

        print(f"hubrelay (relay-hub) {gw_version}")
        return 0
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        print(
            "可用子命令：serve / admin / scan / pool / requests / usage "
            "/ token / clients / pair / toip / audit / check / doctor"
        )
        return 0
    print(__doc__)
    print(
        "用法：python -m relayhub.gateway serve|admin|scan|pool|requests|usage"
        "|token|clients|pair|toip|audit|check|doctor [选项]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
