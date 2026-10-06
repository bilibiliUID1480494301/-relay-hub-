"""relay-hub（PyPI 分发名 hubrelay）：自托管大模型中转站/网关——局域网与公网两用。

上游号池（多 Key 轮转、熔断冷却）+ 双协议适配（Anthropic/OpenAI）+ HTTP 网关
（鉴权、配对、TOIP 动态口令接入、用量记账、MCP / A2A 路由）+ E2E 信封加密 +
按插件分账的插件日志。部署半径跟着用户走：本机回环 → 局域网（--host）→
公网（--public 凭证安全闸，或置于 cloudflared/ngrok/frp/nginx 等隧道与反代之后）。

建站（一行版，细节见 :mod:`relayhub.api`）::

    import hubrelay
    st, url = hubrelay.quickstart("http://127.0.0.1:11434", models=["qwen2.5"])
    print(url, st.create_token("my-phone"))

客户端 SDK（远程接入一座中转站，纯标准库）::

    from relayhub import StationClient
    c = StationClient("http://192.168.1.10:8799", token="rht_...")
    c.whoami()
    c.messages({"model": "...", "max_tokens": 256, "messages": [...]})

E2E 信封（可选依赖 ``hubrelay[e2e]``；未装 cryptography 时 import 不报错，
调用 seal/open 才要求安装）::

    from relayhub import seal_envelope, open_envelope, E2eIdentity

设计立场：核心零第三方依赖（cryptography/qrcode 是可选 extra）；明文流量永远
可用、永不静默降级。``import hubrelay`` 与 ``import relayhub`` 是同一套面的
两个名字。
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = [
    "__version__",
    # -- 服务端建站 API（relayhub.api 镜像）--
    "Station",
    "TokenIssued",
    "UpstreamAdded",
    "doctor",
    "list_providers",
    "quickstart",
    "scan_local",
    # -- 客户端 SDK（relayhub.client）--
    "StationClient",
    "StationError",
    # -- E2E 信封（relayhub.gateway.e2e）--
    "ENVELOPE_CONTENT_TYPE",
    "E2eError",
    "E2eIdentity",
    "INFO",
    "ReplayGuard",
    "SCHEME",
    "TS_WINDOW",
    "derive_key",
    "load_or_create",
    "open_envelope",
    "seal_envelope",
]


def _detect_version() -> str:
    """版本单一来源是 pyproject.toml。

    顺序刻意是「先 pyproject、后发行元数据」：仓库内直接 import 时，跑的就是
    这份源码，同目录 pyproject 里的数才是真相——哪怕环境里还装着旧版 hubrelay
    （importlib.metadata 会报旧数，0.7.0 测试就抓到过 '0.6.0' != '0.7.0'）。
    装好的包（site-packages 旁边没有 pyproject.toml）自然落到元数据，两条路
    都指向同一个数，不再出现「__init__ 写 0.3.0、pyproject 写 0.6.0」的腐烂。
    """
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if pyproject.is_file():
        match = re.search(
            r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M
        )
        if match:
            return match.group(1)
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("hubrelay")
        except PackageNotFoundError:
            pass
    except ImportError:  # pragma: no cover - py3.10+ 恒有 importlib.metadata
        pass
    return "0+unknown"


__version__ = _detect_version()

# -- 导出面 ----------------------------------------------------------------------
# 顺序有讲究：__version__ 必须先于这些 import 赋值——api.py / client.py /
# gateway/service.py 都有 `from . import __version__`，包根半初始化期间
# getattr 能不能成功就看这个赋值有没有先发生。
from .api import (  # noqa: E402
    Station,
    TokenIssued,
    UpstreamAdded,
    doctor,
    list_providers,
    quickstart,
    scan_local,
)
from .client import StationClient, StationError  # noqa: E402
from .gateway.e2e import (  # noqa: E402
    ENVELOPE_CONTENT_TYPE,
    E2eError,
    E2eIdentity,
    INFO,
    ReplayGuard,
    SCHEME,
    TS_WINDOW,
    derive_key,
    load_or_create,
    open_envelope,
    seal_envelope,
)
