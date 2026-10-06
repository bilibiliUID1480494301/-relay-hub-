"""relay-hub：局域网/自托管大模型中转站。

上游号池（多 Key 轮转、熔断冷却）+ 双协议适配（Anthropic/OpenAI）
+ HTTP 网关服务（鉴权、配对、TOIP 动态口令接入、用量记账）
+ 按插件分账的插件日志（pluginlogs/）。

客户端 SDK：`from relayhub.client import StationClient` —— 远程接入中转站的
纯标准库函数面（模型调用 / TOIP 接入 / MCP / A2A，可选 E2E 信封）。
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = ["__version__"]


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
