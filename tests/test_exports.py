# -*- coding: utf-8 -*-
"""包导出面冒烟测试：``import relayhub`` / ``import hubrelay`` 必须是完整的
第三方库体验。

0.7.0 及以前 ``relayhub.__all__`` 只有 ``["__version__"]``，``hubrelay.py`` 的
``__version__`` 还硬编码在 0.2.12——文档让用户自己去 relayhub.client 找
StationClient，这不是一个库该有的入门姿势。0.8.0 起包根直接导出建站
（Station/quickstart）、客户端（StationClient/StationError）与 E2E 信封全套；
本测试把这个面钉住，防止将来悄悄缩回去或版本再次腐烂。
"""

from __future__ import annotations

import importlib
import inspect
import re
from pathlib import Path

import relayhub

CORE = [
    "Station",
    "StationClient",
    "StationError",
    "quickstart",
    "scan_local",
    "doctor",
    "list_providers",
    "seal_envelope",
    "open_envelope",
    "E2eIdentity",
    "derive_key",
    "ReplayGuard",
    "load_or_create",
    "E2eError",
    "SCHEME",
    "ENVELOPE_CONTENT_TYPE",
    "TS_WINDOW",
]


def test_all_names_resolve() -> None:
    for name in relayhub.__all__:
        assert hasattr(relayhub, name), f"__all__ 里的 {name!r} 导不出来"


def test_core_surface_present() -> None:
    for name in CORE:
        assert hasattr(relayhub, name), f"包根缺 {name!r}——0.8.0 的导出面被缩水了？"
    assert callable(relayhub.quickstart)
    assert callable(relayhub.seal_envelope)
    assert callable(relayhub.open_envelope)


def test_identity_parity() -> None:
    """包根导出的必须就是子模块的原对象，不是又一份拷贝。"""
    import relayhub.api
    import relayhub.client

    assert relayhub.StationClient is relayhub.client.StationClient
    assert relayhub.StationError is relayhub.client.StationError
    assert relayhub.Station is relayhub.api.Station
    assert relayhub.__version__ == relayhub.api.__version__
    assert relayhub.__version__ == relayhub.client._PKG_VERSION


def test_version_not_stale() -> None:
    """版本单一来源是 pyproject.toml；api.py / hubrelay stub 不许再写死。"""
    import relayhub.api

    pyproject = Path(relayhub.__file__).resolve().parent.parent / "pyproject.toml"
    if not pyproject.is_file():  # 安装态（site-packages）没有 pyproject，跳过
        return
    match = re.search(
        r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M
    )
    assert match, "pyproject.toml 里没读到 version"
    assert relayhub.__version__ == match.group(1)
    assert relayhub.api.__version__ == match.group(1)


def test_hubrelay_stub_mirrors_package() -> None:
    hub = importlib.import_module("hubrelay")
    for name in relayhub.__all__:
        assert hasattr(hub, name), f"hubrelay 顶层 stub 缺 {name!r}"
    assert hub.__version__ == relayhub.__version__
    assert hub.StationClient is relayhub.StationClient


def test_e2e_imports_stay_stdlib_only() -> None:
    """e2e.py 顶部导入必须是纯标准库——没装 cryptography 的环境也要能
    ``from relayhub import seal_envelope``（调用时才报「pip install hubrelay[e2e]」）。

    用 AST 查顶层 import 语句，而不是子串搜索——模块文档里提到 cryptography
    这个词是合法的，import 它才是破坏懒加载。
    """
    import ast

    from relayhub.gateway import e2e as e2e_mod

    tree = ast.parse(inspect.getsource(e2e_mod))
    roots = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    assert "cryptography" not in roots, (
        "e2e.py 顶部出现了 cryptography 导入——懒加载被破坏，"
        "没装 hubrelay[e2e] 的环境连包根都 import 不了"
    )
