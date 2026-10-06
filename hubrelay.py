"""import hubrelay —— 与 pip 安装名一致的顶层入口。

``import hubrelay`` 与 ``import relayhub`` 是同一套函数面的两个名字：
建站（Station / quickstart / scan_local）、客户端 SDK（StationClient /
StationError）与 E2E 信封（seal_envelope / open_envelope / ...）全在这里::

    import hubrelay
    st, url = hubrelay.quickstart("http://127.0.0.1:11434", models=["qwen2.5"])
    print(url, st.create_token("my-phone"))

    c = hubrelay.StationClient("http://192.168.1.10:8799", token="rht_...")
    print(c.whoami())
"""

from relayhub import __version__ as __version__  # noqa: F401
from relayhub.api import (  # noqa: F401
    Station,
    TokenIssued,
    UpstreamAdded,
    doctor,
    list_providers,
    quickstart,
    scan_local,
)
from relayhub.client import StationClient, StationError  # noqa: F401
from relayhub.gateway.e2e import (  # noqa: F401
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

__all__ = [
    "__version__",
    "Station",
    "StationClient",
    "StationError",
    "TokenIssued",
    "UpstreamAdded",
    "doctor",
    "list_providers",
    "quickstart",
    "scan_local",
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
