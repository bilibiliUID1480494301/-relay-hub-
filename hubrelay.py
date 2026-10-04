"""import hubrelay —— 与 pip 安装名一致的顶层入口。

用法见 relayhub.api 的模块文档；这里是同一套函数的短名字镜像::

    import hubrelay
    st = hubrelay.Station(port=8799)
    st.scan_and_import()
    st.serve()
"""

from relayhub.api import (  # noqa: F401
    Station,
    TokenIssued,
    UpstreamAdded,
    quickstart,
    scan_local,
)

__version__ = "0.2.4"
