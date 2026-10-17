# SPDX-License-Identifier: Apache-2.0
import os

def dsn() -> str:
    v = os.environ.get("DJB_DSN")
    if not v:
        raise SystemExit("缺环境变量 DJB_DSN（postgres 连接串，见 README；凭据不入库）")
    return v
