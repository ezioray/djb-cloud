# SPDX-License-Identifier: Apache-2.0
"""M12 notification（DEV-M12 · S1 主体 + Webhook 订阅）。

模块职责（M12 §1）：消费业务事件 → 按事件矩阵定级别 / 渠道 → 站内信落库与已读 →
邮件 / Webhook 投递（含签名、重试、降级、死信）→ 偏好读写（P0 不可退订）→ 订阅管理。

文件分工::

    facts.py          常量 / 枚举 / dedupe_bucket / payload 零 PII 校验（纯函数）
    errors.py         错误码与 spec Error 信封映射（40001/40101/40401/40902/50001）
    clock.py          UTC 时钟（用例一律显式注入）
    config_source.py  §8.1 notify.* 默认值 + 只读 provider 钩子（S1 不直连 M10）
    features.py       特性开关（owner / expire_at / rollback_rule，默认关闭，无可写面）
    models.py         领域对象 + 行映射 + 对客序列化
    store.py          notifications / delivery_attempts 的 SQL（账户隔离在 SQL 里）
    preferences.py    偏好读写（INV-01）+ 静默时段 / 摘要判定
    inbox.py          站内信列表（游标）/ 已读（幂等，id=all）
    webhooks.py       订阅管理 + SSRF 校验 + secret 一次性 / 只存哈希
    signing.py        HMAC 签名工具（sha256=HMAC(secret, ts + "." + body)，±300 s）
    outbox.py         事件 outbox 入队 / 派发 / 死信（02-events §2）
    events.py         事件消费 + 事件矩阵 + 对客 / 内部模板（INV-03 / INV-09）
    channels.py       in_app / email / webhook 适配器（S1 不发真实邮件、不出网）
    dispatch.py       分派与投递（状态机 / 重试 / 降级，INV-04 / INV-06）
    router.py         create_router(connection_factory=..., principal_resolver=...)
    migrate.py        迁移 1201–1205 正向 / 回滚 / 状态

**未接线项**（由 Lead 合并时统一接线，本模块不碰 ``app/api.py``）：

* ``app.api`` include :func:`app.notify.router.create_router`（主体解析与连接工厂）；
* 事件生产 / 消费的进程内循环（outbox publisher、事件订阅器）；
* 邮件供应商与 Webhook 出网白名单（T4 / S2，特性开关均为关）。
"""
from __future__ import annotations

from .features import FEATURE_SWITCHES, WRITE_SURFACE, enabled
from .router import create_router

__version__ = "0.1.0"
__all__ = ["create_router", "FEATURE_SWITCHES", "WRITE_SURFACE", "enabled", "__version__"]
