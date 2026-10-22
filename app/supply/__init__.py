# SPDX-License-Identifier: Apache-2.0
"""M02 node-supply（DEV-M02 T1+T2：模型 / 迁移 / 状态机 + 注册 / pair / binding / 审核）。

本包是 M02 的**唯一写入口**，也是以下表的唯一写者（01-ownership §2 / M02 §5）::

    nodes · node_upstreams · node_policies · node_events · capacity_announcements

外加本模块自有的三张辅助表（与 M01 的 ``identity_idempotency`` / ``identity_scan_tickets``
同型，**不是身份表**）：``supply_outbox``（事件出站，M02 §5 已登记）·
``supply_idempotency``（24 h 幂等键）· ``node_binding_codes``（一次性绑定码）。

分层（M02 §0 目标路径的精简版；每层职责单一）::

    facts.py        常量（M02 §8.1/§8.2/§3 + spec 枚举），一份事实一个来源
    state.py        生命周期四态机 + 在线派生（权威层 / 派生层严格分离）
    protocol.py     协议 N/N-1/N-2 矩阵与 42601
    security.py     指纹再哈希 / 客户端密钥 / 疑似凭据扫描（INV-03/04/10）
    events.py       4 个事件 + supply_outbox 信封
    models.py       领域模型与唯一写入口（注册 / pair / binding / 审核）
    idempotency.py  X-DJB-Idempotency-Key 24 h（不存明文）
    features.py     特性开关登记（三字段 + 默认关闭）
    migrate.py      200–207 迁移与回滚（证据用 CLI）
    router.py       T2 的 6 个端点（**不接 app/api.py**，由 Lead 合并时 include）

边界：不 import 任何其它 ``app.*`` 业务模块；M01 账户只读 ``v_identity_accounts`` 视图；
不改 ``app/nodes.py``（legacy adapter，只读引用）、``app/api.py``、其它模块、spec、contracts。
"""
from __future__ import annotations

from . import (clock, errors, events, facts, features, idempotency, migrate, models, protocol,
               router, security, state)
from .models import (NODE_COLUMNS, AuthResult, Binding, BindingCode, KeyRotation, Node,
                     RegisterResult, authenticate, bind, binding_dict, binding_of, find_by_fingerprint,
                     get_node, issue_binding_code, list_nodes, normalize_runtime_state, register,
                     review, rotate_key, unbind, uuid7)
from .state import TRANSITIONS, can_transition, derive_online, derive_presence, legal_targets

__version__ = "0.2.0-dev-m02t2"

__all__ = [
    "models", "state", "protocol", "security", "events", "facts", "features", "idempotency",
    "migrate", "router", "clock", "errors",
    "Node", "Binding", "AuthResult", "RegisterResult", "KeyRotation", "BindingCode",
    "NODE_COLUMNS",
    "get_node", "find_by_fingerprint", "binding_of", "binding_dict", "authenticate",
    "register", "rotate_key", "issue_binding_code", "bind", "unbind", "review",
    "normalize_runtime_state", "list_nodes", "uuid7",
    "TRANSITIONS", "can_transition", "legal_targets", "derive_presence", "derive_online",
]
