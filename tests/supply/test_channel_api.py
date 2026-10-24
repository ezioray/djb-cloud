# SPDX-License-Identifier: Apache-2.0
"""节点通道端点（C10a / spec 1.2.9）：鉴权、状态、协议、校验、204、幂等、fail-closed。

口径（01-ownership §1 · CR-C10-01）：

* 端点归 M02，队列归 M03（C10b）：本文件用 ``FakeBackend`` 扮演队列，**不测队列语义**；
* 未接线 → 503 / ``50903``（fail-closed，不回落 Echo）；
* 结果按 ``job_id`` 幂等：同载荷重放 → 200 + ``duplicate=true``；不同载荷 → 409 / ``40919``；
* 正文（``content`` / ``messages``）不进库、不进日志——用例显式断言幂等表里只有摘要。
"""
from __future__ import annotations

import json
import pathlib
import uuid

import pytest

from supplykit import session

from app.supply import channel, errors

POLL = "/api/v1/node/channel/poll"
RESULT = "/api/v1/node/channel/result"
SUPPLY_DIR = pathlib.Path(__file__).resolve().parents[2] / "app" / "supply"


# --------------------------------------------------------------------------- 夹具
def _register(api, **overrides):
    payload = {"platform": "linux", "hardware_fingerprint": f"fp-c10-{uuid.uuid4().hex}",
               "client_version": "1.9.0", "protocol_version": "1.0.0"}
    payload.update(overrides)
    response = api.post("/api/v1/node/register", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _active(api, **overrides):
    node = _register(api, **overrides)
    response = api.post(f"/api/v1/admin/supply/nodes/{node['node_id']}/review",
                        json={"decision": "approve", "reason": "材料齐全"},
                        headers={"X-Admin-Step-Up": "token"})
    assert response.status_code == 200, response.text
    return node


def _job(**overrides):
    """spec ``NodeChannelJob``：``model`` / ``messages`` 在 ``request`` 内，不在顶层。"""
    job = {"job_id": str(uuid.uuid4()), "kind": "chat.completions", "request_id": "req-1",
           "request": {"model": "gpt-4o-mini",
                       "messages": [{"role": "user", "content": "你好"}],
                       "max_tokens": 64, "temperature": 0.2, "stop": ["\n"]},
           "timeout_s": 60, "lease_expires_at": "2026-10-23T00:00:30Z"}
    job.update(overrides)
    return job


def _result(job_id, **overrides):
    body = {"job_id": job_id, "status": "completed", "content": "hello world",
            "finish_reason": "stop", "tokens_in": 3, "tokens_out": 5,
            "usage_source": "actual", "latency_ms": 120, "first_byte_ms": 80,
            "upstream_request_id": "up-1"}
    body.update(overrides)
    return body


class FakeBackend:
    """C10b 队列替身：只实现通道协议，不实现排队 / 租约 / 重派。"""

    def __init__(self, jobs=None, submit_error=None):
        self.jobs = list(jobs or [])
        self.submit_error = submit_error
        self.calls = []
        self.submitted = {}

    def poll(self, node_id, *, wait_s, capabilities):
        self.calls.append({"op": "poll", "node_id": node_id, "wait_s": wait_s,
                           "capabilities": capabilities})
        return self.jobs.pop(0) if self.jobs else None

    def submit(self, node_id, job_id, result):
        self.calls.append({"op": "submit", "node_id": node_id, "job_id": job_id})
        if self.submit_error is not None:
            raise self.submit_error
        self.submitted[job_id] = result
        return {"accepted": True, "duplicate": False}


@pytest.fixture(autouse=True)
def _reset_backend():
    channel.set_channel_backend(None)
    yield
    channel.set_channel_backend(None)


def _error(response):
    error = response.json()["error"]
    assert set(error) >= {"type", "code", "message", "request_id"}
    return error


def _poll(api, node, body=None, **headers):
    return api.post(POLL, json=body if body is not None else {},
                    headers={"X-Client-Key": node["client_key"], **headers})


def _submit(api, node, body, **headers):
    return api.post(RESULT, json=body,
                    headers={"X-Client-Key": node["client_key"], **headers})


# --------------------------------------------------------------------------- 接线位（纯函数）
def test_backend_is_fail_closed_until_injected():
    assert channel.channel_backend() is None
    assert channel.is_wired() is False
    with pytest.raises(errors.ChannelUnavailable) as excinfo:
        channel.require_channel_backend()
    assert (excinfo.value.status_code, excinfo.value.code) == (503, "50903")


def test_set_channel_backend_validates_and_clears():
    backend = FakeBackend()
    channel.set_channel_backend(backend)
    assert channel.channel_backend() is backend and channel.is_wired() is True
    channel.set_channel_backend(None)
    assert channel.channel_backend() is None
    with pytest.raises(TypeError):
        channel.set_channel_backend(object())               # 接线错误在启动期暴露


def test_validate_poll_defaults_and_limits():
    assert channel.validate_poll({}) == (25.0, ())
    assert channel.validate_poll({"wait_s": 5, "capabilities": ["chat_completions"]}) == \
        (5.0, ("chat_completions",))
    for bad in (0, 31, 30.5, "25", True):
        with pytest.raises(errors.InvalidArgument) as excinfo:
            channel.validate_poll({"wait_s": bad})
        assert excinfo.value.details["field"] == "wait_s"


def test_validate_result_drops_unknown_fields_and_requires_failure_reason():
    parsed = channel.validate_result({"job_id": str(uuid.uuid4()), "status": "completed",
                                      "content": "x", "injected": "ignored"})
    assert "injected" not in parsed
    with pytest.raises(errors.InvalidArgument) as excinfo:
        channel.validate_result({"job_id": str(uuid.uuid4()), "status": "failed"})
    assert excinfo.value.details["field"] == "error_code"


# --------------------------------------------------------------------------- poll
def test_poll_requires_client_key(api):
    response = api.post(POLL, json={})
    assert response.status_code == 401
    assert _error(response)["code"] == 40101


def test_poll_rejects_node_that_is_not_active(api):
    node = _register(api)                                   # pending，未经审核
    response = _poll(api, node)
    assert response.status_code == 403
    error = _error(response)
    assert error["code"] == 40305 and error["state"] == "pending"


@pytest.mark.parametrize("wait_s", [0, 31, "25", True, -1])
def test_poll_rejects_bad_wait_s(api, admin_hook, wait_s):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _poll(api, node, {"wait_s": wait_s})
    assert response.status_code == 400
    assert _error(response)["field"] == "wait_s"


def test_poll_returns_204_when_no_job(api, admin_hook):
    node = _active(api)
    backend = FakeBackend()
    channel.set_channel_backend(backend)
    response = _poll(api, node, {}, **{"X-Request-Id": "rid-poll-204"})
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["X-Request-Id"] == "rid-poll-204"
    assert backend.calls[0]["wait_s"] == 25.0               # 默认 25 s


def test_poll_returns_the_job_and_passes_capabilities(api, admin_hook):
    node = _active(api)
    job = _job()
    backend = FakeBackend(jobs=[job])
    channel.set_channel_backend(backend)
    response = _poll(api, node, {"wait_s": 7, "capabilities": ["chat_completions", "notify"]})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["job"] == job
    assert body["job"]["request"]["model"] == "gpt-4o-mini"     # 嵌套 request，不在顶层
    assert "model" not in body["job"] and "messages" not in body["job"]
    assert body["server_time"].endswith("Z")
    assert backend.calls[0] == {"op": "poll", "node_id": node["node_id"], "wait_s": 7.0,
                                "capabilities": ("chat_completions", "notify")}


def test_poll_is_503_when_backend_is_not_wired(api, admin_hook):
    node = _active(api)                                     # 已鉴权但队列未接线
    response = _poll(api, node)
    assert response.status_code == 503
    error = _error(response)
    assert error["code"] == 50903 and error["reason"] == "channel_unavailable"


def test_poll_rejects_incompatible_protocol(api, admin_hook):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _poll(api, node, {}, **{"DJB-Protocol-Version": "2.0.0"})
    assert response.status_code == 426
    assert _error(response)["code"] == 42601


# --------------------------------------------------------------------------- result
def test_result_requires_job_id(api, admin_hook):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _submit(api, node, {"status": "completed", "content": "x"})
    assert response.status_code == 400
    assert _error(response)["field"] == "job_id"


@pytest.mark.parametrize("job_id", ["not-a-uuid", "", 42])
def test_result_rejects_malformed_job_id(api, admin_hook, job_id):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _submit(api, node, {"job_id": job_id, "status": "completed"})
    assert response.status_code == 400
    assert _error(response)["field"] == "job_id"


def test_result_rejects_unknown_status(api, admin_hook):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _submit(api, node, _result(str(uuid.uuid4()), status="running"))
    assert response.status_code == 400
    assert _error(response)["field"] == "status"


@pytest.mark.parametrize("usage_source", ["upstream", "tokenizer", "ACTUAL"])
def test_result_rejects_unknown_usage_source(api, admin_hook, usage_source):
    """1.2.9 定稿枚举：actual / estimated / dual（旧候选值 upstream/tokenizer 不再接受）。"""
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _submit(api, node, _result(str(uuid.uuid4()), usage_source=usage_source))
    assert response.status_code == 400
    assert _error(response)["field"] == "usage_source"


@pytest.mark.parametrize("usage_source", ["actual", "estimated", "dual", None])
def test_result_accepts_the_three_usage_sources(api, admin_hook, usage_source):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _submit(api, node, _result(str(uuid.uuid4()), usage_source=usage_source))
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] is True


def test_result_ignores_client_side_job_shape_fields(api, admin_hook):
    """客户端兼容字段（succeeded / node_id / duration_ms / completed_at / usage）不被采信。"""
    node = _active(api)
    backend = FakeBackend()
    channel.set_channel_backend(backend)
    job_id = str(uuid.uuid4())
    body = _result(job_id, node_id="n_evil", succeeded=True, duration_ms=1,
                   completed_at="2026-10-24T00:00:00Z", usage={"tokens_in": 999})
    response = _submit(api, node, body)
    assert response.status_code == 200
    stored = backend.submitted[job_id]
    for field in ("node_id", "succeeded", "duration_ms", "completed_at", "usage"):
        assert field not in stored


def test_result_accepts_and_stores_only_a_digest(api, admin_hook):
    node = _active(api)
    backend = FakeBackend()
    channel.set_channel_backend(backend)
    job_id = str(uuid.uuid4())
    response = _submit(api, node, _result(job_id, content="绝密正文-should-not-be-stored"))
    assert response.status_code == 200, response.text
    assert response.json() == {"accepted": True, "duplicate": False}
    assert backend.submitted[job_id]["content"] == "绝密正文-should-not-be-stored"

    with session(api.schema) as conn:
        rows = conn.execute(
            "SELECT request_hash, response FROM supply_idempotency WHERE scope = %s",
            (f"channel.result:{job_id}",)).fetchall()
    assert len(rows) == 1                                  # 同一 job 只落一条幂等记录
    request_hash, stored = rows[0]
    assert len(request_hash) == 64 and "绝密" not in request_hash
    assert stored == {"accepted": True, "duplicate": False}
    assert "绝密" not in json.dumps(stored, ensure_ascii=False)   # 正文不落库


def test_result_replay_is_idempotent(api, admin_hook):
    node = _active(api)
    backend = FakeBackend()
    channel.set_channel_backend(backend)
    body = _result(str(uuid.uuid4()))
    first = _submit(api, node, body)
    second = _submit(api, node, body)
    assert (first.status_code, first.json()) == (200, {"accepted": True, "duplicate": False})
    assert (second.status_code, second.json()) == (200, {"accepted": True, "duplicate": True})
    assert [call["op"] for call in backend.calls] == ["submit"]   # 队列只被调一次


def test_result_same_job_different_payload_is_40919(api, admin_hook):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    job_id = str(uuid.uuid4())
    assert _submit(api, node, _result(job_id)).status_code == 200
    conflict = _submit(api, node, _result(job_id, content="另一个结果"))
    assert conflict.status_code == 409
    error = _error(conflict)
    assert error["code"] == 40919 and error["reason"] == "idempotency_conflict"


def test_result_for_unknown_job_is_404(api, admin_hook):
    node = _active(api)
    channel.set_channel_backend(
        FakeBackend(submit_error=errors.ChannelJobNotFound("任务不存在或不属于该节点",
                                                           job_id="x")))
    response = _submit(api, node, _result(str(uuid.uuid4())))
    assert response.status_code == 404
    error = _error(response)
    assert error["code"] == 40401 and error["reason"] == "channel_job_not_found"


def test_result_is_503_when_backend_is_not_wired(api, admin_hook):
    node = _active(api)
    response = _submit(api, node, _result(str(uuid.uuid4())))
    assert response.status_code == 503
    assert _error(response)["code"] == 50903


def test_result_rejects_node_that_is_not_active(api):
    node = _register(api)
    channel.set_channel_backend(FakeBackend())
    response = _submit(api, node, _result(str(uuid.uuid4())))
    assert response.status_code == 403
    assert _error(response)["code"] == 40305


def test_result_echoes_request_id(api, admin_hook):
    node = _active(api)
    channel.set_channel_backend(FakeBackend())
    response = _submit(api, node, _result(str(uuid.uuid4())), **{"X-Request-Id": "rid-result-1"})
    assert response.headers["X-Request-Id"] == "rid-result-1"
    assert response.json()["accepted"] is True


# --------------------------------------------------------------------------- 架构红线
def test_supply_does_not_import_gateway_or_write_queues():
    """C10a 红线：M02 不 import ``app.gateway``（M03），也不自己写队列。

    用 AST 判 import（源码注释里提到 "不 import app.gateway" 不算违规）。
    """
    import ast

    offenders: list[str] = []
    for path in sorted(SUPPLY_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders += [f"{path.name}: {alias.name}" for alias in node.names
                              if alias.name == "app.gateway" or alias.name.startswith("app.gateway.")]
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level == 0 and (module == "app.gateway"
                                        or module.startswith("app.gateway.")):
                    offenders.append(f"{path.name}: {module}")
    assert offenders == [], f"跨模块 import：{offenders}"

    channel_source = (SUPPLY_DIR / "channel.py").read_text(encoding="utf-8")
    assert "class ChannelBackend(Protocol)" in channel_source
    for forbidden in ("queue.Queue", "asyncio.Queue", "INSERT INTO"):
        assert forbidden not in channel_source, forbidden
