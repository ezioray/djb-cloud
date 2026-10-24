# SPDX-License-Identifier: AGPL-3.0-or-later
"""限流（M03 §4.1 / §4.4 的 42901 / INV-M03-05：429 必须带 Retry-After）。不需要 DB。"""
from __future__ import annotations

from datetime import timedelta

import pytest

from app.gateway import errors, facts, ratelimit
from gatewaykit import NOW


@pytest.fixture
def bucket() -> ratelimit.SlidingWindowLimiter:
    return ratelimit.SlidingWindowLimiter()


def test_unlimited_scope_always_allows(bucket):
    for _ in range(100):
        decision = bucket.take("key:1", None, now=NOW)
    assert decision.allowed and decision.limit == 0


def test_zero_or_negative_limit_means_disabled_not_deny_all(bucket):
    assert bucket.take("key:1", 0, now=NOW).allowed
    assert bucket.take("key:1", -5, now=NOW).allowed


def test_sliding_window_allows_up_to_limit_then_denies(bucket):
    for index in range(3):
        assert bucket.take("key:1", 3, now=NOW + timedelta(milliseconds=index * 10)).allowed
    denied = bucket.take("key:1", 3, now=NOW + timedelta(milliseconds=40))
    assert denied.allowed is False
    assert denied.retry_after_s is not None and denied.retry_after_s >= 1
    assert denied.remaining == 0


def test_window_slides_after_one_second(bucket):
    for index in range(3):
        bucket.take("key:1", 3, now=NOW + timedelta(milliseconds=index))
    assert bucket.take("key:1", 3, now=NOW + timedelta(milliseconds=500)).allowed is False
    # 1 秒后最早的一次滑出窗口
    assert bucket.take("key:1", 3, now=NOW + timedelta(seconds=2)).allowed is True


def test_scopes_are_isolated(bucket):
    for index in range(2):
        bucket.take("key:1", 2, now=NOW + timedelta(milliseconds=index))
    assert bucket.take("key:1", 2, now=NOW + timedelta(milliseconds=5)).allowed is False
    assert bucket.take("key:2", 2, now=NOW + timedelta(milliseconds=5)).allowed is True
    assert bucket.take("tenant:t1", 2, now=NOW + timedelta(milliseconds=5)).allowed is True


def test_remaining_and_reset_headers(bucket):
    decision = bucket.take("key:1", 5, now=NOW)
    headers = decision.headers()
    assert headers[facts.RATE_LIMIT_LIMIT_HEADER] == "5"
    assert headers[facts.RATE_LIMIT_REMAINING_HEADER] == "4"
    assert headers[facts.RATE_LIMIT_RESET_HEADER] == "1"


def test_enforce_raises_429_with_retry_after_and_headers(bucket):
    for index in range(2):
        bucket.take("key:1", 2, now=NOW + timedelta(milliseconds=index))
    decision = bucket.take("key:1", 2, now=NOW + timedelta(milliseconds=10))
    with pytest.raises(errors.GatewayError) as info:
        ratelimit.enforce([decision], now=NOW)
    exc = info.value
    assert (exc.http_status, exc.code) == (429, 42901)
    assert exc.reason == "rate_limited"
    assert exc.retry_after_s >= 1
    assert exc.headers[facts.RETRY_AFTER_HEADER] == str(exc.retry_after_s)
    assert exc.headers[facts.RATE_LIMIT_LIMIT_HEADER] == "2"
    body = errors.error_body(exc, "req-1")["error"]
    assert body["retry_after"] == exc.retry_after_s


def test_enforce_returns_the_tightest_allowed_scope(bucket):
    wide = bucket.take("key:1", 100, now=NOW)
    tight = bucket.take("tenant:t1", 3, now=NOW)
    merged = ratelimit.enforce([wide, tight], now=NOW)
    assert merged.limit == 3 and merged.remaining == 2


def test_enforce_without_any_limited_scope_is_a_noop():
    decision = ratelimit.enforce([ratelimit.LimitDecision(True, 0, 0, 0)], now=NOW)
    assert decision.limit == 0


def test_denied_scope_wins_with_largest_retry_after():
    strict = ratelimit.LimitDecision(False, 1, 0, 9, retry_after_s=9)
    looser = ratelimit.LimitDecision(False, 1, 0, 3, retry_after_s=3)
    with pytest.raises(errors.GatewayError) as info:
        ratelimit.enforce([looser, strict], now=NOW)
    assert info.value.retry_after_s == 9


def test_reset_clears_windows(bucket):
    bucket.take("key:1", 1, now=NOW)
    assert bucket.take("key:1", 1, now=NOW + timedelta(milliseconds=5)).allowed is False
    bucket.reset()
    assert bucket.take("key:1", 1, now=NOW + timedelta(milliseconds=6)).allowed is True


def test_default_limiter_is_process_wide():
    ratelimit.LIMITER.reset()
    assert ratelimit.LIMITER.take("global", 1, now=NOW).allowed
    assert ratelimit.LIMITER.take("global", 1, now=NOW + timedelta(milliseconds=1)).allowed is False
