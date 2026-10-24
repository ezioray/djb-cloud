# SPDX-License-Identifier: AGPL-3.0-or-later
"""本地 token 计数（C9a / PROBE-TOKEN-AUDIT §2.2）：纯函数口径、确定性、可选 tiktoken。

不依赖 DB、不联网；``tiktoken`` 缺失时全部走字符口径（本仓库默认环境即如此），
因此这里的期望值都是**算出来的**，不是猜的：ASCII 词 4 字符/token、ASCII 符号 2 字符/token、
非 ASCII（CJK / 全角 / emoji）1 token/字，chat 模板每条消息 +4、回复预备 +3、每个 tool +4。
"""
from __future__ import annotations

import json

from app.gateway import tokenizer


def _tool_text(tool) -> str:
    """与实现同口径的规范文本（排序键 → 计数确定）。"""
    return json.dumps(tool, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# ─────────────────────────────────────────────────────── 纯函数：字符口径
def test_empty_text_counts_zero_tokens():
    assert tokenizer.count_text_tokens("") == 0
    assert tokenizer.count_text_tokens(None) == 0


def test_ascii_words_are_four_chars_per_token_rounded_up():
    assert tokenizer.count_text_tokens("hell") == 1        # 4 字符 → 1
    assert tokenizer.count_text_tokens("hello") == 2       # 5 字符 → 向上取整 2
    assert tokenizer.count_text_tokens("hello world") == 3  # 11 字符（含空格）→ 3


def test_cjk_counts_one_token_per_character():
    assert tokenizer.count_text_tokens("你好世界") == 4
    assert tokenizer.count_text_tokens("中文提示词") == 5
    # 这就是要修的那个偏差：旧口径 len // 4 只给 1，实际约 4
    assert tokenizer.count_text_tokens("你好世界") > len("你好世界") // 4


def test_fullwidth_punctuation_and_emoji_are_one_token_each():
    assert tokenizer.count_text_tokens("，") == 1
    assert tokenizer.count_text_tokens("。！？") == 3
    assert tokenizer.count_text_tokens("😀") == 1


def test_mixed_cjk_and_ascii_adds_up():
    # "hi" → ceil(2/4) = 1；"你好" → 2
    assert tokenizer.count_text_tokens("hi你好") == 3


def test_ascii_symbols_are_two_chars_per_token():
    assert tokenizer.count_text_tokens("!!!") == 2         # 3 符号 → ceil(3/2)
    assert tokenizer.count_text_tokens("a!!b") == 3        # 1 词 + 1 符号 + 1 词


def test_counting_is_pure_and_deterministic():
    text = "混合 mixed 文本！with symbols: []{}"
    first = tokenizer.count_text_tokens(text)
    assert [tokenizer.count_text_tokens(text) for _ in range(3)] == [first] * 3
    assert isinstance(first, int) and first > 0


# ─────────────────────────────────────────────────────── 请求（chat template 近似）
def test_empty_messages_only_cost_the_reply_priming():
    assert tokenizer.count_prompt_tokens("m1", []) == tokenizer.REPLY_PRIMING_TOKENS


def test_single_message_costs_overhead_plus_role_and_content():
    messages = [{"role": "user", "content": "hi"}]
    expected = (tokenizer.REPLY_PRIMING_TOKENS + tokenizer.MESSAGE_OVERHEAD_TOKENS
                + tokenizer.count_text_tokens("user") + tokenizer.count_text_tokens("hi"))
    assert tokenizer.count_prompt_tokens("m1", messages) == expected
    assert expected == 9                                    # 3 + 4 + 1 + 1


def test_each_extra_message_adds_overhead_and_text():
    one = tokenizer.count_prompt_tokens("m1", [{"role": "user", "content": "hi"}])
    two = tokenizer.count_prompt_tokens("m1", [{"role": "user", "content": "hi"},
                                               {"role": "assistant", "content": "ok"}])
    delta = (tokenizer.MESSAGE_OVERHEAD_TOKENS + tokenizer.count_text_tokens("assistant")
             + tokenizer.count_text_tokens("ok"))
    assert two - one == delta


def test_chinese_prompt_is_not_underestimated_by_len_division():
    messages = [{"role": "user", "content": "中文提示"}]
    prompt_tokens = tokenizer.count_prompt_tokens("m1", messages)
    old_estimate = max(1, (len("user") + len("中文提示")) // 4)
    assert prompt_tokens == tokenizer.REPLY_PRIMING_TOKENS + 4 + 1 + 4  # = 12
    assert prompt_tokens > old_estimate


def test_tools_add_a_fixed_overhead_plus_their_canonical_text():
    tool = {"type": "function",
            "function": {"name": "lookup", "parameters": {"type": "object"}}}
    messages = [{"role": "user", "content": "hi"}]
    without = tokenizer.count_prompt_tokens("m1", messages)
    with_tool = tokenizer.count_prompt_tokens("m1", messages, tools=[tool])
    assert with_tool - without == (tokenizer.TOOL_OVERHEAD_TOKENS
                                   + tokenizer.count_text_tokens(_tool_text(tool)))


def test_missing_tools_equals_empty_tools():
    messages = [{"role": "user", "content": "hi"}]
    assert (tokenizer.count_prompt_tokens("m1", messages, tools=None)
            == tokenizer.count_prompt_tokens("m1", messages, tools=[]))


def test_multimodal_content_only_counts_text_parts():
    """图片等非文本片段不计（也不读正文），只有 text 部分进计数。"""
    text_only = [{"role": "user", "content": "看图"}]
    multimodal = [{"role": "user", "content": [{"type": "text", "text": "看图"},
                                               {"type": "image_url", "image_url": "x"}]}]
    assert (tokenizer.count_prompt_tokens("m1", text_only)
            == tokenizer.count_prompt_tokens("m1", multimodal))


# ─────────────────────────────────────────────────────── 回复
def test_completion_of_empty_text_is_zero():
    assert tokenizer.count_completion_tokens("m1", "") == 0
    assert tokenizer.count_completion_tokens("m1", None) == 0


def test_completion_counts_text_with_the_same_rules():
    assert tokenizer.count_completion_tokens("m1", "hello world") == 3
    assert tokenizer.count_completion_tokens("m1", "你好") == 2


# ─────────────────────────────────────────────────────── 可选 tiktoken（降级）
class _FakeEncoding:
    """假编码器：按空格切（证明「装了就用精确编码器」这条路径可达）。"""

    def encode(self, text: str, *, disallowed_special=()):
        return list(range(len(text.split())))


def test_exact_encoder_is_used_when_available(monkeypatch):
    monkeypatch.setattr(tokenizer, "_exact_encoding", lambda model: _FakeEncoding())
    assert tokenizer.uses_exact_encoder("gpt-4o") is True
    assert tokenizer.count_completion_tokens("gpt-4o", "a b c") == 3


def test_missing_tiktoken_degrades_to_character_rules(monkeypatch):
    """tiktoken 不是硬依赖：拿不到编码器就静默降级，且结果仍是确定的。"""
    monkeypatch.setattr(tokenizer, "_exact_encoding", lambda model: None)
    assert tokenizer.uses_exact_encoder("gpt-4o") is False
    assert tokenizer.count_completion_tokens("gpt-4o", "你好") == 2


def test_non_openai_models_never_use_an_exact_encoder():
    """非 OpenAI 系（平台自有 slug）必须走字符口径（与是否安装 tiktoken 无关）。"""
    assert tokenizer.uses_exact_encoder("m1") is False
    assert tokenizer.uses_exact_encoder("") is False


# ─────────────────────────────────────────────────────── 双计比对（纯函数）
def test_delta_ratio_matches_relative_difference():
    assert tokenizer.delta_ratio(100, 100) == 0.0
    assert tokenizer.delta_ratio(150, 100) == 0.5
    assert abs(tokenizer.delta_ratio(100, 150) - 1 / 3) < 1e-9


def test_delta_ratio_handles_zero_baseline():
    assert tokenizer.delta_ratio(0, 0) == 0.0
    assert tokenizer.delta_ratio(5, 0) == 1.0
    assert tokenizer.delta_ratio(0, 5) == 1.0


def test_one_percent_is_the_boundary_and_is_not_a_mismatch():
    threshold = 0.01
    assert tokenizer.is_mismatch(101, 100, threshold) is False     # 正好 1% → 不告警
    assert tokenizer.is_mismatch(99, 100, threshold) is False
    assert tokenizer.is_mismatch(102, 100, threshold) is True      # 超过 1% → 告警
    assert tokenizer.is_mismatch(98, 100, threshold) is True


def test_mismatch_event_carries_numbers_only():
    event = tokenizer.mismatch_event(request_id="r-1", model="m1", source="prompt",
                                     local=150, upstream=100, threshold=0.01)
    assert event is not None
    assert event["event"] == "gateway.token_mismatch"
    assert (event["request_id"], event["model"], event["source"]) == ("r-1", "m1", "prompt")
    assert (event["local"], event["upstream"]) == (150, 100)
    assert event["delta_pct"] == 50.0 and event["threshold_pct"] == 1.0
    # 不落正文：字段里没有 prompt / content / text 之类的载体
    assert not {"prompt", "content", "text", "messages", "response"} & set(event)


def test_mismatch_event_is_none_within_threshold():
    assert tokenizer.mismatch_event(request_id="r-1", model="m1", source="completion",
                                    local=100, upstream=100, threshold=0.01) is None


def test_dual_mismatch_events_covers_prompt_and_completion_separately():
    events = tokenizer.dual_mismatch_events(request_id="r-1", model="m1",
                                            local_in=150, upstream_in=100,
                                            local_out=10, upstream_out=10, threshold=0.01)
    assert [event["source"] for event in events] == ["prompt"]

    events = tokenizer.dual_mismatch_events(request_id="r-1", model="m1",
                                            local_in=150, upstream_in=100,
                                            local_out=10, upstream_out=20, threshold=0.01)
    assert [event["source"] for event in events] == ["prompt", "completion"]
