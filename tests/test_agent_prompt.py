import pytest

from cloudtrail_agent.prompt import REFUSAL_GUIDANCE, SYSTEM_PROMPT

_TOOL_NAMES = [
    "lookup_by_user",
    "lookup_by_resource",
    "lookup_by_event_name",
    "investigate_event",
    "summarize_window",
    "analytical_query",
]


@pytest.mark.parametrize("tool_name", _TOOL_NAMES)
def test_system_prompt_mentions_tool(tool_name):
    assert tool_name in SYSTEM_PROMPT, f"SYSTEM_PROMPT missing tool name: {tool_name}"


def test_system_prompt_cites_event_ids():
    assert "EventId" in SYSTEM_PROMPT or "event ID" in SYSTEM_PROMPT.lower()


def test_system_prompt_forbids_untooled_claims():
    prompt_lower = SYSTEM_PROMPT.lower()
    assert "never" in prompt_lower or "no un-tooled" in prompt_lower or "do not" in prompt_lower


def test_refusal_guidance_suggests_narrower_time_window():
    guidance_lower = REFUSAL_GUIDANCE.lower()
    assert "narrower time window" in guidance_lower or "time window" in guidance_lower


def test_refusal_guidance_suggests_narrower_filter():
    guidance_lower = REFUSAL_GUIDANCE.lower()
    assert "narrower filter" in guidance_lower or "narrow" in guidance_lower
