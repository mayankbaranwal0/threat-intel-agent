import pydantic_ai
import pytest

from threat_intel_agent.memory import EntityMemory
from threat_intel_agent.router import INTENT_TOOLSETS, route, toolset_for
from threat_intel_agent.schemas import RouterOutput


async def test_router_failure_falls_back_to_full_toolset(monkeypatch):
    async def boom(self, *args, **kwargs):
        raise RuntimeError("provider down")

    monkeypatch.setattr(pydantic_ai.Agent, "run", boom)
    output = await route("Is 1.2.3.4 malicious?", [], EntityMemory(), "anthropic:claude-sonnet-5")
    assert output.confidence == 0.0
    assert output.rewritten_query == "Is 1.2.3.4 malicious?"
    assert toolset_for(output) is None


def test_toolsets_cover_all_task_intents():
    assert set(INTENT_TOOLSETS) == {"ioc_lookup", "actor_ttp", "exposure", "pivot"}
    for names in INTENT_TOOLSETS.values():
        assert names


def test_toolset_union_dedupes():
    output = RouterOutput(
        rewritten_query="q", intents=["ioc_lookup", "pivot"], confidence=0.9
    )
    selected = toolset_for(output)
    assert selected is not None
    assert len(selected) == len(set(selected))
    assert "vt_ip_report" in selected and "vt_relations" in selected


def test_low_confidence_triggers_fallback():
    output = RouterOutput(rewritten_query="q", intents=["ioc_lookup"], confidence=0.3)
    assert toolset_for(output) is None


def test_gate_intents_have_no_toolset():
    output = RouterOutput(
        rewritten_query="q", intents=["injection_attempt"], confidence=0.95
    )
    assert toolset_for(output) is None


@pytest.mark.parametrize("intent", ["ioc_lookup", "actor_ttp", "exposure", "pivot"])
def test_single_intent_selects_its_tools(intent):
    output = RouterOutput(rewritten_query="q", intents=[intent], confidence=0.9)
    assert toolset_for(output) == INTENT_TOOLSETS[intent]
