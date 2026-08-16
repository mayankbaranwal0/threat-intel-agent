from threat_intel_agent.memory import EntityMemory
from threat_intel_agent.schemas import Entity


def _e(value: str, etype: str) -> Entity:
    return Entity(value=value, type=etype)


def test_recent_newest_first():
    m = EntityMemory()
    m.push([_e("45.83.122.10", "ipv4"), _e("evil-updates.com", "domain")])
    m.push([_e("a" * 64, "sha256")])
    recent = m.recent()
    assert recent[0].type == "sha256"
    assert [e.value for e in recent[-2:]] == ["45.83.122.10", "evil-updates.com"]


def test_duplicate_repromoted_not_duplicated():
    m = EntityMemory()
    m.push([_e("45.83.122.10", "ipv4")])
    m.push([_e("evil-updates.com", "domain")])
    m.push([_e("45.83.122.10", "ipv4")])
    recent = m.recent()
    assert [e.value for e in recent] == ["45.83.122.10", "evil-updates.com"]


def test_recent_limit():
    m = EntityMemory()
    m.push([_e(f"10.0.0.{i}", "ipv4") for i in range(15)])
    assert len(m.recent(5)) == 5


def test_context_block_content():
    m = EntityMemory()
    m.push([_e("45.83.122.10", "ipv4")])
    block = m.context_block()
    assert "ipv4: 45.83.122.10" in block


def test_context_block_empty():
    assert EntityMemory().context_block() == ""


def test_clear():
    m = EntityMemory()
    m.push([_e("45.83.122.10", "ipv4")])
    m.clear()
    assert m.recent() == [] and m.context_block() == ""
