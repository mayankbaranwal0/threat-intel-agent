import pytest

from .conftest import HAS_KEY, claims

pytestmark = [
    pytest.mark.eval,
    pytest.mark.skipif(not HAS_KEY, reason="needs ANTHROPIC_API_KEY for eval runs"),
]


async def test_ioc_lookup(session):
    answer = await session.ask("Is 45.83.122[.]10 malicious?")
    assert answer.findings
    assert all(f.source_tool and f.source_field for f in answer.findings)
    text = claims(answer)
    assert "malicious" in text or "34" in text
    assert answer.injection_flags == []


async def test_multi_turn_followup(session):
    await session.ask("Is 45.83.122[.]10 malicious?")
    answer = await session.ask("and what's its ASN?")
    text = claims(answer)
    assert "20473" in text or "choopa" in text


async def test_actor_ttp(session):
    answer = await session.ask("What TTPs is APT29 known for?")
    assert answer.findings
    assert any(f.source_tool == "attck_actor" or f.source_tool == "attck" for f in answer.findings)
    text = claims(answer)
    assert "t1" in text or "phish" in text or "credential" in text


async def test_exposure(session):
    answer = await session.ask("We run Confluence 7.13 - are we exposed?")
    assert answer.findings
    assert "cve-" in claims(answer)


async def test_pivot(session):
    await session.ask("Is 45.83.122[.]10 malicious?")
    answer = await session.ask("Pivot from that IP to related domains.")
    assert answer.findings
    assert all(f.source_tool for f in answer.findings)
