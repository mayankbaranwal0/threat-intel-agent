import pytest

from threat_intel_agent.settings import Settings
from threat_intel_agent.tools import attck

settings = Settings()

pytestmark = pytest.mark.skipif(
    not settings.attck_index.exists(),
    reason="attck_index.json not built (run scripts/build_attck_index.py)",
)


def test_actor_profile_apt29():
    env = attck.actor_profile(settings, "APT29")
    assert env.source == "attck" and env.layer == "fixture"
    assert env.data["found"] is True
    assert len(env.data["techniques"]) > 0
    assert env.data["technique_count_total"] >= 10


def test_actor_alias_resolves():
    env = attck.actor_profile(settings, "Cozy Bear")
    assert env.data["found"] is True
    assert "APT29" in (env.data["name"], *env.data["aliases"])


def test_unknown_actor_not_exception():
    env = attck.actor_profile(settings, "definitely-not-a-real-actor-xyz")
    assert env.data == {"found": False, "query": "definitely-not-a-real-actor-xyz"}


def test_technique_lookup():
    env = attck.technique_lookup(settings, "T1566")
    assert env.data["found"] is True
    assert "phish" in env.data["name"].lower()


def test_techniques_capped_for_token_budget():
    env = attck.actor_profile(settings, "APT29")
    assert len(env.data["techniques"]) <= 15
    assert len(env.data["description"]) <= 500
