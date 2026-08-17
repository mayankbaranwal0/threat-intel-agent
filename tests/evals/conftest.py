import pytest

from threat_intel_agent.agent import AgentSession
from threat_intel_agent.schemas import Answer
from threat_intel_agent.settings import REPO_ROOT, Settings

HAS_KEY = bool(Settings().anthropic_api_key)


@pytest.fixture
def session(tmp_path) -> AgentSession:
    settings = Settings(
        resolver_mode="offline",
        cache_dir=tmp_path / "cache",
        fixture_dir=REPO_ROOT / "data" / "fixtures",
    )
    return AgentSession(settings=settings)


def claims(answer: Answer) -> str:
    return " ".join(f.claim for f in answer.findings).lower()


def steps(session: AgentSession) -> list[str]:
    return [event.step for event in session.last_trace]
