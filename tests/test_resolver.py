import json
from datetime import UTC, datetime, timedelta

import pytest

from threat_intel_agent.resolver import ResolveError, Resolver
from threat_intel_agent.settings import Settings


def make_settings(tmp_path, mode: str) -> Settings:
    return Settings(
        resolver_mode=mode,
        cache_dir=tmp_path / "cache",
        fixture_dir=tmp_path / "fixtures",
    )


def write_fixture(settings: Settings, name: str, data: dict) -> None:
    settings.fixture_dir.mkdir(parents=True, exist_ok=True)
    path = settings.fixture_dir / name
    path.write_text(json.dumps({"data": data}), encoding="utf-8")


def write_cache(settings: Settings, name: str, data: dict, age_seconds: int = 0) -> None:
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    fetched = datetime.now(UTC) - timedelta(seconds=age_seconds)
    entry = {"fetched_at": fetched.strftime("%Y-%m-%dT%H:%M:%SZ"), "data": data}
    (settings.cache_dir / name).write_text(json.dumps(entry), encoding="utf-8")


class LiveTracker:
    def __init__(self, data: dict | None = None, error: Exception | None = None):
        self.calls = 0
        self._data = data or {}
        self._error = error

    async def fetch(self) -> dict:
        self.calls += 1
        if self._error:
            raise self._error
        return self._data


async def test_offline_serves_fixture_without_live(tmp_path):
    settings = make_settings(tmp_path, "offline")
    write_fixture(settings, "testsrc__ep__1.2.3.4.json", {"score": 1})
    live = LiveTracker({"score": 99})
    env = await Resolver(settings).resolve(
        source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch
    )
    assert env.layer == "fixture" and env.data == {"score": 1} and live.calls == 0


async def test_prefer_cache_live_then_cached(tmp_path):
    settings = make_settings(tmp_path, "prefer_cache")
    live = LiveTracker({"score": 7})
    resolver = Resolver(settings)
    env1 = await resolver.resolve(source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch)
    env2 = await resolver.resolve(source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch)
    assert env1.layer == "live" and env2.layer == "cache"
    assert env2.data == {"score": 7} and live.calls == 1


async def test_prefer_live_fresh_cache_used(tmp_path):
    settings = make_settings(tmp_path, "prefer_live")
    write_cache(settings, "testsrc__ep__1.2.3.4.json", {"score": 3}, age_seconds=10)
    live = LiveTracker({"score": 99})
    env = await Resolver(settings).resolve(
        source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch
    )
    assert env.layer == "cache" and live.calls == 0


async def test_prefer_live_stale_cache_refetched(tmp_path):
    settings = make_settings(tmp_path, "prefer_live")
    write_cache(settings, "testsrc__ep__1.2.3.4.json", {"score": 3}, age_seconds=99999)
    live = LiveTracker({"score": 99})
    env = await Resolver(settings).resolve(
        source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch, ttl_seconds=3600
    )
    assert env.layer == "live" and env.data == {"score": 99} and live.calls == 1


async def test_live_failure_falls_to_fixture_with_warning(tmp_path):
    settings = make_settings(tmp_path, "prefer_cache")
    write_fixture(settings, "testsrc__ep__1.2.3.4.json", {"score": 1})
    live = LiveTracker(error=RuntimeError("boom"))
    env = await Resolver(settings).resolve(
        source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch
    )
    assert env.layer == "fixture"
    assert any("live fetch failed" in w for w in env.warnings)


async def test_live_failure_stale_cache_served(tmp_path):
    settings = make_settings(tmp_path, "prefer_live")
    write_cache(settings, "testsrc__ep__1.2.3.4.json", {"score": 3}, age_seconds=99999)
    live = LiveTracker(error=RuntimeError("boom"))
    env = await Resolver(settings).resolve(
        source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch
    )
    assert env.layer == "cache" and env.data == {"score": 3}
    assert any("stale" in w for w in env.warnings)


async def test_nothing_available_raises(tmp_path):
    settings = make_settings(tmp_path, "prefer_cache")
    live = LiveTracker(error=RuntimeError("boom"))
    with pytest.raises(ResolveError):
        await Resolver(settings).resolve(
            source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch
        )


async def test_arm_failure_is_one_shot(tmp_path):
    settings = make_settings(tmp_path, "prefer_live")
    write_fixture(settings, "testsrc__ep__1.2.3.4.json", {"score": 1})
    live = LiveTracker({"score": 99})
    resolver = Resolver(settings)
    resolver.arm_failure("testsrc")
    env1 = await resolver.resolve(source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch)
    assert env1.layer == "fixture" and live.calls == 0
    assert any("simulated failure" in w for w in env1.warnings)
    env2 = await resolver.resolve(source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch)
    assert env2.layer == "live" and live.calls == 1


async def test_arm_failure_bypasses_fresh_cache(tmp_path):
    settings = make_settings(tmp_path, "prefer_cache")
    write_cache(settings, "testsrc__ep__1.2.3.4.json", {"score": 3})
    live = LiveTracker({"score": 99})
    resolver = Resolver(settings)
    resolver.arm_failure("testsrc")
    env = await resolver.resolve(
        source="testsrc", endpoint="ep", key="1.2.3.4", fetch_live=live.fetch
    )
    assert env.layer == "cache" and live.calls == 0
    assert any("simulated failure" in w for w in env.warnings)
    assert any("stale" in w for w in env.warnings)


async def test_cache_key_normalized(tmp_path):
    settings = make_settings(tmp_path, "prefer_cache")
    live = LiveTracker({"score": 5})
    resolver = Resolver(settings)
    env1 = await resolver.resolve(source="testsrc", endpoint="ep", key="EVIL.com", fetch_live=live.fetch)
    env2 = await resolver.resolve(source="testsrc", endpoint="ep", key="evil.com", fetch_live=live.fetch)
    assert env1.layer == "live" and env2.layer == "cache" and live.calls == 1
