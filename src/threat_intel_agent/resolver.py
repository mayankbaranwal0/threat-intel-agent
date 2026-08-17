import asyncio
import json
import os
import re
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .schemas import ToolEnvelope, utcnow_iso
from .settings import Settings


class ResolveError(Exception):
    pass


# minimum seconds between live calls per source (VirusTotal free tier: 4/min)
_MIN_INTERVAL = {"virustotal": 16.0, "abuseipdb": 2.0, "otx": 2.0, "nvd": 7.0}


def _slug(key: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "_", key.lower())[:80]


class _Bucket:
    def __init__(self, interval: float) -> None:
        self.interval = interval
        self.last = 0.0

    async def acquire(self) -> None:
        wait = self.interval - (time.monotonic() - self.last)
        if wait > 0:
            await asyncio.sleep(wait)
        self.last = time.monotonic()


class Resolver:
    def __init__(self, settings: Settings) -> None:
        self.mode = settings.resolver_mode
        self.cache_dir = settings.cache_dir
        self.fixture_dir = settings.fixture_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._buckets = {source: _Bucket(interval) for source, interval in _MIN_INTERVAL.items()}
        self._fail_next: set[str] = set()

    def arm_failure(self, source: str) -> None:
        self._fail_next.add(source)

    def _path(self, base: Path, source: str, endpoint: str, key: str) -> Path:
        return base / f"{source}__{endpoint}__{_slug(key)}.json"

    @staticmethod
    def _read(path: Path) -> dict | None:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _age_seconds(entry: dict) -> float:
        fetched = datetime.strptime(entry["fetched_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        return (datetime.now(UTC) - fetched).total_seconds()

    def _write_cache(self, path: Path, entry: dict) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(self.cache_dir), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entry, f)
        os.replace(tmp, path)

    async def resolve(
        self,
        *,
        source: str,
        endpoint: str,
        key: str,
        fetch_live,
        ttl_seconds: int = 3600,
    ) -> ToolEnvelope:
        warnings: list[str] = []
        cache_path = self._path(self.cache_dir, source, endpoint, key)
        cached = self._read(cache_path)
        simulated = source in self._fail_next
        if simulated:
            self._fail_next.discard(source)
            warnings.append(f"simulated failure armed for {source} (HTTP 429)")

        def from_cache() -> ToolEnvelope:
            return ToolEnvelope(
                source=source,
                fetched_at=cached["fetched_at"],
                layer="cache",
                data=cached["data"],
                warnings=warnings,
            )

        if cached and not simulated:
            if self.mode == "prefer_cache" or self.mode == "offline":
                return from_cache()
            if self.mode == "prefer_live" and self._age_seconds(cached) < ttl_seconds:
                return from_cache()

        if self.mode != "offline" and not simulated:
            try:
                await self._buckets.setdefault(source, _Bucket(1.0)).acquire()
                data = await fetch_live()
                entry = {"fetched_at": utcnow_iso(), "data": data}
                self._write_cache(cache_path, entry)
                return ToolEnvelope(
                    source=source,
                    fetched_at=entry["fetched_at"],
                    layer="live",
                    data=data,
                    warnings=warnings,
                )
            except Exception as e:  # noqa: BLE001 - any live-fetch failure falls through to stale cache or fixture
                warnings.append(f"live fetch failed: {type(e).__name__}")

        if cached:
            warnings.append("serving stale cache")
            return from_cache()

        fixture = self._read(self._path(self.fixture_dir, source, endpoint, key))
        if fixture is not None:
            return ToolEnvelope(
                source=source,
                fetched_at=fixture.get("fetched_at", "N/A (curated fixture)"),
                layer="fixture",
                data=fixture.get("data", fixture),
                warnings=warnings,
            )

        detail = "; ".join(warnings) or "no layers available"
        raise ResolveError(f"{source}/{endpoint}: no data available for {key} ({detail})")
