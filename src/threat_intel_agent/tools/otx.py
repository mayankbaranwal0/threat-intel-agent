import httpx

from ..resolver import ResolveError, Resolver
from ..schemas import ToolEnvelope
from ..settings import Settings

_BASE = "https://otx.alienvault.com/api/v1/indicators"


def _trim_pulses(payload: dict) -> dict:
    info = payload.get("pulse_info", {})
    return {
        "pulse_count": info.get("count", 0),
        "pulses": [
            {
                "name": pulse.get("name", ""),
                "description": (pulse.get("description") or "")[:300],
                "tags": pulse.get("tags", [])[:5],
            }
            for pulse in info.get("pulses", [])[:5]
        ],
    }


async def _general(settings: Settings, kind: str, value: str) -> dict:
    if not settings.otx_api_key:
        raise ResolveError("OTX_API_KEY not configured")
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(
            f"{_BASE}/{kind}/{value}/general",
            headers={"X-OTX-API-KEY": settings.otx_api_key},
        )
        response.raise_for_status()
        return _trim_pulses(response.json())


async def ip_general(resolver: Resolver, settings: Settings, ip: str) -> ToolEnvelope:
    async def fetch() -> dict:
        return await _general(settings, "IPv4", ip)

    return await resolver.resolve(source="otx", endpoint="ip_general", key=ip, fetch_live=fetch)


async def domain_general(resolver: Resolver, settings: Settings, domain: str) -> ToolEnvelope:
    async def fetch() -> dict:
        return await _general(settings, "domain", domain)

    return await resolver.resolve(
        source="otx", endpoint="domain_general", key=domain, fetch_live=fetch
    )
