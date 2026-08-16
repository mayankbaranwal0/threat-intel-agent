import httpx

from ..resolver import ResolveError, Resolver
from ..schemas import ToolEnvelope
from ..settings import Settings

_FIELDS = [
    "abuseConfidenceScore", "totalReports", "numDistinctUsers", "countryCode",
    "usageType", "isp", "domain", "lastReportedAt", "isTor",
]


async def check_ip(resolver: Resolver, settings: Settings, ip: str) -> ToolEnvelope:
    async def fetch() -> dict:
        if not settings.abuseipdb_api_key:
            raise ResolveError("ABUSEIPDB_API_KEY not configured")
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            response.raise_for_status()
            data = response.json()["data"]
        return {k: data[k] for k in _FIELDS if k in data}

    return await resolver.resolve(source="abuseipdb", endpoint="check", key=ip, fetch_live=fetch)
