import httpx

from ..resolver import ResolveError, Resolver
from ..schemas import ToolEnvelope
from ..settings import Settings

_BASE = "https://www.virustotal.com/api/v3"

_IP_FIELDS = [
    "last_analysis_stats", "reputation", "asn", "as_owner", "country", "tags",
    "last_analysis_date", "total_votes", "network", "regional_internet_registry",
]
_DOMAIN_FIELDS = [
    "last_analysis_stats", "reputation", "tags", "creation_date", "registrar",
    "last_dns_records", "categories", "total_votes",
]
_FILE_FIELDS = [
    "last_analysis_stats", "meaningful_name", "type_description", "size", "tags",
    "popular_threat_classification", "first_submission_date", "total_votes",
]


def _require_key(settings: Settings) -> str:
    if not settings.vt_api_key:
        raise ResolveError("VT_API_KEY not configured")
    return settings.vt_api_key


async def _get_attributes(settings: Settings, path: str) -> dict:
    key = _require_key(settings)
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.get(f"{_BASE}{path}", headers={"x-apikey": key})
        response.raise_for_status()
        return response.json()["data"]


def _trim(attributes: dict, fields: list[str]) -> dict:
    return {k: attributes[k] for k in fields if k in attributes}


async def ip_report(resolver: Resolver, settings: Settings, ip: str) -> ToolEnvelope:
    async def fetch() -> dict:
        data = await _get_attributes(settings, f"/ip_addresses/{ip}")
        return _trim(data["attributes"], _IP_FIELDS)

    return await resolver.resolve(source="virustotal", endpoint="ip_report", key=ip, fetch_live=fetch)


async def domain_report(resolver: Resolver, settings: Settings, domain: str) -> ToolEnvelope:
    async def fetch() -> dict:
        data = await _get_attributes(settings, f"/domains/{domain}")
        trimmed = _trim(data["attributes"], _DOMAIN_FIELDS)
        if "last_dns_records" in trimmed:
            trimmed["last_dns_records"] = trimmed["last_dns_records"][:5]
        return trimmed

    return await resolver.resolve(
        source="virustotal", endpoint="domain_report", key=domain, fetch_live=fetch
    )


async def file_report(resolver: Resolver, settings: Settings, file_hash: str) -> ToolEnvelope:
    async def fetch() -> dict:
        data = await _get_attributes(settings, f"/files/{file_hash}")
        return _trim(data["attributes"], _FILE_FIELDS)

    return await resolver.resolve(
        source="virustotal", endpoint="file_report", key=file_hash, fetch_live=fetch
    )


async def ip_relations(resolver: Resolver, settings: Settings, ip: str) -> ToolEnvelope:
    async def fetch() -> dict:
        key = _require_key(settings)
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                f"{_BASE}/ip_addresses/{ip}/resolutions",
                headers={"x-apikey": key},
                params={"limit": 10},
            )
            response.raise_for_status()
            items = response.json().get("data", [])
        return {
            "resolutions": [
                {
                    "host_name": item.get("attributes", {}).get("host_name"),
                    "date": item.get("attributes", {}).get("date"),
                }
                for item in items
            ]
        }

    return await resolver.resolve(
        source="virustotal", endpoint="ip_relations", key=ip, fetch_live=fetch
    )
