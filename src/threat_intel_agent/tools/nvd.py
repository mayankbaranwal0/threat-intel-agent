import json
from functools import lru_cache

import httpx
from packaging.version import InvalidVersion, Version

from ..resolver import Resolver
from ..schemas import ToolEnvelope
from ..settings import Settings

_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@lru_cache(maxsize=4)
def _aliases(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _parse(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def version_in_range(version: str, match: dict) -> bool:
    v = _parse(version)
    if v is None:
        return False
    checks = [
        ("versionStartIncluding", lambda bound: v >= bound),
        ("versionStartExcluding", lambda bound: v > bound),
        ("versionEndIncluding", lambda bound: v <= bound),
        ("versionEndExcluding", lambda bound: v < bound),
    ]
    constrained = False
    for field, ok in checks:
        raw = match.get(field)
        if raw is None:
            continue
        bound = _parse(raw)
        if bound is None or not ok(bound):
            return False
        constrained = True
    return constrained


def _trim_cve(cve: dict) -> dict:
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
    )[:400]
    metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
    cvss = metrics[0].get("cvssData", {}) if metrics else {}
    matches = [
        {
            "criteria": m.get("criteria", ""),
            "versionStartIncluding": m.get("versionStartIncluding"),
            "versionStartExcluding": m.get("versionStartExcluding"),
            "versionEndIncluding": m.get("versionEndIncluding"),
            "versionEndExcluding": m.get("versionEndExcluding"),
        }
        for config in cve.get("configurations", [])
        for node in config.get("nodes", [])
        for m in node.get("cpeMatch", [])
        if m.get("vulnerable")
    ]
    return {
        "id": cve.get("id", ""),
        "description": description,
        "baseScore": cvss.get("baseScore"),
        "baseSeverity": cvss.get("baseSeverity"),
        "affected": matches[:5],
    }


async def _query(settings: Settings, params: dict) -> list[dict]:
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(_BASE, headers=headers, params=params)
        response.raise_for_status()
        return [
            _trim_cve(item.get("cve", {}))
            for item in response.json().get("vulnerabilities", [])
        ]


async def cve_lookup(resolver: Resolver, settings: Settings, cve_id: str) -> ToolEnvelope:
    cve_id = cve_id.upper().strip()

    async def fetch() -> dict:
        return {"cves": await _query(settings, {"cveId": cve_id})}

    return await resolver.resolve(source="nvd", endpoint="cve", key=cve_id, fetch_live=fetch)


async def product_exposure(
    resolver: Resolver, settings: Settings, product: str, version: str
) -> ToolEnvelope:
    product = product.lower().strip()
    version = version.strip()
    key = f"{product} {version}"

    async def fetch() -> dict:
        cpe = _aliases(str(settings.cpe_aliases)).get(product)
        if cpe:
            cves = await _query(settings, {"virtualMatchString": cpe, "resultsPerPage": 100})
            exposed = [
                c for c in cves if any(version_in_range(version, m) for m in c["affected"])
            ]
            match_mode = "cpe"
        else:
            exposed = await _query(
                settings, {"keywordSearch": f"{product} {version}", "resultsPerPage": 20}
            )
            match_mode = "keyword (verify applicability manually)"
        exposed.sort(key=lambda c: c.get("baseScore") or 0, reverse=True)
        return {
            "product": product,
            "version": version,
            "match_mode": match_mode,
            "cves": exposed[:5],
        }

    return await resolver.resolve(
        source="nvd", endpoint="cpe_search", key=key, fetch_live=fetch
    )
