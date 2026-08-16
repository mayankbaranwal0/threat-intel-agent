import json

import httpx
import pytest

from threat_intel_agent.resolver import ResolveError, Resolver
from threat_intel_agent.settings import REPO_ROOT, Settings
from threat_intel_agent.tools import abuseipdb, nvd, otx, virustotal
from threat_intel_agent.tools.nvd import version_in_range


def offline_settings(tmp_path) -> Settings:
    return Settings(
        resolver_mode="offline",
        cache_dir=tmp_path / "cache",
        fixture_dir=REPO_ROOT / "data" / "fixtures",
    )


def empty_settings(tmp_path) -> Settings:
    return Settings(
        resolver_mode="prefer_live",
        cache_dir=tmp_path / "cache",
        fixture_dir=tmp_path / "fixtures",
        vt_api_key="",
        abuseipdb_api_key="",
        otx_api_key="",
    )


class FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict:
        return self._payload


def patch_get(monkeypatch, payload: dict, captured: dict | None = None):
    async def fake_get(self, url, **kwargs):
        if captured is not None:
            captured["url"] = url
            captured["params"] = kwargs.get("params", {})
        return FakeResponse(payload)

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)


# offline fixtures cover every tool without network

async def test_vt_ip_report_offline(tmp_path):
    settings = offline_settings(tmp_path)
    env = await virustotal.ip_report(Resolver(settings), settings, "45.83.122.10")
    assert env.layer == "fixture"
    assert env.data["last_analysis_stats"]["malicious"] == 34


async def test_abuseipdb_offline(tmp_path):
    settings = offline_settings(tmp_path)
    env = await abuseipdb.check_ip(Resolver(settings), settings, "45.83.122.10")
    assert env.layer == "fixture" and env.data["abuseConfidenceScore"] == 100


async def test_otx_domain_offline_poisoned(tmp_path):
    settings = offline_settings(tmp_path)
    env = await otx.domain_general(Resolver(settings), settings, "evil-updates.com")
    assert env.layer == "fixture"
    assert "ignore previous instructions" in env.data["pulses"][0]["description"]


async def test_nvd_exposure_offline(tmp_path):
    settings = offline_settings(tmp_path)
    env = await nvd.product_exposure(Resolver(settings), settings, "Confluence", "7.13")
    assert env.layer == "fixture"
    assert any(c["id"] == "CVE-2022-26134" for c in env.data["cves"])


async def test_vt_relations_offline(tmp_path):
    settings = offline_settings(tmp_path)
    env = await virustotal.ip_relations(Resolver(settings), settings, "45.83.122.10")
    assert any(r["host_name"] == "evil-updates.com" for r in env.data["resolutions"])


# trimming

async def test_vt_ip_report_trims_live_response(tmp_path, monkeypatch):
    settings = empty_settings(tmp_path)
    settings.vt_api_key = "fake"
    huge = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 3},
                "reputation": -5,
                "asn": 1234,
                "whois": "x" * 50000,
                "last_analysis_results": {f"engine{i}": {"result": "clean"} for i in range(90)},
            }
        }
    }
    patch_get(monkeypatch, huge)
    env = await virustotal.ip_report(Resolver(settings), settings, "1.2.3.4")
    assert env.layer == "live"
    assert "whois" not in env.data and "last_analysis_results" not in env.data
    assert len(json.dumps(env.data)) < 4000


async def test_otx_trims_pulses(tmp_path, monkeypatch):
    settings = empty_settings(tmp_path)
    settings.otx_api_key = "fake"
    payload = {
        "pulse_info": {
            "count": 40,
            "pulses": [
                {"name": f"pulse{i}", "description": "d" * 2000, "tags": [str(t) for t in range(20)]}
                for i in range(40)
            ],
        }
    }
    patch_get(monkeypatch, payload)
    env = await otx.ip_general(Resolver(settings), settings, "1.2.3.4")
    assert env.data["pulse_count"] == 40
    assert len(env.data["pulses"]) == 5
    assert len(env.data["pulses"][0]["description"]) == 300
    assert len(env.data["pulses"][0]["tags"]) == 5


async def test_nvd_keyword_fallback_for_unknown_product(tmp_path, monkeypatch):
    settings = empty_settings(tmp_path)
    captured: dict = {}
    patch_get(monkeypatch, {"vulnerabilities": []}, captured)
    env = await nvd.product_exposure(Resolver(settings), settings, "obscureapp", "1.0")
    assert "keywordSearch" in captured["params"]
    assert env.data["match_mode"].startswith("keyword")


# graceful failure

async def test_missing_key_no_fixture_raises(tmp_path):
    settings = empty_settings(tmp_path)
    with pytest.raises(ResolveError):
        await virustotal.ip_report(Resolver(settings), settings, "203.0.113.7")


# version range matching

@pytest.mark.parametrize(
    "version,match,expected",
    [
        ("7.13", {"versionStartIncluding": "7.13.0", "versionEndExcluding": "7.13.7"}, True),
        ("7.13.6", {"versionStartIncluding": "7.13.0", "versionEndExcluding": "7.13.7"}, True),
        ("7.13.7", {"versionStartIncluding": "7.13.0", "versionEndExcluding": "7.13.7"}, False),
        ("8.6", {"versionStartIncluding": "7.13.0", "versionEndExcluding": "7.13.7"}, False),
        ("7.12.9", {"versionStartIncluding": "7.13.0", "versionEndExcluding": "7.13.7"}, False),
        ("2.0", {"versionEndIncluding": "2.0"}, True),
        ("2.0.1", {"versionEndIncluding": "2.0"}, False),
        ("not-a-version", {"versionStartIncluding": "1.0"}, False),
        ("1.0", {}, False),
    ],
)
def test_version_in_range(version, match, expected):
    assert version_in_range(version, match) is expected
