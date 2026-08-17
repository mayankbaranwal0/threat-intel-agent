import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_intel_agent.resolver import ResolveError, Resolver
from threat_intel_agent.settings import Settings
from threat_intel_agent.tools import abuseipdb, nvd, otx, virustotal

# Pre-fetches live data for the demo query set so a recording never waits on the
# network. Rate limits are respected automatically by the resolver's per-source
# buckets (VirusTotal is paced at ~16s between calls), so a full run takes a
# couple of minutes.
#
# Deliberately NOT warmed:
# - evil-updates.com (OTX/VT): its poisoned OTX fixture is the indirect-injection
#   demo; warming it would cache a clean live response over the planted payload.
#   Demo that beat with the resolver in offline mode.
# - the demo file hash: its fixture tells the fake-updater story; the live VT
#   record for that hash is an unrelated benign file.


def jobs(resolver: Resolver, settings: Settings) -> list[tuple[str, object]]:
    return [
        ("virustotal ip_report 45.83.122.10", virustotal.ip_report(resolver, settings, "45.83.122.10")),
        ("virustotal ip_relations 45.83.122.10", virustotal.ip_relations(resolver, settings, "45.83.122.10")),
        ("virustotal ip_report 8.8.8.8", virustotal.ip_report(resolver, settings, "8.8.8.8")),
        ("abuseipdb check 45.83.122.10", abuseipdb.check_ip(resolver, settings, "45.83.122.10")),
        ("abuseipdb check 8.8.8.8", abuseipdb.check_ip(resolver, settings, "8.8.8.8")),
        ("otx ip_general 45.83.122.10", otx.ip_general(resolver, settings, "45.83.122.10")),
        ("otx ip_general 8.8.8.8", otx.ip_general(resolver, settings, "8.8.8.8")),
        ("nvd cve CVE-2022-26134", nvd.cve_lookup(resolver, settings, "CVE-2022-26134")),
        ("nvd exposure confluence 7.13", nvd.product_exposure(resolver, settings, "confluence", "7.13")),
    ]


async def main() -> int:
    settings = Settings(resolver_mode="prefer_live")
    resolver = Resolver(settings)
    warmed = failed = 0
    for label, coro in jobs(resolver, settings):
        try:
            envelope = await coro
            warmed += 1
            print(f"  {envelope.layer:<8} {label}")
        except ResolveError as e:
            failed += 1
            print(f"  FAILED   {label}: {e}")
    print(f"\nwarmed {warmed}, failed {failed}"
          + (" (failed entries will serve fixtures at demo time)" if failed else ""))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
