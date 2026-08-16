import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "attck" / "enterprise-attack.json"
OUT = ROOT / "data" / "attck_index.json"
URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def download() -> None:
    RAW.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", URL, follow_redirects=True, timeout=180) as response:
        response.raise_for_status()
        with open(RAW, "wb") as f:
            f.writelines(response.iter_bytes())


def build() -> None:
    objects = json.loads(RAW.read_text(encoding="utf-8"))["objects"]

    technique_by_stix: dict[str, dict] = {}
    techniques: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = next(
            (
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ext_id:
            continue
        technique_by_stix[obj["id"]] = {"id": ext_id, "name": obj.get("name", "")}
        techniques[ext_id] = {
            "id": ext_id,
            "name": obj.get("name", ""),
            "description": (obj.get("description") or "").strip()[:500],
        }

    actors: dict[str, dict] = {}
    actor_by_stix: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "intrusion-set" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        entry = {
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "description": (obj.get("description") or "").strip()[:500],
            "techniques": [],
        }
        actors[entry["name"].lower()] = entry
        actor_by_stix[obj["id"]] = entry

    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        actor = actor_by_stix.get(obj.get("source_ref", ""))
        technique = technique_by_stix.get(obj.get("target_ref", ""))
        if (
            actor is not None
            and technique is not None
            and technique["id"] not in {t["id"] for t in actor["techniques"]}
        ):
            actor["techniques"].append(technique)

    aliases = {
        alias.lower(): key
        for key, entry in actors.items()
        for alias in entry["aliases"]
        if alias.lower() != key
    }

    OUT.write_text(
        json.dumps({"actors": actors, "aliases": aliases, "techniques": techniques}),
        encoding="utf-8",
    )
    print(f"actors={len(actors)} aliases={len(aliases)} techniques={len(techniques)} -> {OUT}")


if __name__ == "__main__":
    if not RAW.exists():
        print("downloading MITRE ATT&CK enterprise bundle (~40MB, one time)...")
        download()
    build()
    sys.exit(0)
