import json
from functools import lru_cache

from ..schemas import ToolEnvelope
from ..settings import Settings

SOURCE_LABEL = "static dataset (MITRE ATT&CK)"


@lru_cache(maxsize=4)
def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def actor_profile(settings: Settings, name: str) -> ToolEnvelope:
    index = _load(str(settings.attck_index))
    key = name.lower().strip()
    actor_key = key if key in index["actors"] else index["aliases"].get(key)
    if actor_key is None:
        data = {"found": False, "query": name}
    else:
        actor = index["actors"][actor_key]
        data = {
            "found": True,
            "name": actor["name"],
            "aliases": actor["aliases"][:10],
            "description": actor["description"],
            "techniques": actor["techniques"][:15],
            "technique_count_total": len(actor["techniques"]),
        }
    return ToolEnvelope(source="attck", fetched_at=SOURCE_LABEL, layer="fixture", data=data)


def technique_lookup(settings: Settings, technique_id: str) -> ToolEnvelope:
    index = _load(str(settings.attck_index))
    technique = index["techniques"].get(technique_id.upper().strip())
    if technique:
        data = {"found": True, **technique}
    else:
        data = {"found": False, "query": technique_id}
    return ToolEnvelope(source="attck", fetched_at=SOURCE_LABEL, layer="fixture", data=data)
