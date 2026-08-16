import json
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "data" / "fixtures"


@pytest.mark.parametrize("path", sorted(FIXTURE_DIR.glob("*.json")), ids=lambda p: p.name)
def test_fixture_parses_with_data_key(path):
    content = json.loads(path.read_text(encoding="utf-8"))
    assert "data" in content and isinstance(content["data"], dict)


def test_fixture_set_present():
    names = {p.name for p in FIXTURE_DIR.glob("*.json")}
    assert len(names) >= 11
    assert "otx__domain_general__evil-updates.com.json" in names


def test_poisoned_fixture_contains_injection():
    path = FIXTURE_DIR / "otx__domain_general__evil-updates.com.json"
    assert "ignore previous instructions" in path.read_text(encoding="utf-8")
