import pytest

from threat_intel_agent.extractor import extract, refang


@pytest.mark.parametrize(
    "fanged,clean",
    [
        ("45.83.122[.]10", "45.83.122.10"),
        ("hxxps://evil[.]com/x", "https://evil.com/x"),
        ("hXXp://a(.)b[.]co", "http://a.b.co"),
        ("no iocs here", "no iocs here"),
    ],
)
def test_refang(fanged, clean):
    assert refang(fanged) == clean


def test_ip_domain_cve_extraction():
    _, ents = extract("Is 45.83.122[.]10 related to evil-updates.com and CVE-2023-22515?")
    found = {(e.type, e.value) for e in ents}
    assert ("ipv4", "45.83.122.10") in found
    assert ("domain", "evil-updates.com") in found
    assert ("cve", "CVE-2023-22515") in found


def test_hash_type_by_length():
    md5, sha1, sha256 = "a" * 32, "b" * 40, "c" * 64
    _, ents = extract(f"hashes: {md5} {sha1} {sha256}")
    assert {e.type for e in ents} == {"md5", "sha1", "sha256"}


def test_invalid_ip_rejected():
    _, ents = extract("version 999.999.999.999 is not an IP")
    assert not [e for e in ents if e.type == "ipv4"]


def test_domain_not_extracted_from_email_or_filename():
    _, ents = extract("mail admin@corp.com about report.docx")
    values = {e.value for e in ents if e.type == "domain"}
    assert "corp.com" not in values
    assert "report.docx" not in values


def test_domain_normalized_lowercase_no_trailing_dot():
    _, ents = extract("check EVIL-updates.COM.")
    domains = [e for e in ents if e.type == "domain"]
    assert domains and domains[0].value == "evil-updates.com"


def test_asn():
    _, ents = extract("hosted on AS20473")
    assert ("asn", "AS20473") in {(e.type, e.value) for e in ents}


def test_dedup():
    _, ents = extract("8.8.8.8 and again 8.8.8.8")
    assert len([e for e in ents if e.type == "ipv4"]) == 1


def test_refanged_text_returned():
    text, _ = extract("pivot from 45.83.122[.]10")
    assert "45.83.122.10" in text


def test_hash_case_normalized():
    _, ents = extract("ABCDEF0123456789ABCDEF0123456789")
    assert ents and ents[0].value == "abcdef0123456789abcdef0123456789"
