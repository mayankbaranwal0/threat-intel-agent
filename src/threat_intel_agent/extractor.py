import re

from .schemas import Entity

_REFANGS = [
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
]

_IPV4 = re.compile(
    r"(?<![\d.])"
    r"((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})"
    r"(?![\d.])"
)
_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_ASN = re.compile(r"\bAS\d{1,10}\b")
_DOMAIN = re.compile(r"(?<![\w@.-])((?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,24})\b\.?")

_FILE_EXTENSIONS = {
    "docx", "xlsx", "pptx", "doc", "xls", "ppt", "pdf", "txt", "md", "csv", "json",
    "html", "php", "exe", "dll", "zip", "rar", "py", "js", "sh", "bat", "log",
}
_HASH_TYPE = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(text: str) -> str:
    for pattern, replacement in _REFANGS:
        text = pattern.sub(replacement, text)
    return text


def extract(text: str) -> tuple[str, list[Entity]]:
    text = refang(text)
    seen: set[tuple[str, str]] = set()
    entities: list[Entity] = []

    def add(value: str, entity_type: str) -> None:
        key = (entity_type, value)
        if key not in seen:
            seen.add(key)
            entities.append(Entity(value=value, type=entity_type, origin="regex"))

    for m in _IPV4.finditer(text):
        add(m.group(1), "ipv4")
    for m in _HASH.finditer(text):
        value = m.group(0).lower()
        add(value, _HASH_TYPE[len(value)])
    for m in _CVE.finditer(text):
        add(m.group(0).upper(), "cve")
    for m in _ASN.finditer(text):
        add(m.group(0), "asn")

    ip_values = {e.value for e in entities if e.type == "ipv4"}
    for m in _DOMAIN.finditer(text):
        value = m.group(1).lower().rstrip(".")
        if value in ip_values:
            continue
        if value.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        add(value, "domain")

    return text, entities
