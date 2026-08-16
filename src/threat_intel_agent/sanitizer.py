import re

QUARANTINE_MARKER = "[QUARANTINED: possible prompt injection removed]"

_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"ignore (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts)[^.\n]*",
        r"disregard (?:all |any )?(?:previous|prior|above|earlier|your)[^.\n]{0,60}",
        r"you are now\b[^.\n]{0,60}",
        r"act as\b[^.\n]{0,30}(?:admin|system|developer|dan)[^.\n]{0,30}",
        r"new (?:system )?instructions?:[^\n]*",
        r"(?:the |your )?system prompt[^.\n]{0,60}",
        r"</?(?:system|assistant|instructions?)>",
        r"do not (?:tell|inform|alert) the (?:user|analyst)[^.\n]*",
        r"report (?:this|it) as (?:clean|safe|benign)[^.\n]*",
        r"\bjailbreak\b",
        r"begin (?:new|system) (?:prompt|instructions)[^\n]*",
    ]
]


def sanitize(data: dict) -> tuple[dict, list[str]]:
    flags: list[str] = []

    def clean_string(value: str) -> str:
        for pattern in _PATTERNS:
            if pattern.search(value):
                value = pattern.sub(QUARANTINE_MARKER, value)
                flags.append(f"injection pattern '{pattern.pattern[:50]}' in retrieved data")
        return value

    def walk(node):
        if isinstance(node, str):
            return clean_string(node)
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(item) for item in node]
        return node

    return walk(data), flags
