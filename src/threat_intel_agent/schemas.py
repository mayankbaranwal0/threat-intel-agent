from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

# Schemas stay flat with Literal types: provider JSON Schema subsets differ for structured output.
EntityType = Literal["ipv4", "domain", "md5", "sha1", "sha256", "cve", "asn", "actor", "product"]
Intent = Literal["ioc_lookup", "actor_ttp", "exposure", "pivot", "out_of_scope", "injection_attempt"]
Layer = Literal["cache", "live", "fixture"]
Step = Literal[
    "extract", "memory", "rewrite", "route", "tool", "sanitize", "synthesize", "error", "refusal"
]


class Entity(BaseModel):
    value: str
    type: EntityType
    origin: Literal["regex", "llm", "memory"] = "regex"


class RouterOutput(BaseModel):
    rewritten_query: str = Field(
        description="Self-contained rewrite of the query with pronouns/references resolved"
    )
    intents: list[Intent]
    entities: list[Entity] = Field(
        default_factory=list,
        description="Fuzzy entities (actor/product names) not caught by regex",
    )
    confidence: float = Field(description="Routing confidence, 0..1")
    refusal_reason: str | None = None


class ToolEnvelope(BaseModel):
    source: str
    fetched_at: str  # ISO 8601 UTC, or a static-data label
    layer: Layer
    data: dict
    warnings: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    claim: str
    source_tool: str
    source_field: str
    confidence: Literal["low", "medium", "high"]


class Answer(BaseModel):
    findings: list[Finding]
    analyst_note: str | None = Field(
        default=None, description="Model background/context; NOT evidence"
    )
    injection_flags: list[str] = Field(default_factory=list)


class TraceEvent(BaseModel):
    step: Step
    detail: str
    source: str | None = None
    layer: Layer | None = None
    age: str | None = None
    flags: list[str] = Field(default_factory=list)


def utcnow_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
