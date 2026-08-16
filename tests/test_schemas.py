import pytest
from pydantic import ValidationError

from threat_intel_agent.schemas import (
    Answer,
    Entity,
    Finding,
    RouterOutput,
    ToolEnvelope,
    TraceEvent,
    utcnow_iso,
)


def test_entity_roundtrip():
    e = Entity(value="45.83.122.10", type="ipv4")
    assert Entity.model_validate(e.model_dump()) == e
    assert e.origin == "regex"


def test_router_output_roundtrip():
    r = RouterOutput(
        rewritten_query="What is the ASN of 45.83.122.10?",
        intents=["ioc_lookup"],
        entities=[Entity(value="apt29", type="actor", origin="llm")],
        confidence=0.97,
    )
    assert RouterOutput.model_validate(r.model_dump()) == r
    assert r.refusal_reason is None


def test_tool_envelope_roundtrip():
    env = ToolEnvelope(
        source="virustotal",
        fetched_at=utcnow_iso(),
        layer="cache",
        data={"reputation": -42},
        warnings=["serving stale cache"],
    )
    assert ToolEnvelope.model_validate(env.model_dump()) == env


def test_finding_requires_sources():
    with pytest.raises(ValidationError):
        Finding(claim="it is malicious", confidence="high")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Finding(claim="x", source_tool="virustotal", confidence="high")  # type: ignore[call-arg]


def test_finding_confidence_literal():
    with pytest.raises(ValidationError):
        Finding(claim="x", source_tool="vt", source_field="stats", confidence="certain")  # type: ignore[arg-type]


def test_answer_roundtrip():
    a = Answer(
        findings=[
            Finding(
                claim="34/94 engines flag it malicious",
                source_tool="virustotal",
                source_field="last_analysis_stats",
                confidence="high",
            )
        ],
        analyst_note="Hosting ASN is common for disposable infra.",
        injection_flags=[],
    )
    assert Answer.model_validate(a.model_dump()) == a


def test_trace_event_defaults():
    t = TraceEvent(step="tool", detail="virustotal.ip_report(45.83.122.10)")
    assert t.flags == [] and t.layer is None


def test_utcnow_iso_format():
    s = utcnow_iso()
    assert len(s) == 20 and s.endswith("Z") and s[4] == "-" and s[10] == "T"
