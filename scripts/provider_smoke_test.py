import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pydantic_ai import Agent

from threat_intel_agent.schemas import Answer, RouterOutput
from threat_intel_agent.settings import Settings, export_provider_keys

MODELS = ["anthropic:claude-sonnet-5", "google:gemini-3.6-flash"]

PROMPT = (
    "This is a schema compatibility test. Return any syntactically valid, plausible instance "
    "for this query: is 1.2.3.4 malicious?"
)


def has_key(model: str, settings: Settings) -> bool:
    if model.startswith("anthropic:"):
        return bool(settings.anthropic_api_key)
    if model.startswith("google:"):
        return bool(settings.gemini_api_key)
    return True


async def check(model: str) -> bool:
    ok = True
    for schema in (RouterOutput, Answer):
        try:
            agent = Agent(model, output_type=schema)
            result = await agent.run(PROMPT)
            assert isinstance(result.output, schema)
            print(f"  OK   {model} -> {schema.__name__}")
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  FAIL {model} -> {schema.__name__}: {type(e).__name__}: {e}")
    return ok


def main() -> int:
    settings = Settings()
    export_provider_keys(settings)
    models = sys.argv[1:] or MODELS
    results: list[bool] = []
    for model in models:
        print(f"\n== {model} ==")
        if not has_key(model, settings):
            print("  SKIP (no API key configured)")
            continue
        results.append(asyncio.run(check(model)))
    if not results:
        print("\nNo provider keys configured - nothing tested.")
        return 2
    print("\nAll providers OK." if all(results) else "\nFailures - see above.")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
