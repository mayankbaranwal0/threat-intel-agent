import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_intel_agent.agent import AgentSession


def main() -> None:
    query = " ".join(sys.argv[1:]) or "Is 45.83.122.10 malicious?"
    session = AgentSession()
    print(f"query: {query}\nmode:  {session.resolver.mode}\n")
    answer = asyncio.run(session.ask(query))

    for event in session.last_trace:
        line = f"  [{event.step}] {event.detail}"
        if event.layer:
            line += f"  ({event.layer}, {event.age})"
        print(line)
        for flag in event.flags:
            print(f"    ! {flag}")

    print()
    for finding in answer.findings:
        print(f"- {finding.claim}")
        print(f"    {finding.source_tool} . {finding.source_field}  [{finding.confidence}]")
    if answer.analyst_note:
        print(f"\nnote: {answer.analyst_note}")
    if answer.injection_flags:
        print(f"\nINJECTION FLAGS: {answer.injection_flags}")


if __name__ == "__main__":
    main()
