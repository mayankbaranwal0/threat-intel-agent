import asyncio

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..agent import AgentSession
from ..schemas import Answer, TraceEvent
from ..settings import Settings

_LAYER_STYLE = {"cache": "blue", "live": "green", "fixture": "bright_black"}
_STEP_STYLE = {"sanitize": "yellow", "refusal": "red", "error": "red"}
_CONFIDENCE_STYLE = {"high": "bold green", "medium": "yellow", "low": "red"}

HELP = """\
/memory              show entities remembered this session
/trace on|off|last   toggle live trace, or reprint the last turn's trace
/mode <m>            set resolver mode: prefer_cache | prefer_live | offline
/fail <source>       simulate a failure on the next call to a source (e.g. /fail virustotal)
/session new         start a fresh session (clears memory)
/help                this help
/quit                exit"""


class Cli:
    def __init__(self) -> None:
        self.console = Console()
        self.trace_enabled = True
        self.settings = Settings()
        self.session = AgentSession(settings=self.settings, on_trace=self._on_trace)

    def _on_trace(self, event: TraceEvent) -> None:
        if self.trace_enabled:
            self._print_trace(event)

    def _print_trace(self, event: TraceEvent) -> None:
        style = _STEP_STYLE.get(event.step, "cyan")
        line = Text("  > ", style="dim")
        line.append(f"{event.step:<11}", style=style)
        line.append(event.detail, style="dim" if style == "cyan" else style)
        if event.layer:
            line.append("  [", style="dim")
            line.append(event.layer, style=_LAYER_STYLE.get(event.layer, "white"))
            if event.age:
                line.append(f" · {event.age}", style="dim")
            line.append("]", style="dim")
        self.console.print(line)
        for flag in event.flags:
            self.console.print(Text(f"      ! {flag}", style="yellow"))

    def _banner(self) -> None:
        s = self.settings
        sources = {
            "virustotal": s.vt_api_key,
            "abuseipdb": s.abuseipdb_api_key,
            "otx": s.otx_api_key,
            "nvd": "keyless ok",
        }
        source_bits = "  ".join(
            f"{name} [{'green' if key else 'bright_black'}]{'ok' if key else 'fixture'}[/]"
            for name, key in sources.items()
        )
        body = (
            f"model    [bold]{s.agent_model}[/]   router [bold]{s.router_model}[/]\n"
            f"resolver [bold]{self.session.resolver.mode}[/]\n"
            f"sources  {source_bits}  attck [green]local[/]\n"
            f"type your question in plain English, or /help for commands"
        )
        self.console.print(
            Panel(body, title="[bold cyan]THREAT INTEL AGENT[/]", border_style="cyan")
        )

    def _print_answer(self, answer: Answer) -> None:
        grid = Table.grid(padding=(0, 2))
        grid.add_column(ratio=3)
        grid.add_column(justify="right", ratio=1)
        for f in answer.findings:
            grid.add_row(
                Text(f"* {f.claim}"),
                Text(
                    f"{f.source_tool} . {f.source_field}\n[{f.confidence}]",
                    style="bright_black",
                ),
            )
        if answer.analyst_note:
            grid.add_row(Text(f"\nnote: {answer.analyst_note}", style="italic dim"), Text(""))

        confidences = [f.confidence for f in answer.findings]
        overall = (
            "high" if "high" in confidences
            else "medium" if "medium" in confidences
            else "low" if confidences
            else None
        )
        if answer.injection_flags:
            title = "[bold red]! INJECTION ATTEMPT FLAGGED[/]"
            border = "red"
        else:
            title = "answer"
            border = "cyan"
        subtitle = (
            f"confidence: [{_CONFIDENCE_STYLE[overall]}]{overall.upper()}[/]" if overall else None
        )
        self.console.print(Panel(grid, title=title, subtitle=subtitle, border_style=border))
        for flag in answer.injection_flags:
            self.console.print(Text(f"  ! {flag}", style="red"))

    def _command(self, line: str) -> bool:
        parts = line.split()
        cmd, args = parts[0], parts[1:]
        if cmd == "/quit":
            return False
        if cmd == "/help":
            self.console.print(Panel(HELP, border_style="cyan", title="commands"))
        elif cmd == "/memory":
            entities = self.session.memory.recent(20)
            if not entities:
                self.console.print("[dim]no entities remembered yet[/]")
            else:
                table = Table(title="session entity memory (newest first)")
                table.add_column("type", style="cyan")
                table.add_column("value")
                table.add_column("origin", style="bright_black")
                for e in entities:
                    table.add_row(e.type, e.value, e.origin)
                self.console.print(table)
        elif cmd == "/trace":
            arg = args[0] if args else "on"
            if arg == "last":
                for event in self.session.last_trace:
                    self._print_trace(event)
            elif arg in ("on", "off"):
                self.trace_enabled = arg == "on"
                self.console.print(f"[dim]trace {arg}[/]")
            else:
                self.console.print("[red]usage: /trace on|off|last[/]")
        elif cmd == "/mode":
            if args and args[0] in ("prefer_cache", "prefer_live", "offline"):
                self.session.resolver.mode = args[0]
                self.console.print(f"[dim]resolver mode -> {args[0]}[/]")
            else:
                self.console.print("[red]usage: /mode prefer_cache|prefer_live|offline[/]")
        elif cmd == "/fail":
            if args:
                self.session.resolver.arm_failure(args[0])
                self.console.print(
                    f"[yellow]armed: next {args[0]} call will simulate an HTTP 429[/]"
                )
            else:
                self.console.print("[red]usage: /fail <source>  e.g. /fail virustotal[/]")
        elif cmd == "/session":
            self.session = AgentSession(settings=self.settings, on_trace=self._on_trace)
            self.console.print("[dim]new session started (memory cleared)[/]")
        else:
            self.console.print(f"[red]unknown command {cmd}[/] - /help for commands")
        return True

    def run(self) -> None:
        self._banner()
        while True:
            try:
                line = self.console.input("\n[bold cyan]analyst >[/] ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not line:
                continue
            if line.startswith("/"):
                if not self._command(line):
                    break
                continue
            try:
                if self.trace_enabled:
                    answer = asyncio.run(self.session.ask(line))
                else:
                    with self.console.status("analyzing..."):
                        answer = asyncio.run(self.session.ask(line))
            except KeyboardInterrupt:
                self.console.print("[yellow]interrupted[/]")
                continue
            self._print_answer(answer)
        self.console.print("[dim]bye[/]")


def main() -> None:
    Cli().run()


if __name__ == "__main__":
    main()
