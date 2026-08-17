# Threat Intel Agent

![CI](https://github.com/mayankbaranwal0/threat-intel-agent/actions/workflows/ci.yml/badge.svg)

A conversational threat-intelligence agent for SOC analysts. Ask questions in plain English;
the agent routes them to the right threat-intel tools (VirusTotal, AbuseIPDB, AlienVault OTX,
NVD, MITRE ATT&CK), correlates the results, and answers with evidence - every claim cites the
tool and field it came from, enforced by the output schema, with prompt-injection defense at
four layers.

Two standalone interfaces over one agent core: a rich terminal REPL and a two-pane web UI with
a live trace of every routing decision, tool call, and sanitizer action.

## What it does

| Query type | Example |
|---|---|
| IOC lookup | `Is 45.83.122[.]10 malicious?` (defanged input handled) |
| Actor & TTP | `What TTPs is APT29 known for?` |
| Exposure | `We run Confluence 7.13 - are we exposed?` |
| Pivoting | `Pivot from that IP to related domains.` |
| Multi-turn follow-ups | `and what's its ASN?` - pronouns resolve against session memory |

## Quickstart (zero threat-intel keys)

Runs fully offline against a curated synthetic dataset - only an LLM key is required.
Needs Python 3.11+.

```bash
git clone https://github.com/mayankbaranwal0/threat-intel-agent && cd threat-intel-agent
pip install -e .            # or: uv sync
cp .env.example .env        # add ANTHROPIC_API_KEY (or GEMINI_API_KEY), set RESOLVER_MODE=offline
tia                         # terminal UI
tia-web                     # web UI at http://127.0.0.1:8000
```

## Full setup (live threat intel)

Add free-tier keys to `.env` (signup links inside `.env.example`): `VT_API_KEY`,
`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, and optionally `NVD_API_KEY` (NVD works keyless).
MITRE ATT&CK data is local: `python scripts/build_attck_index.py` rebuilds the committed index.

Before a demo or offline session, pre-fetch live data for the demo query set (respects
VirusTotal's 4/min free-tier limit automatically):

```bash
python scripts/warm_cache.py
```

## Architecture

```
user text
  -> extractor      refang (hxxp, [.]) + regex entities: IP, hash, CVE, domain, ASN (no LLM)
  -> router         ONE structured LLM call: rewrite (resolves "it"/"that domain" against
                    session memory) + multi-label intent classification + confidence
                    |- injection_attempt / out_of_scope -> polite refusal, tools never run
                    |- confidence < 0.5 -> full-toolset fallback (degrade, never refuse)
  -> agent run      Pydantic AI - toolset = union of per-intent allowlists
                    each tool: resolver (cache -> live -> fixture) -> trim to needed fields
                    -> sanitizer -> untrusted-data envelope
  -> Answer         structured output; citations required by the schema
  every step emits a TraceEvent -> CLI trace lines / web SSE sidebar
```

## Security model

- **L1 - router gate**: out-of-scope means offensive *actions* (scan, exploit, exfiltrate,
  persona changes), never offensive *topics* - "what phishing lures does APT29 use" is a
  legitimate analyst question and is answered.
- **L2 - trust boundaries**: every tool result is wrapped in `<<<UNTRUSTED_TOOL_DATA>>>`
  markers; the system prompt treats that content as data, never as instructions.
- **L3 - sanitizer**: retrieved intel is scanned for injection patterns; matches are
  quarantined, flagged in the trace, and disclosed in the answer.
- **L4 - output contract**: the `Finding` schema requires `source_tool` and `source_field`,
  so uncited claims are structurally impossible; `analyst_note` is the labeled channel for
  model background knowledge.
- **Blast radius**: the toolset is read-only - no write, execute, or outbound-action tools
  exist, so a bypass of L1-L3 yields at worst a wrong answer, never an action.

Try it: ask `Any OTX pulses on evil-updates[.]com?` in offline mode - the synthetic dataset
plants a prompt injection inside that domain's pulse description, and you can watch the
sanitizer quarantine it live.

## Data resolver

Three layers behind every tool - cache, live API, curated fixture - with the mode explicit:

| `RESOLVER_MODE` | Behavior | Use |
|---|---|---|
| `prefer_cache` | warmed cache first, live on miss | demos, development |
| `prefer_live` | fresh cache within TTL, else live | production default |
| `offline` | cache then fixtures, never network | zero-key evaluation |

Every cache entry carries `fetched_at`; answers surface data age ("as of ...") and every
downgrade (rate limit, outage, stale cache) is recorded in the envelope's warnings and shown
in the trace. The warmed cache is intentionally **not committed** - API responses are not
redistributed, per provider terms; `warm_cache.py` rebuilds it from your own keys.

## Interfaces

**CLI** (`tia`): live trace, answer panels with citation columns, and slash commands -
`/memory`, `/trace on|off|last`, `/mode <m>`, `/fail <source>` (simulate a one-shot source
outage to see graceful degradation), `/session new`, `/help`, `/quit`.

**Web** (`tia-web`): chat pane + live agent-trace sidebar (SSE), with the same controls as
header buttons. Single static page, no build step.

Either interface alone covers every capability; they are thin renderers over the same core.

## Evals

```bash
pytest -m "not eval"   # offline suite: unit + pipeline tests, runs in CI (no keys)
pytest -m eval         # behavioral evals with a real LLM against fixtures (needs LLM key;
                       # never calls live threat-intel APIs)
```

The eval set: 5 golden queries (one per query type, including multi-turn), 2 injection tests
(direct instruction override; a poisoned pulse retrieved from a source), and 2 scope tests
(offensive *topics* must be answered; offensive *actions* must be refused).

## Cost controls

Per-source rate-limit buckets (VT paced to its 4/min free tier), tool responses trimmed to
~10 needed fields at the boundary (a raw VT report is 50-150 KB; the model sees < 4 KB),
per-intent tool allowlists so irrelevant sources are never called, and the cache avoids
repeat spend.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | - | at least one for live runs |
| `ROUTER_MODEL` | `anthropic:claude-sonnet-5` | `anthropic:claude-haiku-4-5` is a cheaper option |
| `AGENT_MODEL` | `anthropic:claude-sonnet-5` | `google:gemini-3.6-flash` tested as alternate |
| `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `NVD_API_KEY` | - | all optional |
| `RESOLVER_MODE` | `prefer_cache` | see resolver table |

Built on Pydantic AI's model-agnostic interface: Claude and Gemini are tested; other
supported providers (OpenAI, etc.) should work via `AGENT_MODEL` but are unvalidated.

## Data sources & attribution

VirusTotal, AbuseIPDB, and AlienVault OTX via their free-tier APIs (responses cached locally,
not redistributed). CVE data from the NVD API. Actor/technique data derived from
[MITRE ATT&CK](https://attack.mitre.org); ATT&CK is a registered trademark of The MITRE
Corporation, used under the ATT&CK terms of use. All fixture data in `data/fixtures/` is
synthetic and exists for reproducible, key-free evaluation; `evil-updates.com` and its
indicators are fictional.

## Design note

See [DESIGN-NOTE.md](DESIGN-NOTE.md) for the one-page write-up of intent routing and
injection defense.
