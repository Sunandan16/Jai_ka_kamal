# Sentinel — CAM-LDS Cybersecurity RCA Engine

Explainable, evidence-backed root cause analysis over defender-side telemetry.

**Hybrid pipeline:** deterministic normalization + correlation rules, with an
optional LLM stage that adds semantic correlations and a threat assessment.
Attacker-side files are never used as detection input — only as ground truth
for evaluation.

## Pipeline

```
raw logs ──► normalizer ──► normalized_events.jsonl
                │                │
                │                ▼
                │         correlation (7 deterministic rules)
                │                │
                │                ▼
                └──────►  LLM stage (optional) ──► validated merge
                                    │
                                    ▼
        investigation_graph.json + threat_assessment.json
        hypotheses.json + correlation_prompt.json + rca_report.md
```

## Usage

```bash
# run a scenario (defaults to Data/manifestations_filtered/sequences/7-6)
python rca_engine.py Data/manifestations_filtered/sequences/7-6
# or via the package (no install needed)
PYTHONPATH=src python -m sentinel <scenario-folder>
# or, once installed with uv/pip
sentinel <scenario-folder>
```

Flags:

| Flag | Effect |
|---|---|
| `--quiet` | minimal summary (threat line + attack chain only) |
| `--full` | suspicious-evidence table includes `source_file:source_line` |
| `--evaluate` | compare the result with attacker ground truth (`attacker/logs/attackmate.json`) and write `evaluation.json` — attacker files are read **only** in this mode |

Artifacts are written to `rca_output/<scenario>/`:

| File | Content |
|---|---|
| `normalized_events.jsonl` | all events in the common schema, each with a stable `event_id`, `source_file`, `source_line` |
| `investigation_graph.json` | nodes (events + entities), edges (`from/to/relation/reason/confidence/event_ids/origin`), `attack_chain` |
| `threat_assessment.json` | threat level (`low/medium/high/critical`), score, summary, entry point, MITRE techniques, justification |
| `hypotheses.json` | ranked candidate explanations |
| `correlation_prompt.json` | exactly what was sent to the LLM (transparency) |
| `llm_response.json` | validated LLM output (only when the LLM stage runs) |
| `evaluation.json` | ground-truth comparison (only with `--evaluate`) |
| `rca_report.md` | human-readable report |

## LLM stage (optional)

Paste your provider and key into `.env` (it is gitignored, so the key stays
local). No key → deterministic mode only. With a key, the LLM adds edges,
refines the attack chain, and produces the threat level; all output is
validated against the event store (unknown IDs are dropped, scores clamped).

```ini
# .env
SENTINEL_LLM_PROVIDER=groq        # deepseek | nvidia | groq | openai | openrouter
SENTINEL_LLM_API_KEY=gsk_...      # nvapi-... / sk-... / gsk_...
SENTINEL_LLM_MODEL=               # optional; empty = provider default
SENTINEL_LLM_BASE_URL=            # optional; empty = provider default

# Multi-model failover (optional): tried in order after the primary.
# On a rate limit (HTTP 429), auth error, outage, or invalid output,
# Sentinel switches to the next model instead of stopping.
SENTINEL_LLM_FAILOVER=nvidia:minimaxai/minimax-m3.1-flash,deepseek:deepseek-chat
SENTINEL_LLM_KEY_NVIDIA=nvapi-... # one key per failover provider
SENTINEL_LLM_KEY_DEEPSEEK=sk-...
```

NVIDIA default model: `minimaxai/minimax-m3.1-flash` (verified working with
JSON-mode responses; note that NVIDIA's reasoning models can consume their
whole output budget on `reasoning_content`, and several catalog entries
return 404 for developer keys). Any catalog model can be pinned with
`SENTINEL_LLM_MODEL=`.

The same variables also work as normal environment variables (env wins over
`.env`). If every configured model fails, the pipeline keeps the
deterministic graph and reports the failure. The winning model is recorded in
`threat_assessment.json` (`llm_model`) and `investigation_graph.json`
(`summary.llm_model`).

### Multi-key rotation

Any key value may be comma-separated — each key becomes its own attempt slot:

```ini
SENTINEL_LLM_API_KEY=gsk_key1,gsk_key2,gsk_key3
```

When one key is rate limited or out of token budget, Sentinel tries the next
key of the same provider before failing over to the next provider. Only the
last 4 characters of the winning key are ever recorded (`llm_key`).

### Adaptive prompt tiers

Every model is tried with three prompt sizes, biggest first:

| Tier | Events | Edges | Purpose |
|---|---|---|---|
| full | 100 | 200 | maximum context (NVIDIA, paid tiers) |
| medium | 25 | 50 | mid-sized free tiers |
| small | 15 | 30 | tight budgets (e.g. Groq free tier, 8k tokens/min counted as input + output) |

A provider whose budget cannot fit the full prompt (HTTP 413) automatically
retries with the next smaller tier, and `max_tokens` is shrunk to fit the
remaining budget — so the request adapts instead of failing. The winning
model, tier, and key suffix are shown in the terminal (`Pipeline : ...`)
and recorded in `threat_assessment.json` (`llm_model`, `llm_tier`, `llm_key`).

## Deterministic correlation rules

`same_web_request`, `logged_in_then_acted`, `spawned_process`,
`downloaded_then_executed`, `connected_to`, `resolved_then_connected`,
`created_persistence` — plus entity-level hops (`logged_in_as`, `configured`,
`executed`) so a human-readable attack chain falls out of the graph.

## Frontend

`frontend/index.html` is a self-contained blue/white dashboard (logs table,
threat card, attack chain, hypotheses, graph export). It currently shows
embedded sample data; wiring it to `rca_output/<scenario>/` is the next step.

## Roadmap

- **Batch mode** (planned): `sentinel batch Data/manifestations_filtered/sequences` —
  run every scenario, print a per-scenario summary table (events, threat level,
  chain length, top hypothesis) and an aggregate coverage report.
- **Frontend wiring** (next): fetch `rca_output/<scenario>/` artifacts into the
  existing blue/white dashboard (logs table, threat card, attack chain, graph).

## Layout

```
rca_engine.py          compatibility wrapper (delegates to the package)
src/sentinel/          pipeline package
  normalizer.py        parsers + provenance + DNS burst detection
  correlation.py       deterministic rules + graph + chain derivation
  llm_client.py        provider-agnostic LLM call, prompt, validation, failover
  threat.py            threat assessment + hypothesis ranking
  evaluate.py          ground-truth comparison (--evaluate only)
  schemas.py           frozen JSON contracts
  pipeline.py          orchestration + CLI
Data/manifestations_filtered/   dataset (gitignored)
rca_output/                     generated artifacts (gitignored)
archive/                        previous prototypes (gitignored)
```
