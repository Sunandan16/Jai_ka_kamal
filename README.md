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

Artifacts are written to `rca_output/<scenario>/`:

| File | Content |
|---|---|
| `normalized_events.jsonl` | all events in the common schema, each with a stable `event_id`, `source_file`, `source_line` |
| `investigation_graph.json` | nodes (events + entities), edges (`from/to/relation/reason/confidence/event_ids/origin`), `attack_chain` |
| `threat_assessment.json` | threat level (`low/medium/high/critical`), score, summary, entry point, MITRE techniques, justification |
| `hypotheses.json` | ranked candidate explanations |
| `correlation_prompt.json` | exactly what was sent to the LLM (transparency) |
| `llm_response.json` | validated LLM output (only when the LLM stage runs) |
| `rca_report.md` | human-readable report |

## LLM stage (optional)

Paste your provider and key into `.env` (it is gitignored, so the key stays
local). No key → deterministic mode only. With a key, the LLM adds edges,
refines the attack chain, and produces the threat level; all output is
validated against the event store (unknown IDs are dropped, scores clamped).

```ini
# .env
SENTINEL_LLM_PROVIDER=deepseek     # deepseek | nvidia | groq | openai | openrouter
SENTINEL_LLM_API_KEY=sk-...        # nvapi-... / sk-... / gsk_...
SENTINEL_LLM_MODEL=                # optional; empty = provider default
SENTINEL_LLM_BASE_URL=             # optional; empty = provider default
```

The same variables also work as normal environment variables (env wins over
`.env`). If the LLM call fails for any reason, the pipeline keeps the
deterministic graph and reports the failure.

## Deterministic correlation rules

`same_web_request`, `logged_in_then_acted`, `spawned_process`,
`downloaded_then_executed`, `connected_to`, `resolved_then_connected`,
`created_persistence` — plus entity-level hops (`logged_in_as`, `configured`,
`executed`) so a human-readable attack chain falls out of the graph.

## Frontend

`frontend/index.html` is a self-contained blue/white dashboard (logs table,
threat card, attack chain, hypotheses, graph export). It currently shows
embedded sample data; wiring it to `rca_output/<scenario>/` is the next step.

## Layout

```
rca_engine.py          compatibility wrapper (delegates to the package)
src/sentinel/          pipeline package
  normalizer.py        parsers + provenance + DNS burst detection
  correlation.py       deterministic rules + graph + chain derivation
  llm_client.py        provider-agnostic LLM call, prompt, validation
  threat.py            threat assessment + hypothesis ranking
  schemas.py           frozen JSON contracts
  pipeline.py          orchestration + CLI
Data/manifestations_filtered/   dataset (gitignored)
rca_output/                     generated artifacts (gitignored)
archive/                        previous prototypes (gitignored)
```
