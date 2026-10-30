"""Pipeline orchestration: normalize -> correlate -> LLM -> assess -> artifacts.

Usage:
    sentinel <scenario-folder>          (defaults to sequences/7-6)
    python rca_engine.py <scenario-folder>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .correlation import build_graph
from .llm_client import build_prompt, call_llm, config_from_env, merge_llm_output
from .normalizer import load_events
from .threat import assess, rank_hypotheses

DEFAULT_SCENARIO = "Data/manifestations_filtered/sequences/7-6"
OUTPUT_ROOT = Path("rca_output")


def chain_to_ascii(graph: dict) -> str:
    """Human-friendly '---' chain for the terminal (same aesthetic as the site)."""
    labels = {n["id"]: (n.get("label") or n["id"]) for n in graph.get("nodes", [])}

    def name(node_id):
        label = labels.get(node_id, node_id)
        if node_id.startswith("event:"):
            return f"[{label[:48]}]"
        return label.split(":", 2)[-1] if label.startswith("entity:") else label

    rows = []
    for step in graph.get("attack_chain", []):
        rows.append(f"{name(step['from'])} ---{step['relation']}---> {name(step['to'])}")
    return "\n".join(rows) if rows else "(no chain derived)"


def run(root: Path, use_llm: bool = True) -> dict:
    if not root.is_dir():
        raise SystemExit(f"Scenario folder not found: {root}")

    print(f"[1/4] Normalizing defender telemetry in {root} ...")
    events = load_events(root)
    print(f"      {len(events)} events ({sum(1 for e in events if e.get('suspicious'))} suspicious)")

    out = OUTPUT_ROOT / root.name
    out.mkdir(parents=True, exist_ok=True)
    (out / "normalized_events.jsonl").write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")

    print("[2/4] Building deterministic investigation graph ...")
    graph = build_graph(root.name, events)

    threat = assess(events, graph)
    llm_cfgs = config_from_env() if use_llm else None
    prompt = build_prompt(root.name, events, graph)
    (out / "correlation_prompt.json").write_text(json.dumps(prompt, indent=2, ensure_ascii=False), encoding="utf-8")

    if llm_cfgs:
        chain_desc = " -> ".join(c["model"] for c in llm_cfgs)
        print(f"[3/4] Correlating with LLM ({chain_desc}) ...")
        response, llm_model = call_llm(prompt, llm_cfgs)
        if response:
            (out / "llm_response.json").write_text(json.dumps(response, indent=2, ensure_ascii=False), encoding="utf-8")
            overrides = merge_llm_output(response, graph, {e["event_id"] for e in events})
            for key, value in overrides.items():
                threat[key] = value
            threat["generator"] = "hybrid(deterministic+llm)"
            threat["llm_model"] = llm_model
            graph["generator"] = "sentinel-hybrid"
            graph["summary"]["llm_model"] = llm_model
            print(f"      added {graph['summary'].get('llm_edges_added', 0)} validated LLM edges (via {llm_model})")
        else:
            print("      all configured LLM models failed or unavailable; keeping deterministic graph")
    else:
        print("[3/4] No SENTINEL_LLM_API_KEY set; skipping LLM stage (deterministic only)")

    print("[4/4] Writing artifacts ...")
    (out / "investigation_graph.json").write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "threat_assessment.json").write_text(json.dumps(threat, indent=2, ensure_ascii=False), encoding="utf-8")

    hypotheses = rank_hypotheses(events, graph)
    (out / "hypotheses.json").write_text(json.dumps(
        {"scenario_id": root.name, "generator": threat["generator"],
         "ranked_hypotheses": hypotheses,
         "likely_root_cause_event_id": hypotheses[0]["supporting_event_ids"][0] if hypotheses[0]["supporting_event_ids"] else None},
        indent=2, ensure_ascii=False), encoding="utf-8")

    _write_report(out, root.name, events, graph, threat, hypotheses)

    # terminal summary
    print()
    print(f"Scenario : {root.name}")
    print(f"Threat   : {threat['threat_level'].upper()} (score {threat['score']})")
    print(f"Summary  : {threat['summary']}")
    print(f"Entry    : {threat['entry_point']}")
    print(f"Graph    : {graph['summary']['node_count']} nodes, {graph['summary']['edge_count']} edges")
    print("Chain:")
    print(chain_to_ascii(graph) or "(none)")
    print()
    print("Artifacts:")
    for name in ("normalized_events.jsonl", "investigation_graph.json", "threat_assessment.json",
                 "hypotheses.json", "correlation_prompt.json", "rca_report.md"):
        path = out / name
        if path.exists():
            print(f"  {path}")
    return {"events": events, "graph": graph, "threat": threat}


def _write_report(out: Path, name: str, events, graph, threat, hypotheses) -> None:
    timeline = "\n".join(f"- `{e['timestamp']}` — **{e['event_type']}** — {e['summary']}"
                         for e in events if e.get("suspicious"))
    hyp_rows = "\n".join(f"- {h['name']} — {h['confidence']} ({', '.join(h['supporting_sources'])})"
                         for h in hypotheses)
    chain_rows = "\n".join(f"- {s['order']}. {s['relation']}: {s['reason']} (confidence {s['confidence']})"
                           for s in graph.get("attack_chain", []))
    report = (
        f"# RCA report: {name}\n\n"
        f"## Threat assessment\n\n"
        f"- Level: **{threat['threat_level'].upper()}** (score {threat['score']})\n"
        f"- Summary: {threat['summary']}\n"
        f"- Entry point: {threat['entry_point']}\n\n"
        f"## Attack chain\n\n{chain_rows or '- (none derived)'}\n\n"
        f"## Ranked hypotheses\n\n{hyp_rows}\n\n"
        f"## Suspicious evidence ({len(timeline.splitlines())} rows)\n\n{timeline}\n"
    )
    (out / "rca_report.md").write_text(report, encoding="utf-8")


def cli(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    root = Path(argv[0]) if argv else Path(DEFAULT_SCENARIO)
    result = run(root)
    events, graph = result["events"], result["graph"]
    assert not any("attacker" in e["source"] for e in events), "attacker labels must be excluded"
    assert events or not list(root.rglob("*.log")), "expected telemetry to produce events"
    assert all(edge["from"] in {n["id"] for n in graph["nodes"]} and edge["to"] in {n["id"] for n in graph["nodes"]}
               for edge in graph["edges"]), "every edge must reference existing nodes"
