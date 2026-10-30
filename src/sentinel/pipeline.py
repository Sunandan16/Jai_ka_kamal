"""Pipeline orchestration: normalize -> correlate -> LLM -> assess -> artifacts.

Usage:
    sentinel <scenario-folder>            (defaults to sequences/7-6)
    python rca_engine.py <scenario-folder>

Flags:
    --quiet     minimal summary (threat line + chain only)
    --full      suspicious evidence table includes source_file:line
    --evaluate  compare the result with attacker ground truth (attackmate.json)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .correlation import build_graph
from .llm_client import TIERS, build_prompt, call_llm, config_from_env, merge_llm_output
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
    if not events:
        print("      WARNING: no defender-side telemetry found (only attacker files, or unsupported formats)")

    out = OUTPUT_ROOT / root.name
    out.mkdir(parents=True, exist_ok=True)
    (out / "normalized_events.jsonl").write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")

    print("[2/4] Building deterministic investigation graph ...")
    graph = build_graph(root.name, events)

    threat = assess(events, graph)
    llm_cfgs = config_from_env() if use_llm else None
    tier_prompts = [(tier["name"], build_prompt(root.name, events, graph, tier)) for tier in TIERS]
    # save the full-tier prompt for transparency; smaller tiers are used only on demand
    (out / "correlation_prompt.json").write_text(json.dumps(tier_prompts[0][1], indent=2, ensure_ascii=False), encoding="utf-8")

    if llm_cfgs and events:
        chain_desc = " -> ".join(f"{c['model']} (…{c['api_key'][-4:]})" for c in llm_cfgs)
        print(f"[3/4] Correlating with LLM ({chain_desc}) ...")
        response, llm_model, llm_tier, llm_key = call_llm(tier_prompts, llm_cfgs)
        if response:
            (out / "llm_response.json").write_text(json.dumps(response, indent=2, ensure_ascii=False), encoding="utf-8")
            overrides = merge_llm_output(response, graph, {e["event_id"] for e in events})
            for key, value in overrides.items():
                threat[key] = value
            threat["generator"] = "hybrid(deterministic+llm)"
            threat["llm_model"] = llm_model
            threat["llm_tier"] = llm_tier
            threat["llm_key"] = llm_key
            graph["generator"] = "sentinel-hybrid"
            graph["summary"]["llm_model"] = llm_model
            graph["summary"]["llm_tier"] = llm_tier
            graph["summary"]["llm_key"] = llm_key
            print(f"      added {graph['summary'].get('llm_edges_added', 0)} validated LLM edges (via {llm_model} · tier {llm_tier})")
        else:
            print("      every configured key and tier failed; keeping deterministic graph")
    else:
        if events:
            print("[3/4] No SENTINEL_LLM_API_KEY set; skipping LLM stage (deterministic only)")
        else:
            print("[3/4] Skipping LLM stage (no events to correlate)")

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
    return {"events": events, "graph": graph, "threat": threat, "hypotheses": hypotheses}


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


def print_summary(result: dict, mode: str = "normal") -> None:
    """Rich terminal summary. mode: 'normal' | 'quiet' | 'full'."""
    events, graph = result["events"], result["graph"]
    threat, hypotheses = result["threat"], result["hypotheses"]
    scenario = graph["scenario_id"]
    model = threat.get("llm_model")
    tier = threat.get("llm_tier")
    key_suffix = threat.get("llm_key")
    print()
    print("=" * 66)
    print(f"  Scenario : {scenario}")
    print(f"  Pipeline : {threat.get('generator', 'deterministic')}"
          + (f" · {model} · tier {tier} · key …{key_suffix}" if model else ""))
    print(f"  Threat   : {threat['threat_level'].upper()}  (score {threat['score']})")
    print(f"  Events   : {len(events)} ({sum(1 for e in events if e.get('suspicious'))} suspicious) · "
          f"{graph['summary']['node_count']} nodes · {graph['summary']['edge_count']} edges")
    print(f"  Summary  : {threat['summary']}")
    print(f"  Entry    : {threat['entry_point']}")
    print("=" * 66)

    if mode == "quiet":
        print("  Chain:")
        for line in chain_to_ascii(graph).splitlines():
            print(f"    {line}")
        return

    mitre = [m for m in (threat.get("mitre_techniques") or []) if isinstance(m, dict) and m.get("id")]
    if mitre:
        print()
        print("  MITRE ATT&CK")
        for item in mitre:
            row = f"    {item['id']}"
            name = item.get("name") or ""
            if name:
                row += f"  {name}"
            if item.get("confidence") is not None:
                row += f"  ({float(item['confidence']):.2f})"
            print(row)

    print()
    print("  Ranked Hypotheses")
    for i, h in enumerate(hypotheses[:5], 1):
        sources = len(set(h.get("supporting_sources", [])))
        print(f"    #{i} {h['name'][:44]:<44} {h['confidence']:.2f}  ({sources} source{'s' if sources != 1 else ''})")

    suspicious = [e for e in events if e.get("suspicious")]
    limit = len(suspicious) if mode == "full" else min(12, len(suspicious))
    note = f", showing {limit}" if len(suspicious) > limit else ""
    print()
    print(f"  Suspicious Evidence ({len(suspicious)} events{note})")
    for e in suspicious[:limit]:
        ts = e["timestamp"][11:19] if "T" in e["timestamp"] else str(e["timestamp"])[:19]
        summary = " ".join(e["summary"].split())
        if len(summary) > 70:
            summary = summary[:67] + "..."
        row = f"    {ts}  {e['event_type']:<16}  {summary}"
        if mode == "full":
            row += f"   [{e.get('source_file')}:{e.get('source_line')}]"
        print(row)

    print()
    print("  Attack Chain")
    for line in chain_to_ascii(graph).splitlines():
        print(f"    {line}")

    print()
    print("  Artifacts:")
    out = OUTPUT_ROOT / scenario
    for name in ("normalized_events.jsonl", "investigation_graph.json", "threat_assessment.json",
                 "hypotheses.json", "correlation_prompt.json", "llm_response.json",
                 "evaluation.json", "rca_report.md"):
        path = out / name
        if path.exists():
            print(f"    {path}")


def cli(argv=None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    flags = {"quiet": False, "full": False, "evaluate": False}
    positionals = []
    for arg in args:
        if arg == "--quiet":
            flags["quiet"] = True
        elif arg == "--full":
            flags["full"] = True
        elif arg == "--evaluate":
            flags["evaluate"] = True
        elif arg.startswith("-"):
            raise SystemExit(f"Unknown flag: {arg}. Available: --quiet, --full, --evaluate")
        else:
            positionals.append(arg)
    root = Path(positionals[0]) if positionals else Path(DEFAULT_SCENARIO)

    result = run(root)
    events, graph = result["events"], result["graph"]
    assert not any("attacker" in e["source"] for e in events), "attacker labels must be excluded"
    if not events:
        print("NOTE: scenario produced 0 defender-visible events — nothing to correlate")
    assert all(edge["from"] in {n["id"] for n in graph["nodes"]} and edge["to"] in {n["id"] for n in graph["nodes"]}
               for edge in graph["edges"]), "every edge must reference existing nodes"

    mode = "quiet" if flags["quiet"] else "full" if flags["full"] else "normal"
    print_summary(result, mode)
    if flags["evaluate"]:
        from .evaluate import evaluate
        evaluate(root, result)
