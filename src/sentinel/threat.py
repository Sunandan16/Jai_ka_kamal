"""Deterministic threat assessment and hypothesis ranking.

The LLM stage may override the threat level/score/summary; these values are
the explainable baseline used when no LLM key is configured or the call fails.
"""
from __future__ import annotations

from datetime import datetime

from .schemas import THREAT_LEVELS


def _level(score: float) -> str:
    if score < 0.35:
        return THREAT_LEVELS[0]
    if score < 0.55:
        return THREAT_LEVELS[1]
    if score < 0.75:
        return THREAT_LEVELS[2]
    return THREAT_LEVELS[3]


def assess(events: list[dict], graph: dict) -> dict:
    suspicious = [e for e in events if e.get("suspicious")]
    auth = any(e["event_type"] == "authentication" and e.get("outcome") == "success" for e in events)
    proc = any(e["event_type"] == "process_activity" for e in suspicious)
    network = any(e["event_type"] == "network_alert" for e in suspicious)
    persistence = any(e["event_type"] == "persistence_change" for e in suspicious)
    dns_burst = any(e.get("behavior") == "dns_reconnaissance" for e in suspicious)
    elf = any("elf" in f"{e.get('summary', '')} {e.get('raw_event', '')}".lower()
              or "executable" in str(e.get("mime_type", "")).lower() for e in suspicious)
    mitre = sorted({m for e in events for m in (e.get("mitre_ids") or []) if m})

    score = (0.10
             + 0.10 * min(len({e["source"] for e in suspicious}), 4)
             + 0.15 * auth
             + 0.15 * proc
             + 0.15 * network
             + 0.15 * persistence
             + 0.10 * dns_burst
             + 0.10 * elf
             + 0.02 * min(len(mitre), 5))
    score = round(min(0.97, score), 2)

    # entry point: first chain step reason, else earliest suspicious event
    chain = graph.get("attack_chain", [])
    entry_point = chain[0]["reason"] if chain else (
        f"Earliest suspicious evidence: {suspicious[0]['summary']}" if suspicious else "No suspicious activity detected.")

    justification = [
        {"event_id": e["event_id"], "reason": e["summary"]}
        for e in sorted(suspicious, key=lambda x: x["timestamp"] if "T" in x["timestamp"] else "zzz")[:8]
    ]

    return {
        "scenario_id": events[0].get("scenario_id") if events else None,
        "generator": "deterministic",
        "threat_level": _level(score),
        "score": score,
        "summary": (
            f"{auth and 'Successful external authentication, ' or ''}"
            f"{proc and 'command execution, ' or ''}"
            f"{network and 'network alerts, ' or ''}"
            f"{persistence and 'persistence changes, ' or ''}"
            f"{dns_burst and 'DNS reconnaissance, ' or ''}"
            f"{elf and 'executable transfer, ' or ''}"
            f"{'detected across ' + str(len({e['source'] for e in suspicious})) + ' defender-visible sources.' if suspicious else 'no suspicious activity found.'}"
        ),
        "entry_point": entry_point,
        "mitre_techniques": [{"id": m, "name": "", "confidence": 0.8} for m in mitre],
        "justification": justification,
    }


def rank_hypotheses(events: list[dict], graph: dict) -> list[dict]:
    """Deterministic ranked hypotheses (baseline the LLM can refine)."""
    by_type: dict[str, list[dict]] = {}
    for e in events:
        by_type.setdefault(e["event_type"], []).append(e)
    edges = graph.get("edges", [])

    specs = [
        ("Valid account or remote-service access", ("authentication",),
         "A successful authentication or remote access event exists."),
        ("Web-application workflow or script execution", ("web_activity", "web_access"),
         "Application or web activity contains a suspicious workflow, upload, shell, or exploit action."),
        ("Payload download and execution", ("process_activity", "proxy_request", "network_alert"),
         "A process, proxy, or network event supports a payload transfer or execution chain."),
        ("Command-and-control connection", ("network_alert",),
         "Network security telemetry records suspicious external traffic."),
        ("DNS reconnaissance", ("dns_query",),
         "A DNS reconnaissance burst or repeated suspicious DNS activity exists."),
        ("Account or service persistence", ("persistence_change",),
         "The host records a new account, cron entry, SSH key, or service change."),
    ]
    results = []
    for name, types, reason in specs:
        supporting = [e for e in events if e["event_type"] in types and (e.get("suspicious") or e.get("behavior"))]
        if name == "Payload download and execution":
            linked = {eid for edge in edges if edge["relation"] == "downloaded_then_executed"
                      for eid in edge["event_ids"]}
            supporting = [e for e in events if e["event_id"] in linked]
        if not supporting:
            continue
        source_count = len({e["source"] for e in supporting})
        edge_count = sum(1 for edge in edges if any(eid in (edge["from"], edge["to"]) for eid in
                         {e["event_id"] for e in supporting}))
        confidence = round(min(0.95, 0.35 + 0.12 * source_count + 0.02 * min(edge_count, 10)), 2)
        results.append({
            "name": name, "confidence": confidence, "reason": reason,
            "supporting_event_ids": [e["event_id"] for e in supporting[:20]],
            "supporting_sources": sorted({e["source"] for e in supporting}),
        })
    results.sort(key=lambda item: item["confidence"], reverse=True)
    if not results:
        results = [{"name": "Insufficient correlated suspicious evidence", "confidence": 0.1,
                    "reason": "No rule matched suspicious evidence.", "supporting_event_ids": [],
                    "supporting_sources": []}]
    return results


def sort_time(event: dict) -> datetime:
    try:
        return datetime.fromisoformat(event["timestamp"])
    except (ValueError, TypeError):
        return datetime.max
