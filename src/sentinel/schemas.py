"""Frozen data contracts for the Sentinel RCA pipeline.

Every artifact the pipeline emits must follow these schemas so that any
downstream consumer (terminal tools now, the web dashboard later) can rely
on the exact same shapes.

Artifacts per scenario (written under rca_output/<scenario>/):

    normalized_events.jsonl   - one JSON object per line (common event schema)
    investigation_graph.json  - nodes + edges + attack chain (this module)
    threat_assessment.json    - threat level, score, justification
    hypotheses.json           - ranked candidate explanations
    correlation_prompt.json   - the LLM prompt (when LLM stage is enabled)
    llm_response.json         - validated LLM output (when LLM stage is enabled)
"""
from __future__ import annotations

THREAT_LEVELS = ("low", "medium", "high", "critical")

# Handoff entity types: event, host, user, IP, process, file, domain, URL, request ID
EVENT_NODE = "event"
ENTITY_KINDS = ("host", "user", "ip", "process", "file", "domain", "url", "request_id")

EDGE_KEYS = ("from", "to", "relation", "reason", "confidence", "event_ids", "origin")


def event_node_id(event_id: str) -> str:
    return f"event:{event_id}"


def entity_node_id(kind: str, value: str) -> str:
    return f"entity:{kind}:{value}"


def make_edge(source: str, target: str, relation: str, reason: str,
              confidence: float, event_ids: list[str], origin: str) -> dict:
    return {
        "from": source,
        "to": target,
        "relation": relation,
        "reason": reason,
        "confidence": round(min(1.0, max(0.0, float(confidence))), 2),
        "event_ids": list(event_ids),
        "origin": origin,  # "deterministic" or "llm"
    }


def make_event_node(event: dict) -> dict:
    return {
        "id": event_node_id(event["event_id"]),
        "node_type": EVENT_NODE,
        "label": event.get("summary", ""),
        "event_type": event.get("event_type"),
        "source": event.get("source"),
        "timestamp": event.get("timestamp"),
        "suspicious": bool(event.get("suspicious")),
    }


def make_entity_node(kind: str, value: str, first_seen: str | None = None) -> dict:
    node = {
        "id": entity_node_id(kind, value),
        "node_type": "entity",
        "entity_type": kind,
        "label": str(value),
    }
    if first_seen is not None:
        node["first_seen"] = first_seen
    return node


def empty_graph(scenario_id: str) -> dict:
    return {
        "scenario_id": scenario_id,
        "generator": "sentinel-hybrid",
        "nodes": [],
        "edges": [],
        "attack_chain": [],
        "summary": {"node_count": 0, "edge_count": 0},
    }


def validate_graph(graph: dict, known_event_ids: set[str]) -> tuple[list[dict], list[str]]:
    """Drop malformed edges and report problems. Never raises on content."""
    problems: list[str] = []
    nodes = graph.get("nodes", [])
    node_ids = {node.get("id") for node in nodes if node.get("id")}
    clean: list[dict] = []
    seen: set[tuple] = set()
    for edge in graph.get("edges", []):
        src, dst, rel = edge.get("from"), edge.get("to"), edge.get("relation")
        if not src or not dst or not rel:
            problems.append(f"dropped edge missing from/to/relation: {edge}")
            continue
        if src not in node_ids or dst not in node_ids:
            problems.append(f"dropped edge referencing unknown node: {src} -> {dst}")
            continue
        if (src, dst, rel) in seen:
            problems.append(f"dropped duplicate edge: {src} -> {dst} ({rel})")
            continue
        event_ids = [eid for eid in (edge.get("event_ids") or []) if isinstance(eid, str)]
        if any(eid not in known_event_ids for eid in event_ids):
            problems.append(f"dropped edge citing unknown event id: {edge.get('relation')}")
            continue
        seen.add((src, dst, rel))
        clean.append(make_edge(
            src, dst, rel,
            str(edge.get("reason") or "no reason given"),
            edge.get("confidence", 0.5),
            event_ids,
            edge.get("origin", "llm"),
        ))
    return clean, problems
