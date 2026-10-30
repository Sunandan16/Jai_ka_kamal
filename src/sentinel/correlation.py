"""Deterministic correlation: normalized events -> investigation graph.

Implements the handoff's initial rule set plus entity-level edges so the
expected chain for 7-6 emerges mechanically:

    IP:192.42.1.174 --logged_in_as--> User:alice --configured--> Workflow
        --executed--> Process:curl --downloaded_then_executed--> File:rJZMoLeJ
        --connected_to--> IP:192.42.1.174:4444

Everything here is rule-based, explainable, and reproducible. The LLM stage
(optional) only *adds* edges on top of this skeleton.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .schemas import (
    empty_graph,
    entity_node_id,
    event_node_id,
    make_edge,
    make_entity_node,
    make_event_node,
)

UNKNOWN = {"--", "unknown", "none", "unset", "4294967295", ""}

# filename candidates from web/application command text
FILENAME_RE = re.compile(r"(?:-o\s+|-so\s+|\./)([A-Za-z0-9_.-]+)")


def time_of(item) -> datetime | None:
    try:
        return datetime.fromisoformat(item["timestamp"])
    except (KeyError, ValueError, TypeError):
        return None


def _clean(value):
    value = str(value).strip()
    return None if value.lower() in UNKNOWN else value


def event_entities(event) -> list[tuple[str, str]]:
    """(kind, value) pairs an event observes, in stable order, deduplicated."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind, value):
        value = _clean(value)
        if value is not None and (kind, value) not in seen:
            seen.add((kind, value))
            pairs.append((kind, value))

    add("host", event.get("host"))
    add("user", str(event.get("user", "")).lower())
    add("ip", event.get("src_ip"))
    add("ip", event.get("dst_ip"))
    add("process", event.get("process"))
    add("request_id", event.get("request_id"))
    add("domain", event.get("domain"))
    executable = event.get("executable")
    if executable and Path(str(executable)).name == event.get("process"):
        add("file", Path(str(executable)).name)
    url = event.get("url")
    if url:
        add("url", url)
        hostname = urlparse(str(url)).hostname
        if hostname:
            add("domain", hostname)
    return pairs


class GraphBuilder:
    def __init__(self, scenario_id: str, events: list[dict]):
        self.scenario_id = scenario_id
        self.events = events
        self.by_id = {e["event_id"]: e for e in events}
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_keys: set[tuple] = set()

    # ---- primitives ----------------------------------------------------
    def add_node(self, node: dict) -> None:
        self.nodes.setdefault(node["id"], node)

    def add_edge(self, source, target, relation, reason, confidence, event_ids, origin="deterministic") -> None:
        key = (source, target, relation)
        if key in self._edge_keys or source == target:
            return
        for endpoint in (source, target):
            if endpoint.startswith("entity:") and endpoint not in self.nodes:
                _, kind, value = endpoint.split(":", 2)
                self.nodes[endpoint] = make_entity_node(kind, value)
        self._edge_keys.add(key)
        self.edges.append(make_edge(source, target, relation, reason, confidence, list(event_ids), origin))

    def event_node(self, event_id: str) -> str:
        return event_node_id(event_id)

    def entity_node(self, kind: str, value: str) -> str:
        return entity_node_id(kind, value)

    # ---- stage A: nodes + observed edges --------------------------------
    def extract_entities(self) -> None:
        for event in self.events:
            self.add_node(make_event_node(event))
            for kind, value in event_entities(event):
                node_id = self.entity_node(kind, value)
                self.add_node(make_entity_node(kind, value, first_seen=event.get("timestamp")))
                self.add_edge(
                    self.event_node(event["event_id"]), node_id, f"observed_{kind}",
                    f"Event contains {kind} {value}.", 1.0, [event["event_id"]])

    # ---- stage B: the handoff rules -------------------------------------
    def rule_same_web_request(self, window: float = 120.0) -> None:
        groups: dict[str, list[dict]] = {}
        for e in self.events:
            rid = _clean(e.get("request_id"))
            if rid:
                groups.setdefault(rid, []).append(e)
        for group in groups.values():
            group.sort(key=lambda e: time_of(e) or datetime.max.replace(tzinfo=timezone.utc))
            for a, b in zip(group, group[1:]):
                ta, tb = time_of(a), time_of(b)
                if ta and tb and 0 <= (tb - ta).total_seconds() <= window:
                    self.add_edge(
                        self.event_node(a["event_id"]), self.event_node(b["event_id"]),
                        "same_web_request", "Both events share the same request ID.",
                        0.98, [a["event_id"], b["event_id"]])

    def rule_logged_in_then_acted(self, window: float = 120.0) -> None:
        auth = [e for e in self.events if e["event_type"] == "authentication" and e.get("outcome") == "success"]
        web = [e for e in self.events if e["event_type"] in {"web_activity", "web_access"}]
        for a in auth:
            ta = time_of(a)
            a_user, a_ip = str(a.get("user", "")).lower(), a.get("src_ip")
            if not ta or not a_user or a_user in UNKNOWN or not a_ip:
                continue
            self.add_edge(
                self.entity_node("ip", a_ip), self.entity_node("user", a_user),
                "logged_in_as", f"Successful authentication of {a_user} from {a_ip}.", 0.95, [a["event_id"]])
            for b in web:
                tb = time_of(b)
                if not tb:
                    continue
                if str(b.get("user", "")).lower() == a_user and b.get("src_ip") == a_ip and 0 <= (tb - ta).total_seconds() <= window:
                    self.add_edge(
                        self.event_node(a["event_id"]), self.event_node(b["event_id"]),
                        "logged_in_then_acted",
                        f"Authentication of {a_user} from {a_ip} precedes web activity by the same user and IP.",
                        0.90, [a["event_id"], b["event_id"]])
                    # entity hop: the workflow/URL the account reached
                    b_url = _clean(b.get("url"))
                    if b_url:
                        self.add_edge(
                            self.entity_node("user", a_user), self.entity_node("url", b_url),
                            "configured", f"User {a_user} configured or triggered {b_url}.", 0.85, [a["event_id"], b["event_id"]])
            # same host + window: the account then ran commands (SSH-style access)
            a_host = _clean(a.get("host"))
            if a_host:
                for p in (e for e in self.events if e["event_type"] == "process_activity" and e.get("suspicious")):
                    tp = time_of(p)
                    if not tp:
                        continue
                    if 0 <= (tp - ta).total_seconds() <= window and a_host in (p.get("source_file") or ""):
                        self.add_edge(
                            self.event_node(a["event_id"]), self.event_node(p["event_id"]),
                            "logged_in_then_acted",
                            f"Login as {a_user} on {a_host} precedes {p['process']} execution.",
                            0.85, [a["event_id"], p["event_id"]])
                        self.add_edge(
                            self.entity_node("user", a_user), self.entity_node("process", p["process"]),
                            "executed", f"{a_user} executed {p['process']} on {a_host}.", 0.85,
                            [a["event_id"], p["event_id"]])

    def rule_spawned_process(self, window: float = 60.0) -> None:
        procs = [e for e in self.events if e["event_type"] == "process_activity" and e.get("pid") and e.get("parent_pid")]
        by_pid = {}
        for e in procs:
            by_pid.setdefault((e.get("source_file"), e.get("pid")), []).append(e)
        for a in procs:
            for b in by_pid.get((a.get("source_file"), a.get("parent_pid")), []):
                ta, tb = time_of(a), time_of(b)
                if ta and tb and 0 <= (tb - ta).total_seconds() <= window:
                    self.add_edge(
                        self.event_node(a["event_id"]), self.event_node(b["event_id"]),
                        "spawned_process", f"PID {b['pid']} has parent PID {a['pid']} ({a['process']} -> {b['process']}).",
                        0.95, [a["event_id"], b["event_id"]])
                    self.add_edge(
                        self.entity_node("process", a["process"]), self.entity_node("process", b["process"]),
                        "spawned_process", f"{a['process']} spawned {b['process']}.", 0.95, [a["event_id"], b["event_id"]])

    def rule_downloaded_then_executed(self, window: float = 300.0) -> None:
        web = [e for e in self.events if e["event_type"] in {"web_activity", "web_access", "proxy_request"}]
        procs = [e for e in self.events if e["event_type"] == "process_activity" and e.get("process")]

        def rank(p, name, cmdline):
            """Prefer the true downloader (curl/wget) over shells or the binary itself."""
            if p["process"] in {"curl", "wget"} and any(
                    f"{flag}{sep}{name}" in cmdline for flag in ("-so", "-o") for sep in (" ", " ./", "./")):
                return 3
            if p["process"] == name:
                return 2
            if name in cmdline:
                return 1
            if Path(str(p.get("executable", ""))).name == name:
                return 0
            return -1

        for w in web:
            tw = time_of(w)
            if not tw:
                continue
            text = " ".join(str(x or "") for x in (w.get("summary"), w.get("raw_event"), w.get("url"), w.get("cmdline")))
            candidates = set(FILENAME_RE.findall(text))
            if "executable" in str(w.get("mime_type", "")).lower() and w.get("url"):
                candidates.add(Path(urlparse(w["url"]).path).name)
            for name in candidates:
                name = name.strip().strip('"').strip("'")
                if not name or name in {".", ".."} or len(name) < 2:
                    continue
                matched = []
                for p in procs:
                    tp = time_of(p)
                    if not tp:
                        continue
                    score = rank(p, name, str(p.get("cmdline", "")))
                    if score < 0 or not (0 <= (tp - tw).total_seconds() <= window):
                        continue
                    matched.append((score, p))
                if not matched:
                    continue
                matched.sort(key=lambda item: (-item[0], item[1]["timestamp"]))
                for score, p in matched:  # event-level evidence for every match
                    self.add_edge(
                        self.event_node(w["event_id"]), self.event_node(p["event_id"]),
                        "downloaded_then_executed",
                        f"File {name} appears in web/application evidence, then executes.", 0.90, [w["event_id"], p["event_id"]])
                best = matched[0][1]  # entity-level hops only for the best executor
                self.add_edge(
                    self.entity_node("process", best["process"]), self.entity_node("file", name),
                    "downloaded_then_executed", f"{best['process']} downloads and runs {name}.", 0.90,
                    [w["event_id"], best["event_id"]])
                w_url = _clean(w.get("url"))
                if w_url:
                    self.add_edge(
                        self.entity_node("url", w_url), self.entity_node("process", best["process"]),
                        "executed", f"Workflow/app at {w_url} executed {best['process']}.", 0.88,
                        [w["event_id"], best["event_id"]])

    def rule_connected_to(self, window: float = 120.0) -> None:
        by_ip: dict[str, list[dict]] = {}
        for e in self.events:
            for ip in {_clean(e.get("src_ip")), _clean(e.get("dst_ip"))}:
                if ip:
                    by_ip.setdefault(ip, []).append(e)
        for ip, group in by_ip.items():
            sources = {e["source"] for e in group}
            if len(sources) < 2:
                continue
            group.sort(key=lambda e: time_of(e) or datetime.max.replace(tzinfo=timezone.utc))
            for a, b in zip(group, group[1:]):
                if a["source"] == b["source"]:
                    continue
                ta, tb = time_of(a), time_of(b)
                if ta and tb and abs((tb - ta).total_seconds()) <= window:
                    self.add_edge(
                        self.event_node(a["event_id"]), self.event_node(b["event_id"]),
                        "connected_to", f"Shared IP {ip} across {a['source']} and {b['source']}.",
                        0.80, [a["event_id"], b["event_id"]])
            # proxy requests reveal which IP the fetched URL was served from
            for e in group:
                if e["event_type"] == "proxy_request" and _clean(e.get("dst_ip")) == ip and _clean(e.get("url")):
                    self.add_edge(
                        self.entity_node("url", _clean(e["url"])), self.entity_node("ip", ip),
                        "connected_to", f"Proxy fetched {e['url']} from {ip}.", 0.80, [e["event_id"]])
            # process -> external IP hops (C2 style), plus the payload file hop
            for e in group:
                if e["event_type"] == "process_activity" and e.get("process") and _clean(e.get("dst_ip")) == ip and e.get("dst_port"):
                    self.add_edge(
                        self.entity_node("process", e["process"]), self.entity_node("ip", ip),
                        "connected_to", f"Process {e['process']} connected to {ip}:{e['dst_port']}.",
                        0.85, [e["event_id"]])
                    file_id = self.entity_node("file", e["process"])
                    if file_id in self.nodes:
                        self.add_edge(
                            file_id, self.entity_node("ip", ip),
                            "connected_to", f"Payload {e['process']} connected to {ip}:{e['dst_port']}.",
                            0.85, [e["event_id"]])

    def rule_resolved_then_connected(self, window: float = 300.0) -> None:
        dns = [e for e in self.events if e["event_type"] == "dns_query" and _clean(e.get("domain"))]
        proxy = [e for e in self.events if e["event_type"] == "proxy_request" and e.get("url")]
        for d in dns:
            td = time_of(d)
            if not td:
                continue
            domain = _clean(d.get("domain"))
            for p in proxy:
                tp = time_of(p)
                if not tp:
                    continue
                if urlparse(p["url"]).hostname == domain and 0 <= (tp - td).total_seconds() <= window:
                    self.add_edge(
                        self.event_node(d["event_id"]), self.event_node(p["event_id"]),
                        "resolved_then_connected", f"DNS resolved {domain}, then the proxy fetched it.",
                        0.75, [d["event_id"], p["event_id"]])
                    if p.get("dst_ip"):
                        self.add_edge(
                            self.entity_node("domain", domain), self.entity_node("ip", p["dst_ip"]),
                            "resolved_then_connected", f"{domain} resolved and was contacted at {p['dst_ip']}.",
                            0.75, [d["event_id"], p["event_id"]])

    def rule_created_persistence(self, window: float = 300.0) -> None:
        precursors = [e for e in self.events
                      if (e["event_type"] == "authentication" and e.get("outcome") == "success")
                      or (e["event_type"] == "process_activity" and e.get("suspicious"))]
        persistence = [e for e in self.events if e["event_type"] == "persistence_change"]
        for a in precursors:
            ta = time_of(a)
            if not ta:
                continue
            for b in persistence:
                tb = time_of(b)
                if not tb or tb <= ta:
                    continue
                if (tb - ta).total_seconds() > window:
                    continue
                if a.get("host") and b.get("host") and a["host"] != b["host"]:
                    continue
                self.add_edge(
                    self.event_node(a["event_id"]), self.event_node(b["event_id"]),
                    "created_persistence", "Suspicious access precedes a persistence change.",
                    0.80, [a["event_id"], b["event_id"]])
                a_user = _clean(str(a.get("user", "")).lower())
                if a_user and b.get("host"):
                    self.add_edge(
                        self.entity_node("user", a_user), self.entity_node("host", b["host"]),
                        "created_persistence", f"{a_user} created persistence on {b['host']}.",
                        0.80, [a["event_id"], b["event_id"]])

    # ---- stage C: assembly ----------------------------------------------
    def build(self) -> dict:
        graph = empty_graph(self.scenario_id)
        self.extract_entities()
        for rule in (self.rule_same_web_request, self.rule_logged_in_then_acted, self.rule_spawned_process,
                     self.rule_downloaded_then_executed, self.rule_connected_to,
                     self.rule_resolved_then_connected, self.rule_created_persistence):
            rule()
        graph["nodes"] = list(self.nodes.values())
        graph["edges"] = self.edges
        graph["attack_chain"] = self.derive_chain()
        graph["summary"] = {"node_count": len(self.nodes), "edge_count": len(self.edges)}
        return graph

    # ---- attack chain: walk entity edges from the entry point -----------
    def derive_chain(self, max_steps: int = 12) -> list[dict]:
        outgoing: dict[str, list[dict]] = {}
        for edge in self.edges:
            outgoing.setdefault(edge["from"], []).append(edge)
        for edges in outgoing.values():
            edges.sort(key=lambda e: (-e["confidence"], e["relation"]))

        # entry candidates: earliest successful external authentication, else the
        # earliest suspicious event's url/process/ip entity, else the event itself
        auth = sorted(
            (e for e in self.events if e["event_type"] == "authentication" and e.get("outcome") == "success" and e.get("src_ip")),
            key=lambda e: time_of(e) or datetime.max.replace(tzinfo=timezone.utc))
        start = None
        if auth:
            a = auth[0]
            start = self.entity_node("ip", a["src_ip"])
        if start is None or start not in self.nodes:
            start = None
            for candidate in sorted((e for e in self.events if e.get("suspicious")),
                                    key=lambda e: time_of(e) or datetime.max.replace(tzinfo=timezone.utc)):
                for kind in ("url", "process", "ip"):
                    value = _clean(candidate.get("url") if kind == "url"
                                   else candidate.get("process") if kind == "process"
                                   else candidate.get("src_ip"))
                    if value and self.entity_node(kind, value) in self.nodes:
                        start = self.entity_node(kind, value)
                        break
                if start:
                    break
        if start is None:
            suspicious = [e for e in self.events if e.get("suspicious")]
            if suspicious:
                start = self.event_node(sorted(suspicious, key=lambda e: time_of(e) or datetime.max.replace(tzinfo=timezone.utc))[0]["event_id"])

        chain: list[dict] = []
        current, order, used = start, 1, set()
        while current and order <= max_steps:
            candidates = [e for e in outgoing.get(current, []) if (e["from"], e["to"], e["relation"]) not in used]
            if not candidates:
                break
            edge = candidates[0]
            used.add((edge["from"], edge["to"], edge["relation"]))
            chain.append({"order": order, "from": edge["from"], "to": edge["to"],
                          "relation": edge["relation"], "reason": edge["reason"],
                          "confidence": edge["confidence"], "event_ids": edge["event_ids"]})
            current, order = edge["to"], order + 1
        if not chain:
            chain = self._event_chain_fallback(max_steps)
        if not chain:
            chain = self._sequence_fallback(max_steps)
        return chain

    def _sequence_fallback(self, max_steps: int = 8) -> list[dict]:
        """Last resort: suspicious events in chronological order."""
        suspicious = sorted((e for e in self.events if e.get("suspicious")),
                            key=lambda e: time_of(e) or datetime.max.replace(tzinfo=timezone.utc))
        chain = []
        for a, b in zip(suspicious, suspicious[1:max_steps + 1]):
            chain.append({"order": len(chain) + 1, "from": self.event_node(a["event_id"]),
                          "to": self.event_node(b["event_id"]), "relation": "followed_by",
                          "reason": "Suspicious events in chronological order.",
                          "confidence": 0.5, "event_ids": [a["event_id"], b["event_id"]]})
        return chain

    def _event_chain_fallback(self, max_steps: int = 8) -> list[dict]:
        """If no entity chain exists, walk event-level edges in time order."""
        event_edges = [e for e in self.edges if e["from"].startswith("event:") and e["to"].startswith("event:")
                       and e["relation"] not in {"observed_host", "observed_user", "observed_ip", "observed_process",
                                                 "observed_file", "observed_domain", "observed_url", "observed_request_id"}]
        suspicious = sorted((e for e in self.events if e.get("suspicious")),
                            key=lambda e: time_of(e) or datetime.max.replace(tzinfo=timezone.utc))
        if not suspicious:
            return []
        by_from: dict[str, list[dict]] = {}
        for edge in event_edges:
            by_from.setdefault(edge["from"], []).append(edge)
        for edges in by_from.values():
            edges.sort(key=lambda e: (time_of(self.by_id.get(e["event_ids"][0], {})) or datetime.max, -e["confidence"]))
        chain, current, used = [], self.event_node(suspicious[0]["event_id"]), set()
        for order in range(1, max_steps + 1):
            candidates = [e for e in by_from.get(current, []) if (e["from"], e["to"], e["relation"]) not in used]
            if not candidates:
                break
            edge = candidates[0]
            used.add((edge["from"], edge["to"], edge["relation"]))
            chain.append({"order": order, "from": edge["from"], "to": edge["to"],
                          "relation": edge["relation"], "reason": edge["reason"],
                          "confidence": edge["confidence"], "event_ids": edge["event_ids"]})
            current = edge["to"]
        return chain


def build_graph(scenario_id: str, events: list[dict]) -> dict:
    return GraphBuilder(scenario_id, events).build()
