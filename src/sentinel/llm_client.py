"""Provider-agnostic LLM stage for the hybrid correlation pipeline.

The LLM receives the deterministic skeleton (suspicious events + baseline
edges) and is asked to return:

    - additional semantic edges (must cite real event_ids)
    - an ordered attack chain
    - a threat level with cited justification

Everything the model returns is validated: edges referencing unknown nodes or
event IDs are dropped, confidence values are clamped, threat levels are
restricted to the enum. On any failure the pipeline keeps the deterministic
output.

Configuration (environment variables, provider presets below):
    SENTINEL_LLM_PROVIDER   default "deepseek"  (deepseek|nvidia|groq|openai|openrouter)
    SENTINEL_LLM_API_KEY    the primary API key; if unset, the LLM stage is skipped
    SENTINEL_LLM_MODEL      optional model override
    SENTINEL_LLM_BASE_URL   optional base URL override
    SENTINEL_LLM_FAILOVER   optional fallback chain: comma-separated
                            "provider[:model]" entries tried in order after
                            the primary when a call fails (rate limit, auth
                            error, outage, or invalid output)
    SENTINEL_LLM_KEY_<PROVIDER>  API key for a failover provider, e.g.
                            SENTINEL_LLM_KEY_NVIDIA=nvapi-...

The pipeline never stops on a single model limit: every configured model is
tried in order, and only when all of them fail does the deterministic graph
stand alone.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from .schemas import THREAT_LEVELS, validate_graph

PROVIDERS = {
    "deepseek":   {"base_url": "https://api.deepseek.com/v1",              "model": "deepseek-chat"},
    "nvidia":     {"base_url": "https://integrate.api.nvidia.com/v1",      "model": "minimaxai/minimax-m3.1-flash"},
    "groq":       {"base_url": "https://api.groq.com/openai/v1",           "model": "openai/gpt-oss-120b"},
    "openai":     {"base_url": "https://api.openai.com/v1",                "model": "gpt-4o-mini"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1",             "model": "deepseek/deepseek-chat"},
}

MAX_EVENTS = 100
MAX_EDGES = 200


def load_dotenv(path: Path | None = None) -> Path | None:
    """Load KEY=VALUE pairs from a .env file (stdlib-only, no python-dotenv).

    Searches the given path, then the current directory, then the repo root.
    Existing environment variables always win.
    """
    here = Path(__file__).resolve()
    candidates = [path] if path else [Path.cwd() / ".env", here.parent.parent.parent / ".env"]
    loaded = None
    for candidate in candidates:
        if not candidate or not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and value:  # skip empty values so provider defaults apply
                os.environ.setdefault(key, value)
        loaded = candidate
    return loaded


load_dotenv()  # make .env values visible to config_from_env()


FAILOVER_ENV = "SENTINEL_LLM_FAILOVER"


def _failover_key_env(provider: str) -> str:
    """Env var name holding the key for a failover provider, e.g.
    SENTINEL_LLM_KEY_NVIDIA."""
    normalized = re.sub(r"[^A-Z0-9]", "", provider.upper())
    return f"SENTINEL_LLM_KEY_{normalized}"


def config_from_env() -> list[dict] | None:
    """Build the model failover chain from the environment.

    The primary provider is configured as before; SENTINEL_LLM_FAILOVER adds
    fallback `provider[:model]` entries, each keyed by SENTINEL_LLM_KEY_<PROVIDER>.
    Entries without a usable key are skipped and duplicates are collapsed.
    Returns the ordered list of configs, or None when nothing is configured.
    """
    chain: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(provider: str, model: str, base_url: str, api_key: str) -> None:
        provider = provider.strip().lower()
        preset = PROVIDERS.get(provider, PROVIDERS["deepseek"])
        model = (model or "").strip() or preset["model"]
        base_url = (base_url or "").strip() or preset["base_url"]
        base_url = base_url.rstrip("/")
        api_key = api_key.strip()
        if not api_key:
            return
        dedupe_key = (base_url, model, api_key)
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        chain.append({
            "provider": provider,
            "base_url": base_url,
            "model": model,
            "api_key": api_key,
        })

    add(
        os.environ.get("SENTINEL_LLM_PROVIDER", "deepseek"),
        os.environ.get("SENTINEL_LLM_MODEL", "") or "",
        os.environ.get("SENTINEL_LLM_BASE_URL", "") or "",
        os.environ.get("SENTINEL_LLM_API_KEY", "") or "",
    )

    for entry in (os.environ.get(FAILOVER_ENV, "") or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        provider, sep, model = entry.partition(":")
        key_env = _failover_key_env(provider)
        add(provider, model if sep else "", "", os.environ.get(key_env, "") or "")

    return chain or None


def build_prompt(scenario_id: str, events: list[dict], graph: dict) -> dict:
    """The instruction JSON shown to the LLM (and saved for transparency)."""
    suspicious = [e for e in events if e.get("suspicious")][:MAX_EVENTS]
    return {
        "task": (
            "You are a security analyst co-pilot. Given defender-side normalized log events "
            "and a deterministic skeleton graph, return additional correlations, an ordered "
            "attack chain, and a threat assessment."
        ),
        "scenario_id": scenario_id,
        "output_schema": {
            "edges": [{"from": "<node id>", "to": "<node id>", "relation": "<label>",
                       "reason": "<why, citing event ids>", "confidence": 0.0,
                       "event_ids": ["<event id>"]}],
            "attack_chain": [{"order": 1, "from": "<node id>", "to": "<node id>",
                              "relation": "<label>", "narration": "<sentence>",
                              "event_ids": ["<event id>"]}],
            "threat": {"threat_level": "low|medium|high|critical", "score": 0.0,
                       "summary": "<sentence>", "entry_point": "<sentence>",
                       "mitre_techniques": [{"id": "T1190", "name": "<name>", "confidence": 0.0}],
                       "justification": [{"event_id": "<event id>", "reason": "<why>"}]},
        },
        "constraints": [
            "Cite ONLY node ids and event ids that appear in the supplied events/edges.",
            "Never invent timestamps, IPs, usernames, or event ids.",
            "confidence must be a number between 0.0 and 1.0.",
            "threat_level must be one of: low, medium, high, critical.",
            "Answer with a single JSON object matching output_schema exactly.",
        ],
        "events": [{"event_id": e["event_id"], "timestamp": e["timestamp"], "event_type": e["event_type"],
                    "source": e["source"], "summary": e["summary"], "suspicious": e.get("suspicious"),
                    "src_ip": e.get("src_ip"), "dst_ip": e.get("dst_ip"), "user": e.get("user"),
                    "process": e.get("process"), "pid": e.get("pid"), "parent_pid": e.get("parent_pid"),
                    "request_id": e.get("request_id"), "domain": e.get("domain"), "url": e.get("url"),
                    "cmdline": e.get("cmdline"), "mitre_ids": e.get("mitre_ids"),
                    "source_file": e.get("source_file"), "source_line": e.get("source_line")}
                   for e in suspicious],
        "baseline_edges": graph.get("edges", [])[:MAX_EDGES],
        "baseline_chain": graph.get("attack_chain", []),
    }


def call_llm(prompt: dict, cfgs: list[dict], timeout: int = 360) -> tuple[dict | None, str | None]:
    """Try every configured model in order, failing over automatically.

    A rate limit (HTTP 429), auth failure, outage, network error, or
    unparseable response moves the call to the next model so the pipeline
    keeps working without stopping. Returns (parsed_response, model_name);
    the response is None only when every configured model failed.
    """
    messages = [
        {"role": "system", "content": "You return strictly valid JSON. No markdown, no commentary."},
        {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
    ]
    for index, cfg in enumerate(cfgs):
        parsed = _call_one(cfg, messages, timeout)
        if parsed is not None:
            if index:
                print(f"[llm] failover OK: switched to {cfg['model']} after {index} model(s) failed")
            return parsed, cfg["model"]
        if index + 1 < len(cfgs):
            print(f"[llm] {cfg['model']} failed; switching to {cfgs[index + 1]['model']} ...")
    print("[llm] every configured model failed; keeping deterministic output")
    return None, None


def _call_one(cfg: dict, messages: list[dict], timeout: int) -> dict | None:
    """Call a single model: JSON-object mode first, then plain mode if the
    provider rejects response_format. Returns parsed JSON or None."""
    model = cfg["model"]
    for use_json_mode in (True, False):
        body = {
            "model": model,
            "temperature": 0,
            "max_tokens": 8000,
            "messages": messages,
        }
        if use_json_mode:
            body["response_format"] = {"type": "json_object"}
        request = urllib.request.Request(
            f"{cfg['base_url']}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {cfg['api_key']}", "Content-Type": "application/json",
                     "User-Agent": "Sentinel/0.2"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if use_json_mode and exc.code in (400, 422):
                print(f"[llm] {model} rejected JSON mode (HTTP {exc.code}); retrying plain mode")
                continue  # model does not accept response_format; retry without it
            if exc.code == 429:
                print(f"[llm] {model} rate limited (HTTP 429)")
            else:
                print(f"[llm] {model} HTTP {exc.code}: {_error_detail(exc)}")
            return None
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            print(f"[llm] {model} network/transport error: {exc}")
            return None
        content = (payload.get("choices") or [{}])[0].get("message", {}).get("content")
        if content:
            parsed = _parse_json_content(content)
            if parsed is not None:
                return parsed
        if use_json_mode:
            continue
    print(f"[llm] {model} returned no valid JSON")
    return None


def _error_detail(exc: urllib.error.HTTPError) -> str:
    """Extract a short provider error message from an HTTP error body."""
    try:
        body = exc.read().decode("utf-8", "replace").strip()
        if body:
            data = json.loads(body)
            err = data.get("error") if isinstance(data, dict) else None
            if isinstance(err, dict) and err.get("message"):
                return str(err["message"])[:200]
            if isinstance(err, str) and err:
                return err[:200]
            return body[:200].replace("\n", " ")
    except Exception:
        pass
    return str(exc.reason or exc.code)


def _parse_json_content(content: str) -> dict | None:
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", content, re.DOTALL)  # recover JSON from mixed output
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def merge_llm_output(response: dict, graph: dict, known_event_ids: set[str]) -> dict:
    """Validate the LLM result and merge it into the deterministic graph."""
    problems: list[str] = []
    node_ids = {n["id"] for n in graph["nodes"]}

    # edges
    llm_edges, edge_problems = validate_graph(
        {"nodes": graph["nodes"], "edges": response.get("edges", [])}, known_event_ids)
    problems.extend(edge_problems)
    existing = {(e["from"], e["to"], e["relation"]) for e in graph["edges"]}
    added = 0
    for edge in llm_edges:
        if (edge["from"], edge["to"], edge["relation"]) in existing:
            continue
        graph["edges"].append(edge)
        added += 1

    # attack chain
    chain = []
    for step in response.get("attack_chain", [])[:20]:
        if not isinstance(step, dict):
            continue
        src, dst, rel = step.get("from"), step.get("to"), step.get("relation")
        if not src or not dst or not rel or src not in node_ids or dst not in node_ids:
            problems.append(f"dropped chain step referencing unknown node: {step.get('from')} -> {step.get('to')}")
            continue
        chain.append({
            "order": int(step.get("order", len(chain) + 1)),
            "from": src, "to": dst, "relation": rel,
            "reason": str(step.get("narration") or step.get("reason") or rel),
            "confidence": max(0.0, min(1.0, float(step.get("confidence", 0.5)))),
            "event_ids": [eid for eid in (step.get("event_ids") or []) if eid in known_event_ids],
            "origin": "llm",
        })
    if chain:
        graph["attack_chain"] = chain

    # threat overrides
    threat = {}
    raw = response.get("threat") or {}
    if isinstance(raw, dict):
        level = str(raw.get("threat_level", "")).lower()
        if level in THREAT_LEVELS:
            threat["threat_level"] = level
        try:
            threat["score"] = max(0.0, min(1.0, float(raw.get("score", 0.5))))
        except (TypeError, ValueError):
            pass
        for key in ("summary", "entry_point"):
            if isinstance(raw.get(key), str) and raw[key].strip():
                threat[key] = raw[key].strip()
        if isinstance(raw.get("mitre_techniques"), list):
            threat["mitre_techniques"] = raw["mitre_techniques"][:10]
        if isinstance(raw.get("justification"), list):
            threat["justification"] = [
                j for j in raw["justification"]
                if isinstance(j, dict) and j.get("event_id") in known_event_ids][:10]

    graph["summary"]["node_count"] = len(graph["nodes"])
    graph["summary"]["edge_count"] = len(graph["edges"])
    graph["summary"]["llm_edges_added"] = added
    graph["summary"]["llm_problems"] = problems
    return threat
