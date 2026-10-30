"""Ground-truth evaluation — runs ONLY when `--evaluate` is passed.

Attacker-side files (attacker/logs/attackmate.json) are labels, never
detection input. This module reads them strictly for scoring, after the
analysis has already been produced, and writes
rca_output/<scenario>/evaluation.json.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

TECH_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def load_ground_truth(root: Path) -> dict | None:
    """First attackmate.json found under the scenario (usually attacker/logs/)."""
    candidates = sorted(root.glob("attacker/**/attackmate.json"))
    if not candidates:
        return None
    text = candidates[0].read_text(encoding="utf-8", errors="replace").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        data = rows[0] if rows else None
    if isinstance(data, list):
        data = data[0] if data else None
    return data if isinstance(data, dict) else None


def gt_techniques(gt: dict) -> set[str]:
    metadata = (gt.get("parameters") or {}).get("metadata") or {}
    raw = str(metadata.get("techniques") or "")
    return {t.strip() for t in TECH_RE.findall(raw)}


def gt_tactics(gt: dict) -> set[str]:
    metadata = (gt.get("parameters") or {}).get("metadata") or {}
    raw = str(metadata.get("tactics") or "")
    return {t.strip() for t in raw.replace(";", ",").split(",") if t.strip()}


def evaluate(root: Path, result: dict) -> None:
    from .pipeline import OUTPUT_ROOT  # lazy import: pipeline is fully loaded by now

    gt = load_ground_truth(root)
    if gt is None:
        print("\n--evaluate: no attacker/logs/attackmate.json found (nothing to compare)")
        return

    graph, threat = result["graph"], result["threat"]
    detected = {m["id"] for m in (threat.get("mitre_techniques") or [])
                if isinstance(m, dict) and m.get("id")}
    gt_ids = gt_techniques(gt)
    recall = round(len(gt_ids & detected) / len(gt_ids), 2) if gt_ids else None

    payload = (gt.get("parameters") or {}).get("payload") or gt.get("payload")
    params = gt.get("parameters") or {}
    payload_options = params.get("payload_options") or gt.get("payload_options") or {}
    options = params.get("options") or {}
    lhost = payload_options.get("LHOST") or options.get("LHOST")
    lport = str(payload_options.get("LPORT") or options.get("LPORT") or "")
    reasons = " ".join(e.get("reason", "") for e in graph.get("edges", [])) + " " + str(threat.get("entry_point", ""))
    ip_hit = bool(lhost and lhost in reasons)
    port_hit = bool(lport and lport in reasons)

    verdict = [
        f"entry point {'✓' if ip_hit else '✗'}",
        f"execution {'✓' if any(t.startswith('T1059') for t in detected) else '✗'}",
        f"C2 {'✓' if port_hit or 'T1095' in detected else '✗'}",
    ]

    print()
    print("  Ground Truth Evaluation (attacker labels)")
    print(f"    module     : {gt.get('cmd', '-')}")
    print(f"    payload    : {payload or '-'}")
    if lhost:
        print(f"    LHOST      : {lhost}   {'✓ found in graph' if ip_hit else '✗ not found'}")
    if lport:
        print(f"    LPORT      : {lport}   {'✓ found in graph' if port_hit else '✗ not found'}")
    print(f"    techniques : {', '.join(sorted(gt_ids)) or '-'}")
    print(f"    detected   : {', '.join(sorted(detected)) or '-'}")
    if recall is not None:
        print(f"    recall     : {recall * 100:.0f}%  ({len(gt_ids & detected)}/{len(gt_ids)})")
    print(f"    verdict    : {' · '.join(verdict)}")

    evaluation = {
        "scenario_id": graph["scenario_id"],
        "generator": threat.get("generator"),
        "ground_truth": {
            "module": gt.get("cmd"),
            "payload": payload,
            "techniques": sorted(gt_ids),
            "tactics": sorted(gt_tactics(gt)),
            "lhost": lhost,
            "lport": lport,
        },
        "detected_techniques": sorted(detected),
        "technique_recall": recall,
        "attacker_ip_detected": ip_hit,
        "c2_port_detected": port_hit,
        "verdict": " · ".join(verdict),
    }
    out = OUTPUT_ROOT / graph["scenario_id"] / "evaluation.json"
    out.write_text(json.dumps(evaluation, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"    saved      : {out}")
