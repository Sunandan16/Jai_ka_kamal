"""Normalize defender-side telemetry into the common event schema.

Improvements over the earlier prototype:
- Every event carries a stable SHA-1 ``event_id`` plus ``source_file`` /
  ``source_line`` / ``raw_event`` provenance.
- Linux audit parsing now decodes EXECVE argv (hex or plain) into ``cmdline``
  and captures connect() destinations from SOCKADDR into ``dst_ip``/``dst_port``,
  which unlocks process->network correlation (e.g. C2 on port 4444).
- DNS reconnaissance bursts are detected and collapsed for reporting.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SUSPICIOUS_PROCESSES = {"curl", "wget", "chmod", "nc", "ncat", "bash", "sh", "python", "perl"}


def evt(ts, kind, source, summary, **data):
    return {"timestamp": ts, "event_type": kind, "source": source, "summary": summary, **data}


def iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------- JSON logs
def parse_json_lines(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "rule" in row and "timestamp" in row:  # Wazuh alert
            rule, agent = row["rule"], row.get("agent", {})
            mitre = rule.get("mitre", {})
            events.append(evt(iso(row["timestamp"]), "security_alert", "wazuh.alerts.json", rule.get("description", "Wazuh alert"),
                host=agent.get("name"), host_ip=agent.get("ip"), severity=rule.get("level", 0),
                mitre_ids=mitre.get("id", []), mitre_techniques=mitre.get("technique", []),
                src_ip=row.get("data", {}).get("srcip"), user=row.get("data", {}).get("dstuser"),
                raw=row.get("full_log"), suspicious=rule.get("level", 0) >= 3))
        elif "time" in row and "message" in row:  # Nextcloud application / audit logs
            message = row.get("message", "")
            lower = message.lower()
            login = "login successful" in lower or "login attempt" in lower
            risky = any(x in lower for x in ("run script", "curl ", "chmod ", "workflow", "executing sh"))
            if login or risky:
                source = "nextcloud_app_audit.log" if path.name == "audit.log" else "nextcloud.log"
                events.append(evt(iso(row["time"]), "authentication" if login else "web_activity", source, message,
                    host=row.get("host") or row.get("hostname") or path.parent.name, user=row.get("user"),
                    src_ip=row.get("remoteAddr"), url=row.get("url"), request_id=row.get("reqId"),
                    outcome="success" if "successful" in lower else "attempt" if login else None,
                    suspicious=risky or "successful" in lower))
        elif "log" in row and "time" in row:  # Docker JSON container log
            events.extend(parse_access_line(row.get("log", ""), iso(row["time"]), path.name))
    return events


# ---------------------------------------------------------------- audit.log
def decode_execve(line):
    """Decode EXECVE argv into a command line (plain strings or hex blobs)."""
    argv = []
    for plain, hexv in re.findall(r'a\d+=(?:"([^"]*)"|([0-9A-Fa-f]+))', line):
        if plain:
            argv.append(plain)
        elif hexv and len(hexv) % 2 == 0:
            try:
                argv.append(bytes.fromhex(hexv).decode("utf-8", errors="replace"))
            except ValueError:
                argv.append(hexv)
        else:
            argv.append(hexv)
    return " ".join(argv) if argv else None


def parse_audit(path, year):
    events = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.startswith("type=SYSCALL"):
            i += 1
            continue
        data = dict(re.findall(r'(comm|exe|uid|pid|ppid|key)="?([^\s"]+)', line))
        stamp = re.search(r'audit\((\d+\.\d+):(\d+)\)', line)
        if not stamp or not data:
            i += 1
            continue
        ts = datetime.fromtimestamp(float(stamp.group(1)), timezone.utc).isoformat()
        audit_id, process = stamp.group(2), data.get("comm", "process")
        syscall = (re.search(r'syscall=(\d+)', line) or [None, None])[1]
        cmdline = dst_ip = dst_port = None
        if syscall == "59":  # execve: look ahead for EXECVE argv of the same audit id
            for nxt in lines[i + 1:i + 3]:
                if nxt.startswith("type=EXECVE") and f":{audit_id})" in nxt:
                    cmdline = decode_execve(nxt)
                    break
        elif syscall == "42":  # connect: the SADDR= destination may be 2-4 lines ahead (wrapped format)
            for nxt in lines[i + 1:i + 5]:
                match = re.search(r'laddr=([0-9.]+) lport=(\d+)', nxt)
                if match:
                    dst_ip, dst_port = match.group(1), int(match.group(2))
                    break
        suspicious = process in SUSPICIOUS_PROCESSES or dst_port == 4444
        if not suspicious and cmdline and any(x in cmdline for x in ("curl ", "chmod ", "wget ", "nc ")):
            suspicious = True
        events.append(evt(ts, "process_activity", "linux.audit.log",
            f'{process} executed ({data.get("key", "unclassified")})',
            process=process, executable=data.get("exe"), user=data.get("uid"),
            pid=data.get("pid"), parent_pid=data.get("ppid"), rule_key=data.get("key"),
            cmdline=cmdline, dst_ip=dst_ip, dst_port=dst_port, suspicious=suspicious))
        i += 1
    return events


# ---------------------------------------------------------------- Suricata
FLOW = re.compile(r"\{\w+\}\s+(\S+):(\d+)\s+->\s+(\S+):(\d+)$")


def parse_suricata(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        time_match, flow_match = re.match(r"^(\d\d/\d\d/\d{4}-[\d:.]+)", line), FLOW.search(line)
        if not time_match or not flow_match:
            continue
        src_ip, src_port, dst_ip, dst_port = flow_match.groups()
        signature = line.split("] ", 2)[-1].split(" [**]", 1)[0]
        ts = datetime.strptime(time_match.group(1), "%m/%d/%Y-%H:%M:%S.%f").replace(tzinfo=timezone.utc).isoformat()
        events.append(evt(ts, "network_alert", "suricata.fast.log", signature, src_ip=src_ip, src_port=int(src_port),
            dst_ip=dst_ip, dst_port=int(dst_port), suspicious=True))
    return events


# ---------------------------------------------------------------- web access
def parse_access_line(line, timestamp, source):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*?\"(GET|POST|PUT|DELETE)\s+(\S+).*?\"\s+(\d{3})", line)
    if not match:
        return []
    ip, method, url, status = match.groups()
    risky = method == "DELETE" or any(x in url.lower() for x in ("workflow", "shell", "upload"))
    return [evt(timestamp, "web_access", source, f"{method} {url} -> {status}", src_ip=ip, method=method, url=url,
                status=int(status), suspicious=risky)]


def parse_apache(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r'^(\S+) .*?\[([^\]]+)\] "(GET|POST|PUT|DELETE) (\S+).*?" (\d{3})', line)
        if not match:
            continue
        ip, stamp, method, url, status = match.groups()
        try:
            ts = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
        risky = method in {"POST", "PUT", "DELETE"} or any(x in url.lower() for x in ("upload", "shell", "exploit"))
        events.append(evt(ts, "web_access", "apache.access.log", f"{method} {url} -> {status}", src_ip=ip,
            method=method, url=url, status=int(status), suspicious=risky))
    return events


def parse_squid(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            ts = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%dT%H:%M:%S.%f %z").astimezone(timezone.utc).isoformat()
        except ValueError:
            continue
        method, url, mime = parts[5], parts[6], parts[-1]
        direct = next((part.split("/", 1)[1] for part in parts if part.startswith("HIER_DIRECT/")), None)
        executable = "executable" in mime.lower()
        events.append(evt(ts, "proxy_request", "squid.access.log", f"{method} {url} ({mime})", src_ip=parts[2],
            url=url, dst_ip=direct, mime_type=mime, suspicious=executable))
    return events


# ---------------------------------------------------------------- auth/syslog
def parse_auth_or_syslog(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+(\S+)", line)
        if not match:
            continue
        if year is None:
            ts = f"unknown-year {match.group(1)}"
        else:
            try:
                ts = datetime.strptime(f"{year} {match.group(1)}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
        if "dnsmasq" in line and ("auth[" in line or "query[" in line):
            domain = (re.search(r"(?:auth|query)\[[A-Z]+\]\s+(\S+)", line) or [None, None])[1]
            src_ip = (re.search(r"from (\d+\.\d+\.\d+\.\d+)", line) or [None, None])[1]
            events.append(evt(ts, "dns_query", "dns.syslog", f"DNS query for {domain}", host=match.group(2),
                src_ip=src_ip, domain=domain, suspicious=False))
            continue
        persistence = any(x in line.lower() for x in ("crontab", " cron[", "authorized_keys", "useradd", "adduser", "usermod", "/etc/systemd/system"))
        if persistence:
            events.append(evt(ts, "persistence_change", path.name, line.strip(), host=match.group(2), suspicious=True))
            continue
        if not any(x in line for x in ("Accepted ", "Failed password", "session opened", "sudo:")):
            continue
        src_ip = (re.search(r"from (\d+\.\d+\.\d+\.\d+)", line) or [None, None])[1]
        user = (re.search(r"for (?:invalid user )?([^\s(]+)", line) or [None, None])[1]
        success = "Accepted " in line or "session opened" in line
        events.append(evt(ts, "authentication", path.name, line.strip(), host=match.group(2), src_ip=src_ip, user=user,
            outcome="success" if success else "failure", suspicious=success and src_ip is not None))
    return events


# ---------------------------------------------------------------- dispatch
def parse_path(path, root, year):
    rel = path.relative_to(root).as_posix()
    if "/attacker/" in f"/{rel}":
        return []
    lower = path.name.lower()
    if lower == "alerts.json" or lower == "nextcloud.log" or lower.endswith("-json.log") or (lower == "audit.log" and "nclog" in rel):
        return parse_json_lines(path, year)
    if lower == "audit.log":
        return parse_audit(path, year)
    if lower == "fast.log":
        return parse_suricata(path, year)
    if "squid/access.log" in rel:
        return parse_squid(path, year)
    if "/apache2/access.log" in rel or lower.startswith("access.log"):
        return parse_apache(path, year)
    if lower in {"auth.log", "syslog", "daemon.log", "messages", "kern.log"}:
        return parse_auth_or_syslog(path, year)
    return []


# ---------------------------------------------------------------- provenance
def attach_provenance(path, root, scenario, events):
    """Attach a stable identity and the closest original source line to each event."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    cursor = 0
    relative = path.relative_to(root).as_posix()
    for item in events:
        process, rule, summary = item.get("process"), item.get("rule_key"), item.get("summary", "")
        needles = [summary[:80]] if summary else []
        if ", config:" in summary:
            needles.insert(0, summary.split(", config:", 1)[0])
        if process:
            needles.append(f'comm="{process}"')
        if rule:
            needles.append(f'key="{rule}"')
        weak_needles = [x for x in (item.get("url"), item.get("domain")) if x]
        line_no, raw = None, item.get("summary", "")
        for index in range(cursor, len(lines)):
            if any(needle and needle in lines[index] for needle in needles):
                line_no, raw, cursor = index + 1, lines[index], index + 1
                break
        if line_no is None:
            for index in range(cursor, len(lines)):
                if any(needle in lines[index] for needle in weak_needles):
                    line_no, raw, cursor = index + 1, lines[index], index + 1
                    break
        identity = f"{scenario}|{relative}|{line_no}|{item.get('timestamp')}|{item.get('summary')}"
        item.update(event_id=hashlib.sha1(identity.encode()).hexdigest()[:16], scenario_id=scenario,
                    source_file=relative, source_line=line_no, raw_event=raw)
    return events


def infer_year(root):
    """Use only defender telemetry; classic syslog lines do not contain a year."""
    for path in root.rglob("alerts.json"):
        try:
            return datetime.fromisoformat(json.loads(path.read_text(encoding="utf-8").splitlines()[0])["timestamp"].replace("Z", "+00:00")).year
        except (IndexError, KeyError, ValueError, json.JSONDecodeError):
            pass
    return None


def annotate_dns_bursts(events):
    groups = defaultdict(list)
    for item in events:
        if item["event_type"] == "dns_query":
            groups[(item.get("src_ip"), item["timestamp"])].append(item)
    bursts = []
    for (src_ip, timestamp), items in groups.items():
        unique_domains = {item.get("domain") for item in items if item.get("domain")}
        if len(unique_domains) >= 20:
            burst = {"src_ip": src_ip, "timestamp": timestamp, "event_count": len(items), "unique_domains": len(unique_domains)}
            bursts.append(burst)
            for item in items:
                item.update(suspicious=True, behavior="dns_reconnaissance", burst_event_count=len(items),
                            burst_unique_domains=len(unique_domains))
    return bursts


def sort_key(event):
    try:
        return datetime.fromisoformat(event["timestamp"])
    except (ValueError, TypeError):
        return datetime.max.replace(tzinfo=timezone.utc)


def load_events(root):
    """Parse a scenario folder into a time-sorted list of normalized events."""
    year = infer_year(root)
    events = []
    for path in root.rglob("*"):
        if path.is_file():
            events.extend(attach_provenance(path, root, root.name, parse_path(path, root, year)))
    events.sort(key=sort_key)
    annotate_dns_bursts(events)
    return events


def summarize(events):
    return {
        "event_count": len(events),
        "sources": Counter(e["source"] for e in events),
        "suspicious": sum(1 for e in events if e.get("suspicious")),
    }
