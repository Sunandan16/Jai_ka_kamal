import React, { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Pause, Play, Radio } from "lucide-react";
import { LOGS, SOURCES, EVENT_TYPES } from "@/data/mockData";
import SeverityBadge from "./SeverityBadge";

const rand = (arr) => arr[Math.floor(Math.random() * arr.length)];
const RAND_IPS = [
  "45.133.1.14",
  "52.14.9.221",
  "77.111.247.33",
  "198.51.100.23",
  "10.14.22.19",
  "10.14.6.11",
  "193.27.14.9",
  "117.55.88.12",
];
const RAND_USERS = ["m.okafor", "svc-deploy", "ananya.r", "k.novak", "j.silva", "p.ravi", "—"];
const RAND_HOSTS = ["idp-prod", "aws-iam", "github", "WIN-ENG-27", "edge-fw-01", "db-prod-03"];
const RAND_OUTCOMES = ["allowed", "denied", "blocked", "flagged", "quarantined"];
const RAND_MSGS = [
  "Repeated auth from new ASN",
  "Unusual API burst",
  "C2 beacon pattern",
  "Policy drift detected",
  "Anomalous data egress",
  "Token theft heuristic",
  "DGA-like DNS",
];

const severityWeighted = () => {
  const r = Math.random();
  if (r < 0.08) return "critical";
  if (r < 0.3) return "high";
  if (r < 0.65) return "medium";
  return "low";
};

export const LiveLogs = ({ severityFilter = "all" }) => {
  const [logs, setLogs] = useState(LOGS.slice(0, 42));
  const [paused, setPaused] = useState(false);
  const [sourceFilter, setSourceFilter] = useState("all");
  const idRef = useRef(1042);

  useEffect(() => {
    if (paused) return;
    const t = setInterval(() => {
      idRef.current += 1;
      const next = {
        id: `L-${idRef.current}`,
        t: new Date().toISOString(),
        src: rand(SOURCES),
        user: rand(RAND_USERS),
        host: rand(RAND_HOSTS),
        ip: rand(RAND_IPS),
        event: rand(EVENT_TYPES),
        sev: severityWeighted(),
        outcome: rand(RAND_OUTCOMES),
        msg: rand(RAND_MSGS),
      };
      setLogs((prev) => [next, ...prev].slice(0, 60));
    }, 2500);
    return () => clearInterval(t);
  }, [paused]);

  const visible = logs.filter((l) => {
    if (severityFilter !== "all" && l.sev !== severityFilter) return false;
    if (sourceFilter !== "all" && l.src !== sourceFilter) return false;
    return true;
  });

  return (
    <section
      data-testid="live-logs-section"
      className="flex h-[560px] flex-col rounded-2xl border border-[#2E2822] bg-[#1C1817] p-5"
    >
      <div className="flex items-center justify-between gap-2">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-[#B6CCD1]" />
            <h2 className="font-[Outfit] text-lg font-bold text-[#ECE7E2]">
              Live Security Logs
            </h2>
            <span className="h-2 w-2 rounded-full bg-[#A4BCC2] rk-pulse-dot" />
          </div>
          <div className="rk-mono mt-0.5 text-[10px] uppercase tracking-widest text-[#8A8580]">
            Simulated feed · {visible.length} entries
          </div>
        </div>
        <button
          data-testid="logs-pause-btn"
          onClick={() => setPaused((p) => !p)}
          className="grid h-8 w-8 place-items-center rounded-full border border-[#2E2822] bg-[#231E1C] text-[#BEB8B2] transition hover:border-[#A4BCC2]/40 hover:text-[#B6CCD1] active:scale-95"
        >
          {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
        </button>
      </div>

      <div className="mt-3 flex items-center gap-1.5 overflow-x-auto rk-scroll pb-1">
        {["all", ...SOURCES].map((s) => (
          <button
            key={s}
            data-testid={`log-source-filter-${s.replace(/\s+/g, "-").toLowerCase()}`}
            onClick={() => setSourceFilter(s)}
            className={`whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] font-medium transition ${
              sourceFilter === s
                ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/10 text-[#C9DADE]"
                : "border-[#2E2822] bg-[#231E1C] text-[#A7ACA2] hover:text-[#D7D1CC]"
            }`}
          >
            {s === "all" ? "All" : s}
          </button>
        ))}
      </div>

      <div className="mt-3 flex-1 overflow-y-auto rk-scroll pr-1">
        <AnimatePresence initial={false}>
          {visible.map((l) => (
            <motion.div
              key={l.id}
              initial={{ opacity: 0, y: -8, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="group mb-1.5 rounded-lg border border-transparent bg-[#17130F] p-2.5 hover:border-[#A4BCC2]/25 hover:bg-[#231E1C]"
            >
              <div className="flex items-center gap-2 text-[11px]">
                <span className="rk-mono text-[#8A8580]">
                  {new Date(l.t).toLocaleTimeString([], {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit",
                  })}
                </span>
                <SeverityBadge level={l.sev} />
                <span className="rk-mono text-[10px] uppercase tracking-wider text-[#C9DADE]/80">
                  {l.event}
                </span>
                <span className="ml-auto rk-mono text-[10px] text-[#8A8580]">
                  {l.src}
                </span>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[12px] text-[#BEB8B2]">
                <span className="rk-mono text-[#D7D1CC]">{l.ip}</span>
                <span className="text-[#8A8580]">·</span>
                <span>{l.user}</span>
                <span className="text-[#8A8580]">·</span>
                <span className="text-[#A7ACA2]">{l.host}</span>
                <span className="text-[#8A8580]">·</span>
                <span
                  className={`rk-mono text-[10px] uppercase tracking-wider ${
                    l.outcome === "allowed"
                      ? "text-[#B6CCD1]"
                      : l.outcome === "quarantined" || l.outcome === "flagged"
                      ? "text-[#C4BFB1]"
                      : "text-[#C9A4AC]"
                  }`}
                >
                  {l.outcome}
                </span>
              </div>
              <div className="mt-0.5 text-[12.5px] text-[#A7ACA2]">{l.msg}</div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </section>
  );
};

export default LiveLogs;
