import React from "react";
import { Archive, Clock3, ChevronRight } from "lucide-react";
import SeverityBadge from "./SeverityBadge";

const statusColor = {
  Investigating: "text-[#C4BFB1]",
  Escalated: "text-[#C9A4AC]",
  Resolved: "text-[#B6CCD1]",
};

export const IncidentHistory = ({ incidents, onSelect, selectedId }) => {
  return (
    <section
      data-testid="incident-history-section"
      className="rounded-2xl border border-[#2E2822] bg-[#1C1817] p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Archive className="h-4 w-4 text-[#B6CCD1]" />
            <h2 className="font-[Outfit] text-lg font-bold text-[#ECE7E2]">
              Incident History
            </h2>
          </div>
          <div className="rk-mono mt-0.5 text-[10px] uppercase tracking-widest text-[#8A8580]">
            6 demo incidents · click to investigate
          </div>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
        {incidents.map((inc) => {
          const active = inc.id === selectedId;
          return (
            <button
              key={inc.id}
              data-testid={`history-card-${inc.id}`}
              onClick={() => onSelect?.(inc)}
              className={`group relative overflow-hidden rounded-xl border p-4 text-left transition active:scale-[0.99] ${
                active
                  ? "border-[#A4BCC2]/50 bg-gradient-to-br from-[#A4BCC2]/10 to-[#17130F]"
                  : "border-[#2E2822] bg-[#17130F] hover:border-[#A4BCC2]/30 hover:bg-[#231E1C]"
              }`}
            >
              <div className="pointer-events-none absolute -right-10 -top-10 h-28 w-28 rounded-full bg-[#A4BCC2]/5 blur-2xl" />
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <SeverityBadge level={inc.severity} />
                  <span className="rk-mono text-[10px] text-[#8A8580]">
                    {inc.id}
                  </span>
                </div>
                <span
                  className={`rk-mono text-[10px] font-bold uppercase tracking-wider ${
                    statusColor[inc.status]
                  }`}
                >
                  ● {inc.status}
                </span>
              </div>
              <div className="mt-2 font-[Outfit] text-[15px] font-bold leading-tight text-[#ECE7E2] group-hover:text-[#C9DADE] transition">
                {inc.title}
              </div>
              <div className="mt-1 line-clamp-2 text-[12px] text-[#A7ACA2]">
                {inc.story[0]?.text}
              </div>
              <div className="mt-3 flex items-center justify-between text-[11px] text-[#8A8580]">
                <div className="flex items-center gap-1.5">
                  <Clock3 className="h-3 w-3" />
                  <span className="rk-mono">
                    {new Date(inc.date).toLocaleDateString(undefined, {
                      month: "short",
                      day: "numeric",
                    })}
                  </span>
                  <span>·</span>
                  <span>{inc.category}</span>
                </div>
                <div className="flex items-center gap-1 font-semibold text-[#B6CCD1]/90">
                  Risk {inc.riskScore}
                  <ChevronRight className="h-3.5 w-3.5" />
                </div>
              </div>
            </button>
          );
        })}
      </div>

      <div className="mt-3 flex items-center gap-2 rounded-lg border border-[#A69F88]/20 bg-[#A69F88]/5 p-2 text-[11px] text-[#D3CFC6]/90">
        <span className="rk-mono font-bold uppercase tracking-widest">
          Demo Incidents
        </span>
        <span className="text-[#E1DEDA]/70">
          · All records are SIMULATED DATA for illustration.
        </span>
      </div>
    </section>
  );
};

export default IncidentHistory;
