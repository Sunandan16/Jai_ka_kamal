import React from "react";
import { Filter } from "lucide-react";

const SEV = ["all", "critical", "high", "medium", "low"];
const STATUS = ["all", "Investigating", "Escalated", "Resolved"];

export const Filters = ({ severity, setSeverity, status, setStatus, category, setCategory, categories }) => {
  return (
    <div
      data-testid="filters-bar"
      className="flex flex-wrap items-center gap-3 rounded-2xl border border-[#2E2822] bg-[#1C1817] p-3"
    >
      <div className="flex items-center gap-1.5 pl-1 pr-2">
        <Filter className="h-3.5 w-3.5 text-[#B6CCD1]" />
        <span className="rk-mono text-[10px] uppercase tracking-widest text-[#A7ACA2]">
          Filters
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="rk-mono text-[10px] uppercase tracking-wider text-[#8A8580]">
          Severity:
        </span>
        {SEV.map((s) => (
          <button
            key={s}
            data-testid={`filter-sev-${s}`}
            onClick={() => setSeverity(s)}
            className={`rounded-full border px-2.5 py-1 text-[11px] font-medium capitalize transition ${
              severity === s
                ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/10 text-[#C9DADE]"
                : "border-[#2E2822] bg-[#231E1C] text-[#A7ACA2] hover:text-[#D7D1CC]"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="rk-mono text-[10px] uppercase tracking-wider text-[#8A8580]">
          Status:
        </span>
        {STATUS.map((s) => (
          <button
            key={s}
            data-testid={`filter-status-${s}`}
            onClick={() => setStatus(s)}
            className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition ${
              status === s
                ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/10 text-[#C9DADE]"
                : "border-[#2E2822] bg-[#231E1C] text-[#A7ACA2] hover:text-[#D7D1CC]"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="rk-mono text-[10px] uppercase tracking-wider text-[#8A8580]">
          Category:
        </span>
        {["all", ...categories].map((c) => (
          <button
            key={c}
            data-testid={`filter-cat-${c.replace(/\s+/g, "-").toLowerCase()}`}
            onClick={() => setCategory(c)}
            className={`rounded-full border px-2.5 py-1 text-[11px] font-medium transition ${
              category === c
                ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/10 text-[#C9DADE]"
                : "border-[#2E2822] bg-[#231E1C] text-[#A7ACA2] hover:text-[#D7D1CC]"
            }`}
          >
            {c}
          </button>
        ))}
      </div>
    </div>
  );
};

export default Filters;
