import React from "react";
import { Flame, ArrowRight } from "lucide-react";
import SeverityBadge from "./SeverityBadge";
import { Progress } from "@/components/ui/progress";

export const PriorityQueue = ({ incidents, selected, onSelect }) => {
  const sorted = [...incidents].sort((a, b) => b.riskScore - a.riskScore);
  return (
    <section
      data-testid="priority-queue-section"
      className="rounded-2xl border border-[#2E2822] bg-[#1C1817] p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Flame className="h-4 w-4 text-[#C9A4AC]" />
            <h2 className="font-[Outfit] text-lg font-bold text-[#ECE7E2]">
              Priority Queue
            </h2>
          </div>
          <div className="rk-mono mt-0.5 text-[10px] uppercase tracking-widest text-[#8A8580]">
            Ranked by risk score
          </div>
        </div>
      </div>

      <div className="mt-4 space-y-2">
        {sorted.map((inc) => {
          const active = inc.id === selected?.id;
          return (
            <button
              key={inc.id}
              data-testid={`priority-item-${inc.id}`}
              onClick={() => onSelect?.(inc)}
              className={`group block w-full rounded-xl border p-3 text-left transition active:scale-[0.995] ${
                active
                  ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/5"
                  : "border-[#2E2822] bg-[#17130F] hover:border-[#A4BCC2]/30"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <SeverityBadge level={inc.severity} />
                    <span className="rk-mono text-[10px] text-[#8A8580]">
                      {inc.id}
                    </span>
                  </div>
                  <div className="mt-1 truncate font-[Outfit] text-[13.5px] font-bold text-[#ECE7E2]">
                    {inc.title}
                  </div>
                  <div className="mt-0.5 text-[11px] text-[#A7ACA2]">
                    {inc.category} · {inc.affected.hosts.length} hosts
                  </div>
                </div>
                <div className="shrink-0 text-right">
                  <div className="rk-mono text-[9px] uppercase tracking-widest text-[#8A8580]">
                    Risk
                  </div>
                  <div className="font-[Outfit] text-xl font-bold text-[#C9A4AC] leading-none">
                    {inc.riskScore}
                  </div>
                </div>
              </div>
              <div className="mt-2 flex items-center gap-2">
                <Progress
                  value={inc.riskScore}
                  className="h-1 bg-[#2E2822]"
                />
                <ArrowRight className="h-3.5 w-3.5 text-[#8A8580] group-hover:text-[#B6CCD1] transition" />
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
};

export default PriorityQueue;
