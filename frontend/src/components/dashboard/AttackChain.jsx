import React from "react";
import { ChevronRight, Target } from "lucide-react";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

const chainIntensity = {
  "Initial Access": 65,
  Reconnaissance: 45,
  Execution: 60,
  Persistence: 70,
  "Privilege Escalation": 85,
  "Defense Evasion": 72,
  "Credential Access": 78,
  Discovery: 50,
  "Lateral Movement": 68,
  Collection: 55,
  "Command & Control": 74,
  Exfiltration: 90,
};

export const AttackChain = ({ incident }) => {
  const chain = incident.chain;

  // Build timeline area data from story timestamps
  const data = [...incident.story]
    .sort((a, b) => new Date(a.t) - new Date(b.t))
    .map((s, i) => ({
      i,
      label: new Date(s.t).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      }),
      intensity: s.kind === "fact" ? 70 + i * 4 : 55 + i * 3,
    }));

  return (
    <section
      data-testid="attack-chain-section"
      className="flex h-[520px] flex-col rounded-2xl border border-[#2E2822] bg-[#1C1817] p-5"
    >
      <div className="flex items-center gap-2">
        <Target className="h-4 w-4 text-[#B6CCD1]" />
        <h2 className="font-[Outfit] text-lg font-bold text-[#ECE7E2]">
          MITRE ATT&amp;CK Chain
        </h2>
      </div>
      <div className="rk-mono mt-0.5 text-[10px] uppercase tracking-widest text-[#8A8580]">
        Progression stages for {incident.id}
      </div>

      <div className="mt-4 flex flex-wrap gap-1.5">
        {chain.map((stage, i) => (
          <React.Fragment key={stage}>
            <div
              data-testid={`attack-stage-${i}`}
              className="group rounded-xl border border-[#A4BCC2]/30 bg-gradient-to-br from-[#A4BCC2]/10 to-[#A4BCC2]/5 px-2.5 py-1.5 text-[11px] font-semibold text-[#DBE6E9]"
            >
              <div className="rk-mono text-[9px] uppercase tracking-widest text-[#B6CCD1]/80">
                Stage {i + 1}
              </div>
              <div className="font-[Outfit] text-[12px] font-bold">{stage}</div>
              <div className="rk-mono mt-0.5 text-[9.5px] text-[#A7ACA2]">
                intensity {chainIntensity[stage] || 60}
              </div>
            </div>
            {i < chain.length - 1 && (
              <ChevronRight className="my-auto h-4 w-4 text-[#8A8580]" />
            )}
          </React.Fragment>
        ))}
      </div>

      <div className="mt-4 flex-1 rounded-xl border border-[#2E2822] bg-[#17130F] p-3">
        <div className="rk-mono mb-1 text-[10px] uppercase tracking-widest text-[#8A8580]">
          Attack Timeline — intensity over time
        </div>
        <ResponsiveContainer width="100%" height="90%">
          <AreaChart data={data} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="chain-g" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#A4BCC2" stopOpacity={0.8} />
                <stop offset="100%" stopColor="#A4BCC2" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#2E2822" strokeDasharray="3 3" />
            <XAxis
              dataKey="label"
              stroke="#8A8580"
              tick={{ fontSize: 10, fontFamily: "JetBrains Mono" }}
            />
            <YAxis
              stroke="#8A8580"
              tick={{ fontSize: 10, fontFamily: "JetBrains Mono" }}
            />
            <Tooltip
              contentStyle={{
                background: "#17130F",
                border: "1px solid #2E2822",
                borderRadius: 8,
                fontSize: 11,
              }}
              labelStyle={{ color: "#A7ACA2" }}
            />
            <Area
              type="monotone"
              dataKey="intensity"
              stroke="#A4BCC2"
              strokeWidth={2}
              fill="url(#chain-g)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
};

export default AttackChain;
