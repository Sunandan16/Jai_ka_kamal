import React from "react";
import {
  BarChart,
  Bar,
  Cell,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import { Layers } from "lucide-react";

export const Classification = ({ incidents }) => {
  const counts = incidents.reduce((acc, i) => {
    acc[i.category] = (acc[i.category] || 0) + 1;
    return acc;
  }, {});
  const data = Object.entries(counts).map(([name, value]) => ({ name, value }));
  const colors = ["#9F6D79", "#A69F88", "#A4BCC2", "#A4BCC2", "#A69F88", "#9F6D79"];

  return (
    <section
      data-testid="classification-section"
      className="rounded-2xl border border-[#2E2822] bg-[#1C1817] p-5"
    >
      <div className="flex items-center gap-2">
        <Layers className="h-4 w-4 text-[#B6CCD1]" />
        <h2 className="font-[Outfit] text-lg font-bold text-[#ECE7E2]">
          Attack Classification
        </h2>
      </div>
      <div className="rk-mono mt-0.5 text-[10px] uppercase tracking-widest text-[#8A8580]">
        By category across history
      </div>
      <div className="mt-3 h-[200px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 6, right: 6, left: -20, bottom: 0 }}>
            <XAxis
              dataKey="name"
              stroke="#8A8580"
              tick={{ fontSize: 9.5, fontFamily: "JetBrains Mono" }}
              interval={0}
              angle={-18}
              textAnchor="end"
              height={60}
            />
            <YAxis
              stroke="#8A8580"
              tick={{ fontSize: 10, fontFamily: "JetBrains Mono" }}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: "#17130F",
                border: "1px solid #2E2822",
                borderRadius: 8,
                fontSize: 11,
              }}
              cursor={{ fill: "rgba(164,188,194,0.08)" }}
            />
            <Bar dataKey="value" radius={[6, 6, 0, 0]}>
              {data.map((_, i) => (
                <Cell key={i} fill={colors[i % colors.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
};

export default Classification;
