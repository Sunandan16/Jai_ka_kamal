import React, { useMemo, useState } from "react";
import { Network, ZoomIn, ZoomOut } from "lucide-react";
import { CORRELATION_NODES, CORRELATION_EDGES } from "@/data/mockData";

const kindColor = {
  user: "#A4BCC2",
  ip: "#9F6D79",
  host: "#A4BCC2",
};

// Deterministic layout: group by kind on 3 concentric columns
const layoutNodes = (nodes) => {
  const cols = { user: [], ip: [], host: [] };
  nodes.forEach((n) => cols[n.kind].push(n));
  const w = 620;
  const h = 360;
  const xMap = { user: 90, ip: w / 2, host: w - 90 };
  const positioned = [];
  Object.entries(cols).forEach(([kind, list]) => {
    const spacing = (h - 40) / Math.max(1, list.length);
    list.forEach((n, i) => {
      positioned.push({
        ...n,
        x: xMap[kind],
        y: 25 + spacing * i + spacing / 2,
      });
    });
  });
  return positioned;
};

export const CorrelationGraph = ({ incident, onSelectNode }) => {
  const [zoom, setZoom] = useState(1);
  const [hover, setHover] = useState(null);

  const nodes = useMemo(() => layoutNodes(CORRELATION_NODES), []);
  const posById = useMemo(() => {
    const m = {};
    nodes.forEach((n) => (m[n.id] = n));
    return m;
  }, [nodes]);

  const incidentEdges = CORRELATION_EDGES.filter(
    (e) => !incident || e.incidentId === incident.id
  );
  const incidentNodeIds = new Set();
  incidentEdges.forEach((e) => {
    incidentNodeIds.add(e.s);
    incidentNodeIds.add(e.d);
  });

  return (
    <section
      data-testid="correlation-graph-section"
      className="relative flex flex-col rounded-2xl border border-[#2E2822] bg-[#1C1817] p-5 h-[520px] overflow-hidden"
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-[#B6CCD1]" />
            <h2 className="font-[Outfit] text-lg font-bold text-[#ECE7E2]">
              Event Correlation Graph
            </h2>
          </div>
          <div className="rk-mono mt-0.5 text-[10px] uppercase tracking-widest text-[#8A8580]">
            Users · IPs · Hosts linked by shared events
          </div>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            data-testid="graph-zoom-out"
            onClick={() => setZoom((z) => Math.max(0.6, z - 0.15))}
            className="grid h-7 w-7 place-items-center rounded-full border border-[#2E2822] bg-[#231E1C] text-[#BEB8B2] hover:text-[#B6CCD1] hover:border-[#A4BCC2]/40 active:scale-95"
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <button
            data-testid="graph-zoom-in"
            onClick={() => setZoom((z) => Math.min(1.6, z + 0.15))}
            className="grid h-7 w-7 place-items-center rounded-full border border-[#2E2822] bg-[#231E1C] text-[#BEB8B2] hover:text-[#B6CCD1] hover:border-[#A4BCC2]/40 active:scale-95"
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="relative mt-3 flex-1 overflow-hidden rounded-xl border border-[#2E2822] bg-[#17130F] rk-grid-bg">
        <svg
          viewBox="0 0 620 380"
          className="h-full w-full"
          style={{ transform: `scale(${zoom})`, transformOrigin: "center", transition: "transform 0.25s" }}
        >
          <defs>
            <linearGradient id="edge-active" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#A4BCC2" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#9F6D79" stopOpacity="0.9" />
            </linearGradient>
          </defs>

          {/* edges */}
          {CORRELATION_EDGES.map((e, i) => {
            const a = posById[e.s];
            const b = posById[e.d];
            if (!a || !b) return null;
            const active = incidentEdges.includes(e);
            return (
              <line
                key={i}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={active ? "url(#edge-active)" : "#2E2822"}
                strokeWidth={active ? 1.8 : 1}
                className={active ? "rk-edge-animated" : ""}
                opacity={active ? 1 : 0.5}
              />
            );
          })}

          {/* nodes */}
          {nodes.map((n) => {
            const active = incidentNodeIds.has(n.id);
            const r = active ? 11 : 8;
            return (
              <g
                key={n.id}
                transform={`translate(${n.x}, ${n.y})`}
                onMouseEnter={() => setHover(n)}
                onMouseLeave={() => setHover(null)}
                onClick={() => onSelectNode?.(n)}
                className="cursor-pointer"
                data-testid={`graph-node-${n.id}`}
              >
                {active && (
                  <circle
                    r={r + 6}
                    fill="none"
                    stroke={kindColor[n.kind]}
                    strokeOpacity="0.3"
                    strokeWidth="1"
                  />
                )}
                <circle
                  r={r}
                  fill={kindColor[n.kind]}
                  fillOpacity={active ? 0.9 : 0.5}
                  stroke={kindColor[n.kind]}
                  strokeOpacity="0.8"
                  strokeWidth="1.5"
                />
                <text
                  y={r + 12}
                  textAnchor="middle"
                  fill="#C7C2BC"
                  fontSize="9.5"
                  fontFamily="JetBrains Mono, monospace"
                >
                  {n.label}
                </text>
              </g>
            );
          })}
        </svg>

        {hover && (
          <div className="pointer-events-none absolute top-3 left-3 rounded-lg border border-[#A4BCC2]/30 bg-[#17130F]/90 p-2 text-[11px] text-[#D7D1CC] backdrop-blur">
            <div className="font-[Outfit] font-bold">{hover.label}</div>
            <div className="rk-mono text-[10px] uppercase tracking-wider text-[#A7ACA2]">
              {hover.kind} · risk {hover.risk}
            </div>
          </div>
        )}

        <div className="absolute bottom-2 right-3 flex items-center gap-3 rounded-full border border-[#2E2822] bg-[#17130F]/70 px-3 py-1 text-[10px] rk-mono text-[#A7ACA2]">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-[#A4BCC2]" /> user
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-[#B48892]" /> ip
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-[#B6CCD1]" /> host
          </span>
        </div>
      </div>
    </section>
  );
};

export default CorrelationGraph;
