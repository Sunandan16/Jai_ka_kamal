import React, { useMemo, useState } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { INCIDENTS } from "@/data/mockData";

import TopNav from "@/components/dashboard/TopNav";
import AttackStory from "@/components/dashboard/AttackStory";
import LiveLogs from "@/components/dashboard/LiveLogs";
import CorrelationGraph from "@/components/dashboard/CorrelationGraph";
import AttackChain from "@/components/dashboard/AttackChain";
import PriorityQueue from "@/components/dashboard/PriorityQueue";
import AttackSurface from "@/components/dashboard/AttackSurface";
import Classification from "@/components/dashboard/Classification";
import IncidentHistory from "@/components/dashboard/IncidentHistory";
import IncidentDialog from "@/components/dashboard/IncidentDialog";
import Filters from "@/components/dashboard/Filters";
import { Toaster } from "@/components/ui/sonner";

const Dashboard = () => {
  const [selected, setSelected] = useState(INCIDENTS[0]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [dialogIncident, setDialogIncident] = useState(null);

  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("all");
  const [category, setCategory] = useState("all");

  const categories = useMemo(
    () => Array.from(new Set(INCIDENTS.map((i) => i.category))),
    []
  );

  const filteredIncidents = useMemo(() => {
    return INCIDENTS.filter((i) => {
      if (severity !== "all" && i.severity !== severity) return false;
      if (status !== "all" && i.status !== status) return false;
      if (category !== "all" && i.category !== category) return false;
      return true;
    });
  }, [severity, status, category]);

  const openIncident = (inc) => {
    setDialogIncident(inc);
    setDialogOpen(true);
  };

  return (
    <div className="min-h-screen">
      <TopNav liveCount={INCIDENTS.filter((i) => i.status === "Investigating").length + 3} />

      <main className="mx-auto max-w-[1600px] px-5 py-6 lg:px-8">
        {/* page header */}
        <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
          <div>
            <div className="rk-mono text-[10.5px] uppercase tracking-[0.28em] text-[#B6CCD1]/80">
              SOC Command Center · Demo Workspace
            </div>
            <h1 className="font-[Outfit] text-2xl md:text-[28px] font-extrabold tracking-tight text-[#ECE7E2]">
              Autonomous Threat Correlation &amp;{" "}
              <span className="rk-shimmer-text">Humanized Investigation</span>
            </h1>
          </div>
          <div className="flex items-center gap-2 text-[11px] text-[#A7ACA2]">
            <span className="rk-mono rounded-md border border-[#A69F88]/30 bg-[#A69F88]/5 px-2 py-1 uppercase tracking-widest text-[#D3CFC6]">
              Simulated Data
            </span>
            <span className="rk-mono">All records fictional · for demo only</span>
          </div>
        </div>

        {/* filters */}
        <Filters
          severity={severity}
          setSeverity={setSeverity}
          status={status}
          setStatus={setStatus}
          category={category}
          setCategory={setCategory}
          categories={categories}
        />

        {/* main grid */}
        <div className="mt-6 grid grid-cols-12 gap-5">
          <div className="col-span-12 lg:col-span-8">
            <AttackStory incident={selected} />
          </div>
          <div className="col-span-12 lg:col-span-4">
            <LiveLogs severityFilter={severity} />
          </div>

          <div className="col-span-12 lg:col-span-7">
            <CorrelationGraph incident={selected} />
          </div>
          <div className="col-span-12 lg:col-span-5">
            <AttackChain incident={selected} />
          </div>

          <div className="col-span-12 lg:col-span-4">
            <PriorityQueue
              incidents={filteredIncidents.length ? filteredIncidents : INCIDENTS}
              selected={selected}
              onSelect={setSelected}
            />
          </div>
          <div className="col-span-12 lg:col-span-4">
            <AttackSurface incident={selected} />
          </div>
          <div className="col-span-12 lg:col-span-4">
            <Classification incidents={INCIDENTS} />
          </div>

          <div className="col-span-12">
            <IncidentHistory
              incidents={filteredIncidents.length ? filteredIncidents : INCIDENTS}
              selectedId={selected?.id}
              onSelect={(inc) => {
                setSelected(inc);
                openIncident(inc);
              }}
            />
          </div>
        </div>

        <footer className="mt-10 flex flex-wrap items-center justify-between gap-2 border-t border-[#2E2822] pt-5 text-[11px] text-[#8A8580]">
          <span className="rk-mono uppercase tracking-widest">
            RAKSHANAM · Threat Correlation Suite · v0.9 preview
          </span>
          <span className="rk-mono">
            All data on this page is SIMULATED for demonstration.
          </span>
        </footer>
      </main>

      <IncidentDialog
        incident={dialogIncident}
        open={dialogOpen}
        onOpenChange={setDialogOpen}
      />
      <Toaster theme="dark" position="bottom-right" />
    </div>
  );
};

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Dashboard />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
