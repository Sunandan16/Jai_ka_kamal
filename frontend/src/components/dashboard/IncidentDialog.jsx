import React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import SeverityBadge from "./SeverityBadge";
import { LOGS } from "@/data/mockData";
import { CheckCircle2, AlertCircle, FileText } from "lucide-react";

export const IncidentDialog = ({ incident, open, onOpenChange }) => {
  if (!incident) return null;
  const relatedLogs = LOGS.filter((l) => incident.logIds.includes(l.id));
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        data-testid="incident-dialog"
        className="max-w-4xl border-[#2E2822] bg-[#1C1817] text-[#ECE7E2] rk-scroll"
      >
        <DialogHeader>
          <div className="flex items-center gap-2">
            <SeverityBadge level={incident.severity} />
            <span className="rk-mono text-[10px] text-[#8A8580]">
              {incident.id} · {incident.category}
            </span>
          </div>
          <DialogTitle className="font-[Outfit] text-2xl font-bold tracking-tight text-[#ECE7E2]">
            {incident.title}
          </DialogTitle>
          <DialogDescription className="text-[#A7ACA2]">
            Full investigation — simulated data for demonstration.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="max-h-[62vh] pr-3">
          <section className="rounded-xl border border-[#2E2822] bg-[#17130F] p-4">
            <h3 className="font-[Outfit] text-sm font-bold text-[#B6CCD1]">
              Humanized Story
            </h3>
            <ol className="mt-3 space-y-2 border-l border-[#A4BCC2]/20 pl-5">
              {incident.story.map((s, i) => {
                const fact = s.kind === "fact";
                return (
                  <li key={i} className="relative">
                    <span
                      className={`absolute -left-[27px] top-0.5 grid h-5 w-5 place-items-center rounded-full border ${
                        fact
                          ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/10 text-[#B6CCD1]"
                          : "border-[#A69F88]/40 bg-[#A69F88]/10 text-[#C4BFB1]"
                      }`}
                    >
                      {fact ? (
                        <CheckCircle2 className="h-3 w-3" />
                      ) : (
                        <AlertCircle className="h-3 w-3" />
                      )}
                    </span>
                    <div className="rk-mono text-[10px] uppercase tracking-wider text-[#C9DADE]/80">
                      {new Date(s.t).toLocaleString()}
                    </div>
                    <div className="text-[13.5px] text-[#D7D1CC]">{s.text}</div>
                    <div className="rk-mono text-[10px] text-[#8A8580]">
                      evidence · {s.logId}
                    </div>
                  </li>
                );
              })}
            </ol>
          </section>

          <section className="mt-3 rounded-xl border border-[#2E2822] bg-[#17130F] p-4">
            <h3 className="flex items-center gap-2 font-[Outfit] text-sm font-bold text-[#B6CCD1]">
              <FileText className="h-3.5 w-3.5" /> Associated Raw Logs ({relatedLogs.length})
            </h3>
            <div className="mt-3 space-y-1.5">
              {relatedLogs.map((l) => (
                <div
                  key={l.id}
                  className="rounded-md border border-[#2E2822] bg-[#1C1817] p-2 text-[12px]"
                >
                  <div className="flex items-center gap-2">
                    <span className="rk-mono text-[10px] text-[#8A8580]">
                      {new Date(l.t).toLocaleTimeString()}
                    </span>
                    <SeverityBadge level={l.sev} />
                    <span className="rk-mono text-[10px] uppercase tracking-wider text-[#C9DADE]/80">
                      {l.event}
                    </span>
                    <span className="ml-auto rk-mono text-[10px] text-[#8A8580]">
                      {l.id}
                    </span>
                  </div>
                  <div className="mt-0.5 text-[#BEB8B2]">
                    <span className="rk-mono">{l.ip}</span> · {l.user} · {l.host}
                  </div>
                  <div className="text-[#A7ACA2]">{l.msg}</div>
                </div>
              ))}
            </div>
          </section>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
};

export default IncidentDialog;
