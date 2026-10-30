import React, { useState } from "react";
import { motion } from "framer-motion";
import {
  Heart,
  Bookmark,
  MessageCircle,
  Share2,
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  Flame,
  BrainCircuit,
} from "lucide-react";
import SeverityBadge from "./SeverityBadge";

const StatusChip = ({ status }) => {
  const map = {
    Investigating: "bg-[#A69F88]/10 text-[#C4BFB1] border-[#A69F88]/30",
    Escalated: "bg-[#9F6D79]/10 text-[#C9A4AC] border-[#9F6D79]/40",
    Resolved: "bg-[#A4BCC2]/10 text-[#B6CCD1] border-[#A4BCC2]/30",
  };
  return (
    <span
      data-testid="incident-status-chip"
      className={`rk-mono px-2.5 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-wider ${map[status] || map.Investigating}`}
    >
      {status}
    </span>
  );
};

export const AttackStory = ({ incident }) => {
  const [liked, setLiked] = useState(false);
  const [bookmarked, setBookmarked] = useState(false);
  const [likes, setLikes] = useState(14);

  const toggleLike = () => {
    setLiked((v) => !v);
    setLikes((n) => n + (liked ? -1 : 1));
  };

  return (
    <section
      data-testid="attack-story-section"
      className="relative overflow-hidden rounded-2xl border border-[#A4BCC2]/25 bg-gradient-to-br from-[#1C1817] via-[#1F1B19] to-[#17130F] shadow-2xl"
    >
      <div className="pointer-events-none absolute inset-0 rk-grid-bg opacity-30" />
      <div className="pointer-events-none absolute -top-20 -right-20 h-72 w-72 rounded-full bg-[#A4BCC2]/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-20 -left-20 h-80 w-80 rounded-full bg-[#A4BCC2]/10 blur-3xl" />

      <div className="relative p-6 md:p-8">
        {/* header */}
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="rk-mono text-[10px] font-bold uppercase tracking-[0.3em] text-[#B6CCD1]">
                AI Attack Story
              </span>
              <span className="rk-mono text-[10px] text-[#8A8580]">·</span>
              <span className="rk-mono text-[10px] uppercase tracking-widest text-[#A7ACA2]">
                SIMULATED DATA
              </span>
            </div>
            <h1
              data-testid="attack-story-title"
              className="mt-2 font-[Outfit] text-3xl md:text-4xl font-extrabold tracking-tight text-[#ECE7E2]"
            >
              {incident.title}
            </h1>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-[#A7ACA2]">
              <span className="rk-mono">{incident.id}</span>
              <span>·</span>
              <span>{incident.category}</span>
              <span>·</span>
              <SeverityBadge level={incident.severity} />
              <StatusChip status={incident.status} />
            </div>
          </div>

          <div className="flex items-center gap-5 rounded-xl border border-[#2E2822] bg-[#17130F]/80 px-4 py-3">
            <div className="text-center">
              <div className="rk-mono text-[10px] uppercase tracking-widest text-[#A7ACA2]">
                Risk
              </div>
              <div className="font-[Outfit] text-2xl font-bold text-[#C9A4AC] leading-none">
                {incident.riskScore}
              </div>
            </div>
            <div className="h-10 w-px bg-[#2E2822]" />
            <div className="text-center">
              <div className="rk-mono text-[10px] uppercase tracking-widest text-[#A7ACA2]">
                Confidence
              </div>
              <div className="font-[Outfit] text-2xl font-bold text-[#B6CCD1] leading-none">
                87%
              </div>
            </div>
          </div>
        </div>

        {/* lead paragraph */}
        <p className="mt-6 max-w-4xl text-base md:text-[17px] leading-relaxed text-[#BEB8B2]">
          <BrainCircuit className="mr-2 inline h-4 w-4 text-[#B6CCD1]" />
          RAKSHANAM connected{" "}
          <span className="font-semibold text-[#ECE7E2]">
            {incident.story.length} related events
          </span>{" "}
          across{" "}
          <span className="font-semibold text-[#ECE7E2]">
            {incident.affected.hosts.length} systems
          </span>{" "}
          and reconstructed the following sequence. Confirmed events are shown
          as facts; inferred steps are marked as{" "}
          <span className="text-[#C4BFB1]">suspected</span>.
        </p>

        {/* narrative timeline */}
        <ol className="relative mt-7 space-y-3 border-l border-[#A4BCC2]/20 pl-6">
          {incident.story.map((step, i) => {
            const isFact = step.kind === "fact";
            return (
              <motion.li
                key={i}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.06, duration: 0.35 }}
                className="group relative"
              >
                <span
                  className={`absolute -left-[33px] top-1 grid h-6 w-6 place-items-center rounded-full border ${
                    isFact
                      ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/10 text-[#B6CCD1]"
                      : "border-[#A69F88]/40 bg-[#A69F88]/10 text-[#C4BFB1]"
                  }`}
                >
                  {isFact ? (
                    <CheckCircle2 className="h-3.5 w-3.5" />
                  ) : (
                    <AlertCircle className="h-3.5 w-3.5" />
                  )}
                </span>
                <div className="rounded-xl border border-[#2E2822] bg-[#17130F]/60 p-3.5 transition-colors hover:border-[#A4BCC2]/30">
                  <div className="flex items-center gap-2">
                    <span className="rk-mono text-[10.5px] font-semibold uppercase tracking-wider text-[#C9DADE]/90">
                      {new Date(step.t).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                    <span
                      className={`rk-mono px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase tracking-wider ${
                        isFact
                          ? "border-[#A4BCC2]/40 text-[#B6CCD1] bg-[#A4BCC2]/5"
                          : "border-[#A69F88]/40 text-[#C4BFB1] bg-[#A69F88]/5"
                      }`}
                    >
                      {step.kind}
                    </span>
                    <span className="rk-mono text-[10px] text-[#8A8580]">
                      · evidence {step.logId}
                    </span>
                  </div>
                  <p className="mt-1.5 text-[14.5px] leading-relaxed text-[#D7D1CC]">
                    {step.text}
                  </p>
                </div>
              </motion.li>
            );
          })}
        </ol>

        {/* bottom actions — Instagram style */}
        <div className="mt-7 flex flex-wrap items-center justify-between gap-4 border-t border-[#2E2822] pt-5">
          <div className="flex items-center gap-1.5">
            <button
              data-testid="story-like-btn"
              onClick={toggleLike}
              className={`flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold transition active:scale-95 ${
                liked
                  ? "border-[#9F6D79]/50 bg-[#9F6D79]/10 text-[#C9A4AC]"
                  : "border-[#2E2822] bg-[#231E1C] text-[#BEB8B2] hover:text-[#C9A4AC] hover:border-[#9F6D79]/30"
              }`}
            >
              <Heart
                className={`h-3.5 w-3.5 ${liked ? "fill-[#B48892] text-[#B48892]" : ""}`}
              />
              {likes}
            </button>
            <button
              data-testid="story-bookmark-btn"
              onClick={() => setBookmarked((v) => !v)}
              className={`grid h-8 w-8 place-items-center rounded-full border transition active:scale-95 ${
                bookmarked
                  ? "border-[#A4BCC2]/50 bg-[#A4BCC2]/10 text-[#C9DADE]"
                  : "border-[#2E2822] bg-[#231E1C] text-[#BEB8B2] hover:text-[#C9DADE] hover:border-[#A4BCC2]/30"
              }`}
            >
              <Bookmark
                className={`h-3.5 w-3.5 ${bookmarked ? "fill-[#B6CCD1] text-[#B6CCD1]" : ""}`}
              />
            </button>
            <button
              data-testid="story-comment-btn"
              className="flex items-center gap-1.5 rounded-full border border-[#2E2822] bg-[#231E1C] px-3 py-1.5 text-xs font-semibold text-[#BEB8B2] transition active:scale-95 hover:border-[#A4BCC2]/30 hover:text-[#B6CCD1]"
            >
              <MessageCircle className="h-3.5 w-3.5" />4
            </button>
            <button
              data-testid="story-share-btn"
              className="grid h-8 w-8 place-items-center rounded-full border border-[#2E2822] bg-[#231E1C] text-[#BEB8B2] transition active:scale-95 hover:border-[#A4BCC2]/30 hover:text-[#B6CCD1]"
            >
              <Share2 className="h-3.5 w-3.5" />
            </button>
            <span className="ml-2 rk-mono text-[10.5px] text-[#8A8580]">
              Endorsed by 3 analysts
            </span>
          </div>

          <div className="flex items-center gap-2">
            <button
              data-testid="story-escalate-btn"
              className="flex items-center gap-1.5 rounded-full border border-[#9F6D79]/40 bg-[#9F6D79]/10 px-3.5 py-1.5 text-xs font-bold uppercase tracking-wider text-[#C9A4AC] transition active:scale-95 hover:bg-[#9F6D79]/20"
            >
              <Flame className="h-3.5 w-3.5" />
              Escalate
            </button>
            <button
              data-testid="story-mitigate-btn"
              className="flex items-center gap-1.5 rounded-full bg-gradient-to-r from-[#A4BCC2] to-[#A4BCC2] px-4 py-1.5 text-xs font-bold uppercase tracking-wider text-slate-900 shadow-[0_6px_20px_-6px_rgba(164,188,194,0.6)] transition active:scale-95 hover:brightness-110"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              Begin Mitigation
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default AttackStory;
