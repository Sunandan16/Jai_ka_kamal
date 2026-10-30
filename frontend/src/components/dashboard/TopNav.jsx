import React from "react";
import { Shield, Activity, Bell, Search } from "lucide-react";
import { Input } from "@/components/ui/input";

export const TopNav = ({ liveCount = 0 }) => {
  return (
    <header className="sticky top-0 z-40 border-b border-[#2E2822] bg-[#13100F]/85 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-[1600px] items-center gap-6 px-6">
        <div className="flex items-center gap-2.5" data-testid="brand-logo">
          <div className="relative grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-[#A4BCC2]/30 to-[#A4BCC2]/20 border border-[#A4BCC2]/40">
            <Shield className="h-5 w-5 text-[#B6CCD1]" strokeWidth={2.2} />
            <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 rounded-full bg-[#B6CCD1] rk-pulse-dot" />
          </div>
          <div className="leading-tight">
            <div className="font-[Outfit] text-[17px] font-bold tracking-tight text-[#ECE7E2]">
              RAKSHANAM
            </div>
            <div className="rk-mono text-[9.5px] uppercase tracking-[0.22em] text-[#B6CCD1]/80">
              Threat Correlation Suite
            </div>
          </div>
        </div>

        <div className="hidden md:flex items-center gap-2 rounded-full border border-[#A4BCC2]/30 bg-[#A4BCC2]/5 px-3 py-1">
          <span className="h-2 w-2 rounded-full bg-[#A4BCC2] rk-pulse-dot" />
          <span className="rk-mono text-[10.5px] font-semibold tracking-wider text-[#C9DADE]">
            LIVE · 99.98% HEALTHY
          </span>
        </div>

        <div className="hidden lg:flex items-center gap-2 rounded-full border border-[#2E2822] bg-[#1C1817] px-3 py-1">
          <Activity className="h-3.5 w-3.5 text-[#C9DADE]" />
          <span className="rk-mono text-[10.5px] tracking-wider text-[#BEB8B2]">
            TRIAGE QUEUE · <span className="font-bold text-[#C9DADE]">{liveCount}</span>
          </span>
        </div>

        <div className="ml-auto flex items-center gap-3">
          <div className="relative hidden md:block w-64">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#8A8580]" />
            <Input
              data-testid="global-search-input"
              placeholder="Search IPs, users, hosts…"
              className="h-9 rounded-full border-[#2E2822] bg-[#1C1817] pl-9 text-sm text-[#D7D1CC] placeholder:text-[#8A8580] focus-visible:ring-[#A4BCC2]/40"
            />
          </div>
          <button
            data-testid="notifications-btn"
            className="relative grid h-9 w-9 place-items-center rounded-full border border-[#2E2822] bg-[#1C1817] text-[#BEB8B2] hover:text-[#B6CCD1] hover:border-[#A4BCC2]/40 transition"
          >
            <Bell className="h-4 w-4" />
            <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-[#B48892]" />
          </button>
          <div className="h-9 w-9 rounded-full border border-[#A4BCC2]/30 bg-gradient-to-br from-[#A4BCC2]/20 to-[#A4BCC2]/10 grid place-items-center font-[Outfit] text-sm font-bold text-[#C9DADE]">
            NA
          </div>
        </div>
      </div>
    </header>
  );
};

export default TopNav;
