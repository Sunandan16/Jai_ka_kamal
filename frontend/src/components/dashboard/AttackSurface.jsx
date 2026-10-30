import React from "react";
import { Server, Users, Globe2, HardDrive } from "lucide-react";

const Stat = ({ icon: Icon, label, value, tone = "teal" }) => {
  const toneCls = {
    teal: "text-[#B6CCD1] border-[#A4BCC2]/30 bg-[#A4BCC2]/5",
    cyan: "text-[#C9DADE] border-[#A4BCC2]/30 bg-[#A4BCC2]/5",
    rose: "text-[#C9A4AC] border-[#9F6D79]/30 bg-[#9F6D79]/5",
    amber: "text-[#C4BFB1] border-[#A69F88]/30 bg-[#A69F88]/5",
  }[tone];
  return (
    <div className={`rounded-xl border p-3 ${toneCls}`}>
      <div className="flex items-center gap-1.5">
        <Icon className="h-3.5 w-3.5" />
        <span className="rk-mono text-[10px] uppercase tracking-widest">
          {label}
        </span>
      </div>
      <div className="mt-1 font-[Outfit] text-2xl font-bold leading-none">
        {value}
      </div>
    </div>
  );
};

export const AttackSurface = ({ incident }) => {
  const users = incident.affected.users;
  const ips = incident.affected.ips;
  const hosts = incident.affected.hosts;

  return (
    <section
      data-testid="attack-surface-section"
      className="rounded-2xl border border-[#2E2822] bg-[#1C1817] p-5"
    >
      <h2 className="font-[Outfit] text-lg font-bold text-[#ECE7E2]">
        Attack Surface
      </h2>
      <div className="rk-mono mt-0.5 text-[10px] uppercase tracking-widest text-[#8A8580]">
        Affected assets for {incident.id}
      </div>

      <div className="mt-3 grid grid-cols-2 gap-2">
        <Stat icon={Users} label="Accounts" value={users.length} tone="rose" />
        <Stat icon={Globe2} label="IPs" value={ips.length} tone="amber" />
        <Stat icon={Server} label="Hosts" value={hosts.length} tone="cyan" />
        <Stat
          icon={HardDrive}
          label="Services"
          value={new Set(hosts.map((h) => h.split("-")[0])).size}
          tone="teal"
        />
      </div>

      <div className="mt-4 space-y-2.5 text-[12px]">
        <div>
          <div className="rk-mono text-[10px] uppercase tracking-widest text-[#8A8580]">
            Users
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {users.map((u) => (
              <span
                key={u}
                className="rk-mono rounded-md border border-[#9F6D79]/30 bg-[#9F6D79]/10 px-2 py-0.5 text-[10.5px] text-[#DDC0C6]"
              >
                {u}
              </span>
            ))}
          </div>
        </div>
        <div>
          <div className="rk-mono text-[10px] uppercase tracking-widest text-[#8A8580]">
            Suspicious IPs
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {ips.map((u) => (
              <span
                key={u}
                className="rk-mono rounded-md border border-[#A69F88]/30 bg-[#A69F88]/10 px-2 py-0.5 text-[10.5px] text-[#D3CFC6]"
              >
                {u}
              </span>
            ))}
          </div>
        </div>
        <div>
          <div className="rk-mono text-[10px] uppercase tracking-widest text-[#8A8580]">
            Hosts
          </div>
          <div className="mt-1 flex flex-wrap gap-1">
            {hosts.map((u) => (
              <span
                key={u}
                className="rk-mono rounded-md border border-[#A4BCC2]/30 bg-[#A4BCC2]/10 px-2 py-0.5 text-[10.5px] text-[#DBE6E9]"
              >
                {u}
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default AttackSurface;
