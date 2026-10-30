import React from "react";

const styles = {
  critical:
    "bg-[#9F6D79]/10 text-[#C9A4AC] border-[#9F6D79]/40 shadow-[0_0_12px_rgba(159,109,121,0.2)]",
  high:
    "bg-[#A69F88]/10 text-[#C4BFB1] border-[#A69F88]/40 shadow-[0_0_12px_rgba(166,159,136,0.18)]",
  medium:
    "bg-[#A4BCC2]/10 text-[#C9DADE] border-[#A4BCC2]/40 shadow-[0_0_10px_rgba(164,188,194,0.18)]",
  low:
    "bg-[#A4BCC2]/10 text-[#B6CCD1] border-[#A4BCC2]/40 shadow-[0_0_10px_rgba(164,188,194,0.15)]",
};

export const SeverityBadge = ({ level = "low", className = "" }) => {
  const key = (level || "low").toLowerCase();
  return (
    <span
      data-testid={`severity-badge-${key}`}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full border text-[10px] font-bold uppercase tracking-wider ${styles[key] || styles.low} ${className}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {key}
    </span>
  );
};

export default SeverityBadge;
