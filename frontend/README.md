# RAKSHANAM — Autonomous Threat Correlation & Humanized Investigation

An exact replica of the RAKSHANAM SOC Command Center web application.

## 🚀 Features

- **SOC Command Center Header**: Real-time status indicators ("LIVE · 99.98% HEALTHY"), triage queue live counter, search bar for IPs/users/hosts, notification tray, and profile indicator.
- **Filtering System**: Severity filtering (All, Critical, High, Medium, Low), Incident status filtering (All, Investigating, Escalated, Resolved), and dynamic Category selector.
- **AI Attack Story**: Humanized, narrative-driven incident breakdown with contextual telemetry, sentiment/threat indicators, and action triggers (Bookmark, Like, Share, Escalate).
- **Interactive Live Telemetry Logs**: Real-time streaming log feed with pause/resume controls, log severity tags, and instant filtering.
- **Deterministic Correlation Graph**: SVG-based cyber topology correlation graph connecting actors, compromised endpoints, IP addresses, and command-and-control infrastructures with interactive node focus and zoom controls.
- **MITRE ATT&CK Chain Progression**: Progression matrix showing the kill chain (Initial Access, Reconnaissance, Lateral Movement, Exfiltration, etc.) with progression timeline charts powered by Recharts.
- **Priority Triage Queue**: Ranked queue of threat incidents displaying severity badges, MITRE tactic tags, affected asset counts, and selection sync.
- **Attack Surface Radar / Breakdown**: Visual mapping of impacted assets, risk scores, and affected protocols.
- **Threat Classification Matrix**: Distribution by attack type, vector, and threat category.
- **Historical Incident Log & Detailed Modal**: Interactive history table with full-fidelity incident inspection modal dialogs.

## 🛠️ Tech Stack

- **Framework**: React 18, Vite
- **Styling**: Tailwind CSS with custom Earth-palette design tokens:
  - `--rk-bg`: `#13100F`
  - `--rk-surface`: `#1C1817`
  - `--rk-rose`: `#9F6D79` (critical / danger accent)
  - `--rk-blue`: `#A4BCC2` (primary brand accent)
  - `--rk-taupe`: `#A69F88` (warning / secondary)
  - `--rk-sage`: `#A7ACA2` (neutral / low)
- **UI Components & Icons**: Radix UI primitives, Lucide React, Sonner toasts
- **Animations**: Framer Motion & CSS custom keyframe animations (`rk-pulse-dot`, `rk-shimmer`, `rk-edge-animated`)
- **Data Visualization**: Recharts & custom interactive SVG correlation maps

## 💻 Running Locally

### Development Server:
```bash
npm run dev
```

### Production Build:
```bash
npm run build
npm run preview
```
