import { Suspense } from "react";
import Link from "next/link";
import { getJson } from "../src/api";
import { SidebarNav } from "./components/sidebar-nav";
import "./globals.css";

export const metadata = { title: "Microsoft Vulnerability Intelligence" };

type ShellStats = {
  total_cves?: number | null;
  nvd_enriched_cves?: number | null;
  epss_enriched_cves?: number | null;
  total_kev_vulnerabilities?: number | null;
};

const navItems = [
  { href: "/", label: "Overview", icon: "◇" },
  { href: "/cves", label: "CVE Explorer", icon: "⌕" },
  { href: "/releases", label: "Releases", icon: "▣" },
  { href: "/kev", label: "KEV Catalog", icon: "✦" },
  { href: "/cves?epss=high", label: "EPSS Insights", icon: "⌁" },
  { href: "/reports", label: "Reports", icon: "▤" },
  { href: "/settings", label: "Settings", icon: "⚙" },
];

function safeNumber(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function formatCount(value: number | null | undefined) {
  return safeNumber(value).toLocaleString("en-US");
}

function SourceStatus({ label, count }: { label: string; count: number | null | undefined }) {
  const active = safeNumber(count) > 0;
  return (
    <div className="flex items-center justify-between gap-3 rounded-xl border border-slate-800 bg-slate-950/70 px-3 py-2">
      <span className="truncate text-slate-300">{label}</span>
      <span className="flex items-center gap-2 text-slate-500">
        <span className={`h-2.5 w-2.5 rounded-full ${active ? "bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.8)]" : "bg-slate-600"}`} />
        <span className="tabular-nums">{formatCount(count)}</span>
      </span>
    </div>
  );
}

function DataSourcesCard({ stats }: { stats: ShellStats }) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 text-xs text-slate-400">
      <p className="font-semibold uppercase tracking-[0.2em] text-slate-500">Data Sources</p>
      <div className="mt-3 space-y-2">
        <SourceStatus label="Microsoft MSRC" count={stats.total_cves} />
        <SourceStatus label="NVD" count={stats.nvd_enriched_cves} />
        <SourceStatus label="EPSS" count={stats.epss_enriched_cves} />
        <SourceStatus label="CISA KEV" count={stats.total_kev_vulnerabilities} />
      </div>
    </section>
  );
}

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const stats = await getJson<ShellStats>("/stats", {});

  return (
    <html lang="en" className="dark">
      <body>
        <div className="min-h-screen bg-[#020817] text-slate-100">
          <aside className="fixed inset-y-0 left-0 z-30 hidden w-72 flex-col border-r border-cyan-400/10 bg-slate-950/95 px-5 py-6 shadow-2xl shadow-cyan-950/20 backdrop-blur lg:flex">
            <div className="min-h-0 flex-1 overflow-y-auto pr-1">
              <Link className="flex items-center gap-3" href="/">
                <span className="grid h-11 w-11 place-items-center rounded-2xl border border-cyan-300/30 bg-cyan-400/10 text-cyan-200">MS</span>
                <span>
                  <span className="block text-sm font-black uppercase tracking-[0.22em] text-cyan-100">Vuln Intel</span>
                  <span className="text-xs text-slate-500">Security Operations</span>
                </span>
              </Link>
              <Suspense fallback={<nav className="mt-10" />}><SidebarNav items={navItems} /></Suspense>
            </div>
            <div className="mt-6 shrink-0">
              <DataSourcesCard stats={stats} />
            </div>
          </aside>
          <header className="border-b border-slate-800/80 bg-slate-950/95 px-4 py-4 lg:hidden">
            <Link className="flex items-center gap-3" href="/">
              <span className="grid h-10 w-10 place-items-center rounded-2xl border border-cyan-300/30 bg-cyan-400/10 text-sm text-cyan-200">MS</span>
              <span>
                <span className="block text-sm font-black uppercase tracking-[0.22em] text-cyan-100">Vuln Intel</span>
                <span className="text-xs text-slate-500">Security Operations</span>
              </span>
            </Link>
            <Suspense fallback={<nav className="mt-4" />}><SidebarNav items={navItems} variant="mobile" /></Suspense>
          </header>
          <main className="min-w-0 px-4 py-4 sm:px-6 lg:ml-72 lg:px-8">{children}</main>
        </div>
      </body>
    </html>
  );
}
