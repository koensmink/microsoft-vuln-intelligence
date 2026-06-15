import Link from "next/link";
import { getJson } from "../src/api";

type KevCve = { cve_id: string; title: string | null; product: string | null; epss_score: number | null; cvss_score: number | null; severity: string | null; required_action: string | null; due_date: string | null };

type TopEpssCve = { cve_id: string; title: string | null; epss_score: number; epss_percentile: number | null };

type Stats = {
  total_cves: number;
  total_products: number;
  latest_release: string | null;
  exploited_count: number;
  publicly_disclosed_count: number;
  total_kev_vulnerabilities: number;
  average_epss_score: number | null;
  top_epss_cves?: TopEpssCve[];
  kev_cves?: KevCve[];
};

function pct(value: number | null) {
  return value == null ? "-" : `${(value * 100).toFixed(1)}%`;
}

export default async function DashboardPage() {
  const stats = await getJson<Stats>("/stats", { total_cves: 0, total_products: 0, latest_release: null, exploited_count: 0, publicly_disclosed_count: 0, total_kev_vulnerabilities: 0, average_epss_score: null, top_epss_cves: [], kev_cves: [] });
  const kevCves = stats.kev_cves ?? [];
  const topEpssCves = stats.top_epss_cves ?? [];

  return (
    <section className="space-y-6">
      <h1 className="text-3xl font-bold">Dashboard</h1>
      <div className="grid gap-4 md:grid-cols-3">
        <div className="card"><p className="text-slate-400">Total CVEs</p><p className="text-3xl font-bold">{stats.total_cves}</p></div>
        <div className="card"><p className="text-slate-400">Total CISA KEV vulnerabilities</p><p className="text-3xl font-bold text-red-300">{stats.total_kev_vulnerabilities}</p></div>
        <div className="card"><p className="text-slate-400">Average FIRST EPSS score</p><p className="text-3xl font-bold">{pct(stats.average_epss_score)}</p></div>
      </div>
      <section className="card">
        <h2 className="text-xl font-semibold">Top 10 CVEs by FIRST EPSS score</h2>
        <table className="mt-3 w-full text-left text-sm"><thead><tr><th>CVE</th><th>Title</th><th>EPSS score</th><th>EPSS percentile</th></tr></thead><tbody>{topEpssCves.map((cve) => <tr key={cve.cve_id} className="border-t border-slate-800"><td><Link className="text-blue-400 hover:underline" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td>{cve.title ?? "Untitled"}</td><td>{pct(cve.epss_score)}</td><td>{pct(cve.epss_percentile)}</td></tr>)}</tbody></table>
      </section>
      <section className="card">
        <h2 className="text-xl font-semibold">CISA KEV CVEs</h2>
        {kevCves.length === 0 ? (
          <p className="mt-3 text-sm text-slate-400">No CISA KEV CVEs are available.</p>
        ) : (
          <table className="mt-3 w-full text-left text-sm">
            <thead><tr><th>CVE</th><th>Product</th><th>Severity</th><th>EPSS</th><th>Required action</th><th>Due date</th></tr></thead>
            <tbody>{kevCves.map((cve) => <tr key={cve.cve_id} className="border-t border-slate-800"><td><Link className="text-blue-400 hover:underline" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td>{cve.product ?? "Unknown"}</td><td>{cve.severity ?? "Unknown"}</td><td>{pct(cve.epss_score)}</td><td>{cve.required_action ?? "-"}</td><td>{cve.due_date ?? "-"}</td></tr>)}</tbody>
          </table>
        )}
      </section>
    </section>
  );
}
