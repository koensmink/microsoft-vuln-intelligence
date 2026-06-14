import Link from "next/link";
import { getJson } from "../src/api";

type CountBucket = { label: string; count: number };
type ScoreBucket = CountBucket;
type TopEpssCve = { cve_id: string; title: string | null; epss_score: number; epss_percentile: number | null };
type KevCve = {
  cve_id: string;
  title: string | null;
  product: string | null;
  epss_score: number | null;
  cvss_score: number | null;
  severity: string | null;
  required_action: string | null;
  due_date: string | null;
};

type Stats = {
  total_cves: number;
  total_products: number;
  latest_release: string | null;
  count_by_severity: Record<string, number>;
  exploited_count: number;
  publicly_disclosed_count: number;
  total_kev_vulnerabilities: number;
  average_epss_score: number | null;
  critical_cves: number;
  highest_epss_score: number | null;
  epss_at_least_1_percent: number;
  epss_at_least_10_percent: number;
  nvd_enriched_cves: number;
  cvss_at_least_9: number;
  immediate_action_count: number;
  high_priority_count: number;
  routine_count: number;
  cves_by_severity: CountBucket[];
  cves_by_release: CountBucket[];
  cves_by_impact: CountBucket[];
  kev_distribution: CountBucket[];
  cvss_score_distribution: ScoreBucket[];
  top_epss_cves: TopEpssCve[];
  kev_cves: KevCve[];
};

const emptyStats: Stats = {
  total_cves: 0,
  total_products: 0,
  latest_release: null,
  count_by_severity: {},
  exploited_count: 0,
  publicly_disclosed_count: 0,
  total_kev_vulnerabilities: 0,
  average_epss_score: null,
  critical_cves: 0,
  highest_epss_score: null,
  epss_at_least_1_percent: 0,
  epss_at_least_10_percent: 0,
  nvd_enriched_cves: 0,
  cvss_at_least_9: 0,
  immediate_action_count: 0,
  high_priority_count: 0,
  routine_count: 0,
  cves_by_severity: [],
  cves_by_release: [],
  cves_by_impact: [],
  kev_distribution: [],
  cvss_score_distribution: [],
  top_epss_cves: [],
  kev_cves: [],
};

function pct(value: number | null, digits = 2) {
  return value == null ? "-" : `${(value * 100).toFixed(digits)}%`;
}

function numberValue(value: number | null) {
  return value == null ? "-" : value.toFixed(1);
}

function KpiCard({ label, value, accent = "text-white" }: { label: string; value: string | number; accent?: string }) {
  return <div className="card"><p className="text-sm text-slate-400">{label}</p><p className={`mt-2 text-3xl font-bold ${accent}`}>{value}</p></div>;
}

function EmptyState() {
  return <p className="mt-4 rounded border border-dashed border-slate-700 p-4 text-sm text-slate-400">No data available.</p>;
}

function BarChart({ title, data, valueFormatter = (value: number) => value.toString(), horizontal = false }: { title: string; data?: CountBucket[]; valueFormatter?: (value: number) => string; horizontal?: boolean }) {
  const chartData = data ?? [];
  const max = Math.max(...chartData.map((item) => item.count), 0);
  return (
    <section className="card">
      <h2 className="text-xl font-semibold">{title}</h2>
      {chartData.length === 0 || max === 0 ? <EmptyState /> : <div className="mt-4 space-y-3">{chartData.map((item) => {
        const width = `${Math.max((item.count / max) * 100, 3)}%`;
        return <div key={item.label} className={horizontal ? "grid gap-2 md:grid-cols-[12rem_1fr_5rem] md:items-center" : "space-y-1"}>
          <div className="truncate text-sm text-slate-300" title={item.label}>{item.label}</div>
          <div className="h-6 overflow-hidden rounded bg-slate-800"><div className="h-full rounded bg-blue-500" style={{ width }} /></div>
          <div className="text-sm font-semibold text-slate-200">{valueFormatter(item.count)}</div>
        </div>;
      })}</div>}
    </section>
  );
}

export default async function DashboardPage() {
  const stats = await getJson<Stats>("/stats", emptyStats);
  const kevCves = stats.kev_cves ?? [];
  const topEpssCves = stats.top_epss_cves ?? [];

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-slate-400">Vulnerability intelligence KPIs across MSRC CVEs, FIRST EPSS, CISA KEV, and NVD enrichment.</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-4">
        <KpiCard label="Total CVEs" value={stats.total_cves} />
        <KpiCard label="Critical CVEs" value={stats.critical_cves} accent="text-red-300" />
        <KpiCard label="Publicly disclosed CVEs" value={stats.publicly_disclosed_count} accent="text-amber-300" />
        <KpiCard label="Total CISA KEV vulnerabilities" value={stats.total_kev_vulnerabilities} accent="text-red-300" />
        <KpiCard label="Average FIRST EPSS score" value={pct(stats.average_epss_score)} />
        <KpiCard label="Highest EPSS score" value={pct(stats.highest_epss_score)} accent="text-purple-300" />
        <KpiCard label="CVEs with EPSS >= 1%" value={stats.epss_at_least_1_percent} />
        <KpiCard label="CVEs with EPSS >= 10%" value={stats.epss_at_least_10_percent} />
        <KpiCard label="NVD enriched CVEs" value={stats.nvd_enriched_cves} />
        <KpiCard label="CVEs with CVSS >= 9" value={stats.cvss_at_least_9} accent="text-red-300" />
      </div>

      <section className="card">
        <h2 className="text-xl font-semibold">Risk prioritization summary</h2>
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <KpiCard label="Immediate Action" value={stats.immediate_action_count} accent="text-red-300" />
          <KpiCard label="High Priority" value={stats.high_priority_count} accent="text-amber-300" />
          <KpiCard label="Routine" value={stats.routine_count} accent="text-emerald-300" />
        </div>
      </section>

      <div className="grid gap-6 xl:grid-cols-2">
        <BarChart title="CVEs by severity" data={stats.cves_by_severity} />
        <BarChart title="CVEs by release" data={stats.cves_by_release} />
        <BarChart title="CVEs by impact" data={stats.cves_by_impact} />
        <BarChart title="KEV vs non-KEV distribution" data={stats.kev_distribution} />
        <BarChart title="CVSS score distribution" data={stats.cvss_score_distribution} />
        <BarChart title="Top 20 CVEs by FIRST EPSS score" data={topEpssCves.map((cve) => ({ label: cve.cve_id, count: cve.epss_score }))} valueFormatter={(value) => pct(value)} horizontal />
      </div>

      <section className="card overflow-x-auto">
        <h2 className="text-xl font-semibold">CISA KEV focus</h2>
        {kevCves.length === 0 ? <EmptyState /> : <table className="mt-3 w-full text-left text-sm"><thead><tr><th className="p-2">CVE</th><th className="p-2">Title</th><th className="p-2">Product</th><th className="p-2">EPSS score</th><th className="p-2">CVSS score</th><th className="p-2">Severity</th><th className="p-2">Required action</th><th className="p-2">Due date</th></tr></thead><tbody>{kevCves.map((cve) => <tr key={cve.cve_id} className="border-t border-slate-800"><td className="p-2"><Link className="text-blue-400 hover:underline" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td className="p-2">{cve.title ?? "Untitled"}</td><td className="p-2">{cve.product ?? "-"}</td><td className="p-2">{pct(cve.epss_score)}</td><td className="p-2">{numberValue(cve.cvss_score)}</td><td className="p-2">{cve.severity ?? "Unknown"}</td><td className="p-2">{cve.required_action ?? "-"}</td><td className="p-2">{cve.due_date ?? "-"}</td></tr>)}</tbody></table>}
      </section>
    </section>
  );
}
