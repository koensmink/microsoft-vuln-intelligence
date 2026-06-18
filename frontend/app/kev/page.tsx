import Link from "next/link";
import { getJson } from "../../src/api";

type Cve = {
  cve_id: string;
  title: string | null;
  severity: string | null;
  cvss_score: number | null;
  nvd_cvss_score: number | null;
  epss_score: number | null;
  kev_due_date: string | null;
  kev_vendor_project: string | null;
  kev_product: string | null;
  kev_required_action: string | null;
};

function pct(value: number | null | undefined) {
  return typeof value === "number" && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : "—";
}

function cvss(cve: Cve) {
  const score = cve.nvd_cvss_score ?? cve.cvss_score;
  return typeof score === "number" && Number.isFinite(score) ? score.toFixed(1) : "—";
}

function truncate(value: string | null | undefined, max = 96) {
  if (!value) return "—";
  return value.length > max ? `${value.slice(0, max).trimEnd()}…` : value;
}

export default async function KevPage() {
  const cves = await getJson<Cve[]>("/cves?kev_only=true&limit=500", []);
  const items = cves ?? [];

  return (
    <section className="space-y-6">
      <header className="rounded-3xl border border-fuchsia-400/20 bg-[radial-gradient(circle_at_top_left,rgba(217,70,239,0.18),transparent_35%),linear-gradient(135deg,rgba(15,23,42,0.95),rgba(2,6,23,0.95))] p-6 shadow-2xl shadow-fuchsia-950/20">
        <p className="text-sm font-semibold uppercase tracking-[0.35em] text-fuchsia-300">CISA Known Exploited Vulnerabilities</p>
        <h1 className="mt-3 text-4xl font-black tracking-tight">KEV Catalog</h1>
        <p className="mt-3 max-w-3xl text-slate-300">Microsoft CVEs matched to CISA KEV entries. Rows link to CVE detail pages.</p>
      </header>
      <div className="card overflow-x-auto">
        <table className="data-table">
          <thead><tr><th>CVE</th><th>Vendor / product</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Required action</th><th>Due date</th></tr></thead>
          <tbody>
            {items.length === 0 ? (
              <tr><td className="py-6 text-center text-slate-400" colSpan={7}>No CISA KEV vulnerabilities are available.</td></tr>
            ) : items.map((cve) => (
              <tr key={cve.cve_id}>
                <td><Link className="link" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td>
                <td>{cve.kev_vendor_project ?? "Unknown"} / {cve.kev_product ?? "Unknown"}</td>
                <td>{cve.severity ?? "Unknown"}</td>
                <td>{cvss(cve)}</td>
                <td>{pct(cve.epss_score)}</td>
                <td title={cve.kev_required_action ?? undefined}>{truncate(cve.kev_required_action)}</td>
                <td>{cve.kev_due_date ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
