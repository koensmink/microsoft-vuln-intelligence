import Link from "next/link";
import { getJson } from "../../src/api";

type Cve = {
  id: number;
  cve_id: string;
  title: string | null;
  severity: string | null;
  cvss_score: number | null;
  epss_score: number | null;
  epss_percentile: number | null;
  kev_known_exploited: boolean;
  nvd_cvss_score: number | null;
  exploited: boolean;
  publicly_disclosed: boolean;
  affected_product_count: number | null;
  release: { release_name: string } | null;
};

function pct(value: number | null) {
  return value == null ? "-" : `${(value * 100).toFixed(1)}%`;
}

export default async function CvesPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const params = await searchParams;
  const qs = new URLSearchParams();
  for (const key of ["search", "severity", "exploited", "publicly_disclosed", "release_name", "min_epss_score", "min_cvss_score"]) {
    if (params[key]) qs.set(key, params[key]!);
  }
  if (params.kev_only === "true") qs.set("kev_only", "true");
  const cves = await getJson<Cve[]>(`/cves${qs.size ? `?${qs}` : ""}`, []);

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Vulnerabilities</h1>
        <p className="text-slate-400">MSRC CVRF vulnerabilities enriched with FIRST EPSS, CISA KEV, and NVD data when available.</p>
      </div>
      <form className="grid gap-3 rounded border border-slate-800 p-4 md:grid-cols-4">
        <input className="rounded bg-slate-900 p-2" name="search" placeholder="Search CVE, title, product" defaultValue={params.search} />
        <select className="rounded bg-slate-900 p-2" name="severity" defaultValue={params.severity ?? ""}><option value="">Any severity</option><option>Critical</option><option>Important</option><option>Moderate</option><option>Low</option></select>
        <select className="rounded bg-slate-900 p-2" name="exploited" defaultValue={params.exploited ?? ""}><option value="">MSRC exploited?</option><option value="true">Yes</option><option value="false">No</option></select>
        <select className="rounded bg-slate-900 p-2" name="publicly_disclosed" defaultValue={params.publicly_disclosed ?? ""}><option value="">Publicly disclosed?</option><option value="true">Yes</option><option value="false">No</option></select>
        <input className="rounded bg-slate-900 p-2" name="release_name" placeholder="Release" defaultValue={params.release_name} />
        <label className="flex items-center gap-2 rounded bg-slate-900 p-2"><input type="checkbox" name="kev_only" value="true" defaultChecked={params.kev_only === "true"} /> CISA KEV only</label>
        <input className="rounded bg-slate-900 p-2" name="min_epss_score" type="number" min="0" max="1" step="0.01" placeholder="Min FIRST EPSS" defaultValue={params.min_epss_score} />
        <input className="rounded bg-slate-900 p-2" name="min_cvss_score" type="number" min="0" max="10" step="0.1" placeholder="Min NVD CVSS" defaultValue={params.min_cvss_score} />
        <button className="rounded bg-blue-600 p-2 font-semibold" type="submit">Apply filters</button>
      </form>
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-300"><tr><th className="p-3">CVE</th><th className="p-3">Title</th><th className="p-3">Release</th><th className="p-3">Products</th><th className="p-3">Severity</th><th className="p-3">NVD CVSS</th><th className="p-3">FIRST EPSS</th><th className="p-3">EPSS percentile</th><th className="p-3">CISA KEV</th></tr></thead>
          <tbody>{cves.map((cve) => <tr key={cve.cve_id} className="border-t border-slate-800"><td className="p-3"><Link className="text-blue-400 hover:underline" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td className="p-3">{cve.title ?? "Untitled"}</td><td className="p-3">{cve.release?.release_name ?? "-"}</td><td className="p-3">{cve.affected_product_count ?? "-"}</td><td className="p-3">{cve.severity ?? "Unknown"}</td><td className="p-3">{cve.nvd_cvss_score ?? "-"}</td><td className="p-3">{pct(cve.epss_score)}</td><td className="p-3">{pct(cve.epss_percentile)}</td><td className="p-3">{cve.kev_known_exploited ? <span className="rounded bg-red-600 px-2 py-1 text-xs font-bold text-white">CISA KEV</span> : "-"}</td></tr>)}</tbody>
        </table>
      </div>
    </section>
  );
}
