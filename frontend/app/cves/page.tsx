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
  priority: string | null;
  impact: string | null;
  release: { release_name: string } | null;
};

function pct(value: number | null) {
  return value == null ? "-" : `${(value * 100).toFixed(1)}%`;
}
function asBool(value: string | undefined) { return value === "true" ? true : value === "false" ? false : undefined; }
function inCvssBucket(score: number | null, bucket: string | undefined) {
  if (!bucket || score == null) return true;
  const numbers = bucket.match(/\d+(?:\.\d+)?/g)?.map(Number) ?? [];
  if (numbers.length >= 2) return score >= numbers[0] && score <= numbers[1];
  if (/critical/i.test(bucket)) return score >= 9;
  if (/high/i.test(bucket)) return score >= 7 && score < 9;
  if (/medium|moderate/i.test(bucket)) return score >= 4 && score < 7;
  if (/low/i.test(bucket)) return score > 0 && score < 4;
  return true;
}

export default async function CvesPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const params = await searchParams;
  const qs = new URLSearchParams();
  const severity = params.severity;
  const release = params.release ?? params.release_name;
  const minEpss = params.min_epss ?? params.min_epss_score;
  const minCvss = params.min_cvss ?? params.min_cvss_score;
  const kev = params.kev ?? params.kev_only;
  for (const key of ["search", "severity", "exploited", "publicly_disclosed"]) {
    if (params[key]) qs.set(key, params[key]!);
  }
  if (release) qs.set("release_name", release);
  if (minEpss) qs.set("min_epss_score", minEpss);
  if (minCvss) qs.set("min_cvss_score", minCvss);
  if (kev === "true") qs.set("kev_only", "true");
  const apiCves = await getJson<Cve[]>(`/cves${qs.size ? `?${qs}` : ""}`, []);
  const cves = (apiCves ?? []).filter((cve) => {
    if (severity && cve.severity !== severity) return false;
    if (params.impact && cve.impact !== params.impact) return false;
    if (release && cve.release?.release_name !== release) return false;
    if (kev === "true" && !cve.kev_known_exploited) return false;
    if (minEpss && (cve.epss_score ?? 0) < Number(minEpss)) return false;
    if (minCvss && (cve.nvd_cvss_score ?? cve.cvss_score ?? 0) < Number(minCvss)) return false;
    if (!inCvssBucket(cve.nvd_cvss_score ?? cve.cvss_score, params.cvss_bucket)) return false;
    if (asBool(params.publicly_disclosed) !== undefined && cve.publicly_disclosed !== asBool(params.publicly_disclosed)) return false;
    if (asBool(params.exploited) !== undefined && cve.exploited !== asBool(params.exploited)) return false;
    if (params.priority && cve.priority !== params.priority) return false;
    return true;
  });

  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Vulnerabilities</h1>
        <p className="text-slate-400">MSRC CVRF vulnerabilities enriched with FIRST EPSS, CISA KEV, and NVD data when available.</p>
      </div>
      <form className="grid gap-3 rounded border border-slate-800 p-4 md:grid-cols-4">
        <input className="rounded bg-slate-900 p-2" name="search" placeholder="Search CVE, title, product" defaultValue={params.search} />
        <select className="rounded bg-slate-900 p-2" name="severity" defaultValue={severity ?? ""}><option value="">Any severity</option><option>Critical</option><option>Important</option><option>Moderate</option><option>Low</option></select>
        <select className="rounded bg-slate-900 p-2" name="exploited" defaultValue={params.exploited ?? ""}><option value="">MSRC exploited?</option><option value="true">Yes</option><option value="false">No</option></select>
        <select className="rounded bg-slate-900 p-2" name="publicly_disclosed" defaultValue={params.publicly_disclosed ?? ""}><option value="">Publicly disclosed?</option><option value="true">Yes</option><option value="false">No</option></select>
        <input className="rounded bg-slate-900 p-2" name="release" placeholder="Release" defaultValue={release} />
        <label className="flex items-center gap-2 rounded bg-slate-900 p-2"><input type="checkbox" name="kev" value="true" defaultChecked={kev === "true"} /> CISA KEV only</label>
        <input className="rounded bg-slate-900 p-2" name="min_epss" type="number" min="0" max="1" step="0.01" placeholder="Min FIRST EPSS" defaultValue={minEpss} />
        <input className="rounded bg-slate-900 p-2" name="min_cvss" type="number" min="0" max="10" step="0.1" placeholder="Min NVD CVSS" defaultValue={minCvss} />
        <button className="rounded bg-blue-600 p-2 font-semibold" type="submit">Apply filters</button>
      </form>
      <div className="overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-300"><tr><th className="p-3">CVE</th><th className="p-3">Title</th><th className="p-3">Release</th><th className="p-3">Products</th><th className="p-3">Severity</th><th className="p-3">NVD CVSS</th><th className="p-3">FIRST EPSS</th><th className="p-3">EPSS percentile</th><th className="p-3">CISA KEV</th></tr></thead>
          <tbody>{cves.length === 0 ? <tr><td className="p-6 text-center text-slate-400" colSpan={9}>No CVEs match the selected filters.</td></tr> : cves.map((cve) => <tr key={cve.cve_id} className="border-t border-slate-800"><td className="p-3"><Link className="text-blue-400 hover:underline" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td className="p-3">{cve.title ?? "Untitled"}</td><td className="p-3">{cve.release?.release_name ?? "-"}</td><td className="p-3">{cve.affected_product_count ?? "-"}</td><td className="p-3">{cve.severity ?? "Unknown"}</td><td className="p-3">{cve.nvd_cvss_score ?? "-"}</td><td className="p-3">{pct(cve.epss_score)}</td><td className="p-3">{pct(cve.epss_percentile)}</td><td className="p-3">{cve.kev_known_exploited ? <span className="rounded bg-red-600 px-2 py-1 text-xs font-bold text-white">CISA KEV</span> : "-"}</td></tr>)}</tbody>
        </table>
      </div>
    </section>
  );
}
