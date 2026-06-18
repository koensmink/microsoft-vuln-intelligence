import Link from "next/link";
import { getJson } from "../../src/api";

type Cve = { id: number; cve_id: string; title: string | null; severity: string | null; cvss_score: number | null; epss_score: number | null; epss_percentile: number | null; kev_known_exploited: boolean; nvd_cvss_score: number | null; exploited: boolean; publicly_disclosed: boolean; affected_product_count: number | null; priority: string | null; impact: string | null; release: { release_name: string } | null };
function pct(value: number | null | undefined) { return value == null ? "—" : `${(value * 100).toFixed(1)}%`; }
function score(value: number | null | undefined) { return value == null ? "—" : value.toFixed(1); }
function asBool(value: string | undefined) { return value === "true" ? true : value === "false" ? false : undefined; }
function inCvssBucket(score: number | null, bucket: string | undefined) { if (!bucket || score == null) return true; const numbers = bucket.match(/\d+(?:\.\d+)?/g)?.map(Number) ?? []; if (numbers.length >= 2) return score >= numbers[0] && score <= numbers[1]; if (/critical/i.test(bucket)) return score >= 9; if (/high/i.test(bucket)) return score >= 7 && score < 9; if (/medium|moderate/i.test(bucket)) return score >= 4 && score < 7; if (/low/i.test(bucket)) return score > 0 && score < 4; return true; }
function Chip({ label, value }: { label: string; value: string }) { return <span className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-3 py-1 text-xs font-semibold text-cyan-100"><span className="text-slate-400">{label}:</span> {value}</span>; }

export default async function CvesPage({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const params = await searchParams;
  const qs = new URLSearchParams();
  const severity = params.severity;
  const release = params.release ?? params.release_name;
  const minEpss = params.epss === "high" ? "0.10" : params.min_epss ?? params.min_epss_score;
  const minCvss = params.min_cvss ?? params.min_cvss_score;
  const kev = params.kev ?? params.kev_only;
  for (const key of ["search", "severity", "exploited", "publicly_disclosed"]) if (params[key]) qs.set(key, params[key]!);
  if (release) qs.set("release_name", release);
  if (minEpss) qs.set("min_epss_score", minEpss);
  if (minCvss) qs.set("min_cvss_score", minCvss);
  if (kev === "true") qs.set("kev_only", "true");
  const apiCves = await getJson<Cve[]>(`/cves${qs.size ? `?${qs}` : ""}`, []);
  const filteredCves = (apiCves ?? []).filter((cve) => {
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
    if (params.nvd === "missing" && cve.nvd_cvss_score != null) return false;
    return true;
  });
  const cves = params.sort === "cvss" ? [...filteredCves].sort((a, b) => (b.nvd_cvss_score ?? b.cvss_score ?? -1) - (a.nvd_cvss_score ?? a.cvss_score ?? -1)) : filteredCves;
  const activeFilters = [["Search", params.search], ["Severity", severity], ["Release", release], ["Exploited", params.exploited], ["Public", params.publicly_disclosed], ["KEV", kev === "true" ? "CISA KEV only" : undefined], ["Min EPSS", minEpss], ["Min CVSS", minCvss], ["Impact", params.impact], ["CVSS bucket", params.cvss_bucket], ["Priority", params.priority], ["NVD", params.nvd], ["Sort", params.sort]].filter(([, value]) => Boolean(value));

  return <section className="space-y-6"><div className="rounded-3xl border border-slate-800 bg-slate-900/70 p-6"><p className="text-xs font-semibold uppercase tracking-[0.3em] text-cyan-300">CVE Explorer</p><div className="mt-2 flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between"><div><h1 className="text-3xl font-black tracking-tight">Vulnerabilities</h1><p className="mt-2 max-w-3xl text-slate-400">Browse MSRC CVRF vulnerabilities enriched with FIRST EPSS, CISA KEV, and NVD data when available.</p></div><div className="rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 text-sm"><span className="text-slate-400">Showing</span> <span className="font-bold text-cyan-200">{cves.length.toLocaleString("en-US")}</span> <span className="text-slate-400">of {(apiCves ?? []).length.toLocaleString("en-US")}</span></div></div></div>
    <form className="card grid gap-3 md:grid-cols-4"><input className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="search" placeholder="Search CVE, title, product" defaultValue={params.search} /><select className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="severity" defaultValue={severity ?? ""}><option value="">Any severity</option><option>Critical</option><option>Important</option><option>Moderate</option><option>Low</option></select><select className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="exploited" defaultValue={params.exploited ?? ""}><option value="">MSRC exploited?</option><option value="true">Yes</option><option value="false">No</option></select><select className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="publicly_disclosed" defaultValue={params.publicly_disclosed ?? ""}><option value="">Publicly disclosed?</option><option value="true">Yes</option><option value="false">No</option></select><input className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="release" placeholder="Release" defaultValue={release} /><label className="flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-950 p-3"><input type="checkbox" name="kev" value="true" defaultChecked={kev === "true"} /> CISA KEV only</label><input className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="min_epss" type="number" min="0" max="1" step="0.01" placeholder="Min FIRST EPSS" defaultValue={minEpss} /><input className="rounded-xl border border-slate-800 bg-slate-950 p-3" name="min_cvss" type="number" min="0" max="10" step="0.1" placeholder="Min CVSS" defaultValue={minCvss} /><button className="rounded-xl bg-cyan-500 p-3 font-bold text-slate-950 hover:bg-cyan-400" type="submit">Apply filters</button><Link className="rounded-xl border border-slate-700 p-3 text-center font-semibold text-slate-300 hover:bg-slate-800" href="/cves">Clear filters</Link></form>
    <div className="flex flex-wrap gap-2">{activeFilters.length === 0 ? <span className="text-sm text-slate-500">No active filters. Use the controls above or dashboard drill-down links to refine results.</span> : activeFilters.map(([label, value]) => <Chip key={`${label}-${value}`} label={label ?? "Filter"} value={value ?? ""} />)}</div>
    <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-900/70"><table className="data-table min-w-[980px]"><thead><tr>{["CVE ↕", "Title", "Release ↕", "Products", "Severity ↕", "CVSS ↕", "EPSS ↕", "Percentile", "Signals"].map((h) => <th className="px-4 pt-4" key={h}>{h}</th>)}</tr></thead><tbody>{cves.length === 0 ? <tr><td className="p-8 text-center text-slate-400" colSpan={9}>No CVEs match the selected filters. Clear filters or broaden the query.</td></tr> : cves.map((cve) => <tr key={cve.cve_id} className="hover:bg-slate-800/50"><td className="px-4"><Link className="link" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td className="px-4"><span className="line-clamp-2">{cve.title ?? "Untitled"}</span></td><td className="px-4">{cve.release?.release_name ?? "—"}</td><td className="px-4">{cve.affected_product_count ?? "—"}</td><td className="px-4"><span className="rounded-full bg-slate-800 px-2 py-1 text-xs font-semibold">{cve.severity ?? "Unknown"}</span></td><td className="px-4 tabular-nums">{score(cve.nvd_cvss_score ?? cve.cvss_score)}</td><td className="px-4 tabular-nums">{pct(cve.epss_score)}</td><td className="px-4 tabular-nums">{pct(cve.epss_percentile)}</td><td className="px-4">{cve.kev_known_exploited ? <span className="rounded bg-red-600 px-2 py-1 text-xs font-bold text-white">CISA KEV</span> : cve.exploited ? <span className="rounded bg-orange-500/20 px-2 py-1 text-xs font-bold text-orange-200">MSRC exploited</span> : "—"}</td></tr>)}</tbody></table></div></section>;
}
