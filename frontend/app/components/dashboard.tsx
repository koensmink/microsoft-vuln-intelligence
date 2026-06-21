import Link from "next/link";

export type CountBucket = { label: string | null; count: number | null };
export type KevCve = { cve_id: string; title: string | null; product: string | null; epss_score: number | null; cvss_score: number | null; severity: string | null; required_action: string | null; due_date: string | null };
export type TopEpssCve = { cve_id: string; title: string | null; epss_score: number | null; epss_percentile: number | null };
export type StatsTimeseriesPoint = { label: string; release_date: string | null; total_cves: number; critical_cves: number; high_epss_count: number; kev_count: number; average_cvss_score: number | null };

export type Stats = {
  total_cves?: number | null; total_products?: number | null; latest_release?: string | null; exploited_count?: number | null; publicly_disclosed_count?: number | null;
  total_kev_vulnerabilities?: number | null; average_epss_score?: number | null; average_cvss_score?: number | null; highest_epss_score?: number | null; epss_enriched_cves?: number | null; epss_at_least_10_percent?: number | null;
  nvd_enriched_cves?: number | null; impact_known_cves?: number | null; critical_cves?: number | null; immediate_action_count?: number | null; high_priority_count?: number | null; routine_count?: number | null;
  cves_by_severity?: CountBucket[] | null; cves_by_release?: CountBucket[] | null; cves_by_impact?: CountBucket[] | null; kev_distribution?: CountBucket[] | null; cvss_score_distribution?: CountBucket[] | null;
  top_epss_cves?: TopEpssCve[] | null; kev_cves?: KevCve[] | null;
};

type Tone = "blue" | "red" | "orange" | "purple" | "green" | "yellow";

const toneStyles: Record<Tone, { text: string; bg: string; bgSoft: string; border: string; fill: string; shadow: string }> = {
  blue: { text: "text-cyan-200", bg: "bg-cyan-400", bgSoft: "bg-cyan-400/70", border: "border-cyan-300/35", fill: "#38bdf8", shadow: "shadow-cyan-500/10" },
  red: { text: "text-rose-200", bg: "bg-rose-400", bgSoft: "bg-rose-400/70", border: "border-rose-300/35", fill: "#fb7185", shadow: "shadow-rose-500/10" },
  orange: { text: "text-orange-200", bg: "bg-orange-400", bgSoft: "bg-orange-400/70", border: "border-orange-300/35", fill: "#fb923c", shadow: "shadow-orange-500/10" },
  purple: { text: "text-violet-200", bg: "bg-violet-400", bgSoft: "bg-violet-400/70", border: "border-violet-300/35", fill: "#a78bfa", shadow: "shadow-violet-500/10" },
  green: { text: "text-emerald-200", bg: "bg-emerald-400", bgSoft: "bg-emerald-400/70", border: "border-emerald-300/35", fill: "#34d399", shadow: "shadow-emerald-500/10" },
  yellow: { text: "text-amber-200", bg: "bg-amber-300", bgSoft: "bg-amber-300/70", border: "border-amber-300/35", fill: "#facc15", shadow: "shadow-amber-500/10" },
};

const severityColors: Record<string, string> = { Critical: "#fb7185", Important: "#fb923c", High: "#fb923c", Moderate: "#facc15", Low: "#3b82f6", Unknown: "#64748b", None: "#64748b" };
const palette = ["#38bdf8", "#a78bfa", "#f472b6", "#2dd4bf", "#facc15", "#fb923c", "#34d399"];

export const emptyStats: Stats = { total_cves: 0, total_products: 0, latest_release: null, exploited_count: 0, publicly_disclosed_count: 0, total_kev_vulnerabilities: 0, average_epss_score: null, average_cvss_score: null, highest_epss_score: null, epss_enriched_cves: 0, epss_at_least_10_percent: 0, nvd_enriched_cves: 0, impact_known_cves: 0, critical_cves: 0, immediate_action_count: 0, high_priority_count: 0, routine_count: 0, cves_by_severity: [], cves_by_release: [], cves_by_impact: [], kev_distribution: [], cvss_score_distribution: [], top_epss_cves: [], kev_cves: [] };

export function safeNumber(value: number | null | undefined) { return typeof value === "number" && Number.isFinite(value) ? value : 0; }
export function formatCount(value: number | null | undefined) { return safeNumber(value).toLocaleString("en-US"); }
export function formatPct(value: number | null | undefined) { return typeof value === "number" && Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : "—"; }
export function formatCvss(value: number | null | undefined) { return typeof value === "number" && Number.isFinite(value) ? value.toFixed(1) : "—"; }

function normalizeBuckets(buckets: CountBucket[] | null | undefined) { return (buckets ?? []).map((bucket) => ({ label: bucket?.label ?? "Unknown", count: safeNumber(bucket?.count) })); }
function formatTruncated(value: string | null | undefined, maxLength = 78) { return !value ? "—" : value.length > maxLength ? `${value.slice(0, maxLength).trimEnd()}…` : value; }
function colorFor(label: string, index: number) { return severityColors[label] ?? palette[index % palette.length]; }

function Sparkline({ tone, values = [] }: { tone: Tone; values?: Array<number | null | undefined> }) {
  const stroke = toneStyles[tone].fill;
  const numericValues = values.filter((value): value is number => typeof value === "number" && Number.isFinite(value));

  if (numericValues.length < 2) {
    return <div className="mt-3 h-11 w-full" aria-label="Not enough release history for trend"><svg viewBox="0 0 160 42" className="h-full w-full overflow-visible" role="img" aria-label="No trend available"><line x1="8" y1="24" x2="152" y2="24" stroke="#64748b" strokeWidth="2" strokeLinecap="round" strokeDasharray="2 7" opacity="0.45" /><circle cx="80" cy="24" r="3" fill="#94a3b8" opacity="0.5" /></svg></div>;
  }

  const width = 160;
  const height = 42;
  const paddingX = 4;
  const paddingY = 6;
  const min = Math.min(...numericValues);
  const max = Math.max(...numericValues);
  const range = max - min;
  const points = numericValues.map((value, index) => {
    const x = paddingX + (index / (numericValues.length - 1)) * (width - paddingX * 2);
    const normalized = range === 0 ? 0.5 : (value - min) / range;
    const y = height - paddingY - normalized * (height - paddingY * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const areaPath = `M${points.replaceAll(" ", " L")} L${width - paddingX},${height} L${paddingX},${height} Z`;

  return <div className="mt-3 h-11 w-full"><svg viewBox="0 0 160 42" className="h-full w-full overflow-visible" aria-hidden="true"><path d={areaPath} fill={stroke} opacity="0.16" /><polyline points={points} fill="none" stroke={stroke} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" style={{ filter: `drop-shadow(0 0 8px ${stroke}99)` }} /><polyline points={points} fill="none" stroke="#e2e8f0" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" opacity="0.28" /></svg></div>;
}

export function KpiCard({ label, value, helper, href, tone = "blue", series = [] }: { label: string; value: string; helper: string; href: string; tone?: Tone; series?: Array<number | null | undefined> }) {
  const styles = toneStyles[tone];
  return <Link href={href} className={`soc-card group block min-h-36 cursor-pointer border ${styles.border} ${styles.shadow} transition hover:-translate-y-0.5 hover:bg-slate-900/85`}><div className="flex items-start justify-between gap-3"><p className="text-[0.66rem] font-bold uppercase tracking-[0.22em] text-slate-500">{label}</p><span className={`block h-2.5 w-2.5 rounded-full ${styles.bg} shadow-[0_0_18px_currentColor]`} /></div><p className={`mt-3 text-3xl font-black tabular-nums ${styles.text}`}>{value}</p><p className="mt-1 min-h-9 text-xs leading-5 text-slate-400">{helper}</p><Sparkline tone={tone} values={series} /></Link>;
}

export function DonutChart({ title, buckets, param }: { title: string; buckets: CountBucket[] | null | undefined; param: string }) {
  const rows = normalizeBuckets(buckets);
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  const radius = 54;
  const strokeWidth = 22;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;

  return <section className="soc-card"><h2 className="panel-title">{title}</h2><div className="mt-5 grid gap-5 sm:grid-cols-[10rem_1fr] sm:items-center"><Link aria-label={`${title} details`} href="/cves" className="relative grid h-40 w-40 place-items-center rounded-full shadow-2xl shadow-cyan-950/30"><svg viewBox="0 0 160 160" className="absolute inset-0 h-40 w-40 -rotate-90" aria-hidden="true"><circle cx="80" cy="80" r={radius} fill="none" stroke="#334155" strokeWidth={strokeWidth} />{total > 0 && rows.map((row, index) => { const segmentLength = (row.count / total) * circumference; const segmentOffset = offset; offset += segmentLength; return <circle key={`${row.label}-${index}`} cx="80" cy="80" r={radius} fill="none" stroke={colorFor(row.label, index)} strokeWidth={strokeWidth} strokeDasharray={`${segmentLength} ${circumference - segmentLength}`} strokeDashoffset={-segmentOffset} strokeLinecap="butt" />; })}</svg><div className="relative z-10 grid place-items-center rounded-full border border-slate-700/80 bg-[#06101f] text-center" style={{ width: "5.5rem", height: "5.5rem" }}><span className="text-2xl font-black tabular-nums">{formatCount(total)}</span><span className="-mt-6 text-[0.62rem] uppercase tracking-[0.2em] text-slate-500">CVEs</span></div></Link><div className="space-y-2">{rows.length === 0 || total === 0 ? <p className="empty-state">No chart data available.</p> : rows.map((row, index) => <Link href={`/cves?${param}=${encodeURIComponent(row.label)}`} key={row.label} className="grid grid-cols-[0.75rem_1fr_auto] items-center gap-2 rounded-lg px-2 py-1.5 text-sm hover:bg-cyan-400/10"><span className="block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: colorFor(row.label, index) }} /><span className="truncate text-slate-300">{row.label}</span><span className="font-bold tabular-nums text-slate-100">{formatCount(row.count)}</span></Link>)}</div></div></section>;
}

export function BarChart({ title, buckets, param = "", tone = "blue" }: { title: string; buckets: CountBucket[] | null | undefined; param?: string; tone?: Tone }) {
  const rows = normalizeBuckets(buckets).slice(0, 12);
  const max = Math.max(...rows.map((row) => row.count), 0);
  const fill = tone === "purple" ? "#8b5cf6" : "#3b82f6";
  const chartWidth = 420;
  const chartHeight = 220;
  const baseline = 170;
  const maxBarHeight = 150;
  const slotWidth = rows.length > 0 ? chartWidth / rows.length : chartWidth;
  const barWidth = Math.min(34, slotWidth * 0.55);

  return <section className="soc-card"><h2 className="panel-title">{title}</h2><div className="mt-5 border-b border-l border-slate-700/70 px-3 pb-2">{rows.length === 0 || max === 0 ? <div className="flex h-60 items-center"><p className="empty-state w-full">No chart data available.</p></div> : <svg viewBox="0 0 420 220" className="h-60 w-full overflow-visible" role="img" aria-label={title}>{rows.map((row, index) => { const barHeight = row.count > 0 ? Math.max((row.count / max) * maxBarHeight, 4) : 0; const x = slotWidth * index + (slotWidth - barWidth) / 2; const y = baseline - barHeight; const labelY = Math.min(y - 8, baseline - 8); const bucketLabel = row.label.length > 14 ? `${row.label.slice(0, 13)}…` : row.label; const content = <g key={row.label} className="transition hover:opacity-80"><text x={x + barWidth / 2} y={labelY} textAnchor="middle" className="fill-slate-300 text-[10px] font-semibold">{formatCount(row.count)}</text><rect x={x} y={y} width={barWidth} height={barHeight} rx="5" fill={fill} filter={`drop-shadow(0 0 10px ${fill}66)`} /><text x={x + barWidth / 2} y="200" textAnchor="middle" className="fill-slate-400 text-[10px]"><title>{row.label}</title>{bucketLabel}</text></g>; return param ? <Link href={`/cves?${param}=${encodeURIComponent(row.label)}`} key={row.label}>{content}</Link> : content; })}</svg>}</div></section>;
}


function ActionRow({ label, value, tone, href }: { label: string; value: number | null | undefined; tone: string; href?: string }) { const content = <><span className="text-slate-300">{label}</span><span className={`text-lg font-black tabular-nums ${tone}`}>{formatCount(value)}</span></>; return href ? <Link href={href} className="flex cursor-pointer items-center justify-between rounded-xl border border-slate-800/70 bg-slate-950/60 px-3 py-2 transition hover:border-cyan-400/30 hover:bg-cyan-400/10">{content}</Link> : <div className="flex items-center justify-between rounded-xl border border-slate-800/70 bg-slate-950/60 px-3 py-2">{content}</div>; }

function Coverage({ label, value, helper }: { label: string; value: number | null; helper: string }) { const pct = value == null ? 0 : Math.max(0, Math.min(value * 100, 100)); return <div><div className="flex justify-between text-sm"><span className="text-slate-300">{label}</span><span className="font-bold text-emerald-200">{value == null ? "—" : `${pct.toFixed(1)}%`}</span></div><div className="mt-2 h-2 rounded-full bg-slate-800"><div className="h-full rounded-full bg-emerald-400 shadow-[0_0_14px_rgba(52,211,153,0.55)]" style={{ width: `${pct}%` }} /></div><p className="mt-1 text-xs text-slate-500">{helper}</p></div>; }

export function RiskPanel({ stats }: { stats: Stats }) { const total = safeNumber(stats.total_cves); const withoutNvd = Math.max(total - safeNumber(stats.nvd_enriched_cves), 0); return <aside className="space-y-4"><section className="soc-card"><h2 className="panel-title">Immediate Actions</h2><div className="mt-4 space-y-3"><ActionRow href="/cves?severity=Critical" label="Critical CVEs" value={stats.critical_cves} tone="text-rose-300" /><ActionRow href="/cves?epss=high" label="High EPSS CVEs" value={stats.epss_at_least_10_percent} tone="text-orange-300" /><ActionRow href="/kev" label="KEV vulnerabilities" value={stats.total_kev_vulnerabilities} tone="text-violet-300" /><ActionRow href="/cves?nvd=missing" label="Missing NVD coverage" value={withoutNvd} tone="text-cyan-300" /></div></section><CoveragePanel stats={stats} /></aside>; }

export function CoveragePanel({ stats }: { stats: Stats }) { const total = safeNumber(stats.total_cves); const epssCoverage = total > 0 ? safeNumber(stats.epss_enriched_cves) / total : null; const nvdCoverage = total > 0 ? safeNumber(stats.nvd_enriched_cves) / total : null; const impactCoverage = total > 0 ? safeNumber(stats.impact_known_cves) / total : null; return <section className="soc-card"><h2 className="panel-title">Enrichment Coverage</h2><div className="mt-4 space-y-4"><Coverage label="EPSS coverage" value={epssCoverage} helper={`${formatCount(stats.epss_enriched_cves)} EPSS-enriched CVEs`} /><Coverage label="NVD coverage" value={nvdCoverage} helper={`${formatCount(stats.nvd_enriched_cves)} NVD-enriched CVEs`} /><Coverage label="Impact coverage" value={impactCoverage} helper={`${formatCount(stats.impact_known_cves)} CVEs with known impact`} /><ActionRow label="CISA KEV matches" value={stats.total_kev_vulnerabilities} tone="text-violet-300" /></div></section>; }

export function TopEpssTable({ cves }: { cves: TopEpssCve[] | null | undefined }) { const rows = cves ?? []; return <section className="soc-card"><h2 className="panel-title">Top CVEs by EPSS Score</h2>{rows.length === 0 ? <p className="empty-state mt-4">No EPSS-ranked CVEs available.</p> : <div className="mt-4 overflow-x-auto"><table className="data-table"><thead><tr><th>CVE</th><th>Title</th><th>EPSS score</th><th>Percentile</th></tr></thead><tbody>{rows.map((cve) => <tr key={cve.cve_id}><td><Link className="link" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td>{cve.title ?? "Untitled"}</td><td>{formatPct(cve.epss_score)}</td><td>{formatPct(cve.epss_percentile)}</td></tr>)}</tbody></table></div>}</section>; }

export function KevTable({ cves }: { cves: KevCve[] | null | undefined }) { const rows = cves ?? []; return <section className="soc-card"><h2 className="panel-title">Known Exploited Vulnerabilities</h2>{rows.length === 0 ? <p className="empty-state mt-4">No CISA KEV CVEs are available.</p> : <div className="mt-4 overflow-x-auto"><table className="data-table"><thead><tr><th>CVE</th><th>Product</th><th>Severity</th><th>EPSS</th><th>CVSS</th><th>Required action</th><th>Due date</th></tr></thead><tbody>{rows.map((cve) => <tr key={cve.cve_id}><td><Link className="link" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</Link></td><td>{cve.product ?? "Unknown"}</td><td>{cve.severity ?? "Unknown"}</td><td>{formatPct(cve.epss_score)}</td><td>{formatCvss(cve.cvss_score)}</td><td title={cve.required_action ?? undefined}>{formatTruncated(cve.required_action)}</td><td>{cve.due_date ?? "—"}</td></tr>)}</tbody></table></div>}</section>; }
