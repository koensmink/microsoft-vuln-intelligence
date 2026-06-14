import { getJson } from "../../../src/api";

function pct(value: number | null) {
  return value == null ? "-" : `${(value * 100).toFixed(1)}%`;
}

export default async function CveDetails({ params }: { params: Promise<{ cve_id: string }> }) {
  const { cve_id } = await params;
  const cve = await getJson<any>(`/cves/${cve_id}`, { cve_id, affected_products: [], remediations: [] });
  return (
    <article className="space-y-4">
      <h1 className="text-3xl font-bold">{cve.cve_id}</h1>
      <div className="card"><h2 className="text-xl font-semibold">{cve.title}</h2><p>{cve.description ?? "No description loaded yet."}</p><p className="mt-2 text-slate-400">Release: {cve.release?.release_name ?? "-"}</p></div>
      <section className="card">
        <h2 className="font-semibold">Enrichment details</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div className="rounded border border-slate-800 p-3"><h3 className="font-semibold text-blue-300">FIRST EPSS</h3><p>Score: {pct(cve.epss_score)}</p><p>Percentile: {pct(cve.epss_percentile)}</p></div>
          <div className="rounded border border-slate-800 p-3"><h3 className="font-semibold text-red-300">CISA KEV</h3><p>Status: {cve.kev_known_exploited ? <span className="rounded bg-red-600 px-2 py-1 text-xs font-bold text-white">Known exploited</span> : "Not listed"}</p><p>Due date: {cve.kev_due_date ?? "-"}</p><p>Vendor/project: {cve.kev_vendor_project ?? "-"}</p><p>Product: {cve.kev_product ?? "-"}</p><p>Required action: {cve.kev_required_action ?? "-"}</p></div>
          <div className="rounded border border-slate-800 p-3"><h3 className="font-semibold text-emerald-300">NVD</h3>{cve.nvd_cvss_score == null ? <p>No NVD CVSS enrichment available.</p> : <><p>CVSS: {cve.nvd_cvss_score}</p><p>Vector: {cve.nvd_cvss_vector ?? "-"}</p></>}</div>
        </div>
      </section>
      <section className="card"><h2 className="font-semibold">Affected products</h2><table className="mt-3 w-full text-left text-sm"><thead><tr><th>Product</th><th>ProductID</th><th>Severity</th><th>Impact</th><th>MSRC CVSS</th><th>Vector</th></tr></thead><tbody>{cve.affected_products?.map((p:any)=><tr key={p.id} className="border-t border-slate-800"><td>{p.product?.name}</td><td>{p.product?.product_id}</td><td>{p.severity ?? "-"}</td><td>{p.impact ?? "-"}</td><td>{p.cvss_base_score ?? "-"}</td><td>{p.cvss_vector ?? "-"}</td></tr>)}</tbody></table>{cve.affected_products?.map((p:any)=><p key={`why-${p.id}`} className="mt-2 text-slate-400">Included because MSRC maps this CVE to the following Microsoft product/context: {p.product?.name}</p>)}</section>
      <section className="card"><h2 className="font-semibold">Remediations</h2><ul>{cve.remediations?.map((r:any)=><li key={r.id}>{r.product?.name ? `${r.product.name}: ` : ""}{r.description ?? r.url}{r.url ? <a className="ml-2 text-blue-400" href={r.url}>URL</a> : null}</li>)}</ul></section>
    </article>
  );
}
