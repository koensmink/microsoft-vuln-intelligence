import { getJson } from "../../../src/api";

export default async function CveDetails({ params }: { params: Promise<{ cve_id: string }> }) {
  const { cve_id } = await params;
  const cve = await getJson<any>(`/cves/${cve_id}`, { cve_id, affected_products: [], remediations: [] });
  return (
    <article className="space-y-4">
      <h1 className="text-3xl font-bold">{cve.cve_id}</h1>
      <div className="card"><h2 className="text-xl font-semibold">{cve.title}</h2><p>{cve.description ?? "No description loaded yet."}</p><p className="mt-2 text-slate-400">Release: {cve.release?.release_name ?? "-"}</p></div>
      <section className="card"><h2 className="font-semibold">Affected products</h2><table className="mt-3 w-full text-left text-sm"><thead><tr><th>Product</th><th>ProductID</th><th>Severity</th><th>Impact</th><th>CVSS</th><th>Vector</th></tr></thead><tbody>{cve.affected_products?.map((p:any)=><tr key={p.id} className="border-t border-slate-800"><td>{p.product?.name}</td><td>{p.product?.product_id}</td><td>{p.severity ?? "-"}</td><td>{p.impact ?? "-"}</td><td>{p.cvss_base_score ?? "-"}</td><td>{p.cvss_vector ?? "-"}</td></tr>)}</tbody></table>{cve.affected_products?.map((p:any)=><p key={`why-${p.id}`} className="mt-2 text-slate-400">Included because MSRC maps this CVE to the following Microsoft product/context: {p.product?.name}</p>)}</section>
      <section className="card"><h2 className="font-semibold">Remediations</h2><ul>{cve.remediations?.map((r:any)=><li key={r.id}>{r.product?.name ? `${r.product.name}: ` : ""}{r.description ?? r.url}{r.url ? <a className="ml-2 text-blue-400" href={r.url}>URL</a> : null}</li>)}</ul></section>
    </article>
  );
}
