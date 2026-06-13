import { getJson } from '../../../src/api';
export default async function CveDetails({ params }: { params: Promise<{ cve_id: string }> }) {
  const { cve_id } = await params;
  const cve = await getJson<any>(`/cves/${cve_id}`, { cve_id, affected_products: [], remediations: [] });
  return <article className="space-y-4"><h1 className="text-3xl font-bold">{cve.cve_id}</h1><div className="card"><p>{cve.description ?? 'No description loaded yet.'}</p><dl className="mt-4 grid gap-2 md:grid-cols-4"><dt>Severity</dt><dd>{cve.severity ?? '-'}</dd><dt>Impact</dt><dd>{cve.impact ?? '-'}</dd><dt>CVSS</dt><dd>{cve.cvss_score ?? '-'}</dd><dt>Exploited</dt><dd>{String(Boolean(cve.exploited))}</dd></dl></div><section className="card"><h2 className="font-semibold">Affected products</h2><ul>{cve.affected_products?.map((p:any)=><li key={p.id}>{p.product?.name} {p.kb_article}</li>)}</ul></section><section className="card"><h2 className="font-semibold">Remediations</h2><ul>{cve.remediations?.map((r:any)=><li key={r.id}>{r.description ?? r.url}</li>)}</ul></section></article>;
}
