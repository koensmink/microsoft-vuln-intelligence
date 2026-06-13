import { getJson } from '../../src/api';

type Cve = {
  cve_id: string;
  severity?: string;
  impact?: string;
  exploited: boolean;
  publicly_disclosed: boolean;
  release?: { release_name: string };
};

export default async function Vulnerabilities({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const params = await searchParams;
  const query = new URLSearchParams();
  for (const key of ['severity', 'product', 'exploited', 'publicly_disclosed']) {
    if (params[key]) query.set(key, params[key]!);
  }
  const cves = await getJson<Cve[]>(`/cves${query.toString() ? `?${query}` : ''}`, []);
  const search = (params.search ?? '').toLowerCase();
  const rows = search ? cves.filter((cve) => cve.cve_id.toLowerCase().includes(search) || (cve.impact ?? '').toLowerCase().includes(search)) : cves;
  return <section className="space-y-4"><h1 className="text-3xl font-bold">Vulnerabilities</h1><form className="card grid gap-3 md:grid-cols-5"><input className="rounded bg-slate-950 p-2" name="search" placeholder="Search CVE or impact" defaultValue={params.search} /><input className="rounded bg-slate-950 p-2" name="severity" placeholder="Severity" defaultValue={params.severity} /><input className="rounded bg-slate-950 p-2" name="product" placeholder="Product" defaultValue={params.product} /><select className="rounded bg-slate-950 p-2" name="exploited" defaultValue={params.exploited ?? ''}><option value="">Exploited?</option><option value="true">true</option><option value="false">false</option></select><button className="rounded bg-blue-600 p-2 font-semibold">Filter</button></form><div className="card overflow-x-auto"><table className="w-full text-left text-sm"><thead className="text-slate-400"><tr><th className="p-2">CVE</th><th>Severity</th><th>Impact</th><th>Release</th><th>Exploited</th><th>Publicly disclosed</th></tr></thead><tbody>{rows.map((cve) => <tr className="border-t border-slate-800" key={cve.cve_id}><td className="p-2"><a className="text-blue-300" href={`/cves/${cve.cve_id}`}>{cve.cve_id}</a></td><td>{cve.severity ?? '-'}</td><td>{cve.impact ?? '-'}</td><td>{cve.release?.release_name ?? '-'}</td><td>{String(cve.exploited)}</td><td>{String(cve.publicly_disclosed)}</td></tr>)}</tbody></table></div></section>;
}
