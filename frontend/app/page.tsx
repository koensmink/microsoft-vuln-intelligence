import { getJson } from '../src/api';
type Cve = { severity?: string; exploited: boolean };
export default async function Dashboard() {
  const cves = await getJson<Cve[]>('/cves', []);
  const releases = await getJson<{release_name: string}[]>('/releases', []);
  const stats = [{label:'Total CVEs', value:cves.length},{label:'Critical', value:cves.filter(c=>c.severity==='Critical').length},{label:'Important', value:cves.filter(c=>c.severity==='Important').length},{label:'Exploited', value:cves.filter(c=>c.exploited).length},{label:'Latest release', value:releases[0]?.release_name ?? 'No data'}];
  return <section><h1 className="mb-6 text-3xl font-bold">Dashboard</h1><div className="grid gap-4 md:grid-cols-5">{stats.map(s=><div className="card" key={s.label}><p className="text-sm text-slate-400">{s.label}</p><p className="mt-2 text-2xl font-semibold">{s.value}</p></div>)}</div></section>;
}
