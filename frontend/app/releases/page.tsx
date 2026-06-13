import { getJson } from '../../src/api';
export default async function Releases(){const releases=await getJson<any[]>('/releases',[]);return <section><h1 className="mb-4 text-3xl font-bold">Releases</h1><div className="card"><ul>{releases.map(r=><li key={r.id} className="border-b border-slate-800 py-2">{r.release_name} — {r.document_title}</li>)}</ul></div></section>}
